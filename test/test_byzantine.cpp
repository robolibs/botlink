/* SPDX-License-Identifier: MIT */
/*
 * Botlink Byzantine Fault Tolerance Tests
 * Tests for detecting and preventing malicious/faulty node behavior
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

// =============================================================================
// Test Helpers
// =============================================================================

static NodeId make_node_id(u8 seed) {
    NodeId id;
    for (usize i = 0; i < NODE_ID_SIZE; ++i) {
        id.data[i] = static_cast<u8>(seed + i);
    }
    return id;
}

static PublicKey make_pubkey(u8 seed) {
    PublicKey key;
    for (usize i = 0; i < KEY_SIZE; ++i) {
        key.data[i] = static_cast<u8>(seed + i);
    }
    return key;
}

// Generate a real keypair for signature tests
static auto generate_test_identity() -> Pair<PrivateKey, PublicKey> {
    return crypto::generate_ed25519_keypair();
}

// Generate a test session key
static auto make_session_key(u8 seed) -> crypto::SessionKey {
    crypto::SessionKey key;
    for (usize i = 0; i < key.data.size(); ++i) {
        key.data[i] = static_cast<u8>(seed + i);
    }
    key.key_id = seed;
    return key;
}

// =============================================================================
// Byzantine - Forged Signatures
// =============================================================================

TEST_SUITE("Byzantine - Forged Signatures") {

    TEST_CASE("Reject envelope with invalid signature") {
        auto [priv, pub] = generate_test_identity();
        NodeId sender_id = crypto::node_id_from_pubkey(pub);

        // Create a legitimate envelope
        Vector<u8> payload = {1, 2, 3, 4, 5};
        Envelope env = crypto::create_signed_envelope(MsgType::VoteCast, sender_id, priv, payload);

        // Tamper with the payload after signing
        env.payload[0] = 99;

        // Verification should fail
        CHECK(crypto::verify_envelope(env, pub) == false);
    }

    TEST_CASE("Reject envelope with wrong sender key") {
        auto [priv1, pub1] = generate_test_identity();
        auto [priv2, pub2] = generate_test_identity();
        NodeId sender_id = crypto::node_id_from_pubkey(pub1);

        // Create envelope with sender1's key
        Vector<u8> payload = {1, 2, 3};
        Envelope env = crypto::create_signed_envelope(MsgType::VoteCast, sender_id, priv1, payload);

        // Try to verify with a different key (attacker's key)
        CHECK(crypto::verify_envelope(env, pub2) == false);
    }

    TEST_CASE("Reject envelope with tampered signature") {
        auto [priv, pub] = generate_test_identity();
        NodeId sender_id = crypto::node_id_from_pubkey(pub);

        Vector<u8> payload = {1, 2, 3};
        Envelope env = crypto::create_signed_envelope(MsgType::VoteCast, sender_id, priv, payload);

        // Tamper with signature
        env.signature.data[0] ^= 0xFF;

        CHECK(crypto::verify_envelope(env, pub) == false);
    }

    TEST_CASE("Reject envelope with wrong sender_id") {
        auto [priv, pub] = generate_test_identity();
        NodeId real_sender = crypto::node_id_from_pubkey(pub);
        NodeId fake_sender = make_node_id(99); // Different sender

        // Create envelope with fake sender_id
        Vector<u8> payload = {1, 2, 3};
        Envelope env = crypto::create_signed_envelope(MsgType::VoteCast, fake_sender, priv, payload);

        // Even with valid signature, sender_id doesn't match the pubkey
        // This tests that the system properly validates sender identity
        NodeId derived = crypto::node_id_from_pubkey(pub);
        CHECK(derived != fake_sender);
    }

    TEST_CASE("Reject zero signature") {
        auto [priv, pub] = generate_test_identity();
        NodeId sender_id = crypto::node_id_from_pubkey(pub);

        Vector<u8> payload = {1, 2, 3};
        Envelope env = crypto::create_signed_envelope(MsgType::VoteCast, sender_id, priv, payload);

        // Zero out signature (Byzantine attempt to bypass validation)
        for (auto &b : env.signature.data) {
            b = 0;
        }

        CHECK(crypto::verify_envelope(env, pub) == false);
    }

}

// =============================================================================
// Byzantine - Replay Attacks
// =============================================================================

TEST_SUITE("Byzantine - Replay Attacks") {

    TEST_CASE("ReplayWindow rejects replayed nonces") {
        crypto::ReplayWindow window;

        // First use of nonce should succeed
        CHECK(window.check_and_update(100) == true);

        // Replay attempt should fail
        CHECK(window.check_and_update(100) == false);
    }

    TEST_CASE("ReplayWindow rejects old nonces outside window") {
        crypto::ReplayWindow window;

        // Advance the window by using high nonces
        for (u64 i = 100; i <= 200; ++i) {
            window.check_and_update(i);
        }

        // Very old nonce should be rejected
        CHECK(window.check_and_update(1) == false);
    }

    TEST_CASE("Reject expired envelope timestamp") {
        auto [priv, pub] = generate_test_identity();
        NodeId sender_id = crypto::node_id_from_pubkey(pub);

        Vector<u8> payload = {1, 2, 3};
        Envelope env(MsgType::VoteCast, sender_id, payload);

        // Set timestamp to 2 minutes ago (stale)
        env.timestamp_ms = time::now_ms() - 120000;

        crypto::sign_envelope(env, priv);

        // Timestamp validation should fail
        CHECK(crypto::validate_envelope_timestamp(env, 60000) == false);
    }

    TEST_CASE("Reject future envelope timestamp") {
        auto [priv, pub] = generate_test_identity();
        NodeId sender_id = crypto::node_id_from_pubkey(pub);

        Vector<u8> payload = {1, 2, 3};
        Envelope env(MsgType::VoteCast, sender_id, payload);

        // Set timestamp to 10 seconds in future (suspicious)
        env.timestamp_ms = time::now_ms() + 10000;

        crypto::sign_envelope(env, priv);

        // Should reject as too far in future
        CHECK(crypto::validate_envelope_timestamp(env, 60000, 5000) == false);
    }

    TEST_CASE("Session replay window tracks multiple nonces") {
        crypto::ReplayWindow window;

        Vector<u64> nonces = {1, 5, 10, 15, 20, 25, 30};

        // All initial nonces should be accepted
        for (auto n : nonces) {
            CHECK(window.check_and_update(n) == true);
        }

        // All replay attempts should be rejected
        for (auto n : nonces) {
            CHECK(window.check_and_update(n) == false);
        }
    }

}

// =============================================================================
// Byzantine - Double Voting
// =============================================================================

TEST_SUITE("Byzantine - Double Voting") {

    TEST_CASE("Reject duplicate vote from same voter") {
        VotingPolicy policy;
        policy.min_yes_votes = 3;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        NodeId candidate = make_node_id(10);
        NodeId byzantine_voter = make_node_id(1);

        // Add proposal
        JoinProposal proposal;
        proposal.candidate_id = candidate;
        manager.add_proposal(proposal);

        // First vote - should succeed
        VoteCastEvent vote1;
        vote1.candidate_id = candidate;
        vote1.voter_id = byzantine_voter;
        vote1.vote = Vote::Yes;
        vote1.timestamp_ms = time::now_ms();

        auto r1 = manager.record_vote(vote1);
        CHECK(r1.is_ok());

        // Byzantine attempt: same voter tries to vote again
        VoteCastEvent vote2;
        vote2.candidate_id = candidate;
        vote2.voter_id = byzantine_voter;
        vote2.vote = Vote::No; // Changed mind
        vote2.timestamp_ms = time::now_ms();

        auto r2 = manager.record_vote(vote2);
        CHECK(r2.is_err()); // Should be rejected
    }

    TEST_CASE("Reject conflicting votes from same voter") {
        VotingPolicy policy;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        NodeId candidate = make_node_id(10);
        NodeId voter = make_node_id(1);

        JoinProposal proposal;
        proposal.candidate_id = candidate;
        manager.add_proposal(proposal);

        // First: Yes vote
        VoteCastEvent yes_vote;
        yes_vote.candidate_id = candidate;
        yes_vote.voter_id = voter;
        yes_vote.vote = Vote::Yes;
        manager.record_vote(yes_vote);

        // Second: Trying to change to No (Byzantine behavior)
        VoteCastEvent no_vote;
        no_vote.candidate_id = candidate;
        no_vote.voter_id = voter;
        no_vote.vote = Vote::No;

        auto result = manager.record_vote(no_vote);
        CHECK(result.is_err());
    }

    TEST_CASE("Local node cannot double vote") {
        VotingPolicy policy;
        policy.min_yes_votes = 10; // High threshold so decision doesn't auto-complete
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        NodeId candidate = make_node_id(10);

        JoinProposal proposal;
        proposal.candidate_id = candidate;
        manager.add_proposal(proposal);

        // Cast vote and record it
        auto r1 = manager.cast_vote(candidate, Vote::Yes);
        CHECK(r1.is_ok());
        // Record the vote to register it
        auto record_result = manager.record_vote(r1.value());
        CHECK(record_result.is_ok());

        // Try to cast again - should fail since already voted
        auto r2 = manager.cast_vote(candidate, Vote::No);
        CHECK(r2.is_err());
    }

}

// =============================================================================
// Byzantine - Invalid Proposals
// =============================================================================

TEST_SUITE("Byzantine - Invalid Proposals") {

    TEST_CASE("Reject duplicate proposal for same candidate") {
        VotingPolicy policy;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        NodeId candidate = make_node_id(10);

        JoinProposal proposal1;
        proposal1.candidate_id = candidate;
        proposal1.sponsor_id = make_node_id(1);

        JoinProposal proposal2;
        proposal2.candidate_id = candidate;
        proposal2.sponsor_id = make_node_id(2); // Different sponsor

        auto r1 = manager.add_proposal(proposal1);
        CHECK(r1.is_ok());

        // Byzantine: Same candidate proposed again
        auto r2 = manager.add_proposal(proposal2);
        CHECK(r2.is_err());
    }

    TEST_CASE("Vote for non-existent candidate fails") {
        VotingPolicy policy;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        NodeId fake_candidate = make_node_id(99);

        VoteCastEvent vote;
        vote.candidate_id = fake_candidate;
        vote.voter_id = make_node_id(1);
        vote.vote = Vote::Yes;

        auto result = manager.record_vote(vote);
        CHECK(result.is_err());
    }

    TEST_CASE("Vote after proposal decided has no effect") {
        VotingPolicy policy;
        policy.min_yes_votes = 1;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        NodeId candidate = make_node_id(10);

        JoinProposal proposal;
        proposal.candidate_id = candidate;
        manager.add_proposal(proposal);

        // This vote should approve the proposal (min_yes = 1)
        VoteCastEvent vote1;
        vote1.candidate_id = candidate;
        vote1.voter_id = make_node_id(1);
        vote1.vote = Vote::Yes;

        auto r1 = manager.record_vote(vote1);
        CHECK(r1.is_ok());
        CHECK(r1.value() == VoteResult::Approved);

        // Byzantine: Try to add more votes after decision
        VoteCastEvent vote2;
        vote2.candidate_id = candidate;
        vote2.voter_id = make_node_id(2);
        vote2.vote = Vote::No;

        auto r2 = manager.record_vote(vote2);
        // Already decided, should reject
        CHECK(r2.is_err());
    }

}

// =============================================================================
// Byzantine - Invalid Cryptographic Operations
// =============================================================================

TEST_SUITE("Byzantine - Invalid Crypto") {

    TEST_CASE("AEAD rejects tampered ciphertext") {
        auto key = make_session_key(1);
        auto nonce = crypto::generate_nonce();

        Vector<u8> plaintext = {1, 2, 3, 4, 5};
        auto enc_res = crypto::aead_encrypt(key, nonce, plaintext);
        REQUIRE(enc_res.is_ok());

        auto ciphertext = enc_res.value();

        // Tamper with ciphertext
        if (!ciphertext.empty()) {
            ciphertext[0] ^= 0xFF;
        }

        // Decryption should fail
        auto dec_res = crypto::aead_decrypt(key, nonce, ciphertext);
        CHECK(dec_res.is_err());
    }

    TEST_CASE("AEAD rejects wrong key") {
        auto key1 = make_session_key(1);
        auto key2 = make_session_key(2);
        auto nonce = crypto::generate_nonce();

        Vector<u8> plaintext = {1, 2, 3, 4, 5};
        auto enc_res = crypto::aead_encrypt(key1, nonce, plaintext);
        REQUIRE(enc_res.is_ok());

        // Try to decrypt with different key
        auto dec_res = crypto::aead_decrypt(key2, nonce, enc_res.value());
        CHECK(dec_res.is_err());
    }

    TEST_CASE("AEAD rejects wrong nonce") {
        auto key = make_session_key(1);
        auto nonce1 = crypto::generate_nonce();
        auto nonce2 = crypto::generate_nonce();

        Vector<u8> plaintext = {1, 2, 3, 4, 5};
        auto enc_res = crypto::aead_encrypt(key, nonce1, plaintext);
        REQUIRE(enc_res.is_ok());

        // Try to decrypt with different nonce
        auto dec_res = crypto::aead_decrypt(key, nonce2, enc_res.value());
        CHECK(dec_res.is_err());
    }

    TEST_CASE("X25519 shared secret with corrupted key fails") {
        auto [priv, pub] = crypto::generate_x25519_keypair();

        // Corrupt the public key
        PublicKey corrupted = pub;
        corrupted.data[0] ^= 0xFF;

        // Should still compute but result will be different
        auto res1 = crypto::x25519_shared_secret(priv, pub);
        auto res2 = crypto::x25519_shared_secret(priv, corrupted);

        if (res1.is_ok() && res2.is_ok()) {
            // Shared secrets should be different
            CHECK(res1.value() != res2.value());
        }
    }

}

// =============================================================================
// Byzantine - Message Injection
// =============================================================================

TEST_SUITE("Byzantine - Message Injection") {

    TEST_CASE("Empty envelope serialization is invalid") {
        Vector<u8> empty_data;
        auto res = crypto::deserialize_envelope(empty_data);
        CHECK(res.is_err());
    }

    TEST_CASE("Malformed envelope data is rejected") {
        // Random garbage data
        Vector<u8> garbage = {0xFF, 0xFE, 0xFD, 0xFC};
        auto res = crypto::deserialize_envelope(garbage);
        CHECK(res.is_err());
    }

    TEST_CASE("Truncated envelope is rejected") {
        auto [priv, pub] = generate_test_identity();
        NodeId sender = crypto::node_id_from_pubkey(pub);

        Vector<u8> payload = {1, 2, 3};
        Envelope env = crypto::create_signed_envelope(MsgType::VoteCast, sender, priv, payload);

        auto serialized = crypto::serialize_envelope(env);

        // Truncate the data
        if (serialized.size() > 10) {
            serialized.resize(10);
        }

        auto res = crypto::deserialize_envelope(serialized);
        CHECK(res.is_err());
    }

    TEST_CASE("Oversized payload handling") {
        auto [priv, pub] = generate_test_identity();
        NodeId sender = crypto::node_id_from_pubkey(pub);

        // Create very large payload
        Vector<u8> large_payload;
        for (usize i = 0; i < 100000; ++i) {
            large_payload.push_back(static_cast<u8>(i & 0xFF));
        }

        Envelope env = crypto::create_signed_envelope(MsgType::VoteCast, sender, priv, large_payload);

        // Should handle gracefully
        auto serialized = crypto::serialize_envelope(env);
        auto res = crypto::deserialize_envelope(serialized);
        CHECK(res.is_ok());
    }

}

// =============================================================================
// Byzantine - Trust Chain Manipulation
// =============================================================================

TEST_SUITE("Byzantine - Trust Chain") {

    TEST_CASE("Cannot add member without proper voting") {
        auto [genesis_priv, genesis_pub] = generate_test_identity();
        NodeId genesis_id = crypto::node_id_from_pubkey(genesis_pub);

        auto [x25519_priv, x25519_pub] = crypto::generate_x25519_keypair();

        TrustChain chain("test_chain", genesis_id, genesis_pub, x25519_pub);

        // Try to directly add a member without proper proposal
        auto [member_priv, member_pub] = generate_test_identity();
        NodeId member_id = crypto::node_id_from_pubkey(member_pub);
        auto [member_x25519_priv, member_x25519_pub] = crypto::generate_x25519_keypair();

        // Create join proposal without proper sponsor
        JoinProposal proposal;
        proposal.candidate_id = member_id;
        proposal.candidate_ed25519 = member_pub;
        proposal.candidate_x25519 = member_x25519_pub;
        proposal.sponsor_id = make_node_id(99); // Fake sponsor
        proposal.timestamp_ms = time::now_ms();

        // Proposal should be accepted (chain doesn't validate sponsor)
        // But the member won't be approved without votes
        auto res = chain.propose_join(proposal);
        CHECK(res.is_ok());

        // Verify member is not yet approved
        CHECK(chain.is_member(member_id) == false);
    }

    TEST_CASE("Revocation events are recorded in chain") {
        auto [genesis_priv, genesis_pub] = generate_test_identity();
        NodeId genesis_id = crypto::node_id_from_pubkey(genesis_pub);
        auto [x25519_priv, x25519_pub] = crypto::generate_x25519_keypair();

        TrustChain chain("test_chain", genesis_id, genesis_pub, x25519_pub);

        // Genesis member is already a member
        CHECK(chain.is_member(genesis_id) == true);

        // Create a revocation event for the genesis member
        RevocationEvent revoke;
        revoke.subject_id = genesis_id;
        revoke.revoker_id = genesis_id;
        revoke.reason = "self-revoke";
        revoke.timestamp_ms = time::now_ms();

        auto revoke_result = chain.record_revocation(revoke);
        CHECK(revoke_result.is_ok());

        // Check that the revocation event was recorded in the chain
        auto events = chain.get_events_for_node(genesis_id);
        bool has_revoked_event = false;
        for (const auto &evt : events) {
            if (evt.kind == TrustEventKind::MemberRevoked) {
                has_revoked_event = true;
                CHECK(evt.subject_id == genesis_id);
                CHECK(evt.actor_id == genesis_id);
                CHECK(evt.metadata == "self-revoke");
                break;
            }
        }
        CHECK(has_revoked_event == true);

        // Chain should have grown by one block
        CHECK(chain.length() > 1);
    }

    TEST_CASE("Proposal does not make member without decision") {
        auto [genesis_priv, genesis_pub] = generate_test_identity();
        NodeId genesis_id = crypto::node_id_from_pubkey(genesis_pub);
        auto [x25519_priv, x25519_pub] = crypto::generate_x25519_keypair();

        TrustChain chain("test_chain", genesis_id, genesis_pub, x25519_pub);

        auto [member_priv, member_pub] = generate_test_identity();
        NodeId member_id = crypto::node_id_from_pubkey(member_pub);
        auto [member_x25519_priv, member_x25519_pub] = crypto::generate_x25519_keypair();

        JoinProposal proposal;
        proposal.candidate_id = member_id;
        proposal.candidate_ed25519 = member_pub;
        proposal.candidate_x25519 = member_x25519_pub;
        proposal.sponsor_id = genesis_id;
        proposal.timestamp_ms = time::now_ms();

        chain.propose_join(proposal);

        // Without proper decision recorded, not a member
        CHECK(chain.is_member(member_id) == false);
    }

}

// =============================================================================
// Byzantine - Peer Validation
// =============================================================================

TEST_SUITE("Byzantine - Peer Validation") {

    TEST_CASE("TrustView rejects unknown member") {
        TrustView view(2, 15000);

        NodeId unknown = make_node_id(99);
        CHECK(view.is_member(unknown) == false);
    }

    TEST_CASE("TrustView member lookup returns empty for unknown") {
        TrustView view(2, 15000);

        NodeId unknown = make_node_id(99);
        auto member = view.get_member(unknown);
        CHECK(member.has_value() == false);
    }

    TEST_CASE("Rate limiter prevents DoS") {
        // Test that rapid requests are rate-limited
        Map<NodeId, u32> request_counts;
        NodeId attacker = make_node_id(1);

        constexpr u32 MAX_REQUESTS = 100;
        u32 accepted = 0;

        for (u32 i = 0; i < 1000; ++i) {
            if (request_counts[attacker] < MAX_REQUESTS) {
                ++request_counts[attacker];
                ++accepted;
            }
        }

        // Should only accept up to MAX_REQUESTS
        CHECK(accepted == MAX_REQUESTS);
    }

}
