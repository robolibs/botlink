/* SPDX-License-Identifier: MIT */
/*
 * Botlink Integration Tests
 * End-to-end tests for handshake, replay protection, and voting
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

// =============================================================================
// Test Fixtures
// =============================================================================

struct TestNode {
    NodeId id;
    PrivateKey ed25519_priv;
    PublicKey ed25519_pub;
    PrivateKey x25519_priv;
    PublicKey x25519_pub;

    TestNode() {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        ed25519_priv = ed_priv;
        ed25519_pub = ed_pub;
        x25519_priv = x_priv;
        x25519_pub = x_pub;
        id = crypto::node_id_from_pubkey(ed_pub);
    }
};

// =============================================================================
// Handshake Flow Tests
// =============================================================================

TEST_SUITE("Integration - Handshake Flow") {

    TEST_CASE("Key exchange produces matching shared secrets") {
        TestNode alice;
        TestNode bob;

        // Alice generates ephemeral key
        auto [alice_eph_priv, alice_eph_pub] = crypto::generate_x25519_keypair();

        // Bob generates ephemeral key
        auto [bob_eph_priv, bob_eph_pub] = crypto::generate_x25519_keypair();

        // Alice computes shared secret with Bob's ephemeral
        auto alice_shared = crypto::x25519_shared_secret(alice_eph_priv, bob_eph_pub);
        REQUIRE(alice_shared.is_ok());

        // Bob computes shared secret with Alice's ephemeral
        auto bob_shared = crypto::x25519_shared_secret(bob_eph_priv, alice_eph_pub);
        REQUIRE(bob_shared.is_ok());

        // Shared secrets should match
        CHECK(alice_shared.value() == bob_shared.value());
    }

    TEST_CASE("Session key derivation produces correct initiator/responder keys") {
        TestNode alice;
        TestNode bob;

        // Simulate shared secret from DH exchange
        Array<u8, 32> shared_secret;
        randombytes_buf(shared_secret.data(), 32);

        // Alice is initiator
        auto [alice_send, alice_recv] = crypto::derive_initiator_keys(shared_secret, alice.id, bob.id, 1);

        // Bob is responder
        auto [bob_send, bob_recv] = crypto::derive_responder_keys(shared_secret, alice.id, bob.id, 1);

        // Alice's send key should match Bob's recv key
        CHECK(alice_send.data == bob_recv.data);

        // Alice's recv key should match Bob's send key
        CHECK(alice_recv.data == bob_send.data);

        // Keys should not be the same (directional)
        CHECK(alice_send.data != alice_recv.data);
    }

    TEST_CASE("Full handshake simulation") {
        TestNode alice;
        TestNode bob;

        // Step 1: Alice creates handshake init
        auto [alice_eph_priv, alice_eph_pub] = crypto::generate_x25519_keypair();
        net::HandshakeInit init;
        init.initiator_id = alice.id;
        init.initiator_x25519 = alice_eph_pub;
        init.timestamp_ms = time::now_ms();
        init.nonce = crypto::generate_nonce();

        // Step 2: Bob receives init and creates response
        auto [bob_eph_priv, bob_eph_pub] = crypto::generate_x25519_keypair();

        // Bob computes shared secret
        auto bob_shared = crypto::x25519_shared_secret(bob_eph_priv, init.initiator_x25519);
        REQUIRE(bob_shared.is_ok());

        // Bob derives keys (as responder)
        auto [bob_send, bob_recv] = crypto::derive_responder_keys(bob_shared.value(), alice.id, bob.id, 1);

        // Bob creates response
        net::HandshakeResp resp;
        resp.responder_id = bob.id;
        resp.responder_x25519 = bob_eph_pub;
        resp.timestamp_ms = time::now_ms();
        resp.nonce = crypto::generate_nonce();

        // Step 3: Alice receives response
        auto alice_shared = crypto::x25519_shared_secret(alice_eph_priv, resp.responder_x25519);
        REQUIRE(alice_shared.is_ok());

        // Alice derives keys (as initiator)
        auto [alice_send, alice_recv] = crypto::derive_initiator_keys(alice_shared.value(), alice.id, bob.id, 1);

        // Verify keys match
        CHECK(alice_send.data == bob_recv.data);
        CHECK(alice_recv.data == bob_send.data);

        // Step 4: Test encrypted communication
        Vector<u8> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
        auto nonce = crypto::generate_nonce();

        auto enc = crypto::aead_encrypt(alice_send, nonce, plaintext);
        REQUIRE(enc.is_ok());

        auto dec = crypto::aead_decrypt(bob_recv, nonce, enc.value());
        REQUIRE(dec.is_ok());

        CHECK(dec.value() == plaintext);
    }
}

// =============================================================================
// Replay Attack Tests
// =============================================================================

TEST_SUITE("Integration - Replay Protection") {

    TEST_CASE("Replay window rejects duplicate nonces") {
        crypto::ReplayWindow window;

        // First packet should be accepted
        CHECK(window.check_and_update(1));
        CHECK(window.check_and_update(2));
        CHECK(window.check_and_update(3));

        // Replay of same nonces should be rejected
        CHECK_FALSE(window.check_and_update(1));
        CHECK_FALSE(window.check_and_update(2));
        CHECK_FALSE(window.check_and_update(3));

        // New nonces should still be accepted
        CHECK(window.check_and_update(4));
        CHECK(window.check_and_update(5));
    }

    TEST_CASE("Replay window handles out-of-order packets") {
        crypto::ReplayWindow window;

        // Receive packets out of order
        CHECK(window.check_and_update(5));
        CHECK(window.check_and_update(3));
        CHECK(window.check_and_update(7));
        CHECK(window.check_and_update(1));

        // Replays should be rejected
        CHECK_FALSE(window.check_and_update(5));
        CHECK_FALSE(window.check_and_update(3));

        // Later packets should still work
        CHECK(window.check_and_update(10));
    }

    TEST_CASE("Replay window handles window advancement") {
        crypto::ReplayWindow window;

        // Accept initial packets
        CHECK(window.check_and_update(1));
        CHECK(window.check_and_update(2));

        // Large jump advances window
        CHECK(window.check_and_update(100));

        // Old packets (outside window) should be rejected
        CHECK_FALSE(window.check_and_update(1));
        CHECK_FALSE(window.check_and_update(2));

        // Packets within new window should work
        CHECK(window.check_and_update(99));
        CHECK(window.check_and_update(101));
    }

    TEST_CASE("Simulated replay attack scenario") {
        TestNode alice;
        TestNode bob;

        // Setup session keys
        Array<u8, 32> shared_secret;
        randombytes_buf(shared_secret.data(), 32);
        auto [alice_send, alice_recv] = crypto::derive_initiator_keys(shared_secret, alice.id, bob.id, 1);
        auto [bob_send, bob_recv] = crypto::derive_responder_keys(shared_secret, alice.id, bob.id, 1);

        // Bob's replay window
        crypto::ReplayWindow bob_window;

        // Alice sends packet with nonce counter 1
        u64 nonce_counter_1 = 1;
        auto nonce1 = crypto::nonce_from_counter(nonce_counter_1);
        Vector<u8> msg1 = {0x01, 0x02, 0x03};
        auto enc1 = crypto::aead_encrypt(alice_send, nonce1, msg1);
        REQUIRE(enc1.is_ok());

        // Bob receives and processes packet 1
        CHECK(bob_window.check_and_update(nonce_counter_1));
        auto dec1 = crypto::aead_decrypt(bob_recv, nonce1, enc1.value());
        REQUIRE(dec1.is_ok());
        CHECK(dec1.value() == msg1);

        // Attacker replays packet 1
        CHECK_FALSE(bob_window.check_and_update(nonce_counter_1)); // Rejected!

        // Alice sends packet with nonce counter 2
        u64 nonce_counter_2 = 2;
        auto nonce2 = crypto::nonce_from_counter(nonce_counter_2);
        Vector<u8> msg2 = {0x04, 0x05, 0x06};
        auto enc2 = crypto::aead_encrypt(alice_send, nonce2, msg2);
        REQUIRE(enc2.is_ok());

        // Bob receives packet 2
        CHECK(bob_window.check_and_update(nonce_counter_2));
        auto dec2 = crypto::aead_decrypt(bob_recv, nonce2, enc2.value());
        REQUIRE(dec2.is_ok());
        CHECK(dec2.value() == msg2);

        // Attacker modifies ciphertext
        Vector<u8> modified = enc2.value();
        modified[0] ^= 0xFF; // Corrupt first byte
        auto dec_modified = crypto::aead_decrypt(bob_recv, nonce2, modified);
        CHECK(dec_modified.is_err()); // Authentication fails
    }
}

// =============================================================================
// Voting Flow Tests
// =============================================================================

TEST_SUITE("Integration - Voting Flow") {

    TEST_CASE("Complete membership proposal and voting flow") {
        // Setup: 3 existing members
        TestNode member1, member2, member3;
        TestNode candidate;

        // Create trust view with existing members
        TrustView trust_view(2, 15000); // min 2 yes votes

        MemberEntry m1_info;
        m1_info.node_id = member1.id;
        m1_info.ed25519_pubkey = member1.ed25519_pub;
        m1_info.x25519_pubkey = member1.x25519_pub;
        m1_info.status = MemberStatus::Approved;
        m1_info.joined_at_ms = time::now_ms();
        trust_view.add_member(m1_info);

        MemberEntry m2_info;
        m2_info.node_id = member2.id;
        m2_info.ed25519_pubkey = member2.ed25519_pub;
        m2_info.x25519_pubkey = member2.x25519_pub;
        m2_info.status = MemberStatus::Approved;
        m2_info.joined_at_ms = time::now_ms();
        trust_view.add_member(m2_info);

        MemberEntry m3_info;
        m3_info.node_id = member3.id;
        m3_info.ed25519_pubkey = member3.ed25519_pub;
        m3_info.x25519_pubkey = member3.x25519_pub;
        m3_info.status = MemberStatus::Approved;
        m3_info.joined_at_ms = time::now_ms();
        trust_view.add_member(m3_info);

        CHECK(trust_view.member_count() == 3);

        // Voting policy
        VotingPolicy policy;
        policy.min_yes_votes = 2;
        policy.min_no_votes = 2;
        policy.vote_timeout_ms = 15000;

        // Create voting manager (member1 is our local node)
        VotingManager voting(policy, member1.id);

        // Step 1: Member1 sponsors candidate
        JoinProposal proposal;
        proposal.candidate_id = candidate.id;
        proposal.candidate_ed25519 = candidate.ed25519_pub;
        proposal.candidate_x25519 = candidate.x25519_pub;
        proposal.sponsor_id = member1.id;
        proposal.timestamp_ms = time::now_ms();

        auto add_res = voting.add_proposal(proposal);
        REQUIRE(add_res.is_ok());
        CHECK(voting.has_proposal(candidate.id));

        // Step 2: Member1 votes yes
        auto vote1_res = voting.cast_vote(candidate.id, Vote::Yes, "I sponsor this candidate");
        REQUIRE(vote1_res.is_ok());

        // Record the vote
        VoteCastEvent vote1_evt = vote1_res.value();
        auto record1_res = voting.record_vote(vote1_evt);
        REQUIRE(record1_res.is_ok());
        CHECK(record1_res.value() == VoteResult::Pending); // Need 2 votes

        // Step 3: Member2 votes yes
        VoteCastEvent vote2_evt;
        vote2_evt.candidate_id = candidate.id;
        vote2_evt.voter_id = member2.id;
        vote2_evt.vote = Vote::Yes;
        vote2_evt.timestamp_ms = time::now_ms();

        auto record2_res = voting.record_vote(vote2_evt);
        REQUIRE(record2_res.is_ok());
        CHECK(record2_res.value() == VoteResult::Approved); // Reached threshold!

        // Step 4: Verify proposal state
        auto state = voting.get_proposal(candidate.id);
        REQUIRE(state.has_value());
        CHECK(state->decided);
        CHECK(state->approved);
        CHECK(state->count_yes() == 2);
    }

    TEST_CASE("Voting flow with rejection") {
        TestNode member1, member2, member3;
        TestNode candidate;

        VotingPolicy policy;
        policy.min_yes_votes = 2;
        policy.min_no_votes = 2;
        policy.vote_timeout_ms = 15000;

        VotingManager voting(policy, member1.id);

        // Create proposal
        JoinProposal proposal;
        proposal.candidate_id = candidate.id;
        proposal.candidate_ed25519 = candidate.ed25519_pub;
        proposal.candidate_x25519 = candidate.x25519_pub;
        proposal.sponsor_id = member1.id;
        proposal.timestamp_ms = time::now_ms();

        voting.add_proposal(proposal);

        // Two no votes
        VoteCastEvent vote1;
        vote1.candidate_id = candidate.id;
        vote1.voter_id = member2.id;
        vote1.vote = Vote::No;
        vote1.timestamp_ms = time::now_ms();
        vote1.reason = "Not trusted";

        auto res1 = voting.record_vote(vote1);
        REQUIRE(res1.is_ok());
        CHECK(res1.value() == VoteResult::Pending);

        VoteCastEvent vote2;
        vote2.candidate_id = candidate.id;
        vote2.voter_id = member3.id;
        vote2.vote = Vote::No;
        vote2.timestamp_ms = time::now_ms();

        auto res2 = voting.record_vote(vote2);
        REQUIRE(res2.is_ok());
        CHECK(res2.value() == VoteResult::Rejected);

        auto state = voting.get_proposal(candidate.id);
        REQUIRE(state.has_value());
        CHECK(state->decided);
        CHECK_FALSE(state->approved);
    }

    TEST_CASE("Duplicate vote rejection") {
        TestNode member1, member2;
        TestNode candidate;

        VotingPolicy policy;
        policy.min_yes_votes = 2;

        VotingManager voting(policy, member1.id);

        JoinProposal proposal;
        proposal.candidate_id = candidate.id;
        proposal.candidate_ed25519 = candidate.ed25519_pub;
        proposal.candidate_x25519 = candidate.x25519_pub;
        proposal.sponsor_id = member1.id;
        proposal.timestamp_ms = time::now_ms();

        voting.add_proposal(proposal);

        // First vote
        VoteCastEvent vote1;
        vote1.candidate_id = candidate.id;
        vote1.voter_id = member2.id;
        vote1.vote = Vote::Yes;
        vote1.timestamp_ms = time::now_ms();

        auto res1 = voting.record_vote(vote1);
        REQUIRE(res1.is_ok());

        // Duplicate vote should be rejected
        auto res2 = voting.record_vote(vote1);
        CHECK(res2.is_err());
    }

    TEST_CASE("TrustChain and TrustView synchronization") {
        TestNode genesis_node;

        // Create trust chain with genesis
        TrustChain chain("test_chain", genesis_node.id, genesis_node.ed25519_pub, genesis_node.x25519_pub);

        // Create trust view
        TrustView view(2, 15000);

        // Sync view from chain (void return)
        view.sync_from_chain(chain);

        // Genesis should be a member
        CHECK(view.is_member(genesis_node.id));
        CHECK(view.member_count() == 1);

        // Add a new member via chain
        TestNode new_member;
        TrustEvent approve_evt;
        approve_evt.kind = TrustEventKind::JoinApproved;
        approve_evt.subject_id = new_member.id;
        approve_evt.actor_id = genesis_node.id;
        approve_evt.timestamp_ms = time::now_ms();
        approve_evt.subject_pubkey = new_member.ed25519_pub;
        approve_evt.subject_x25519 = new_member.x25519_pub;

        auto add_res = chain.add_event(approve_evt);
        REQUIRE(add_res.is_ok());

        // Re-sync view
        view.sync_from_chain(chain);

        CHECK(view.is_member(new_member.id));
        CHECK(view.member_count() == 2);
    }
}

// =============================================================================
// End-to-End Integration Tests
// =============================================================================

TEST_SUITE("Integration - End-to-End") {

    TEST_CASE("Full peer connection scenario") {
        TestNode alice;
        TestNode bob;

        // Both nodes create trust views with each other as members
        TrustView alice_view(2, 15000);
        TrustView bob_view(2, 15000);

        MemberEntry alice_info;
        alice_info.node_id = alice.id;
        alice_info.ed25519_pubkey = alice.ed25519_pub;
        alice_info.x25519_pubkey = alice.x25519_pub;
        alice_info.status = MemberStatus::Approved;
        alice_info.joined_at_ms = time::now_ms();

        MemberEntry bob_info;
        bob_info.node_id = bob.id;
        bob_info.ed25519_pubkey = bob.ed25519_pub;
        bob_info.x25519_pubkey = bob.x25519_pub;
        bob_info.status = MemberStatus::Approved;
        bob_info.joined_at_ms = time::now_ms();

        alice_view.add_member(alice_info);
        alice_view.add_member(bob_info);
        bob_view.add_member(alice_info);
        bob_view.add_member(bob_info);

        // Create peer tables
        PeerTable alice_peers(25000, 120000, 180000);
        PeerTable bob_peers(25000, 120000, 180000);

        alice_peers.add_peer(bob.id, bob.ed25519_pub, bob.x25519_pub);
        bob_peers.add_peer(alice.id, alice.ed25519_pub, alice.x25519_pub);

        // Simulate handshake
        auto [alice_eph_priv, alice_eph_pub] = crypto::generate_x25519_keypair();
        auto [bob_eph_priv, bob_eph_pub] = crypto::generate_x25519_keypair();

        // Compute shared secrets
        auto alice_shared = crypto::x25519_shared_secret(alice_eph_priv, bob_eph_pub);
        auto bob_shared = crypto::x25519_shared_secret(bob_eph_priv, alice_eph_pub);
        REQUIRE(alice_shared.is_ok());
        REQUIRE(bob_shared.is_ok());
        CHECK(alice_shared.value() == bob_shared.value());

        // Derive session keys
        auto [alice_send, alice_recv] = crypto::derive_initiator_keys(alice_shared.value(), alice.id, bob.id, 1);
        auto [bob_send, bob_recv] = crypto::derive_responder_keys(bob_shared.value(), alice.id, bob.id, 1);

        // Create sessions
        alice_peers.create_session(bob.id, alice_send, alice_recv);
        bob_peers.create_session(alice.id, bob_send, bob_recv);

        // Verify sessions
        auto alice_peer = alice_peers.get_peer(bob.id);
        REQUIRE(alice_peer.has_value());
        CHECK((*alice_peer)->has_session());

        auto bob_peer = bob_peers.get_peer(alice.id);
        REQUIRE(bob_peer.has_value());
        CHECK((*bob_peer)->has_session());

        // Simulate bidirectional communication
        Vector<u8> alice_msg = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
        u64 alice_nonce = (*alice_peer)->session->next_send_nonce();
        auto alice_enc = crypto::aead_encrypt(alice_send, crypto::nonce_from_counter(alice_nonce), alice_msg);
        REQUIRE(alice_enc.is_ok());

        // Bob decrypts
        auto bob_dec = crypto::aead_decrypt(bob_recv, crypto::nonce_from_counter(alice_nonce), alice_enc.value());
        REQUIRE(bob_dec.is_ok());
        CHECK(bob_dec.value() == alice_msg);

        // Bob sends response
        Vector<u8> bob_msg = {0x57, 0x6f, 0x72, 0x6c, 0x64}; // "World"
        u64 bob_nonce = (*bob_peer)->session->next_send_nonce();
        auto bob_enc = crypto::aead_encrypt(bob_send, crypto::nonce_from_counter(bob_nonce), bob_msg);
        REQUIRE(bob_enc.is_ok());

        // Alice decrypts
        auto alice_dec = crypto::aead_decrypt(alice_recv, crypto::nonce_from_counter(bob_nonce), bob_enc.value());
        REQUIRE(alice_dec.is_ok());
        CHECK(alice_dec.value() == bob_msg);
    }

    TEST_CASE("Metrics are updated during operations") {
        // Reset metrics
        metrics::global().reset();

        // Verify initial state
        CHECK(metrics::global().handshakes_initiated.load() == 0);
        CHECK(metrics::global().packets_dropped_replay.load() == 0);

        // Simulate some operations
        metrics::inc_handshakes_initiated();
        metrics::inc_handshakes_completed();
        metrics::inc_packets_dropped_replay();
        metrics::inc_proposals_approved();
        metrics::add_bytes_sent(1000);

        // Verify updates
        CHECK(metrics::global().handshakes_initiated.load() == 1);
        CHECK(metrics::global().handshakes_completed.load() == 1);
        CHECK(metrics::global().packets_dropped_replay.load() == 1);
        CHECK(metrics::global().proposals_approved.load() == 1);
        CHECK(metrics::global().bytes_sent.load() == 1000);
    }
}
