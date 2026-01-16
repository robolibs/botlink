/* SPDX-License-Identifier: MIT */
/*
 * Botlink Trust Chain Tests
 * Tests for blockchain-backed membership tracking
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("TrustChain - Initialization") {

    TEST_CASE("Create trust chain with genesis node") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(ed_pub);

        TrustChain chain("test-chain", genesis_id, ed_pub, x_pub);

        CHECK(chain.chain_id() == "test-chain");
        CHECK(chain.length() >= 1);  // Genesis block
    }

    TEST_CASE("Genesis node is a member") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(ed_pub);

        TrustChain chain("test-chain", genesis_id, ed_pub, x_pub);

        CHECK(chain.is_member(genesis_id));
    }

    TEST_CASE("Non-existent node is not a member") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(ed_pub);

        TrustChain chain("test-chain", genesis_id, ed_pub, x_pub);

        // Create another node
        auto [other_priv, other_pub] = crypto::generate_ed25519_keypair();
        NodeId other_id = crypto::node_id_from_pubkey(other_pub);

        CHECK_FALSE(chain.is_member(other_id));
    }

}

TEST_SUITE("TrustChain - Member Operations") {

    TEST_CASE("Get members returns genesis") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(ed_pub);

        TrustChain chain("test-chain", genesis_id, ed_pub, x_pub);

        auto members = chain.get_members();
        CHECK(members.size() == 1);
        CHECK(members[0] == genesis_id);
    }

    TEST_CASE("Get events for genesis node") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(ed_pub);

        TrustChain chain("test-chain", genesis_id, ed_pub, x_pub);

        auto events = chain.get_events_for_node(genesis_id);
        CHECK(events.size() == 1);
        CHECK(events[0].kind == TrustEventKind::JoinApproved);
        CHECK(events[0].subject_id == genesis_id);
    }

    TEST_CASE("Get latest event for node") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(ed_pub);

        TrustChain chain("test-chain", genesis_id, ed_pub, x_pub);

        auto latest = chain.get_latest_event_for_node(genesis_id);
        REQUIRE(latest.has_value());
        CHECK(latest->kind == TrustEventKind::JoinApproved);
    }

    TEST_CASE("Get latest event for non-existent node returns nullopt") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(ed_pub);

        TrustChain chain("test-chain", genesis_id, ed_pub, x_pub);

        auto [other_priv, other_pub] = crypto::generate_ed25519_keypair();
        NodeId other_id = crypto::node_id_from_pubkey(other_pub);

        auto latest = chain.get_latest_event_for_node(other_id);
        CHECK_FALSE(latest.has_value());
    }

}

TEST_SUITE("TrustChain - Event Signing") {

    TEST_CASE("Sign and verify event") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(ed_pub);

        TrustChain chain("test-chain", genesis_id, ed_pub, x_pub);
        chain.set_local_keys(ed_priv, ed_pub);

        // Create a test event
        TrustEvent evt;
        evt.kind = TrustEventKind::JoinProposed;
        evt.subject_id = genesis_id;
        evt.actor_id = genesis_id;
        evt.timestamp_ms = time::now_ms();

        // Sign the event
        Vector<u8> signature = chain.sign_event(evt);
        CHECK(signature.size() == SIGNATURE_SIZE);

        // Verify the signature
        bool valid = chain.verify_event_signature(evt, signature, ed_pub);
        CHECK(valid);
    }

    TEST_CASE("Signature verification fails with wrong key") {
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(ed_pub1);

        TrustChain chain("test-chain", genesis_id, ed_pub1, x_pub);
        chain.set_local_keys(ed_priv1, ed_pub1);

        TrustEvent evt;
        evt.kind = TrustEventKind::JoinProposed;
        evt.subject_id = genesis_id;
        evt.actor_id = genesis_id;
        evt.timestamp_ms = time::now_ms();

        Vector<u8> signature = chain.sign_event(evt);

        // Verify with wrong key should fail
        bool valid = chain.verify_event_signature(evt, signature, ed_pub2);
        CHECK_FALSE(valid);
    }

    TEST_CASE("Signature verification fails with modified event") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(ed_pub);

        TrustChain chain("test-chain", genesis_id, ed_pub, x_pub);
        chain.set_local_keys(ed_priv, ed_pub);

        TrustEvent evt;
        evt.kind = TrustEventKind::JoinProposed;
        evt.subject_id = genesis_id;
        evt.actor_id = genesis_id;
        evt.timestamp_ms = time::now_ms();

        Vector<u8> signature = chain.sign_event(evt);

        // Modify the event
        evt.timestamp_ms += 1000;

        // Verify should fail with modified event
        bool valid = chain.verify_event_signature(evt, signature, ed_pub);
        CHECK_FALSE(valid);
    }

}

TEST_SUITE("TrustChain - Chain State") {

    TEST_CASE("Empty default chain has zero length") {
        TrustChain chain;
        // Default chain has no genesis
        CHECK(chain.length() == 0);
    }

    TEST_CASE("Chain with genesis has non-zero length") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(ed_pub);

        TrustChain chain("test-chain", genesis_id, ed_pub, x_pub);

        CHECK(chain.length() >= 1);
    }

    TEST_CASE("Chain ID is set correctly") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(ed_pub);

        TrustChain chain("my-test-chain", genesis_id, ed_pub, x_pub);

        CHECK(chain.chain_id() == "my-test-chain");
    }

}

TEST_SUITE("TrustChain - Member Pubkey Registration") {

    TEST_CASE("Register member pubkey") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(ed_pub);

        TrustChain chain("test-chain", genesis_id, ed_pub, x_pub);

        // Register another member's pubkey
        auto [other_priv, other_pub] = crypto::generate_ed25519_keypair();
        NodeId other_id = crypto::node_id_from_pubkey(other_pub);

        chain.register_member_pubkey(other_id, other_pub);

        // The registration itself doesn't make them a member,
        // but it allows signature verification for their events
    }

}

