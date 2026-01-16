/* SPDX-License-Identifier: MIT */
/*
 * Botlink Stress Tests
 * High volume packet handling and performance testing
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>
#include <chrono>
#include <thread>
#include <vector>

using namespace botlink;
using namespace dp;

// =============================================================================
// Test Fixtures
// =============================================================================

struct StressTestNode {
    NodeId id;
    PrivateKey ed25519_priv;
    PublicKey ed25519_pub;
    PrivateKey x25519_priv;
    PublicKey x25519_pub;

    StressTestNode() {
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
// High Volume Packet Tests
// =============================================================================

TEST_SUITE("Stress - High Volume Packets") {

    TEST_CASE("Encrypt/decrypt many packets without memory issues") {
        StressTestNode alice;
        StressTestNode bob;

        // Create session keys
        Array<u8, 32> shared_secret;
        randombytes_buf(shared_secret.data(), 32);

        auto [alice_send, alice_recv] = crypto::derive_initiator_keys(shared_secret, alice.id, bob.id, 1);
        auto [bob_send, bob_recv] = crypto::derive_responder_keys(shared_secret, alice.id, bob.id, 1);

        constexpr usize NUM_PACKETS = 10000;
        constexpr usize PACKET_SIZE = 1024;

        // Generate test data
        Vector<u8> plaintext(PACKET_SIZE);
        randombytes_buf(plaintext.data(), PACKET_SIZE);

        auto start = std::chrono::high_resolution_clock::now();

        for (usize i = 0; i < NUM_PACKETS; ++i) {
            // Encrypt with Alice's send key
            auto nonce = crypto::nonce_from_counter(i);
            auto enc_res = crypto::aead_encrypt(alice_send, nonce, plaintext);
            REQUIRE(enc_res.is_ok());

            // Decrypt with Bob's recv key
            auto dec_res = crypto::aead_decrypt(bob_recv, nonce, enc_res.value());
            REQUIRE(dec_res.is_ok());
            CHECK(dec_res.value() == plaintext);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        MESSAGE("Processed ", NUM_PACKETS, " packets in ", duration.count(), "ms");
        MESSAGE("Throughput: ", (NUM_PACKETS * 1000) / (duration.count() + 1), " packets/second");
    }

    TEST_CASE("Replay window handles high-speed sequential packets") {
        crypto::ReplayWindow window;

        constexpr u64 NUM_PACKETS = 100000;

        auto start = std::chrono::high_resolution_clock::now();

        // Start from 1 since nonce 0 == initial last_seen (0) is treated as replay
        for (u64 nonce = 1; nonce <= NUM_PACKETS; ++nonce) {
            bool allowed = window.check_and_update(nonce);
            REQUIRE(allowed);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        MESSAGE("Processed ", NUM_PACKETS, " nonces in ", duration.count(), "us");
        MESSAGE("Throughput: ", (NUM_PACKETS * 1000000) / (duration.count() + 1), " nonces/second");
    }

    TEST_CASE("Replay window handles out-of-order packets at scale") {
        crypto::ReplayWindow window;

        constexpr u64 NUM_PACKETS = 10000;

        // Simulate out-of-order delivery within window
        Vector<u64> nonces;
        for (u64 i = 0; i < NUM_PACKETS; ++i) {
            nonces.push_back(i);
        }

        // Shuffle within groups of 32 (simulating network reordering)
        for (usize i = 0; i + 32 < nonces.size(); i += 32) {
            for (usize j = 0; j < 16; ++j) {
                std::swap(nonces[i + j], nonces[i + 31 - j]);
            }
        }

        usize accepted = 0;
        usize rejected = 0;

        for (u64 nonce : nonces) {
            if (window.check_and_update(nonce)) {
                ++accepted;
            } else {
                ++rejected;
            }
        }

        MESSAGE("Accepted: ", accepted, ", Rejected: ", rejected);
        // Most packets should be accepted even with reordering
        CHECK(accepted > NUM_PACKETS * 0.9);
    }

    TEST_CASE("Session key derivation is fast") {
        constexpr usize NUM_DERIVATIONS = 1000;

        StressTestNode alice;
        StressTestNode bob;

        Array<u8, 32> shared_secret;
        randombytes_buf(shared_secret.data(), 32);

        auto start = std::chrono::high_resolution_clock::now();

        for (usize i = 0; i < NUM_DERIVATIONS; ++i) {
            auto [send_key, recv_key] = crypto::derive_initiator_keys(shared_secret, alice.id, bob.id, static_cast<u32>(i));
            (void)send_key;
            (void)recv_key;
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        MESSAGE("Derived ", NUM_DERIVATIONS, " key pairs in ", duration.count(), "us");
        MESSAGE("Throughput: ", (NUM_DERIVATIONS * 1000000) / (duration.count() + 1), " derivations/second");
    }
}

// =============================================================================
// Rate Limiting Stress Tests
// =============================================================================

TEST_SUITE("Stress - Rate Limiting") {

    TEST_CASE("Rate limiting tracks many peers efficiently") {
        StressTestNode local;
        TrustView trust_view;
        PeerTable peer_table;

        // Create DataPlane without socket for testing
        net::DataPlane data_plane(local.id, local.x25519_priv, local.x25519_pub,
                                  &trust_view, &peer_table, nullptr);

        // Configure tight rate limits for testing
        data_plane.set_rate_limit_window_ms(100);
        data_plane.set_max_packets_per_window(10);
        data_plane.set_max_handshakes_per_window(2);

        constexpr usize NUM_PEERS = 1000;

        // Generate many peer IDs
        Vector<NodeId> peer_ids;
        for (usize i = 0; i < NUM_PEERS; ++i) {
            StressTestNode peer;
            peer_ids.push_back(peer.id);
        }

        auto start = std::chrono::high_resolution_clock::now();

        // Check rate limits for all peers
        for (const auto &peer_id : peer_ids) {
            for (usize j = 0; j < 15; ++j) {
                data_plane.check_rate_limit(peer_id);
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        MESSAGE("Checked rate limits for ", NUM_PEERS, " peers (15 times each) in ", duration.count(), "ms");
    }

    TEST_CASE("Rate limiting correctly blocks excess packets") {
        StressTestNode local;
        StressTestNode peer;
        TrustView trust_view;
        PeerTable peer_table;

        net::DataPlane data_plane(local.id, local.x25519_priv, local.x25519_pub,
                                  &trust_view, &peer_table, nullptr);

        // Tight rate limit
        data_plane.set_rate_limit_window_ms(1000);
        data_plane.set_max_packets_per_window(50);

        usize allowed = 0;
        usize blocked = 0;

        // Send 100 packets from same peer
        for (usize i = 0; i < 100; ++i) {
            if (data_plane.check_rate_limit(peer.id)) {
                ++allowed;
            } else {
                ++blocked;
            }
        }

        CHECK(allowed == 50);
        CHECK(blocked == 50);
    }

    TEST_CASE("Handshake rate limiting is stricter than packet rate limiting") {
        StressTestNode local;
        StressTestNode peer;
        TrustView trust_view;
        PeerTable peer_table;

        net::DataPlane data_plane(local.id, local.x25519_priv, local.x25519_pub,
                                  &trust_view, &peer_table, nullptr);

        data_plane.set_rate_limit_window_ms(1000);
        data_plane.set_max_packets_per_window(100);
        data_plane.set_max_handshakes_per_window(5);

        usize handshakes_allowed = 0;
        for (usize i = 0; i < 20; ++i) {
            if (data_plane.check_handshake_rate_limit(peer.id)) {
                ++handshakes_allowed;
            }
        }

        CHECK(handshakes_allowed == 5);
    }

    TEST_CASE("Stale rate limit entries are cleaned up") {
        StressTestNode local;
        TrustView trust_view;
        PeerTable peer_table;

        net::DataPlane data_plane(local.id, local.x25519_priv, local.x25519_pub,
                                  &trust_view, &peer_table, nullptr);

        data_plane.set_rate_limit_window_ms(10); // 10ms window

        // Create entries for many peers
        for (usize i = 0; i < 100; ++i) {
            StressTestNode peer;
            data_plane.check_rate_limit(peer.id);
        }

        // Wait for entries to become stale
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        // Cleanup should remove stale entries
        usize removed = data_plane.cleanup_stale_rate_limits();
        CHECK(removed == 100);
    }
}

// =============================================================================
// Peer Table Stress Tests
// =============================================================================

TEST_SUITE("Stress - Peer Table") {

    TEST_CASE("Peer table handles many peers") {
        PeerTable table;

        constexpr usize NUM_PEERS = 500;

        auto start = std::chrono::high_resolution_clock::now();

        for (usize i = 0; i < NUM_PEERS; ++i) {
            StressTestNode peer;
            table.add_peer(peer.id, peer.ed25519_pub, peer.x25519_pub);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        MESSAGE("Added ", NUM_PEERS, " peers in ", duration.count(), "us");

        // Verify all peers exist
        CHECK(table.get_all_peers().size() == NUM_PEERS);
    }

    TEST_CASE("Peer lookups are efficient") {
        PeerTable table;

        constexpr usize NUM_PEERS = 100;

        Vector<NodeId> peer_ids;
        for (usize i = 0; i < NUM_PEERS; ++i) {
            StressTestNode peer;
            table.add_peer(peer.id, peer.ed25519_pub, peer.x25519_pub);
            peer_ids.push_back(peer.id);
        }

        constexpr usize NUM_LOOKUPS = 100000;

        auto start = std::chrono::high_resolution_clock::now();

        for (usize i = 0; i < NUM_LOOKUPS; ++i) {
            auto peer = table.get_peer(peer_ids[i % NUM_PEERS]);
            REQUIRE(peer.has_value());
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        MESSAGE("Performed ", NUM_LOOKUPS, " lookups in ", duration.count(), "us");
        MESSAGE("Throughput: ", (NUM_LOOKUPS * 1000000) / (duration.count() + 1), " lookups/second");
    }
}

// =============================================================================
// Trust View Stress Tests
// =============================================================================

TEST_SUITE("Stress - Trust View") {

    TEST_CASE("Trust view handles many members") {
        TrustView view;

        constexpr usize NUM_MEMBERS = 200;

        auto start = std::chrono::high_resolution_clock::now();

        for (usize i = 0; i < NUM_MEMBERS; ++i) {
            StressTestNode member;
            MemberEntry entry;
            entry.node_id = member.id;
            entry.ed25519_pubkey = member.ed25519_pub;
            entry.x25519_pubkey = member.x25519_pub;
            entry.status = MemberStatus::Approved;
            entry.joined_at_ms = time::now_ms();
            view.add_member(entry);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        MESSAGE("Added ", NUM_MEMBERS, " members in ", duration.count(), "us");
        CHECK(view.member_count() == NUM_MEMBERS);
    }

    TEST_CASE("Membership checks are efficient") {
        TrustView view;

        constexpr usize NUM_MEMBERS = 100;
        Vector<NodeId> member_ids;

        for (usize i = 0; i < NUM_MEMBERS; ++i) {
            StressTestNode member;
            MemberEntry entry;
            entry.node_id = member.id;
            entry.ed25519_pubkey = member.ed25519_pub;
            entry.x25519_pubkey = member.x25519_pub;
            entry.status = MemberStatus::Approved;
            entry.joined_at_ms = time::now_ms();
            view.add_member(entry);
            member_ids.push_back(member.id);
        }

        constexpr usize NUM_CHECKS = 100000;

        auto start = std::chrono::high_resolution_clock::now();

        for (usize i = 0; i < NUM_CHECKS; ++i) {
            bool is_member = view.is_member(member_ids[i % NUM_MEMBERS]);
            REQUIRE(is_member);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        MESSAGE("Performed ", NUM_CHECKS, " membership checks in ", duration.count(), "us");
    }
}

// =============================================================================
// Envelope Signing Stress Tests
// =============================================================================

TEST_SUITE("Stress - Envelope Signing") {

    TEST_CASE("Signing many envelopes is efficient") {
        StressTestNode sender;

        constexpr usize NUM_ENVELOPES = 1000;
        constexpr usize PAYLOAD_SIZE = 256;

        Vector<u8> payload(PAYLOAD_SIZE);
        randombytes_buf(payload.data(), PAYLOAD_SIZE);

        auto start = std::chrono::high_resolution_clock::now();

        for (usize i = 0; i < NUM_ENVELOPES; ++i) {
            auto env = crypto::create_signed_envelope(MsgType::JoinRequest, sender.id, sender.ed25519_priv, payload);
            (void)env;
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        MESSAGE("Signed ", NUM_ENVELOPES, " envelopes in ", duration.count(), "ms");
        MESSAGE("Throughput: ", (NUM_ENVELOPES * 1000) / (duration.count() + 1), " signatures/second");
    }

    TEST_CASE("Verifying many envelopes is efficient") {
        StressTestNode sender;

        constexpr usize NUM_ENVELOPES = 1000;
        constexpr usize PAYLOAD_SIZE = 256;

        Vector<u8> payload(PAYLOAD_SIZE);
        randombytes_buf(payload.data(), PAYLOAD_SIZE);

        // Pre-create envelopes
        Vector<Envelope> envelopes;
        for (usize i = 0; i < NUM_ENVELOPES; ++i) {
            envelopes.push_back(crypto::create_signed_envelope(MsgType::JoinRequest, sender.id, sender.ed25519_priv, payload));
        }

        auto start = std::chrono::high_resolution_clock::now();

        for (const auto &env : envelopes) {
            auto result = crypto::validate_envelope(env, sender.ed25519_pub, 60000);
            REQUIRE(result.is_ok());
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        MESSAGE("Verified ", NUM_ENVELOPES, " envelopes in ", duration.count(), "ms");
        MESSAGE("Throughput: ", (NUM_ENVELOPES * 1000) / (duration.count() + 1), " verifications/second");
    }
}

// =============================================================================
// Scheduler Stress Tests
// =============================================================================

TEST_SUITE("Stress - Scheduler") {

    TEST_CASE("Scheduler handles many timers") {
        runtime::Scheduler scheduler;

        constexpr usize NUM_TIMERS = 1000;
        usize callback_count = 0;

        auto start = std::chrono::high_resolution_clock::now();

        for (usize i = 0; i < NUM_TIMERS; ++i) {
            scheduler.create_oneshot("stress_timer", static_cast<u64>(i + 1), [&callback_count]() {
                ++callback_count;
            });
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        MESSAGE("Scheduled ", NUM_TIMERS, " timers in ", duration.count(), "us");

        // Run scheduler to fire some timers
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        scheduler.process();

        CHECK(callback_count > 0);
    }
}

// =============================================================================
// Memory Pressure Tests
// =============================================================================

TEST_SUITE("Stress - Memory Pressure") {

    TEST_CASE("Large payload encryption/decryption") {
        StressTestNode alice;
        StressTestNode bob;

        Array<u8, 32> shared_secret;
        randombytes_buf(shared_secret.data(), 32);

        auto [alice_send, alice_recv] = crypto::derive_initiator_keys(shared_secret, alice.id, bob.id, 1);
        auto [bob_send, bob_recv] = crypto::derive_responder_keys(shared_secret, alice.id, bob.id, 1);

        // Large payload close to MTU limit
        constexpr usize PAYLOAD_SIZE = 1350;
        Vector<u8> plaintext(PAYLOAD_SIZE);
        randombytes_buf(plaintext.data(), PAYLOAD_SIZE);

        constexpr usize NUM_ITERATIONS = 5000;

        auto start = std::chrono::high_resolution_clock::now();

        for (usize i = 0; i < NUM_ITERATIONS; ++i) {
            auto nonce = crypto::nonce_from_counter(i);
            auto enc_res = crypto::aead_encrypt(alice_send, nonce, plaintext);
            REQUIRE(enc_res.is_ok());

            auto dec_res = crypto::aead_decrypt(bob_recv, nonce, enc_res.value());
            REQUIRE(dec_res.is_ok());
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        u64 bytes_processed = NUM_ITERATIONS * PAYLOAD_SIZE * 2; // encrypt + decrypt
        MESSAGE("Processed ", bytes_processed / 1024, " KB in ", duration.count(), "ms");
        MESSAGE("Throughput: ", (bytes_processed / 1024 * 1000) / (duration.count() + 1), " KB/second");
    }
}
