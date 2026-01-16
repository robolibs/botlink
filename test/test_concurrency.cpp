/* SPDX-License-Identifier: MIT */
/*
 * Botlink Concurrency Tests
 * Thread-safety and concurrent access testing
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>
#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

using namespace botlink;
using namespace dp;

// =============================================================================
// Test Fixtures
// =============================================================================

struct ConcurrencyTestNode {
    NodeId id;
    PrivateKey ed25519_priv;
    PublicKey ed25519_pub;
    PrivateKey x25519_priv;
    PublicKey x25519_pub;

    ConcurrencyTestNode() {
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
// Metrics Thread Safety Tests
// =============================================================================

TEST_SUITE("Concurrency - Metrics") {

    TEST_CASE("Concurrent metrics increments are thread-safe") {
        metrics::global().reset();

        constexpr usize NUM_THREADS = 8;
        constexpr usize INCREMENTS_PER_THREAD = 10000;

        std::vector<std::thread> threads;

        for (usize t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([]() {
                for (usize i = 0; i < INCREMENTS_PER_THREAD; ++i) {
                    metrics::inc_packets_sent();
                    metrics::inc_packets_received();
                    metrics::inc_handshakes_initiated();
                }
            });
        }

        for (auto &thread : threads) {
            thread.join();
        }

        u64 expected = NUM_THREADS * INCREMENTS_PER_THREAD;
        CHECK(metrics::global().packets_sent.load() == expected);
        CHECK(metrics::global().packets_received.load() == expected);
        CHECK(metrics::global().handshakes_initiated.load() == expected);
    }

    TEST_CASE("Concurrent byte counter additions are thread-safe") {
        metrics::global().reset();

        constexpr usize NUM_THREADS = 8;
        constexpr usize ADDS_PER_THREAD = 10000;
        constexpr u64 BYTES_PER_ADD = 1024;

        std::vector<std::thread> threads;

        for (usize t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([]() {
                for (usize i = 0; i < ADDS_PER_THREAD; ++i) {
                    metrics::add_bytes_sent(BYTES_PER_ADD);
                    metrics::add_bytes_received(BYTES_PER_ADD);
                }
            });
        }

        for (auto &thread : threads) {
            thread.join();
        }

        u64 expected = NUM_THREADS * ADDS_PER_THREAD * BYTES_PER_ADD;
        CHECK(metrics::global().bytes_sent.load() == expected);
        CHECK(metrics::global().bytes_received.load() == expected);
    }
}

// =============================================================================
// Replay Window Thread Safety Tests
// =============================================================================

TEST_SUITE("Concurrency - Replay Window") {

    TEST_CASE("Replay window sequential access from multiple threads") {
        // Note: ReplayWindow is NOT designed to be thread-safe
        // This test verifies that sequential nonce processing works
        // when threads take turns (simulating mutex-protected access)

        crypto::ReplayWindow window;
        std::atomic<u64> next_nonce{0};
        std::atomic<usize> accepted{0};
        std::atomic<usize> rejected{0};

        constexpr usize NUM_THREADS = 4;
        constexpr usize NONCES_PER_THREAD = 1000;

        std::vector<std::thread> threads;

        // Use a mutex to simulate thread-safe usage
        std::mutex window_mutex;

        for (usize t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&]() {
                for (usize i = 0; i < NONCES_PER_THREAD; ++i) {
                    u64 nonce = next_nonce.fetch_add(1);
                    std::lock_guard<std::mutex> lock(window_mutex);
                    if (window.check_and_update(nonce)) {
                        accepted.fetch_add(1);
                    } else {
                        rejected.fetch_add(1);
                    }
                }
            });
        }

        for (auto &thread : threads) {
            thread.join();
        }

        // Most nonces should be accepted - some may be rejected due to thread ordering
        // which can cause out-of-order processing despite mutex protection
        usize total = accepted.load() + rejected.load();
        CHECK(total == NUM_THREADS * NONCES_PER_THREAD);
        // At least 99% should be accepted
        CHECK(accepted.load() >= (NUM_THREADS * NONCES_PER_THREAD * 99) / 100);
    }
}

// =============================================================================
// Session Key Thread Safety Tests
// =============================================================================

TEST_SUITE("Concurrency - Session Keys") {

    TEST_CASE("Concurrent session key derivation is independent") {
        ConcurrencyTestNode alice;
        ConcurrencyTestNode bob;

        Array<u8, 32> shared_secret;
        randombytes_buf(shared_secret.data(), 32);

        constexpr usize NUM_THREADS = 8;
        constexpr usize DERIVATIONS_PER_THREAD = 1000;

        std::atomic<usize> success_count{0};
        std::vector<std::thread> threads;

        for (usize t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&, t]() {
                for (usize i = 0; i < DERIVATIONS_PER_THREAD; ++i) {
                    u32 key_id = static_cast<u32>(t * DERIVATIONS_PER_THREAD + i);
                    auto [send_key, recv_key] = crypto::derive_initiator_keys(shared_secret, alice.id, bob.id, key_id);

                    // Verify keys are valid (non-zero)
                    bool send_valid = false;
                    bool recv_valid = false;
                    for (usize j = 0; j < send_key.data.size(); ++j) {
                        if (send_key.data[j] != 0) send_valid = true;
                        if (recv_key.data[j] != 0) recv_valid = true;
                    }

                    if (send_valid && recv_valid) {
                        success_count.fetch_add(1);
                    }
                }
            });
        }

        for (auto &thread : threads) {
            thread.join();
        }

        CHECK(success_count.load() == NUM_THREADS * DERIVATIONS_PER_THREAD);
    }

    TEST_CASE("Session key cleanup is safe") {
        constexpr usize NUM_THREADS = 4;
        constexpr usize OPERATIONS_PER_THREAD = 1000;

        std::atomic<usize> operations_completed{0};
        std::vector<std::thread> threads;

        for (usize t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&]() {
                for (usize i = 0; i < OPERATIONS_PER_THREAD; ++i) {
                    ConcurrencyTestNode alice;
                    ConcurrencyTestNode bob;

                    Array<u8, 32> shared_secret;
                    randombytes_buf(shared_secret.data(), 32);

                    // Create keys
                    auto [send_key, recv_key] = crypto::derive_initiator_keys(shared_secret, alice.id, bob.id, static_cast<u32>(i));

                    // Keys should be automatically cleared on destruction
                    (void)send_key;
                    (void)recv_key;

                    operations_completed.fetch_add(1);
                }
            });
        }

        for (auto &thread : threads) {
            thread.join();
        }

        CHECK(operations_completed.load() == NUM_THREADS * OPERATIONS_PER_THREAD);
    }
}

// =============================================================================
// Encryption/Decryption Thread Safety Tests
// =============================================================================

TEST_SUITE("Concurrency - AEAD") {

    TEST_CASE("Concurrent encryption with different keys is safe") {
        constexpr usize NUM_THREADS = 8;
        constexpr usize OPERATIONS_PER_THREAD = 500;

        std::atomic<usize> success_count{0};
        std::vector<std::thread> threads;

        for (usize t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&, t]() {
                ConcurrencyTestNode alice;
                ConcurrencyTestNode bob;

                Array<u8, 32> shared_secret;
                randombytes_buf(shared_secret.data(), 32);

                auto [send_key, recv_key] = crypto::derive_initiator_keys(shared_secret, alice.id, bob.id, static_cast<u32>(t));
                auto [bob_send, bob_recv] = crypto::derive_responder_keys(shared_secret, alice.id, bob.id, static_cast<u32>(t));

                Vector<u8> plaintext(256);
                randombytes_buf(plaintext.data(), 256);

                for (usize i = 0; i < OPERATIONS_PER_THREAD; ++i) {
                    auto nonce = crypto::nonce_from_counter(i);

                    auto enc_res = crypto::aead_encrypt(send_key, nonce, plaintext);
                    if (enc_res.is_err()) continue;

                    auto dec_res = crypto::aead_decrypt(bob_recv, nonce, enc_res.value());
                    if (dec_res.is_err()) continue;

                    if (dec_res.value() == plaintext) {
                        success_count.fetch_add(1);
                    }
                }
            });
        }

        for (auto &thread : threads) {
            thread.join();
        }

        CHECK(success_count.load() == NUM_THREADS * OPERATIONS_PER_THREAD);
    }
}

// =============================================================================
// Peer Table Thread Safety Tests
// =============================================================================

TEST_SUITE("Concurrency - Peer Table") {

    TEST_CASE("Concurrent peer additions are handled") {
        // Note: PeerTable may need external synchronization
        // This test documents the expected behavior

        PeerTable table;
        std::mutex table_mutex;

        constexpr usize NUM_THREADS = 4;
        constexpr usize PEERS_PER_THREAD = 100;

        std::vector<std::thread> threads;

        for (usize t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&]() {
                for (usize i = 0; i < PEERS_PER_THREAD; ++i) {
                    ConcurrencyTestNode peer;
                    std::lock_guard<std::mutex> lock(table_mutex);
                    table.add_peer(peer.id, peer.ed25519_pub, peer.x25519_pub);
                }
            });
        }

        for (auto &thread : threads) {
            thread.join();
        }

        CHECK(table.get_all_peers().size() == NUM_THREADS * PEERS_PER_THREAD);
    }

    TEST_CASE("Concurrent peer lookups and additions are safe with mutex") {
        PeerTable table;
        std::mutex table_mutex;

        constexpr usize NUM_ADDERS = 2;
        constexpr usize NUM_READERS = 4;
        constexpr usize OPS_PER_THREAD = 500;

        std::atomic<bool> running{true};
        std::atomic<usize> adds_completed{0};
        std::atomic<usize> reads_completed{0};

        Vector<NodeId> added_ids;
        std::mutex ids_mutex;

        std::vector<std::thread> threads;

        // Adder threads
        for (usize t = 0; t < NUM_ADDERS; ++t) {
            threads.emplace_back([&]() {
                for (usize i = 0; i < OPS_PER_THREAD && running; ++i) {
                    ConcurrencyTestNode peer;
                    {
                        std::lock_guard<std::mutex> lock(table_mutex);
                        table.add_peer(peer.id, peer.ed25519_pub, peer.x25519_pub);
                    }
                    {
                        std::lock_guard<std::mutex> lock(ids_mutex);
                        added_ids.push_back(peer.id);
                    }
                    adds_completed.fetch_add(1);
                }
            });
        }

        // Reader threads
        for (usize t = 0; t < NUM_READERS; ++t) {
            threads.emplace_back([&]() {
                for (usize i = 0; i < OPS_PER_THREAD && running; ++i) {
                    NodeId id_to_lookup;
                    {
                        std::lock_guard<std::mutex> lock(ids_mutex);
                        if (!added_ids.empty()) {
                            id_to_lookup = added_ids[i % added_ids.size()];
                        }
                    }

                    if (!id_to_lookup.data.empty()) {
                        std::lock_guard<std::mutex> lock(table_mutex);
                        auto peer = table.get_peer(id_to_lookup);
                        (void)peer;
                    }
                    reads_completed.fetch_add(1);
                }
            });
        }

        for (auto &thread : threads) {
            thread.join();
        }

        MESSAGE("Adds: ", adds_completed.load(), ", Reads: ", reads_completed.load());
        CHECK(adds_completed.load() == NUM_ADDERS * OPS_PER_THREAD);
    }
}

// =============================================================================
// Trust View Thread Safety Tests
// =============================================================================

TEST_SUITE("Concurrency - Trust View") {

    TEST_CASE("Concurrent member additions with mutex") {
        TrustView view;
        std::mutex view_mutex;

        constexpr usize NUM_THREADS = 4;
        constexpr usize MEMBERS_PER_THREAD = 100;

        std::vector<std::thread> threads;

        for (usize t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&]() {
                for (usize i = 0; i < MEMBERS_PER_THREAD; ++i) {
                    ConcurrencyTestNode member;
                    MemberEntry entry;
                    entry.node_id = member.id;
                    entry.ed25519_pubkey = member.ed25519_pub;
                    entry.x25519_pubkey = member.x25519_pub;
                    entry.status = MemberStatus::Approved;
                    entry.joined_at_ms = time::now_ms();

                    std::lock_guard<std::mutex> lock(view_mutex);
                    view.add_member(entry);
                }
            });
        }

        for (auto &thread : threads) {
            thread.join();
        }

        CHECK(view.member_count() == NUM_THREADS * MEMBERS_PER_THREAD);
    }

    TEST_CASE("Concurrent membership checks with mutex") {
        TrustView view;
        std::mutex view_mutex;

        // Pre-populate with members
        Vector<NodeId> member_ids;
        for (usize i = 0; i < 50; ++i) {
            ConcurrencyTestNode member;
            MemberEntry entry;
            entry.node_id = member.id;
            entry.ed25519_pubkey = member.ed25519_pub;
            entry.x25519_pubkey = member.x25519_pub;
            entry.status = MemberStatus::Approved;
            entry.joined_at_ms = time::now_ms();
            view.add_member(entry);
            member_ids.push_back(member.id);
        }

        constexpr usize NUM_THREADS = 8;
        constexpr usize CHECKS_PER_THREAD = 5000;

        std::atomic<usize> found_count{0};
        std::vector<std::thread> threads;

        for (usize t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&]() {
                for (usize i = 0; i < CHECKS_PER_THREAD; ++i) {
                    const NodeId &id = member_ids[i % member_ids.size()];
                    std::lock_guard<std::mutex> lock(view_mutex);
                    if (view.is_member(id)) {
                        found_count.fetch_add(1);
                    }
                }
            });
        }

        for (auto &thread : threads) {
            thread.join();
        }

        CHECK(found_count.load() == NUM_THREADS * CHECKS_PER_THREAD);
    }
}

// =============================================================================
// Signing Thread Safety Tests
// =============================================================================

TEST_SUITE("Concurrency - Signing") {

    TEST_CASE("Concurrent signing with different keys is safe") {
        constexpr usize NUM_THREADS = 8;
        constexpr usize SIGNS_PER_THREAD = 500;

        std::atomic<usize> success_count{0};
        std::vector<std::thread> threads;

        for (usize t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&]() {
                ConcurrencyTestNode node;

                Vector<u8> payload(128);
                randombytes_buf(payload.data(), 128);

                for (usize i = 0; i < SIGNS_PER_THREAD; ++i) {
                    auto env = crypto::create_signed_envelope(MsgType::JoinRequest, node.id, node.ed25519_priv, payload);

                    auto result = crypto::validate_envelope(env, node.ed25519_pub, 60000);
                    if (result.is_ok()) {
                        success_count.fetch_add(1);
                    }
                }
            });
        }

        for (auto &thread : threads) {
            thread.join();
        }

        CHECK(success_count.load() == NUM_THREADS * SIGNS_PER_THREAD);
    }
}

// =============================================================================
// Key Generation Thread Safety Tests
// =============================================================================

TEST_SUITE("Concurrency - Key Generation") {

    TEST_CASE("Concurrent Ed25519 key generation is safe") {
        constexpr usize NUM_THREADS = 8;
        constexpr usize GENS_PER_THREAD = 100;

        std::atomic<usize> success_count{0};
        std::vector<std::thread> threads;

        for (usize t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&]() {
                for (usize i = 0; i < GENS_PER_THREAD; ++i) {
                    auto [priv_key, pub_key] = crypto::generate_ed25519_keypair();

                    // Verify keys are non-zero
                    bool priv_valid = false;
                    bool pub_valid = false;
                    for (usize j = 0; j < KEY_SIZE; ++j) {
                        if (priv_key.data[j] != 0) priv_valid = true;
                        if (pub_key.data[j] != 0) pub_valid = true;
                    }

                    if (priv_valid && pub_valid) {
                        success_count.fetch_add(1);
                    }
                }
            });
        }

        for (auto &thread : threads) {
            thread.join();
        }

        CHECK(success_count.load() == NUM_THREADS * GENS_PER_THREAD);
    }

    TEST_CASE("Concurrent X25519 key generation is safe") {
        constexpr usize NUM_THREADS = 8;
        constexpr usize GENS_PER_THREAD = 100;

        std::atomic<usize> success_count{0};
        std::vector<std::thread> threads;

        for (usize t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&]() {
                for (usize i = 0; i < GENS_PER_THREAD; ++i) {
                    auto [priv_key, pub_key] = crypto::generate_x25519_keypair();

                    // Verify keys are non-zero
                    bool priv_valid = false;
                    bool pub_valid = false;
                    for (usize j = 0; j < KEY_SIZE; ++j) {
                        if (priv_key.data[j] != 0) priv_valid = true;
                        if (pub_key.data[j] != 0) pub_valid = true;
                    }

                    if (priv_valid && pub_valid) {
                        success_count.fetch_add(1);
                    }
                }
            });
        }

        for (auto &thread : threads) {
            thread.join();
        }

        CHECK(success_count.load() == NUM_THREADS * GENS_PER_THREAD);
    }
}

// =============================================================================
// Scheduler Thread Safety Tests
// =============================================================================

TEST_SUITE("Concurrency - Scheduler") {

    TEST_CASE("Scheduler operations with external synchronization") {
        runtime::Scheduler scheduler;
        std::mutex scheduler_mutex;

        constexpr usize NUM_THREADS = 4;
        constexpr usize SCHEDULES_PER_THREAD = 100;

        std::atomic<usize> scheduled_count{0};
        std::vector<std::thread> threads;

        for (usize t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&]() {
                for (usize i = 0; i < SCHEDULES_PER_THREAD; ++i) {
                    std::lock_guard<std::mutex> lock(scheduler_mutex);
                    scheduler.create_oneshot("test_timer", static_cast<u64>(100 + i), []() {
                        // Empty callback
                    });
                    scheduled_count.fetch_add(1);
                }
            });
        }

        for (auto &thread : threads) {
            thread.join();
        }

        CHECK(scheduled_count.load() == NUM_THREADS * SCHEDULES_PER_THREAD);
    }
}
