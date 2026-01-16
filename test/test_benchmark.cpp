/* SPDX-License-Identifier: MIT */
/*
 * Botlink Performance Benchmarks
 * Measures throughput and latency of core operations
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>
#include <chrono>

using namespace botlink;
using namespace dp;

// =============================================================================
// Benchmark Helpers
// =============================================================================

struct BenchmarkResult {
    String name;
    usize iterations;
    u64 total_ns;
    double ops_per_sec;
    double ns_per_op;
};

template <typename Func>
static auto run_benchmark(const String &name, usize iterations, Func &&func) -> BenchmarkResult {
    // Warmup
    for (usize i = 0; i < std::min(iterations / 10, static_cast<usize>(100)); ++i) {
        func();
    }

    auto start = std::chrono::high_resolution_clock::now();

    for (usize i = 0; i < iterations; ++i) {
        func();
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    BenchmarkResult result;
    result.name = name;
    result.iterations = iterations;
    result.total_ns = static_cast<u64>(duration);
    result.ns_per_op = static_cast<double>(duration) / static_cast<double>(iterations);
    result.ops_per_sec = 1e9 / result.ns_per_op;

    return result;
}

static void print_result(const BenchmarkResult &r) {
    MESSAGE(r.name.c_str() << ": " << r.ops_per_sec << " ops/sec (" << r.ns_per_op << " ns/op)");
}

// Helper to generate test data
static NodeId make_node_id(u8 seed) {
    NodeId id;
    for (usize i = 0; i < NODE_ID_SIZE; ++i) {
        id.data[i] = static_cast<u8>(seed + i);
    }
    return id;
}

static auto make_session_key(u8 seed) -> crypto::SessionKey {
    crypto::SessionKey key;
    for (usize i = 0; i < key.data.size(); ++i) {
        key.data[i] = static_cast<u8>(seed + i);
    }
    key.key_id = seed;
    return key;
}

// =============================================================================
// Cryptographic Benchmarks
// =============================================================================

TEST_SUITE("Benchmark - Cryptography") {

    TEST_CASE("Ed25519 key generation") {
        auto result = run_benchmark("Ed25519 KeyGen", 1000, []() {
            auto [priv, pub] = crypto::generate_ed25519_keypair();
            (void)priv;
            (void)pub;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 100); // At least 100 keys/sec
    }

    TEST_CASE("X25519 key generation") {
        auto result = run_benchmark("X25519 KeyGen", 1000, []() {
            auto [priv, pub] = crypto::generate_x25519_keypair();
            (void)priv;
            (void)pub;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 100);
    }

    TEST_CASE("Ed25519 signing") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        Vector<u8> message(256);
        for (usize i = 0; i < message.size(); ++i) {
            message[i] = static_cast<u8>(i & 0xFF);
        }

        auto result = run_benchmark("Ed25519 Sign", 1000, [&]() {
            auto sig = crypto::ed25519_sign(priv, message.data(), message.size());
            (void)sig;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 1000); // At least 1000 signs/sec
    }

    TEST_CASE("Ed25519 verification") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        Vector<u8> message(256);
        for (usize i = 0; i < message.size(); ++i) {
            message[i] = static_cast<u8>(i & 0xFF);
        }
        auto sig = crypto::ed25519_sign(priv, message.data(), message.size());

        auto result = run_benchmark("Ed25519 Verify", 1000, [&]() {
            auto valid = crypto::ed25519_verify(pub, message.data(), message.size(), sig);
            (void)valid;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 1000); // At least 1000 verifies/sec
    }

    TEST_CASE("X25519 shared secret") {
        auto [priv1, pub1] = crypto::generate_x25519_keypair();
        auto [priv2, pub2] = crypto::generate_x25519_keypair();

        auto result = run_benchmark("X25519 SharedSecret", 1000, [&]() {
            auto shared = crypto::x25519_shared_secret(priv1, pub2);
            (void)shared;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 1000);
    }

    TEST_CASE("AEAD encryption (256 bytes)") {
        auto key = make_session_key(1);
        auto nonce = crypto::generate_nonce();
        Vector<u8> plaintext(256);
        for (usize i = 0; i < plaintext.size(); ++i) {
            plaintext[i] = static_cast<u8>(i & 0xFF);
        }

        auto result = run_benchmark("AEAD Encrypt 256B", 10000, [&]() {
            auto encrypted = crypto::aead_encrypt(key, nonce, plaintext);
            (void)encrypted;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 10000); // At least 10k encrypts/sec
    }

    TEST_CASE("AEAD decryption (256 bytes)") {
        auto key = make_session_key(1);
        auto nonce = crypto::generate_nonce();
        Vector<u8> plaintext(256);
        for (usize i = 0; i < plaintext.size(); ++i) {
            plaintext[i] = static_cast<u8>(i & 0xFF);
        }
        auto encrypted = crypto::aead_encrypt(key, nonce, plaintext).value();

        auto result = run_benchmark("AEAD Decrypt 256B", 10000, [&]() {
            auto decrypted = crypto::aead_decrypt(key, nonce, encrypted);
            (void)decrypted;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 10000);
    }

    TEST_CASE("AEAD encryption (1KB)") {
        auto key = make_session_key(1);
        auto nonce = crypto::generate_nonce();
        Vector<u8> plaintext(1024);
        for (usize i = 0; i < plaintext.size(); ++i) {
            plaintext[i] = static_cast<u8>(i & 0xFF);
        }

        auto result = run_benchmark("AEAD Encrypt 1KB", 10000, [&]() {
            auto encrypted = crypto::aead_encrypt(key, nonce, plaintext);
            (void)encrypted;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 5000);
    }

    TEST_CASE("AEAD encryption (MTU size)") {
        auto key = make_session_key(1);
        auto nonce = crypto::generate_nonce();
        Vector<u8> plaintext(1420); // MTU size
        for (usize i = 0; i < plaintext.size(); ++i) {
            plaintext[i] = static_cast<u8>(i & 0xFF);
        }

        auto result = run_benchmark("AEAD Encrypt MTU", 10000, [&]() {
            auto encrypted = crypto::aead_encrypt(key, nonce, plaintext);
            (void)encrypted;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 5000);
    }

}

// =============================================================================
// Envelope Benchmarks
// =============================================================================

TEST_SUITE("Benchmark - Envelope") {

    TEST_CASE("Envelope creation and signing") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(pub);
        Vector<u8> payload(128);
        for (usize i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<u8>(i & 0xFF);
        }

        auto result = run_benchmark("Envelope Create+Sign", 1000, [&]() {
            auto env = crypto::create_signed_envelope(MsgType::VoteCast, sender, priv, payload);
            (void)env;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 500);
    }

    TEST_CASE("Envelope verification") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(pub);
        Vector<u8> payload(128);
        auto env = crypto::create_signed_envelope(MsgType::VoteCast, sender, priv, payload);

        auto result = run_benchmark("Envelope Verify", 1000, [&]() {
            auto valid = crypto::verify_envelope(env, pub);
            (void)valid;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 500);
    }

    TEST_CASE("Envelope serialization") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(pub);
        Vector<u8> payload(128);
        auto env = crypto::create_signed_envelope(MsgType::VoteCast, sender, priv, payload);

        auto result = run_benchmark("Envelope Serialize", 10000, [&]() {
            auto serialized = crypto::serialize_envelope(env);
            (void)serialized;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 10000);
    }

    TEST_CASE("Envelope deserialization") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(pub);
        Vector<u8> payload(128);
        auto env = crypto::create_signed_envelope(MsgType::VoteCast, sender, priv, payload);
        auto serialized = crypto::serialize_envelope(env);

        auto result = run_benchmark("Envelope Deserialize", 10000, [&]() {
            auto deserialized = crypto::deserialize_envelope(serialized);
            (void)deserialized;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 10000);
    }

}

// =============================================================================
// Voting Benchmarks
// =============================================================================

TEST_SUITE("Benchmark - Voting") {

    TEST_CASE("Proposal creation") {
        auto result = run_benchmark("Proposal Create", 10000, []() {
            JoinProposal proposal;
            proposal.candidate_id = make_node_id(1);
            proposal.sponsor_id = make_node_id(2);
            proposal.timestamp_ms = time::now_ms();
            (void)proposal;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 100000);
    }

    TEST_CASE("Vote recording") {
        VotingPolicy policy;
        policy.min_yes_votes = 1000; // High so proposals don't auto-complete
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        // Pre-add proposals
        for (u8 i = 0; i < 100; ++i) {
            JoinProposal proposal;
            proposal.candidate_id = make_node_id(i);
            manager.add_proposal(proposal);
        }

        u8 voter_seed = 100;
        u8 candidate_idx = 0;

        auto result = run_benchmark("Vote Record", 5000, [&]() {
            VoteCastEvent vote;
            vote.candidate_id = make_node_id(candidate_idx);
            vote.voter_id = make_node_id(voter_seed++);
            vote.vote = Vote::Yes;
            vote.timestamp_ms = time::now_ms();

            auto res = manager.record_vote(vote);
            (void)res;

            // Cycle through candidates
            candidate_idx = (candidate_idx + 1) % 100;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 10000);
    }

}

// =============================================================================
// Trust Chain Benchmarks
// =============================================================================

TEST_SUITE("Benchmark - Trust Chain") {

    TEST_CASE("Chain event addition") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(pub);
        auto [x25519_priv, x25519_pub] = crypto::generate_x25519_keypair();

        TrustChain chain("bench_chain", genesis_id, pub, x25519_pub);

        u8 seed = 10;
        auto result = run_benchmark("Chain AddEvent", 1000, [&]() {
            auto [member_priv, member_pub] = crypto::generate_ed25519_keypair();
            NodeId member_id = crypto::node_id_from_pubkey(member_pub);
            auto [mx25519_priv, mx25519_pub] = crypto::generate_x25519_keypair();

            JoinProposal proposal;
            proposal.candidate_id = member_id;
            proposal.candidate_ed25519 = member_pub;
            proposal.candidate_x25519 = mx25519_pub;
            proposal.sponsor_id = genesis_id;
            proposal.timestamp_ms = time::now_ms();

            chain.propose_join(proposal);
            ++seed;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 100);
    }

    TEST_CASE("Chain membership lookup") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId genesis_id = crypto::node_id_from_pubkey(pub);
        auto [x25519_priv, x25519_pub] = crypto::generate_x25519_keypair();

        TrustChain chain("bench_chain", genesis_id, pub, x25519_pub);

        auto result = run_benchmark("Chain Membership Check", 100000, [&]() {
            auto is_member = chain.is_member(genesis_id);
            (void)is_member;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 100000);
    }

}

// =============================================================================
// Replay Window Benchmarks
// =============================================================================

TEST_SUITE("Benchmark - Replay Protection") {

    TEST_CASE("Replay window check and update") {
        crypto::ReplayWindow window;
        u64 nonce = 1;

        auto result = run_benchmark("ReplayWindow Check", 100000, [&]() {
            window.check_and_update(nonce++);
        });
        print_result(result);
        CHECK(result.ops_per_sec > 1000000); // At least 1M ops/sec
    }

}

// =============================================================================
// Endpoint Benchmarks
// =============================================================================

TEST_SUITE("Benchmark - Endpoint") {

    TEST_CASE("IPv4 parsing") {
        auto result = run_benchmark("IPv4 Parse", 100000, []() {
            auto res = net::parse_ipv4_addr("192.168.1.100");
            (void)res;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 100000);
    }

    TEST_CASE("Endpoint parsing") {
        auto result = run_benchmark("Endpoint Parse", 50000, []() {
            auto res = net::parse_endpoint("192.168.1.100:51820");
            (void)res;
        });
        print_result(result);
        CHECK(result.ops_per_sec > 50000);
    }

}

// =============================================================================
// Summary
// =============================================================================

TEST_SUITE("Benchmark - Summary") {

    TEST_CASE("Print benchmark summary") {
        MESSAGE("===============================================");
        MESSAGE("Performance benchmarks completed");
        MESSAGE("All benchmarks should meet minimum thresholds");
        MESSAGE("===============================================");
        CHECK(true);
    }

}
