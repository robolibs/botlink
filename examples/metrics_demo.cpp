/* SPDX-License-Identifier: MIT */
/*
 * Botlink Metrics Demo
 * Demonstrates runtime statistics tracking
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <thread>

using namespace botlink;
using namespace dp;

void print_separator() { std::cout << "----------------------------------------\n"; }

void print_metrics() {
    auto& m = metrics::global();

    std::cout << "Current Metrics Snapshot:\n";
    std::cout << "  Handshakes:\n";
    std::cout << "    initiated:  " << m.handshakes_initiated.load() << "\n";
    std::cout << "    completed:  " << m.handshakes_completed.load() << "\n";
    std::cout << "    failed:     " << m.handshakes_failed.load() << "\n";
    std::cout << "    timed_out:  " << m.handshakes_timed_out.load() << "\n";

    std::cout << "  Packets:\n";
    std::cout << "    sent:       " << m.packets_sent.load() << "\n";
    std::cout << "    received:   " << m.packets_received.load() << "\n";
    std::cout << "    dropped:    " << (m.packets_dropped_replay.load() +
                                        m.packets_dropped_invalid.load() +
                                        m.packets_dropped_no_session.load() +
                                        m.packets_dropped_decrypt_fail.load()) << "\n";

    std::cout << "  Bytes:\n";
    std::cout << "    sent:       " << m.bytes_sent.load() << "\n";
    std::cout << "    received:   " << m.bytes_received.load() << "\n";

    std::cout << "  Sessions:\n";
    std::cout << "    created:    " << m.sessions_created.load() << "\n";
    std::cout << "    expired:    " << m.sessions_expired.load() << "\n";
    std::cout << "    rekeys:     " << m.rekeys_completed.load() << "\n";

    std::cout << "  Trust:\n";
    std::cout << "    proposals:  " << m.proposals_received.load() << "\n";
    std::cout << "    approved:   " << m.proposals_approved.load() << "\n";
    std::cout << "    rejected:   " << m.proposals_rejected.load() << "\n";
    std::cout << "    votes cast: " << m.votes_cast.load() << "\n";

    std::cout << "  Relay:\n";
    std::cout << "    routes:     " << m.relay_routes_established.load() << "\n";
    std::cout << "    forwarded:  " << m.relay_packets_forwarded.load() << "\n";

    std::cout << "  Errors:\n";
    std::cout << "    crypto:     " << m.crypto_errors.load() << "\n";
    std::cout << "    validation: " << m.envelope_validation_failures.load() << "\n";
    std::cout << "    rate limit: " << m.rate_limit_rejections.load() << "\n";
}

void simulate_handshake() {
    metrics::inc_handshakes_initiated();
    time::sleep_ms(10);
    metrics::inc_handshakes_completed();
    metrics::inc_sessions_created();
}

void simulate_packet_exchange() {
    for (int i = 0; i < 100; ++i) {
        metrics::inc_packets_sent();
        metrics::add_bytes_sent(1500);

        metrics::inc_packets_received();
        metrics::add_bytes_received(1500);
    }
}

void simulate_voting() {
    metrics::inc_proposals_received();
    metrics::inc_votes_cast();
    metrics::inc_votes_received();
    metrics::inc_votes_received();
    metrics::inc_proposals_approved();
}

auto main() -> int {
    auto init_result = botlink::init();
    if (init_result.is_err()) {
        std::cerr << "Failed to initialize: " << init_result.error().message.c_str() << "\n";
        return 1;
    }

    std::cout << "Botlink Metrics Demo\n";
    std::cout << "====================\n\n";

    // Ensure clean state
    metrics::global().reset();

    print_separator();
    std::cout << "Initial state (all zeros):\n";
    print_metrics();

    print_separator();
    std::cout << "\nSimulating handshake...\n";
    simulate_handshake();
    std::cout << "Done.\n\n";

    print_separator();
    std::cout << "\nSimulating packet exchange (100 packets each direction)...\n";
    simulate_packet_exchange();
    std::cout << "Done.\n\n";

    print_separator();
    std::cout << "\nSimulating trust voting...\n";
    simulate_voting();
    std::cout << "Done.\n\n";

    print_separator();
    std::cout << "\nSimulating some failures...\n";
    metrics::inc_handshakes_failed();
    metrics::inc_packets_dropped_invalid();
    metrics::inc_packets_dropped_replay();
    metrics::inc_crypto_errors();
    std::cout << "Done.\n\n";

    print_separator();
    std::cout << "\nFinal metrics state:\n";
    print_metrics();

    print_separator();
    std::cout << "\nDemonstrating thread-safe concurrent updates...\n";

    metrics::global().reset();

    constexpr int num_threads = 4;
    constexpr int ops_per_thread = 10000;

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([]() {
            for (int j = 0; j < ops_per_thread; ++j) {
                metrics::inc_packets_sent();
                metrics::add_bytes_sent(100);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    std::cout << "  " << num_threads << " threads x " << ops_per_thread << " operations each\n";
    std::cout << "  Expected packets_sent: " << (num_threads * ops_per_thread) << "\n";
    std::cout << "  Actual packets_sent:   " << metrics::global().packets_sent.load() << "\n";
    std::cout << "  Expected bytes_sent:   " << (num_threads * ops_per_thread * 100ULL) << "\n";
    std::cout << "  Actual bytes_sent:     " << metrics::global().bytes_sent.load() << "\n";

    print_separator();
    std::cout << "\nMetrics demo completed successfully!\n";

    return 0;
}
