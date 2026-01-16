/* SPDX-License-Identifier: MIT */
/*
 * Botlink Metrics Tests
 * Tests for atomic metric counters
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>
#include <thread>

using namespace botlink;
using namespace dp;

TEST_SUITE("Metrics - Counters") {

    TEST_CASE("Counters default to zero") {
        metrics::Counters counters;

        CHECK(counters.handshakes_initiated.load() == 0);
        CHECK(counters.handshakes_completed.load() == 0);
        CHECK(counters.packets_sent.load() == 0);
        CHECK(counters.packets_received.load() == 0);
        CHECK(counters.bytes_sent.load() == 0);
        CHECK(counters.sessions_created.load() == 0);
        CHECK(counters.proposals_received.load() == 0);
        CHECK(counters.relay_packets_forwarded.load() == 0);
        CHECK(counters.crypto_errors.load() == 0);
    }

    TEST_CASE("Counter increment") {
        metrics::Counters counters;

        counters.handshakes_initiated.fetch_add(1);
        CHECK(counters.handshakes_initiated.load() == 1);

        counters.handshakes_initiated.fetch_add(5);
        CHECK(counters.handshakes_initiated.load() == 6);
    }

    TEST_CASE("Counters reset") {
        metrics::Counters counters;

        counters.handshakes_initiated.store(100);
        counters.packets_sent.store(200);
        counters.bytes_sent.store(300);
        counters.sessions_created.store(400);

        CHECK(counters.handshakes_initiated.load() == 100);
        CHECK(counters.packets_sent.load() == 200);
        CHECK(counters.bytes_sent.load() == 300);
        CHECK(counters.sessions_created.load() == 400);

        counters.reset();

        CHECK(counters.handshakes_initiated.load() == 0);
        CHECK(counters.packets_sent.load() == 0);
        CHECK(counters.bytes_sent.load() == 0);
        CHECK(counters.sessions_created.load() == 0);
    }

}

TEST_SUITE("Metrics - Global Instance") {

    TEST_CASE("Global metrics instance exists") {
        // Reset to known state
        metrics::global().reset();

        metrics::Counters& counters = metrics::global();
        CHECK(counters.handshakes_initiated.load() == 0);
    }

    TEST_CASE("Global instance is singleton") {
        metrics::global().reset();

        metrics::Counters& c1 = metrics::global();
        metrics::Counters& c2 = metrics::global();

        c1.packets_sent.store(42);
        CHECK(c2.packets_sent.load() == 42);
    }

}

TEST_SUITE("Metrics - Convenience Functions") {

    TEST_CASE("Handshake increment functions") {
        metrics::global().reset();

        metrics::inc_handshakes_initiated();
        CHECK(metrics::global().handshakes_initiated.load() == 1);

        metrics::inc_handshakes_completed();
        CHECK(metrics::global().handshakes_completed.load() == 1);

        metrics::inc_handshakes_failed();
        CHECK(metrics::global().handshakes_failed.load() == 1);

        metrics::inc_handshakes_timed_out();
        CHECK(metrics::global().handshakes_timed_out.load() == 1);
    }

    TEST_CASE("Packet increment functions") {
        metrics::global().reset();

        metrics::inc_packets_sent();
        metrics::inc_packets_sent();
        CHECK(metrics::global().packets_sent.load() == 2);

        metrics::inc_packets_received();
        CHECK(metrics::global().packets_received.load() == 1);

        metrics::inc_packets_dropped_replay();
        CHECK(metrics::global().packets_dropped_replay.load() == 1);

        metrics::inc_packets_dropped_invalid();
        CHECK(metrics::global().packets_dropped_invalid.load() == 1);

        metrics::inc_packets_dropped_no_session();
        CHECK(metrics::global().packets_dropped_no_session.load() == 1);

        metrics::inc_packets_dropped_decrypt_fail();
        CHECK(metrics::global().packets_dropped_decrypt_fail.load() == 1);
    }

    TEST_CASE("Byte counter functions") {
        metrics::global().reset();

        metrics::add_bytes_sent(100);
        CHECK(metrics::global().bytes_sent.load() == 100);

        metrics::add_bytes_sent(50);
        CHECK(metrics::global().bytes_sent.load() == 150);

        metrics::add_bytes_received(1024);
        CHECK(metrics::global().bytes_received.load() == 1024);
    }

    TEST_CASE("Session increment functions") {
        metrics::global().reset();

        metrics::inc_rekeys_initiated();
        CHECK(metrics::global().rekeys_initiated.load() == 1);

        metrics::inc_rekeys_completed();
        CHECK(metrics::global().rekeys_completed.load() == 1);

        metrics::inc_sessions_created();
        CHECK(metrics::global().sessions_created.load() == 1);

        metrics::inc_sessions_expired();
        CHECK(metrics::global().sessions_expired.load() == 1);
    }

    TEST_CASE("Trust/voting increment functions") {
        metrics::global().reset();

        metrics::inc_proposals_received();
        CHECK(metrics::global().proposals_received.load() == 1);

        metrics::inc_proposals_approved();
        CHECK(metrics::global().proposals_approved.load() == 1);

        metrics::inc_proposals_rejected();
        CHECK(metrics::global().proposals_rejected.load() == 1);

        metrics::inc_proposals_expired();
        CHECK(metrics::global().proposals_expired.load() == 1);

        metrics::inc_votes_cast();
        CHECK(metrics::global().votes_cast.load() == 1);

        metrics::inc_votes_received();
        CHECK(metrics::global().votes_received.load() == 1);
    }

    TEST_CASE("Control plane increment functions") {
        metrics::global().reset();

        metrics::inc_join_requests_received();
        CHECK(metrics::global().join_requests_received.load() == 1);

        metrics::inc_join_requests_rejected();
        CHECK(metrics::global().join_requests_rejected.load() == 1);

        metrics::inc_membership_updates_sent();
        CHECK(metrics::global().membership_updates_sent.load() == 1);

        metrics::inc_membership_updates_received();
        CHECK(metrics::global().membership_updates_received.load() == 1);
    }

    TEST_CASE("Relay increment functions") {
        metrics::global().reset();

        metrics::inc_relay_routes_established();
        CHECK(metrics::global().relay_routes_established.load() == 1);

        metrics::inc_relay_packets_forwarded();
        CHECK(metrics::global().relay_packets_forwarded.load() == 1);

        metrics::inc_relay_packets_received();
        CHECK(metrics::global().relay_packets_received.load() == 1);
    }

    TEST_CASE("Error increment functions") {
        metrics::global().reset();

        metrics::inc_crypto_errors();
        CHECK(metrics::global().crypto_errors.load() == 1);

        metrics::inc_envelope_validation_failures();
        CHECK(metrics::global().envelope_validation_failures.load() == 1);

        metrics::inc_rate_limit_rejections();
        CHECK(metrics::global().rate_limit_rejections.load() == 1);
    }

}

TEST_SUITE("Metrics - Thread Safety") {

    TEST_CASE("Concurrent increments are atomic") {
        metrics::global().reset();

        constexpr int num_threads = 4;
        constexpr int increments_per_thread = 1000;

        std::vector<std::thread> threads;
        for (int i = 0; i < num_threads; ++i) {
            threads.emplace_back([]() {
                for (int j = 0; j < increments_per_thread; ++j) {
                    metrics::inc_packets_sent();
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        CHECK(metrics::global().packets_sent.load() == num_threads * increments_per_thread);
    }

}
