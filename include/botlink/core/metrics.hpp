/* SPDX-License-Identifier: MIT */
/*
 * Botlink Metrics
 * Atomic counters for runtime statistics
 */

#pragma once

#include <atomic>
#include <botlink/core/types.hpp>

namespace botlink {

    using namespace dp;

    namespace metrics {

        // =============================================================================
        // Metric Counters (thread-safe atomic counters)
        // =============================================================================

        struct Counters {
            // Handshake metrics
            std::atomic<u64> handshakes_initiated{0};
            std::atomic<u64> handshakes_completed{0};
            std::atomic<u64> handshakes_failed{0};
            std::atomic<u64> handshakes_timed_out{0};

            // Packet metrics
            std::atomic<u64> packets_sent{0};
            std::atomic<u64> packets_received{0};
            std::atomic<u64> packets_dropped_replay{0};
            std::atomic<u64> packets_dropped_invalid{0};
            std::atomic<u64> packets_dropped_no_session{0};
            std::atomic<u64> packets_dropped_decrypt_fail{0};
            std::atomic<u64> packets_dropped_rate_limit{0};

            // Byte counters
            std::atomic<u64> bytes_sent{0};
            std::atomic<u64> bytes_received{0};

            // Session metrics
            std::atomic<u64> rekeys_initiated{0};
            std::atomic<u64> rekeys_completed{0};
            std::atomic<u64> sessions_created{0};
            std::atomic<u64> sessions_expired{0};

            // Trust/voting metrics
            std::atomic<u64> proposals_received{0};
            std::atomic<u64> proposals_approved{0};
            std::atomic<u64> proposals_rejected{0};
            std::atomic<u64> proposals_expired{0};
            std::atomic<u64> votes_cast{0};
            std::atomic<u64> votes_received{0};

            // Control plane metrics
            std::atomic<u64> join_requests_received{0};
            std::atomic<u64> join_requests_rejected{0};
            std::atomic<u64> membership_updates_sent{0};
            std::atomic<u64> membership_updates_received{0};

            // Relay metrics
            std::atomic<u64> relay_routes_established{0};
            std::atomic<u64> relay_packets_forwarded{0};
            std::atomic<u64> relay_packets_received{0};

            // Netdev metrics
            std::atomic<u64> packets_to_netdev{0};
            std::atomic<u64> packets_from_netdev{0};

            // Error metrics
            std::atomic<u64> crypto_errors{0};
            std::atomic<u64> envelope_validation_failures{0};
            std::atomic<u64> rate_limit_rejections{0};

            Counters() = default;

            // Reset all counters
            void reset() {
                handshakes_initiated.store(0);
                handshakes_completed.store(0);
                handshakes_failed.store(0);
                handshakes_timed_out.store(0);

                packets_sent.store(0);
                packets_received.store(0);
                packets_dropped_replay.store(0);
                packets_dropped_invalid.store(0);
                packets_dropped_no_session.store(0);
                packets_dropped_decrypt_fail.store(0);
                packets_dropped_rate_limit.store(0);

                bytes_sent.store(0);
                bytes_received.store(0);

                rekeys_initiated.store(0);
                rekeys_completed.store(0);
                sessions_created.store(0);
                sessions_expired.store(0);

                proposals_received.store(0);
                proposals_approved.store(0);
                proposals_rejected.store(0);
                proposals_expired.store(0);
                votes_cast.store(0);
                votes_received.store(0);

                join_requests_received.store(0);
                join_requests_rejected.store(0);
                membership_updates_sent.store(0);
                membership_updates_received.store(0);

                relay_routes_established.store(0);
                relay_packets_forwarded.store(0);
                relay_packets_received.store(0);

                packets_to_netdev.store(0);
                packets_from_netdev.store(0);

                crypto_errors.store(0);
                envelope_validation_failures.store(0);
                rate_limit_rejections.store(0);
            }
        };

        // =============================================================================
        // Global Metrics Instance
        // =============================================================================

        inline Counters &global() {
            static Counters instance;
            return instance;
        }

        // =============================================================================
        // Convenience increment functions
        // =============================================================================

        // Handshake
        inline void inc_handshakes_initiated() { global().handshakes_initiated.fetch_add(1); }
        inline void inc_handshakes_completed() { global().handshakes_completed.fetch_add(1); }
        inline void inc_handshakes_failed() { global().handshakes_failed.fetch_add(1); }
        inline void inc_handshakes_timed_out() { global().handshakes_timed_out.fetch_add(1); }

        // Packets
        inline void inc_packets_sent() { global().packets_sent.fetch_add(1); }
        inline void inc_packets_received() { global().packets_received.fetch_add(1); }
        inline void inc_packets_dropped_replay() { global().packets_dropped_replay.fetch_add(1); }
        inline void inc_packets_dropped_invalid() { global().packets_dropped_invalid.fetch_add(1); }
        inline void inc_packets_dropped_no_session() { global().packets_dropped_no_session.fetch_add(1); }
        inline void inc_packets_dropped_decrypt_fail() { global().packets_dropped_decrypt_fail.fetch_add(1); }
        inline void inc_packets_dropped_rate_limit() { global().packets_dropped_rate_limit.fetch_add(1); }

        // Bytes
        inline void add_bytes_sent(u64 n) { global().bytes_sent.fetch_add(n); }
        inline void add_bytes_received(u64 n) { global().bytes_received.fetch_add(n); }

        // Sessions
        inline void inc_rekeys_initiated() { global().rekeys_initiated.fetch_add(1); }
        inline void inc_rekeys_completed() { global().rekeys_completed.fetch_add(1); }
        inline void inc_sessions_created() { global().sessions_created.fetch_add(1); }
        inline void inc_sessions_expired() { global().sessions_expired.fetch_add(1); }

        // Trust/voting
        inline void inc_proposals_received() { global().proposals_received.fetch_add(1); }
        inline void inc_proposals_approved() { global().proposals_approved.fetch_add(1); }
        inline void inc_proposals_rejected() { global().proposals_rejected.fetch_add(1); }
        inline void inc_proposals_expired() { global().proposals_expired.fetch_add(1); }
        inline void inc_votes_cast() { global().votes_cast.fetch_add(1); }
        inline void inc_votes_received() { global().votes_received.fetch_add(1); }

        // Control plane
        inline void inc_join_requests_received() { global().join_requests_received.fetch_add(1); }
        inline void inc_join_requests_rejected() { global().join_requests_rejected.fetch_add(1); }
        inline void inc_membership_updates_sent() { global().membership_updates_sent.fetch_add(1); }
        inline void inc_membership_updates_received() { global().membership_updates_received.fetch_add(1); }

        // Relay
        inline void inc_relay_routes_established() { global().relay_routes_established.fetch_add(1); }
        inline void inc_relay_packets_forwarded() { global().relay_packets_forwarded.fetch_add(1); }
        inline void inc_relay_packets_received() { global().relay_packets_received.fetch_add(1); }

        // Netdev
        inline void inc_packets_to_netdev() { global().packets_to_netdev.fetch_add(1); }
        inline void inc_packets_from_netdev() { global().packets_from_netdev.fetch_add(1); }

        // Errors
        inline void inc_crypto_errors() { global().crypto_errors.fetch_add(1); }
        inline void inc_envelope_validation_failures() { global().envelope_validation_failures.fetch_add(1); }
        inline void inc_rate_limit_rejections() { global().rate_limit_rejections.fetch_add(1); }

    } // namespace metrics

} // namespace botlink
