/* SPDX-License-Identifier: MIT */
/*
 * Botlink Time Utilities
 * Time-related types and functions using datapod
 */

#pragma once

#include <chrono>
#include <datapod/datapod.hpp>
#include <thread>

namespace botlink {

    using namespace dp;

    // =============================================================================
    // Type Aliases from Datapod
    // =============================================================================

    template <typename T> using Stamped = dp::Stamp<T>;

    // =============================================================================
    // Time Utilities
    // =============================================================================

    namespace time {

        // Get current timestamp in nanoseconds
        inline auto now_ns() -> i64 { return dp::Stamp<u8>::now(); }

        // Get current timestamp in milliseconds
        inline auto now_ms() -> u64 { return static_cast<u64>(now_ns() / 1'000'000); }

        // Get current timestamp in seconds
        inline auto now_secs() -> f64 { return static_cast<f64>(now_ns()) / 1e9; }

        // Convert nanoseconds to milliseconds
        inline auto ns_to_ms(i64 ns) -> u64 { return static_cast<u64>(ns / 1'000'000); }

        // Convert milliseconds to nanoseconds
        inline auto ms_to_ns(u64 ms) -> i64 { return static_cast<i64>(ms) * 1'000'000; }

        // Convert seconds to milliseconds
        inline auto secs_to_ms(f64 secs) -> u64 { return static_cast<u64>(secs * 1000.0); }

        // Convert milliseconds to seconds
        inline auto ms_to_secs(u64 ms) -> f64 { return static_cast<f64>(ms) / 1000.0; }

        // Sleep for specified milliseconds
        inline auto sleep_ms(u64 ms) -> void { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

    } // namespace time

    // =============================================================================
    // Timeout Calculation
    // =============================================================================

    struct Timeout {
        u64 deadline_ms = 0;

        Timeout() = default;

        explicit Timeout(u64 duration_ms) : deadline_ms(time::now_ms() + duration_ms) {}

        [[nodiscard]] auto is_expired() const -> boolean { return time::now_ms() >= deadline_ms; }

        [[nodiscard]] auto remaining_ms() const -> u64 {
            u64 now = time::now_ms();
            if (now >= deadline_ms)
                return 0;
            return deadline_ms - now;
        }

        static auto from_secs(u64 secs) -> Timeout { return Timeout(secs * 1000); }

        auto members() noexcept { return std::tie(deadline_ms); }
        auto members() const noexcept { return std::tie(deadline_ms); }
    };

    // =============================================================================
    // Interval Timer
    // =============================================================================

    struct IntervalTimer {
        u64 interval_ms = 0;
        u64 last_tick_ms = 0;

        IntervalTimer() = default;

        explicit IntervalTimer(u64 interval) : interval_ms(interval), last_tick_ms(time::now_ms()) {}

        [[nodiscard]] auto should_tick() -> boolean {
            u64 now = time::now_ms();
            if (now - last_tick_ms >= interval_ms) {
                last_tick_ms = now;
                return true;
            }
            return false;
        }

        auto reset() -> void { last_tick_ms = time::now_ms(); }

        auto members() noexcept { return std::tie(interval_ms, last_tick_ms); }
        auto members() const noexcept { return std::tie(interval_ms, last_tick_ms); }
    };

} // namespace botlink
