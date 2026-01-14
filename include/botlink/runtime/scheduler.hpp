/* SPDX-License-Identifier: MIT */
/*
 * Botlink Scheduler
 * Timer management for keepalive, rekey, and vote timeouts
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/time.hpp>
#include <botlink/core/types.hpp>
#include <datapod/datapod.hpp>
#include <echo/echo.hpp>
#include <functional>

namespace botlink {

    using namespace dp;

    namespace runtime {

        // =============================================================================
        // Timer ID
        // =============================================================================

        using TimerId = u32;
        inline constexpr TimerId INVALID_TIMER_ID = 0;

        // =============================================================================
        // Timer Types
        // =============================================================================

        enum class TimerType : u8 {
            OneShot = 0,
            Repeating = 1,
        };

        // =============================================================================
        // Timer Entry
        // =============================================================================

        struct TimerEntry {
            TimerId id = INVALID_TIMER_ID;
            String name;
            TimerType type = TimerType::OneShot;
            u64 interval_ms = 0;
            u64 next_fire_ms = 0;
            boolean active = false;
            std::function<void()> callback;

            TimerEntry() = default;

            [[nodiscard]] auto is_due() const -> boolean { return active && time::now_ms() >= next_fire_ms; }

            [[nodiscard]] auto time_until_fire_ms() const -> i64 {
                if (!active) {
                    return -1;
                }
                i64 diff = static_cast<i64>(next_fire_ms) - static_cast<i64>(time::now_ms());
                return diff > 0 ? diff : 0;
            }
        };

        // =============================================================================
        // Scheduler
        // =============================================================================

        class Scheduler {
          private:
            Vector<TimerEntry> timers_;
            TimerId next_id_ = 1;

          public:
            Scheduler() = default;

            // =============================================================================
            // Timer Creation
            // =============================================================================

            // Create a one-shot timer
            auto create_oneshot(const String &name, u64 delay_ms, std::function<void()> callback) -> TimerId {
                TimerEntry entry;
                entry.id = next_id_++;
                entry.name = name;
                entry.type = TimerType::OneShot;
                entry.interval_ms = delay_ms;
                entry.next_fire_ms = time::now_ms() + delay_ms;
                entry.active = true;
                entry.callback = std::move(callback);

                timers_.push_back(entry);
                echo::debug("Scheduler: Created oneshot timer '", name.c_str(), "' with delay ", delay_ms, "ms");
                return entry.id;
            }

            // Create a repeating timer
            auto create_repeating(const String &name, u64 interval_ms, std::function<void()> callback) -> TimerId {
                TimerEntry entry;
                entry.id = next_id_++;
                entry.name = name;
                entry.type = TimerType::Repeating;
                entry.interval_ms = interval_ms;
                entry.next_fire_ms = time::now_ms() + interval_ms;
                entry.active = true;
                entry.callback = std::move(callback);

                timers_.push_back(entry);
                echo::debug("Scheduler: Created repeating timer '", name.c_str(), "' with interval ", interval_ms,
                            "ms");
                return entry.id;
            }

            // =============================================================================
            // Timer Control
            // =============================================================================

            // Cancel a timer
            auto cancel(TimerId id) -> boolean {
                for (auto &timer : timers_) {
                    if (timer.id == id) {
                        timer.active = false;
                        echo::debug("Scheduler: Cancelled timer '", timer.name.c_str(), "'");
                        return true;
                    }
                }
                return false;
            }

            // Reset a timer (restart countdown)
            auto reset(TimerId id) -> boolean {
                for (auto &timer : timers_) {
                    if (timer.id == id) {
                        timer.next_fire_ms = time::now_ms() + timer.interval_ms;
                        timer.active = true;
                        return true;
                    }
                }
                return false;
            }

            // Reschedule a timer with new interval
            auto reschedule(TimerId id, u64 new_interval_ms) -> boolean {
                for (auto &timer : timers_) {
                    if (timer.id == id) {
                        timer.interval_ms = new_interval_ms;
                        timer.next_fire_ms = time::now_ms() + new_interval_ms;
                        timer.active = true;
                        return true;
                    }
                }
                return false;
            }

            // =============================================================================
            // Processing
            // =============================================================================

            // Process all due timers
            auto process() -> usize {
                usize fired = 0;
                u64 now = time::now_ms();

                for (auto &timer : timers_) {
                    if (timer.active && now >= timer.next_fire_ms) {
                        // Fire callback
                        if (timer.callback) {
                            timer.callback();
                        }
                        ++fired;

                        // Handle timer type
                        if (timer.type == TimerType::OneShot) {
                            timer.active = false;
                        } else {
                            // Repeating: schedule next fire
                            timer.next_fire_ms = now + timer.interval_ms;
                        }
                    }
                }

                return fired;
            }

            // Get time until next timer fires (for sleep/poll timeout)
            [[nodiscard]] auto time_until_next_ms() const -> i64 {
                i64 min_time = -1;

                for (const auto &timer : timers_) {
                    if (timer.active) {
                        i64 time_left = timer.time_until_fire_ms();
                        if (min_time < 0 || time_left < min_time) {
                            min_time = time_left;
                        }
                    }
                }

                return min_time;
            }

            // =============================================================================
            // Query
            // =============================================================================

            [[nodiscard]] auto get_timer(TimerId id) const -> Optional<TimerEntry> {
                for (const auto &timer : timers_) {
                    if (timer.id == id) {
                        return timer;
                    }
                }
                return Optional<TimerEntry>();
            }

            [[nodiscard]] auto timer_count() const -> usize { return timers_.size(); }

            [[nodiscard]] auto active_timer_count() const -> usize {
                usize count = 0;
                for (const auto &timer : timers_) {
                    if (timer.active) {
                        ++count;
                    }
                }
                return count;
            }

            // =============================================================================
            // Cleanup
            // =============================================================================

            // Remove inactive timers
            auto cleanup() -> usize {
                Vector<TimerEntry> active_timers;
                for (const auto &timer : timers_) {
                    if (timer.active) {
                        active_timers.push_back(timer);
                    }
                }
                usize removed = timers_.size() - active_timers.size();
                timers_ = active_timers;
                return removed;
            }

            // Clear all timers
            auto clear() -> void { timers_.clear(); }
        };

        // =============================================================================
        // Standard Timer Names
        // =============================================================================

        namespace timer_names {
            inline constexpr const char *KEEPALIVE = "keepalive";
            inline constexpr const char *REKEY = "rekey";
            inline constexpr const char *VOTE_TIMEOUT = "vote_timeout";
            inline constexpr const char *ENDPOINT_REFRESH = "endpoint_refresh";
            inline constexpr const char *TRUST_SYNC = "trust_sync";
            inline constexpr const char *PEER_CLEANUP = "peer_cleanup";
        } // namespace timer_names

    } // namespace runtime

} // namespace botlink
