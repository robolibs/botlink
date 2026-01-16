/* SPDX-License-Identifier: MIT */
/*
 * Scheduler Demo
 * Demonstrates timer management for keepalive, rekey, and timeouts
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <thread>
#include <chrono>

using namespace botlink;
using namespace dp;

int main() {
    std::cout << "=== Scheduler Demo ===\n\n";

    // ==========================================================================
    // Step 1: Create scheduler
    // ==========================================================================
    std::cout << "1. Creating scheduler...\n";

    runtime::Scheduler scheduler;

    std::cout << "   Initial timer count: " << scheduler.timer_count() << "\n";
    std::cout << "   Active timer count: " << scheduler.active_timer_count() << "\n\n";

    // ==========================================================================
    // Step 2: Create one-shot timer
    // ==========================================================================
    std::cout << "2. Creating one-shot timer (100ms delay)...\n";

    int oneshot_fired = 0;
    auto oneshot_id = scheduler.create_oneshot("demo_oneshot", 100, [&oneshot_fired]() {
        oneshot_fired++;
        std::cout << "   [CALLBACK] One-shot timer fired!\n";
    });

    std::cout << "   Timer ID: " << oneshot_id << "\n";
    std::cout << "   Timer count: " << scheduler.timer_count() << "\n\n";

    // ==========================================================================
    // Step 3: Create repeating timer
    // ==========================================================================
    std::cout << "3. Creating repeating timer (50ms interval)...\n";

    int repeat_count = 0;
    auto repeat_id = scheduler.create_repeating("demo_repeating", 50, [&repeat_count]() {
        repeat_count++;
        std::cout << "   [CALLBACK] Repeating timer fired (count: " << repeat_count << ")\n";
    });

    std::cout << "   Timer ID: " << repeat_id << "\n";
    std::cout << "   Timer count: " << scheduler.timer_count() << "\n\n";

    // ==========================================================================
    // Step 4: Query timer info
    // ==========================================================================
    std::cout << "4. Querying timer information...\n";

    auto oneshot_info = scheduler.get_timer(oneshot_id);
    if (oneshot_info.has_value()) {
        std::cout << "   One-shot timer:\n";
        std::cout << "     Name: " << oneshot_info->name.c_str() << "\n";
        std::cout << "     Interval: " << oneshot_info->interval_ms << "ms\n";
        std::cout << "     Active: " << (oneshot_info->active ? "YES" : "NO") << "\n";
        std::cout << "     Type: " << (oneshot_info->type == runtime::TimerType::OneShot ? "OneShot" : "Repeating") << "\n";
    }

    auto repeat_info = scheduler.get_timer(repeat_id);
    if (repeat_info.has_value()) {
        std::cout << "   Repeating timer:\n";
        std::cout << "     Name: " << repeat_info->name.c_str() << "\n";
        std::cout << "     Interval: " << repeat_info->interval_ms << "ms\n";
        std::cout << "     Active: " << (repeat_info->active ? "YES" : "NO") << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 5: Wait and process timers
    // ==========================================================================
    std::cout << "5. Processing timers (waiting 200ms total)...\n";

    for (int i = 0; i < 4; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        usize fired = scheduler.process();
        if (fired > 0) {
            std::cout << "   Processed " << fired << " timer(s)\n";
        }
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 6: Check timer states
    // ==========================================================================
    std::cout << "6. Checking timer states...\n";

    std::cout << "   One-shot fired count: " << oneshot_fired << "\n";
    std::cout << "   Repeating fired count: " << repeat_count << "\n";

    oneshot_info = scheduler.get_timer(oneshot_id);
    if (oneshot_info.has_value()) {
        std::cout << "   One-shot still active: " << (oneshot_info->active ? "YES" : "NO") << "\n";
    }

    repeat_info = scheduler.get_timer(repeat_id);
    if (repeat_info.has_value()) {
        std::cout << "   Repeating still active: " << (repeat_info->active ? "YES" : "NO") << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 7: Reset and reschedule timer
    // ==========================================================================
    std::cout << "7. Resetting and rescheduling...\n";

    // Create a new one-shot for reset demo
    auto reset_id = scheduler.create_oneshot("reset_demo", 1000, []() {
        std::cout << "   [CALLBACK] Reset demo timer fired!\n";
    });

    std::cout << "   Created timer with 1000ms delay\n";

    // Reschedule to 50ms
    scheduler.reschedule(reset_id, 50);
    std::cout << "   Rescheduled to 50ms\n";

    // Reset the timer (restarts countdown)
    scheduler.reset(reset_id);
    std::cout << "   Reset timer countdown\n";

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    scheduler.process();
    std::cout << "\n";

    // ==========================================================================
    // Step 8: Cancel timer
    // ==========================================================================
    std::cout << "8. Cancelling repeating timer...\n";

    std::cout << "   Active timers before cancel: " << scheduler.active_timer_count() << "\n";
    bool cancelled = scheduler.cancel(repeat_id);
    std::cout << "   Cancel result: " << (cancelled ? "SUCCESS" : "FAILED") << "\n";
    std::cout << "   Active timers after cancel: " << scheduler.active_timer_count() << "\n\n";

    // ==========================================================================
    // Step 9: Timer names
    // ==========================================================================
    std::cout << "9. Standard timer names...\n";

    std::cout << "   KEEPALIVE: " << runtime::timer_names::KEEPALIVE << "\n";
    std::cout << "   REKEY: " << runtime::timer_names::REKEY << "\n";
    std::cout << "   VOTE_TIMEOUT: " << runtime::timer_names::VOTE_TIMEOUT << "\n";
    std::cout << "   ENDPOINT_REFRESH: " << runtime::timer_names::ENDPOINT_REFRESH << "\n";
    std::cout << "   TRUST_SYNC: " << runtime::timer_names::TRUST_SYNC << "\n";
    std::cout << "   PEER_CLEANUP: " << runtime::timer_names::PEER_CLEANUP << "\n\n";

    // ==========================================================================
    // Step 10: Cleanup and clear
    // ==========================================================================
    std::cout << "10. Cleanup and clear...\n";

    std::cout << "   Total timers: " << scheduler.timer_count() << "\n";
    std::cout << "   Active timers: " << scheduler.active_timer_count() << "\n";

    usize cleaned = scheduler.cleanup();
    std::cout << "   Cleaned up " << cleaned << " inactive timer(s)\n";
    std::cout << "   Timer count after cleanup: " << scheduler.timer_count() << "\n";

    scheduler.clear();
    std::cout << "   Cleared all timers\n";
    std::cout << "   Timer count after clear: " << scheduler.timer_count() << "\n\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
