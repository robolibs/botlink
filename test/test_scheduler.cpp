/* SPDX-License-Identifier: MIT */
/*
 * Botlink Scheduler Tests
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>
#include <thread>

using namespace botlink;
using namespace dp;

TEST_SUITE("Scheduler - Timer Creation") {

    TEST_CASE("Create oneshot timer") {
        runtime::Scheduler scheduler;

        boolean fired = false;
        auto id = scheduler.create_oneshot("test_oneshot", 100, [&fired]() { fired = true; });

        CHECK(id != runtime::INVALID_TIMER_ID);
        CHECK(scheduler.timer_count() == 1);
        CHECK(scheduler.active_timer_count() == 1);
    }

    TEST_CASE("Create repeating timer") {
        runtime::Scheduler scheduler;

        int fire_count = 0;
        auto id = scheduler.create_repeating("test_repeating", 100, [&fire_count]() { fire_count++; });

        CHECK(id != runtime::INVALID_TIMER_ID);
        CHECK(scheduler.timer_count() == 1);
        CHECK(scheduler.active_timer_count() == 1);
    }

    TEST_CASE("Create multiple timers") {
        runtime::Scheduler scheduler;

        auto id1 = scheduler.create_oneshot("timer1", 100, []() {});
        auto id2 = scheduler.create_oneshot("timer2", 200, []() {});
        auto id3 = scheduler.create_repeating("timer3", 300, []() {});

        CHECK(id1 != id2);
        CHECK(id2 != id3);
        CHECK(scheduler.timer_count() == 3);
        CHECK(scheduler.active_timer_count() == 3);
    }

    TEST_CASE("Timer IDs are unique") {
        runtime::Scheduler scheduler;

        Vector<runtime::TimerId> ids;
        for (int i = 0; i < 10; ++i) {
            ids.push_back(scheduler.create_oneshot("timer" + String(std::to_string(i).c_str()), 100, []() {}));
        }

        // Check all IDs are unique
        for (usize i = 0; i < ids.size(); ++i) {
            for (usize j = i + 1; j < ids.size(); ++j) {
                CHECK(ids[i] != ids[j]);
            }
        }
    }

}

TEST_SUITE("Scheduler - Timer Control") {

    TEST_CASE("Cancel timer") {
        runtime::Scheduler scheduler;

        auto id = scheduler.create_oneshot("test", 1000, []() {});
        CHECK(scheduler.active_timer_count() == 1);

        boolean cancelled = scheduler.cancel(id);
        CHECK(cancelled == true);
        CHECK(scheduler.active_timer_count() == 0);
    }

    TEST_CASE("Cancel non-existent timer returns false") {
        runtime::Scheduler scheduler;

        boolean cancelled = scheduler.cancel(9999);
        CHECK(cancelled == false);
    }

    TEST_CASE("Reset timer") {
        runtime::Scheduler scheduler;

        auto id = scheduler.create_oneshot("test", 100, []() {});
        auto timer = scheduler.get_timer(id);
        REQUIRE(timer.has_value());
        u64 original_fire = timer->next_fire_ms;

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        boolean reset = scheduler.reset(id);
        CHECK(reset == true);

        timer = scheduler.get_timer(id);
        REQUIRE(timer.has_value());
        CHECK(timer->next_fire_ms > original_fire);
    }

    TEST_CASE("Reschedule timer with new interval") {
        runtime::Scheduler scheduler;

        auto id = scheduler.create_oneshot("test", 100, []() {});
        auto timer = scheduler.get_timer(id);
        REQUIRE(timer.has_value());
        CHECK(timer->interval_ms == 100);

        boolean rescheduled = scheduler.reschedule(id, 500);
        CHECK(rescheduled == true);

        timer = scheduler.get_timer(id);
        REQUIRE(timer.has_value());
        CHECK(timer->interval_ms == 500);
    }

}

TEST_SUITE("Scheduler - Timer Firing") {

    TEST_CASE("Oneshot timer fires once") {
        runtime::Scheduler scheduler;

        int fire_count = 0;
        scheduler.create_oneshot("test", 10, [&fire_count]() { fire_count++; });

        // Wait for timer to fire
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        usize fired = scheduler.process();
        CHECK(fired == 1);
        CHECK(fire_count == 1);

        // Process again - should not fire
        fired = scheduler.process();
        CHECK(fired == 0);
        CHECK(fire_count == 1);
    }

    TEST_CASE("Repeating timer fires multiple times") {
        runtime::Scheduler scheduler;

        int fire_count = 0;
        scheduler.create_repeating("test", 10, [&fire_count]() { fire_count++; });

        // Wait and process multiple times
        for (int i = 0; i < 3; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
            scheduler.process();
        }

        CHECK(fire_count >= 2);
    }

    TEST_CASE("Timer not fired before delay") {
        runtime::Scheduler scheduler;

        boolean fired = false;
        scheduler.create_oneshot("test", 1000, [&fired]() { fired = true; });

        usize processed = scheduler.process();
        CHECK(processed == 0);
        CHECK(fired == false);
    }

}

TEST_SUITE("Scheduler - Query") {

    TEST_CASE("Get timer by ID") {
        runtime::Scheduler scheduler;

        auto id = scheduler.create_oneshot("my_timer", 100, []() {});

        auto timer = scheduler.get_timer(id);
        REQUIRE(timer.has_value());
        CHECK(timer->id == id);
        CHECK(timer->name == "my_timer");
        CHECK(timer->interval_ms == 100);
        CHECK(timer->type == runtime::TimerType::OneShot);
        CHECK(timer->active == true);
    }

    TEST_CASE("Get non-existent timer returns empty") {
        runtime::Scheduler scheduler;

        auto timer = scheduler.get_timer(9999);
        CHECK_FALSE(timer.has_value());
    }

    TEST_CASE("Time until next fire") {
        runtime::Scheduler scheduler;

        // No timers - returns -1
        CHECK(scheduler.time_until_next_ms() == -1);

        // Add timer
        scheduler.create_oneshot("test", 1000, []() {});
        i64 time_left = scheduler.time_until_next_ms();
        CHECK(time_left > 0);
        CHECK(time_left <= 1000);
    }

    TEST_CASE("TimerEntry is_due check") {
        runtime::TimerEntry entry;
        entry.active = true;
        entry.next_fire_ms = time::now_ms() - 100; // Already past

        CHECK(entry.is_due() == true);

        entry.next_fire_ms = time::now_ms() + 1000; // In the future
        CHECK(entry.is_due() == false);

        entry.active = false;
        CHECK(entry.is_due() == false);
    }

    TEST_CASE("TimerEntry time_until_fire_ms") {
        runtime::TimerEntry entry;
        entry.active = false;
        CHECK(entry.time_until_fire_ms() == -1);

        entry.active = true;
        entry.next_fire_ms = time::now_ms() + 500;
        i64 time_left = entry.time_until_fire_ms();
        CHECK(time_left > 0);
        CHECK(time_left <= 500);
    }

}

TEST_SUITE("Scheduler - Cleanup") {

    TEST_CASE("Cleanup removes inactive timers") {
        runtime::Scheduler scheduler;

        auto id1 = scheduler.create_oneshot("timer1", 1000, []() {});
        auto id2 = scheduler.create_oneshot("timer2", 1000, []() {});
        scheduler.create_oneshot("timer3", 1000, []() {});

        scheduler.cancel(id1);
        scheduler.cancel(id2);

        CHECK(scheduler.timer_count() == 3);
        CHECK(scheduler.active_timer_count() == 1);

        usize removed = scheduler.cleanup();
        CHECK(removed == 2);
        CHECK(scheduler.timer_count() == 1);
        CHECK(scheduler.active_timer_count() == 1);
    }

    TEST_CASE("Clear removes all timers") {
        runtime::Scheduler scheduler;

        scheduler.create_oneshot("timer1", 100, []() {});
        scheduler.create_oneshot("timer2", 200, []() {});
        scheduler.create_repeating("timer3", 300, []() {});

        CHECK(scheduler.timer_count() == 3);

        scheduler.clear();

        CHECK(scheduler.timer_count() == 0);
        CHECK(scheduler.active_timer_count() == 0);
    }

}

TEST_SUITE("Scheduler - Timer Names") {

    TEST_CASE("Standard timer name constants exist") {
        CHECK(runtime::timer_names::KEEPALIVE != nullptr);
        CHECK(runtime::timer_names::REKEY != nullptr);
        CHECK(runtime::timer_names::VOTE_TIMEOUT != nullptr);
        CHECK(runtime::timer_names::ENDPOINT_REFRESH != nullptr);
        CHECK(runtime::timer_names::TRUST_SYNC != nullptr);
        CHECK(runtime::timer_names::PEER_CLEANUP != nullptr);
    }

}
