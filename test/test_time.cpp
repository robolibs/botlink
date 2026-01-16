/* SPDX-License-Identifier: MIT */
/*
 * Botlink Time Utilities Tests
 * Tests for time functions, Timeout, and IntervalTimer
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>
#include <thread>

using namespace botlink;
using namespace dp;

TEST_SUITE("Time - Utility Functions") {

    TEST_CASE("now_ns returns positive value") {
        i64 ns = time::now_ns();
        CHECK(ns > 0);
    }

    TEST_CASE("now_ms returns positive value") {
        u64 ms = time::now_ms();
        CHECK(ms > 0);
    }

    TEST_CASE("now_secs returns positive value") {
        f64 secs = time::now_secs();
        CHECK(secs > 0.0);
    }

    TEST_CASE("Time values increase") {
        u64 ms1 = time::now_ms();
        time::sleep_ms(10);
        u64 ms2 = time::now_ms();

        CHECK(ms2 >= ms1);
    }

    TEST_CASE("ns_to_ms conversion") {
        CHECK(time::ns_to_ms(1'000'000) == 1);
        CHECK(time::ns_to_ms(5'000'000) == 5);
        CHECK(time::ns_to_ms(1'000'000'000) == 1000);
    }

    TEST_CASE("ms_to_ns conversion") {
        CHECK(time::ms_to_ns(1) == 1'000'000);
        CHECK(time::ms_to_ns(5) == 5'000'000);
        CHECK(time::ms_to_ns(1000) == 1'000'000'000);
    }

    TEST_CASE("secs_to_ms conversion") {
        CHECK(time::secs_to_ms(1.0) == 1000);
        CHECK(time::secs_to_ms(0.5) == 500);
        CHECK(time::secs_to_ms(2.5) == 2500);
    }

    TEST_CASE("ms_to_secs conversion") {
        CHECK(time::ms_to_secs(1000) == doctest::Approx(1.0));
        CHECK(time::ms_to_secs(500) == doctest::Approx(0.5));
        CHECK(time::ms_to_secs(2500) == doctest::Approx(2.5));
    }

    TEST_CASE("Conversion roundtrip") {
        u64 original_ms = 12345;
        i64 ns = time::ms_to_ns(original_ms);
        u64 result_ms = time::ns_to_ms(ns);
        CHECK(result_ms == original_ms);
    }

}

TEST_SUITE("Time - Timeout") {

    TEST_CASE("Timeout default constructor") {
        Timeout t;
        CHECK(t.deadline_ms == 0);
        CHECK(t.is_expired() == true);  // 0 deadline is always expired
    }

    TEST_CASE("Timeout with duration") {
        Timeout t(1000);  // 1 second
        CHECK(t.is_expired() == false);
        CHECK(t.remaining_ms() > 0);
        CHECK(t.remaining_ms() <= 1000);
    }

    TEST_CASE("Timeout expires") {
        Timeout t(50);  // 50ms
        CHECK(t.is_expired() == false);

        time::sleep_ms(60);  // Wait longer than timeout

        CHECK(t.is_expired() == true);
        CHECK(t.remaining_ms() == 0);
    }

    TEST_CASE("Timeout from_secs") {
        Timeout t = Timeout::from_secs(2);
        CHECK(t.is_expired() == false);
        // Should be roughly 2000ms remaining (minus tiny execution time)
        CHECK(t.remaining_ms() > 1900);
        CHECK(t.remaining_ms() <= 2000);
    }

    TEST_CASE("Timeout remaining decreases") {
        Timeout t(200);
        u64 r1 = t.remaining_ms();

        time::sleep_ms(50);
        u64 r2 = t.remaining_ms();

        CHECK(r2 < r1);
    }

    TEST_CASE("Timeout members for POD") {
        Timeout t(1000);
        auto [deadline] = t.members();
        CHECK(deadline == t.deadline_ms);
    }

}

TEST_SUITE("Time - IntervalTimer") {

    TEST_CASE("IntervalTimer default constructor") {
        IntervalTimer timer;
        CHECK(timer.interval_ms == 0);
    }

    TEST_CASE("IntervalTimer with interval") {
        IntervalTimer timer(100);  // 100ms interval
        CHECK(timer.interval_ms == 100);
        CHECK(timer.last_tick_ms > 0);
    }

    TEST_CASE("IntervalTimer should_tick initially false") {
        IntervalTimer timer(100);
        // Just created, shouldn't tick immediately
        CHECK(timer.should_tick() == false);
    }

    TEST_CASE("IntervalTimer should_tick after interval") {
        IntervalTimer timer(50);  // 50ms interval

        CHECK(timer.should_tick() == false);

        time::sleep_ms(60);

        CHECK(timer.should_tick() == true);
        // After ticking, last_tick is updated, so shouldn't tick again immediately
        CHECK(timer.should_tick() == false);
    }

    TEST_CASE("IntervalTimer reset") {
        IntervalTimer timer(100);

        time::sleep_ms(50);

        u64 old_tick = timer.last_tick_ms;
        timer.reset();
        CHECK(timer.last_tick_ms >= old_tick);
    }

    TEST_CASE("IntervalTimer members for POD") {
        IntervalTimer timer(100);
        auto [interval, last_tick] = timer.members();
        CHECK(interval == timer.interval_ms);
        CHECK(last_tick == timer.last_tick_ms);
    }

    TEST_CASE("IntervalTimer multiple ticks") {
        IntervalTimer timer(30);  // 30ms interval

        int tick_count = 0;
        u64 start = time::now_ms();

        // Run for ~150ms, should get ~5 ticks
        while (time::now_ms() - start < 150) {
            if (timer.should_tick()) {
                tick_count++;
            }
            time::sleep_ms(5);
        }

        // Should have gotten at least 3 ticks
        CHECK(tick_count >= 3);
    }

}

TEST_SUITE("Time - Stamped") {

    TEST_CASE("Stamped template alias exists") {
        Stamped<u32> stamped_value;
        stamped_value.value = 42;
        stamped_value.timestamp = time::now_ns();
        CHECK(stamped_value.value == 42);
        CHECK(stamped_value.timestamp > 0);
    }

    TEST_CASE("Stamped with value constructor") {
        Stamped<f64> temp(23.5);
        CHECK(temp.value == doctest::Approx(23.5));
        CHECK(temp.timestamp > 0);
    }

    TEST_CASE("Stamped comparison by timestamp") {
        Stamped<u32> s1(time::now_ns() - 1000, 1);
        Stamped<u32> s2(time::now_ns(), 2);

        CHECK(s1 < s2);
        CHECK(s2 > s1);
    }

}
