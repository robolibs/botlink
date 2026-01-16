/* SPDX-License-Identifier: MIT */
/*
 * Botlink Time Utilities Demo
 * Demonstrates time functions, Timeout, and IntervalTimer
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>

using namespace botlink;
using namespace dp;

void print_separator() { std::cout << "----------------------------------------\n"; }

auto main() -> int {
    auto init_result = botlink::init();
    if (init_result.is_err()) {
        std::cerr << "Failed to initialize: " << init_result.error().message.c_str() << "\n";
        return 1;
    }

    std::cout << "Botlink Time Utilities Demo\n";
    std::cout << "===========================\n\n";

    print_separator();
    std::cout << "Time Functions:\n";

    i64 ns = time::now_ns();
    u64 ms = time::now_ms();
    f64 secs = time::now_secs();

    std::cout << "  Current time:\n";
    std::cout << "    Nanoseconds:  " << ns << "\n";
    std::cout << "    Milliseconds: " << ms << "\n";
    std::cout << "    Seconds:      " << std::fixed << std::setprecision(3) << secs << "\n\n";

    print_separator();
    std::cout << "Time Conversions:\n";

    u64 test_ms = 2500;
    std::cout << "  " << test_ms << "ms = " << time::ms_to_ns(test_ms) << "ns\n";
    std::cout << "  " << test_ms << "ms = " << std::fixed << std::setprecision(2)
              << time::ms_to_secs(test_ms) << "s\n";

    i64 test_ns = 1234567890;
    std::cout << "  " << test_ns << "ns = " << time::ns_to_ms(test_ns) << "ms\n";

    f64 test_secs = 3.75;
    std::cout << "  " << std::fixed << std::setprecision(2) << test_secs << "s = "
              << time::secs_to_ms(test_secs) << "ms\n\n";

    print_separator();
    std::cout << "Timeout Demo:\n";

    std::cout << "  Creating 500ms timeout...\n";
    Timeout timeout(500);

    std::cout << "  Initial state:\n";
    std::cout << "    is_expired:    " << (timeout.is_expired() ? "yes" : "no") << "\n";
    std::cout << "    remaining_ms:  " << timeout.remaining_ms() << "\n";

    std::cout << "  Sleeping 200ms...\n";
    time::sleep_ms(200);

    std::cout << "  After 200ms:\n";
    std::cout << "    is_expired:    " << (timeout.is_expired() ? "yes" : "no") << "\n";
    std::cout << "    remaining_ms:  " << timeout.remaining_ms() << "\n";

    std::cout << "  Sleeping 400ms...\n";
    time::sleep_ms(400);

    std::cout << "  After 600ms total:\n";
    std::cout << "    is_expired:    " << (timeout.is_expired() ? "yes" : "no") << "\n";
    std::cout << "    remaining_ms:  " << timeout.remaining_ms() << "\n\n";

    print_separator();
    std::cout << "Timeout::from_secs Demo:\n";

    Timeout t2 = Timeout::from_secs(2);
    std::cout << "  Created 2 second timeout\n";
    std::cout << "    remaining_ms: " << t2.remaining_ms() << "\n\n";

    print_separator();
    std::cout << "IntervalTimer Demo:\n";

    IntervalTimer timer(100);  // 100ms interval
    std::cout << "  Created 100ms interval timer\n";
    std::cout << "  Running for ~350ms, counting ticks...\n";

    int tick_count = 0;
    u64 start_time = time::now_ms();

    while (time::now_ms() - start_time < 350) {
        if (timer.should_tick()) {
            tick_count++;
            std::cout << "    Tick " << tick_count << " at " << (time::now_ms() - start_time) << "ms\n";
        }
        time::sleep_ms(10);  // Small sleep to avoid busy loop
    }

    std::cout << "  Total ticks: " << tick_count << "\n\n";

    print_separator();
    std::cout << "IntervalTimer reset Demo:\n";

    IntervalTimer timer2(200);
    std::cout << "  Created 200ms timer\n";

    time::sleep_ms(100);
    std::cout << "  After 100ms: should_tick = " << (timer2.should_tick() ? "yes" : "no") << "\n";

    std::cout << "  Resetting timer...\n";
    timer2.reset();

    time::sleep_ms(100);
    std::cout << "  After reset + 100ms: should_tick = " << (timer2.should_tick() ? "yes" : "no") << "\n";

    time::sleep_ms(120);
    std::cout << "  After reset + 220ms: should_tick = " << (timer2.should_tick() ? "yes" : "no") << "\n\n";

    print_separator();
    std::cout << "Stamped<T> Demo:\n";

    Stamped<f64> sensor_reading(23.5);
    std::cout << "  Created Stamped<double> with value 23.5\n";
    std::cout << "    timestamp: " << sensor_reading.timestamp << " ns\n";
    std::cout << "    value:     " << std::fixed << std::setprecision(1) << sensor_reading.value << "\n";
    std::cout << "    age:       " << sensor_reading.age() << " ns\n";
    std::cout << "    seconds:   " << std::fixed << std::setprecision(3) << sensor_reading.seconds() << " s\n\n";

    print_separator();
    std::cout << "Timing measurement example:\n";

    u64 op_start = time::now_ms();

    // Simulate some work
    volatile int sum = 0;
    for (int i = 0; i < 1000000; ++i) {
        sum += i;
    }

    u64 op_end = time::now_ms();
    std::cout << "  Operation took: " << (op_end - op_start) << "ms\n\n";

    print_separator();
    std::cout << "Time demo completed successfully!\n";

    return 0;
}
