/* SPDX-License-Identifier: MIT */
/*
 * Endpoint Parsing Demo
 * Demonstrates network endpoint parsing and formatting
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

int main() {
    std::cout << "=== Endpoint Parsing Demo ===\n\n";

    // ==========================================================================
    // Parse IPv4 endpoints
    // ==========================================================================
    std::cout << "1. Parsing IPv4 endpoints...\n";

    auto ep1_result = net::parse_endpoint("192.168.1.1:51820");
    if (ep1_result.is_ok()) {
        auto& ep = ep1_result.value();
        std::cout << "   Input: 192.168.1.1:51820\n";
        std::cout << "   Family: " << (ep.family == AddrFamily::IPv4 ? "IPv4" : "IPv6") << "\n";
        std::cout << "   Port: " << ep.port << "\n";
        std::cout << "   IP: " << static_cast<int>(ep.ipv4.octets[0]) << "."
                  << static_cast<int>(ep.ipv4.octets[1]) << "."
                  << static_cast<int>(ep.ipv4.octets[2]) << "."
                  << static_cast<int>(ep.ipv4.octets[3]) << "\n";
    }

    auto ep2_result = net::parse_endpoint("10.42.0.1:8080");
    if (ep2_result.is_ok()) {
        auto& ep = ep2_result.value();
        std::cout << "\n   Input: 10.42.0.1:8080\n";
        std::cout << "   Port: " << ep.port << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Parse IPv6 endpoints
    // ==========================================================================
    std::cout << "2. Parsing IPv6 endpoints...\n";

    auto ep3_result = net::parse_endpoint("[::1]:8080");
    if (ep3_result.is_ok()) {
        auto& ep = ep3_result.value();
        std::cout << "   Input: [::1]:8080\n";
        std::cout << "   Family: " << (ep.family == AddrFamily::IPv6 ? "IPv6" : "IPv4") << "\n";
        std::cout << "   Port: " << ep.port << "\n";
    }

    auto ep4_result = net::parse_endpoint("[2001:db8::1]:51820");
    if (ep4_result.is_ok()) {
        std::cout << "\n   Input: [2001:db8::1]:51820\n";
        std::cout << "   Parsed successfully!\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Parse URIs
    // ==========================================================================
    std::cout << "3. Parsing URIs...\n";

    auto uri1_result = net::parse_uri("udp://192.168.1.1:51820");
    if (uri1_result.is_ok()) {
        auto& uri = uri1_result.value();
        std::cout << "   Input: udp://192.168.1.1:51820\n";
        std::cout << "   Scheme: " << net::scheme_to_string(uri.scheme) << "\n";
        std::cout << "   Host: " << uri.host.c_str() << "\n";
        std::cout << "   Port: " << uri.port << "\n";
        std::cout << "   Is IPv6: " << (uri.is_ipv6 ? "yes" : "no") << "\n";
    }

    auto uri2_result = net::parse_uri("tcp://[::1]:3000");
    if (uri2_result.is_ok()) {
        auto& uri = uri2_result.value();
        std::cout << "\n   Input: tcp://[::1]:3000\n";
        std::cout << "   Scheme: " << net::scheme_to_string(uri.scheme) << "\n";
        std::cout << "   Host: " << uri.host.c_str() << "\n";
        std::cout << "   Port: " << uri.port << "\n";
        std::cout << "   Is IPv6: " << (uri.is_ipv6 ? "yes" : "no") << "\n";
    }

    // URI without port uses default
    auto uri3_result = net::parse_uri("udp://10.0.0.1");
    if (uri3_result.is_ok()) {
        auto& uri = uri3_result.value();
        std::cout << "\n   Input: udp://10.0.0.1 (no port)\n";
        std::cout << "   Port: " << uri.port << " (default)\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Parse endpoint lists
    // ==========================================================================
    std::cout << "4. Parsing endpoint lists...\n";

    auto list_result = net::parse_endpoint_list("192.168.1.1:51820, 10.0.0.1:8080, [::1]:3000");
    if (list_result.is_ok()) {
        auto& endpoints = list_result.value();
        std::cout << "   Input: 192.168.1.1:51820, 10.0.0.1:8080, [::1]:3000\n";
        std::cout << "   Parsed " << endpoints.size() << " endpoints:\n";
        for (usize i = 0; i < endpoints.size(); ++i) {
            auto& ep = endpoints[i];
            std::cout << "   - [" << i << "] ";
            if (ep.family == AddrFamily::IPv4) {
                std::cout << static_cast<int>(ep.ipv4.octets[0]) << "."
                          << static_cast<int>(ep.ipv4.octets[1]) << "."
                          << static_cast<int>(ep.ipv4.octets[2]) << "."
                          << static_cast<int>(ep.ipv4.octets[3]) << ":" << ep.port << "\n";
            } else {
                std::cout << "[IPv6]:" << ep.port << "\n";
            }
        }
    }
    std::cout << "\n";

    // ==========================================================================
    // Port validation
    // ==========================================================================
    std::cout << "5. Port validation...\n";

    auto port1 = net::parse_port("51820");
    std::cout << "   Port '51820': " << (port1.is_ok() ? "valid" : "invalid") << "\n";

    auto port2 = net::parse_port("0");
    std::cout << "   Port '0': " << (port2.is_ok() ? "valid" : "invalid (reserved)") << "\n";

    auto port3 = net::parse_port("65536");
    std::cout << "   Port '65536': " << (port3.is_ok() ? "valid" : "invalid (out of range)") << "\n";

    auto port4 = net::parse_port("abc");
    std::cout << "   Port 'abc': " << (port4.is_ok() ? "valid" : "invalid (not a number)") << "\n\n";

    // ==========================================================================
    // IP address detection
    // ==========================================================================
    std::cout << "6. IP address detection...\n";

    std::cout << "   '192.168.1.1' looks like IP: " << (net::looks_like_ip_address("192.168.1.1") ? "yes" : "no") << "\n";
    std::cout << "   '::1' looks like IP: " << (net::looks_like_ip_address("::1") ? "yes" : "no") << "\n";
    std::cout << "   '2001:db8::1' looks like IP: " << (net::looks_like_ip_address("2001:db8::1") ? "yes" : "no") << "\n";
    std::cout << "   'localhost' looks like IP: " << (net::looks_like_ip_address("localhost") ? "yes" : "no") << "\n";
    std::cout << "   'example.com' looks like IP: " << (net::looks_like_ip_address("example.com") ? "yes" : "no") << "\n\n";

    // ==========================================================================
    // IPv6 formatting
    // ==========================================================================
    std::cout << "7. IPv6 address formatting...\n";

    // Loopback
    IPv6Addr loopback{};
    loopback.octets[15] = 1;
    std::cout << "   ::1 formatted: " << net::format_ipv6_addr(loopback).c_str() << "\n";

    // All zeros
    IPv6Addr zeros{};
    std::cout << "   :: formatted: " << net::format_ipv6_addr(zeros).c_str() << "\n\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
