/* SPDX-License-Identifier: MIT */
/*
 * Transport Demo
 * Demonstrates UDP transport utilities and endpoint conversion
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>

using namespace botlink;
using namespace dp;

int main() {
    std::cout << "=== Transport Demo ===\n\n";

    std::cout << "This demo shows the transport layer utilities for\n";
    std::cout << "UDP communication, including endpoint conversion and\n";
    std::cout << "message handling structures.\n\n";

    // ==========================================================================
    // Step 1: Create botlink endpoints
    // ==========================================================================
    std::cout << "1. Creating botlink endpoints...\n";

    // IPv4 endpoint
    Endpoint ipv4_ep;
    ipv4_ep.family = AddrFamily::IPv4;
    ipv4_ep.ipv4.octets[0] = 192;
    ipv4_ep.ipv4.octets[1] = 168;
    ipv4_ep.ipv4.octets[2] = 1;
    ipv4_ep.ipv4.octets[3] = 100;
    ipv4_ep.port = 51820;

    std::cout << "   IPv4 endpoint: " << net::format_endpoint(ipv4_ep).c_str() << "\n";
    std::cout << "   Is IPv4: " << (ipv4_ep.is_ipv4() ? "YES" : "NO") << "\n";
    std::cout << "   Is IPv6: " << (ipv4_ep.is_ipv6() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 2: Parse endpoints from strings
    // ==========================================================================
    std::cout << "2. Parsing endpoints from strings...\n";

    auto ep1 = net::parse_endpoint("10.0.0.1:8080");
    if (ep1.is_ok()) {
        std::cout << "   Parsed '10.0.0.1:8080': " << net::format_endpoint(ep1.value()).c_str() << "\n";
    }

    auto ep2 = net::parse_endpoint("0.0.0.0:51820");
    if (ep2.is_ok()) {
        std::cout << "   Parsed '0.0.0.0:51820': " << net::format_endpoint(ep2.value()).c_str() << "\n";
    }

    auto ep3 = net::parse_endpoint("127.0.0.1:12345");
    if (ep3.is_ok()) {
        std::cout << "   Parsed '127.0.0.1:12345': " << net::format_endpoint(ep3.value()).c_str() << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 3: Convert to UDP endpoint (netpipe)
    // ==========================================================================
    std::cout << "3. Converting to UDP endpoints (netpipe)...\n";

    net::UdpEndpoint udp_ep = net::to_udp_endpoint(ipv4_ep);
    std::cout << "   UdpEndpoint host: " << udp_ep.host.c_str() << "\n";
    std::cout << "   UdpEndpoint port: " << udp_ep.port << "\n\n";

    // ==========================================================================
    // Step 4: Convert back from UDP endpoint
    // ==========================================================================
    std::cout << "4. Converting back from UDP endpoint...\n";

    Endpoint converted = net::from_udp_endpoint(udp_ep);
    std::cout << "   Converted back: " << net::format_endpoint(converted).c_str() << "\n";
    std::cout << "   Matches original: " << (converted == ipv4_ep ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 5: Transport constants
    // ==========================================================================
    std::cout << "5. Transport constants...\n";

    std::cout << "   MAX_UDP_SIZE: " << net::MAX_UDP_SIZE << " bytes\n";
    std::cout << "   DEFAULT_PORT: " << DEFAULT_PORT << "\n";
    std::cout << "   DEFAULT_MTU: " << DEFAULT_MTU << "\n\n";

    // ==========================================================================
    // Step 6: Endpoint comparison
    // ==========================================================================
    std::cout << "6. Endpoint comparison...\n";

    auto ep_a = net::parse_endpoint("192.168.1.1:51820");
    auto ep_b = net::parse_endpoint("192.168.1.1:51820");
    auto ep_c = net::parse_endpoint("192.168.1.2:51820");

    if (ep_a.is_ok() && ep_b.is_ok() && ep_c.is_ok()) {
        std::cout << "   ep_a == ep_b: " << (ep_a.value() == ep_b.value() ? "YES" : "NO") << "\n";
        std::cout << "   ep_a == ep_c: " << (ep_a.value() == ep_c.value() ? "YES" : "NO") << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 7: Create message (Vector<u8>)
    // ==========================================================================
    std::cout << "7. Creating messages...\n";

    net::Message msg;
    const char* content = "Hello, transport!";
    for (const char* p = content; *p; ++p) {
        msg.push_back(static_cast<u8>(*p));
    }

    std::cout << "   Message size: " << msg.size() << " bytes\n";
    std::cout << "   Message content: \"";
    for (const auto& byte : msg) {
        std::cout << static_cast<char>(byte);
    }
    std::cout << "\"\n\n";

    // ==========================================================================
    // Step 8: Port parsing
    // ==========================================================================
    std::cout << "8. Port parsing utilities...\n";

    auto port1 = net::parse_port("51820");
    std::cout << "   parse_port(\"51820\"): "
              << (port1.is_ok() ? to_str(port1.value()).c_str() : "ERROR") << "\n";

    auto port2 = net::parse_port("65535");
    std::cout << "   parse_port(\"65535\"): "
              << (port2.is_ok() ? to_str(port2.value()).c_str() : "ERROR") << "\n";

    auto port3 = net::parse_port("99999");
    std::cout << "   parse_port(\"99999\"): "
              << (port3.is_ok() ? to_str(port3.value()).c_str() : "ERROR (expected)") << "\n";

    auto port4 = net::parse_port("abc");
    std::cout << "   parse_port(\"abc\"): "
              << (port4.is_ok() ? to_str(port4.value()).c_str() : "ERROR (expected)") << "\n\n";

    // ==========================================================================
    // Step 9: Endpoint error handling
    // ==========================================================================
    std::cout << "9. Endpoint parsing error handling...\n";

    auto bad1 = net::parse_endpoint("invalid");
    std::cout << "   Parse 'invalid': " << (bad1.is_ok() ? "SUCCESS" : "FAILED (expected)") << "\n";

    auto bad2 = net::parse_endpoint("192.168.1.1");
    std::cout << "   Parse '192.168.1.1' (no port): " << (bad2.is_ok() ? "SUCCESS" : "FAILED (expected)") << "\n";

    auto bad3 = net::parse_endpoint("192.168.1.1:");
    std::cout << "   Parse '192.168.1.1:' (empty port): " << (bad3.is_ok() ? "SUCCESS" : "FAILED (expected)") << "\n\n";

    // ==========================================================================
    // Step 10: Overlay address operations
    // ==========================================================================
    std::cout << "10. Overlay address operations...\n";

    OverlayAddr overlay1;
    overlay1.addr = "10.42.0.1";
    overlay1.prefix_len = 24;

    std::cout << "   Overlay addr: " << overlay1.addr.c_str() << "/" << static_cast<int>(overlay1.prefix_len) << "\n";
    std::cout << "   Is valid: " << (overlay1.is_valid() ? "YES" : "NO") << "\n";

    OverlayAddr overlay2;
    overlay2.addr = "";
    overlay2.prefix_len = 24;
    std::cout << "   Empty overlay is valid: " << (overlay2.is_valid() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 11: Interface name operations
    // ==========================================================================
    std::cout << "11. Interface name operations...\n";

    InterfaceName iface1("botlink0");
    std::cout << "   Interface: " << iface1.c_str() << "\n";
    std::cout << "   Is empty: " << (iface1.is_empty() ? "YES" : "NO") << "\n";

    InterfaceName iface2("");
    std::cout << "   Empty interface is_empty: " << (iface2.is_empty() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 12: Multiple endpoint list
    // ==========================================================================
    std::cout << "12. Managing multiple endpoints...\n";

    Vector<Endpoint> endpoints;
    endpoints.push_back(net::parse_endpoint("192.168.1.1:51820").value());
    endpoints.push_back(net::parse_endpoint("10.0.0.1:51820").value());
    endpoints.push_back(net::parse_endpoint("172.16.0.1:51820").value());

    std::cout << "   Endpoints in list: " << endpoints.size() << "\n";
    for (usize i = 0; i < endpoints.size(); ++i) {
        std::cout << "   [" << i << "] " << net::format_endpoint(endpoints[i]).c_str() << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 13: Summary
    // ==========================================================================
    std::cout << "13. Summary...\n";
    std::cout << "   Transport layer provides:\n";
    std::cout << "   - Endpoint parsing and formatting\n";
    std::cout << "   - Conversion to/from netpipe types\n";
    std::cout << "   - Message (Vector<u8>) handling\n";
    std::cout << "   - UDP socket wrapper (UdpSocket)\n\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
