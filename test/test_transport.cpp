/* SPDX-License-Identifier: MIT */
/*
 * Botlink Transport Tests
 * Tests for transport utilities and endpoint conversion
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Transport - Endpoint Conversion") {

    TEST_CASE("to_udp_endpoint IPv4") {
        Endpoint ep(IPv4Addr(192, 168, 1, 100), 51820);
        auto udp_ep = net::to_udp_endpoint(ep);

        CHECK(udp_ep.host == "192.168.1.100");
        CHECK(udp_ep.port == 51820);
    }

    TEST_CASE("to_udp_endpoint loopback") {
        Endpoint ep(IPv4Addr(127, 0, 0, 1), 8080);
        auto udp_ep = net::to_udp_endpoint(ep);

        CHECK(udp_ep.host == "127.0.0.1");
        CHECK(udp_ep.port == 8080);
    }

    TEST_CASE("to_udp_endpoint zeros") {
        Endpoint ep(IPv4Addr(0, 0, 0, 0), 51820);
        auto udp_ep = net::to_udp_endpoint(ep);

        CHECK(udp_ep.host == "0.0.0.0");
        CHECK(udp_ep.port == 51820);
    }

    TEST_CASE("from_udp_endpoint IPv4") {
        net::UdpEndpoint udp_ep;
        udp_ep.host = "10.42.0.5";
        udp_ep.port = 51820;

        Endpoint ep = net::from_udp_endpoint(udp_ep);

        CHECK(ep.is_ipv4());
        CHECK(ep.port == 51820);
        CHECK(ep.ipv4.octets[0] == 10);
        CHECK(ep.ipv4.octets[1] == 42);
        CHECK(ep.ipv4.octets[2] == 0);
        CHECK(ep.ipv4.octets[3] == 5);
    }

    TEST_CASE("from_udp_endpoint IPv6 loopback") {
        net::UdpEndpoint udp_ep;
        udp_ep.host = "::1";
        udp_ep.port = 8080;

        Endpoint ep = net::from_udp_endpoint(udp_ep);

        CHECK(ep.is_ipv6());
        CHECK(ep.port == 8080);
        CHECK(ep.ipv6.octets[15] == 1);
    }

    TEST_CASE("from_udp_endpoint IPv6 with brackets") {
        net::UdpEndpoint udp_ep;
        udp_ep.host = "[::1]";
        udp_ep.port = 8080;

        Endpoint ep = net::from_udp_endpoint(udp_ep);

        CHECK(ep.is_ipv6());
        CHECK(ep.port == 8080);
    }

    TEST_CASE("Roundtrip IPv4 conversion") {
        Endpoint original(IPv4Addr(172, 16, 0, 1), 3000);
        auto udp_ep = net::to_udp_endpoint(original);
        Endpoint converted = net::from_udp_endpoint(udp_ep);

        CHECK(converted.family == original.family);
        CHECK(converted.port == original.port);
        CHECK(converted.ipv4 == original.ipv4);
    }

}

TEST_SUITE("Transport - Endpoint String Parsing") {

    TEST_CASE("parse_endpoint_str IPv4 basic") {
        auto result = net::parse_endpoint_str("192.168.1.1:51820");
        REQUIRE(result.is_ok());

        auto& ep = result.value();
        CHECK(ep.is_ipv4());
        CHECK(ep.port == 51820);
    }

    TEST_CASE("parse_endpoint_str IPv6 bracketed") {
        auto result = net::parse_endpoint_str("[::1]:8080");
        REQUIRE(result.is_ok());

        auto& ep = result.value();
        CHECK(ep.is_ipv6());
        CHECK(ep.port == 8080);
    }

    TEST_CASE("parse_endpoint_str empty fails") {
        auto result = net::parse_endpoint_str("");
        CHECK(result.is_err());
    }

}

TEST_SUITE("Transport - Endpoint Formatting") {

    TEST_CASE("format_endpoint IPv4") {
        Endpoint ep(IPv4Addr(192, 168, 1, 1), 51820);
        String formatted = net::format_endpoint(ep);
        CHECK(formatted == "192.168.1.1:51820");
    }

    TEST_CASE("format_endpoint IPv4 zeros") {
        Endpoint ep(IPv4Addr(0, 0, 0, 0), 51820);
        String formatted = net::format_endpoint(ep);
        CHECK(formatted == "0.0.0.0:51820");
    }

    TEST_CASE("format_endpoint IPv6 loopback") {
        IPv6Addr addr{};
        addr.octets[15] = 1;
        Endpoint ep(addr, 8080);
        String formatted = net::format_endpoint(ep);
        CHECK(formatted == "[::1]:8080");
    }

    TEST_CASE("format_endpoint IPv6 all zeros") {
        IPv6Addr addr{};
        Endpoint ep(addr, 51820);
        String formatted = net::format_endpoint(ep);
        CHECK(formatted == "[::]:51820");
    }

}

TEST_SUITE("Transport - Constants") {

    TEST_CASE("MAX_UDP_SIZE is reasonable") {
        CHECK(net::MAX_UDP_SIZE > 0);
        CHECK(net::MAX_UDP_SIZE <= 1500);  // Standard MTU
        CHECK(net::MAX_UDP_SIZE >= 1200);  // Minimum useful size
    }

}

TEST_SUITE("Transport - Message Types") {

    TEST_CASE("Message is Vector<u8>") {
        net::Message msg;
        msg.push_back(0x01);
        msg.push_back(0x02);
        msg.push_back(0x03);

        CHECK(msg.size() == 3);
        CHECK(msg[0] == 0x01);
        CHECK(msg[1] == 0x02);
        CHECK(msg[2] == 0x03);
    }

    TEST_CASE("Message can hold packet data") {
        net::Message msg;
        msg.reserve(net::MAX_UDP_SIZE);

        // Fill with test pattern
        for (usize i = 0; i < 100; ++i) {
            msg.push_back(static_cast<u8>(i % 256));
        }

        CHECK(msg.size() == 100);
        CHECK(msg[50] == 50);
    }

}
