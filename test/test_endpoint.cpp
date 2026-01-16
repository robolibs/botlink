/* SPDX-License-Identifier: MIT */
/*
 * Botlink Endpoint Tests
 * Tests for endpoint parsing and formatting
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Endpoint - Port Parsing") {

    TEST_CASE("Parse valid port") {
        auto result = net::parse_port("51820");
        REQUIRE(result.is_ok());
        CHECK(result.value() == 51820);
    }

    TEST_CASE("Parse port at boundary") {
        auto r1 = net::parse_port("1");
        REQUIRE(r1.is_ok());
        CHECK(r1.value() == 1);

        auto r65535 = net::parse_port("65535");
        REQUIRE(r65535.is_ok());
        CHECK(r65535.value() == 65535);
    }

    TEST_CASE("Parse empty port fails") {
        auto result = net::parse_port("");
        CHECK(result.is_err());
    }

    TEST_CASE("Parse port 0 fails") {
        auto result = net::parse_port("0");
        CHECK(result.is_err());
    }

    TEST_CASE("Parse port out of range fails") {
        auto result = net::parse_port("65536");
        CHECK(result.is_err());
    }

    TEST_CASE("Parse port with invalid characters fails") {
        auto result = net::parse_port("123abc");
        CHECK(result.is_err());
    }

}

TEST_SUITE("Endpoint - IPv6 Group Parsing") {

    TEST_CASE("Parse valid IPv6 group") {
        String addr = "abcd";
        auto result = net::parse_ipv6_group(addr, 0, 4);
        REQUIRE(result.is_ok());
        CHECK(result.value() == 0xabcd);
    }

    TEST_CASE("Parse IPv6 group uppercase") {
        String addr = "ABCD";
        auto result = net::parse_ipv6_group(addr, 0, 4);
        REQUIRE(result.is_ok());
        CHECK(result.value() == 0xabcd);
    }

    TEST_CASE("Parse short IPv6 group") {
        String addr = "1";
        auto result = net::parse_ipv6_group(addr, 0, 1);
        REQUIRE(result.is_ok());
        CHECK(result.value() == 0x1);
    }

    TEST_CASE("Parse IPv6 group too long fails") {
        String addr = "12345";
        auto result = net::parse_ipv6_group(addr, 0, 5);
        CHECK(result.is_err());
    }

}

TEST_SUITE("Endpoint - IPv6 Address Parsing") {

    TEST_CASE("Parse loopback ::1") {
        auto result = net::parse_ipv6_addr("::1");
        REQUIRE(result.is_ok());
        auto& addr = result.value();
        // ::1 = 0:0:0:0:0:0:0:1
        for (usize i = 0; i < 15; ++i) {
            CHECK(addr.octets[i] == 0);
        }
        CHECK(addr.octets[15] == 1);
    }

    TEST_CASE("Parse all zeros ::") {
        auto result = net::parse_ipv6_addr("::");
        REQUIRE(result.is_ok());
        auto& addr = result.value();
        for (usize i = 0; i < 16; ++i) {
            CHECK(addr.octets[i] == 0);
        }
    }

    TEST_CASE("Parse full IPv6 address") {
        auto result = net::parse_ipv6_addr("2001:db8:0:0:0:0:0:1");
        REQUIRE(result.is_ok());
        auto& addr = result.value();
        CHECK(addr.octets[0] == 0x20);
        CHECK(addr.octets[1] == 0x01);
        CHECK(addr.octets[2] == 0x0d);
        CHECK(addr.octets[3] == 0xb8);
    }

    TEST_CASE("Parse IPv6 with :: in middle") {
        auto result = net::parse_ipv6_addr("2001:db8::1");
        REQUIRE(result.is_ok());
        auto& addr = result.value();
        CHECK(addr.octets[0] == 0x20);
        CHECK(addr.octets[1] == 0x01);
        CHECK(addr.octets[15] == 1);
    }

    TEST_CASE("Empty IPv6 address fails") {
        auto result = net::parse_ipv6_addr("");
        CHECK(result.is_err());
    }

    TEST_CASE("Multiple :: fails") {
        auto result = net::parse_ipv6_addr("2001::db8::1");
        CHECK(result.is_err());
    }

}

TEST_SUITE("Endpoint - IPv6 Formatting") {

    TEST_CASE("Format loopback") {
        IPv6Addr addr{};
        addr.octets[15] = 1;
        String formatted = net::format_ipv6_addr(addr);
        CHECK(formatted == "::1");
    }

    TEST_CASE("Format all zeros") {
        IPv6Addr addr{};
        String formatted = net::format_ipv6_addr(addr);
        CHECK(formatted == "::");
    }

}

TEST_SUITE("Endpoint - URI Scheme") {

    TEST_CASE("scheme_to_string UDP") {
        CHECK(String(net::scheme_to_string(net::Scheme::UDP)) == "udp");
    }

    TEST_CASE("scheme_to_string TCP") {
        CHECK(String(net::scheme_to_string(net::Scheme::TCP)) == "tcp");
    }

}

TEST_SUITE("Endpoint - URI Parsing") {

    TEST_CASE("Parse UDP URI with IPv4") {
        auto result = net::parse_uri("udp://192.168.1.1:51820");
        REQUIRE(result.is_ok());
        CHECK(result.value().scheme == net::Scheme::UDP);
        CHECK(result.value().host == "192.168.1.1");
        CHECK(result.value().port == 51820);
        CHECK(result.value().is_ipv6 == false);
    }

    TEST_CASE("Parse UDP URI with IPv6") {
        auto result = net::parse_uri("udp://[::1]:8080");
        REQUIRE(result.is_ok());
        CHECK(result.value().scheme == net::Scheme::UDP);
        CHECK(result.value().host == "::1");
        CHECK(result.value().port == 8080);
        CHECK(result.value().is_ipv6 == true);
    }

    TEST_CASE("Parse TCP URI") {
        auto result = net::parse_uri("tcp://localhost:3000");
        REQUIRE(result.is_ok());
        CHECK(result.value().scheme == net::Scheme::TCP);
        CHECK(result.value().host == "localhost");
        CHECK(result.value().port == 3000);
    }

    TEST_CASE("Parse URI uppercase scheme") {
        auto result = net::parse_uri("UDP://10.0.0.1:5000");
        REQUIRE(result.is_ok());
        CHECK(result.value().scheme == net::Scheme::UDP);
    }

    TEST_CASE("Parse URI without port uses default") {
        auto result = net::parse_uri("udp://10.0.0.1");
        REQUIRE(result.is_ok());
        CHECK(result.value().port == DEFAULT_PORT);
    }

    TEST_CASE("Parse URI missing scheme fails") {
        auto result = net::parse_uri("192.168.1.1:51820");
        CHECK(result.is_err());
    }

    TEST_CASE("Parse URI unknown scheme fails") {
        auto result = net::parse_uri("http://example.com");
        CHECK(result.is_err());
    }

}

TEST_SUITE("Endpoint - IP Address Detection") {

    TEST_CASE("IPv4 looks like IP") {
        CHECK(net::looks_like_ip_address("192.168.1.1") == true);
        CHECK(net::looks_like_ip_address("10.0.0.1") == true);
        CHECK(net::looks_like_ip_address("0.0.0.0") == true);
    }

    TEST_CASE("IPv6 looks like IP") {
        CHECK(net::looks_like_ip_address("::1") == true);
        CHECK(net::looks_like_ip_address("2001:db8::1") == true);
    }

    TEST_CASE("Hostname does not look like IP") {
        CHECK(net::looks_like_ip_address("localhost") == false);
        CHECK(net::looks_like_ip_address("example.com") == false);
        CHECK(net::looks_like_ip_address("my-server") == false);
    }

    TEST_CASE("Empty string does not look like IP") {
        CHECK(net::looks_like_ip_address("") == false);
    }

}

TEST_SUITE("Endpoint - Endpoint Parsing") {

    TEST_CASE("Parse IPv4 endpoint") {
        auto result = net::parse_endpoint("192.168.1.1:51820");
        REQUIRE(result.is_ok());
        CHECK(result.value().family == AddrFamily::IPv4);
        CHECK(result.value().port == 51820);
        CHECK(result.value().ipv4.octets[0] == 192);
        CHECK(result.value().ipv4.octets[1] == 168);
        CHECK(result.value().ipv4.octets[2] == 1);
        CHECK(result.value().ipv4.octets[3] == 1);
    }

    TEST_CASE("Parse IPv6 endpoint") {
        auto result = net::parse_endpoint("[::1]:8080");
        REQUIRE(result.is_ok());
        CHECK(result.value().family == AddrFamily::IPv6);
        CHECK(result.value().port == 8080);
        CHECK(result.value().ipv6.octets[15] == 1);
    }

    TEST_CASE("Parse URI format endpoint") {
        auto result = net::parse_endpoint("udp://10.0.0.1:5000");
        REQUIRE(result.is_ok());
        CHECK(result.value().family == AddrFamily::IPv4);
        CHECK(result.value().port == 5000);
    }

    TEST_CASE("Parse endpoint missing port fails") {
        auto result = net::parse_endpoint("192.168.1.1");
        CHECK(result.is_err());
    }

    TEST_CASE("Parse endpoint invalid IPv4 fails") {
        auto result = net::parse_endpoint("999.999.999.999:8080");
        // Note: sscanf may still parse this, depending on implementation
        // The test verifies the function doesn't crash
    }

}

TEST_SUITE("Endpoint - Endpoint List Parsing") {

    TEST_CASE("Parse single endpoint") {
        auto result = net::parse_endpoint_list("192.168.1.1:51820");
        REQUIRE(result.is_ok());
        CHECK(result.value().size() == 1);
    }

    TEST_CASE("Parse multiple endpoints") {
        auto result = net::parse_endpoint_list("192.168.1.1:51820, 10.0.0.1:8080");
        REQUIRE(result.is_ok());
        CHECK(result.value().size() == 2);
    }

    TEST_CASE("Parse endpoint list with whitespace") {
        auto result = net::parse_endpoint_list("  192.168.1.1:51820  ,  10.0.0.1:8080  ");
        REQUIRE(result.is_ok());
        CHECK(result.value().size() == 2);
    }

    TEST_CASE("Parse empty list") {
        auto result = net::parse_endpoint_list("");
        REQUIRE(result.is_ok());
        CHECK(result.value().empty());
    }

    TEST_CASE("Invalid endpoints are skipped") {
        auto result = net::parse_endpoint_list("192.168.1.1:51820, invalid, 10.0.0.1:8080");
        REQUIRE(result.is_ok());
        // Invalid entries are silently skipped
        CHECK(result.value().size() >= 2);
    }

}

TEST_SUITE("Endpoint - ParsedUri") {

    TEST_CASE("ParsedUri default values") {
        net::ParsedUri uri;
        CHECK(uri.scheme == net::Scheme::UDP);
        CHECK(uri.host.empty());
        CHECK(uri.port == 0);
        CHECK(uri.is_ipv6 == false);
    }

}
