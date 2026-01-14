/* SPDX-License-Identifier: MIT */
/*
 * Botlink Core Types Tests
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Core Types") {

    TEST_CASE("NodeId") {
        SUBCASE("Default constructor creates zero NodeId") {
            NodeId id;
            CHECK(id.is_zero());
        }

        SUBCASE("NodeId comparison") {
            NodeId id1, id2;
            CHECK(id1 == id2);

            id1.data[0] = 1;
            CHECK(id1 != id2);
        }
    }

    TEST_CASE("PublicKey") {
        SUBCASE("Default constructor creates zero key") {
            PublicKey key;
            CHECK(key.is_zero());
        }

        SUBCASE("Key comparison") {
            PublicKey key1, key2;
            CHECK(key1 == key2);

            key1.data[0] = 0x42;
            CHECK(key1 != key2);
        }
    }

    TEST_CASE("PrivateKey") {
        SUBCASE("Default constructor creates zero key") {
            PrivateKey key;
            CHECK(key.is_zero());
        }

        SUBCASE("Clear zeros the key") {
            PrivateKey key;
            key.data[0] = 0xFF;
            key.clear();
            CHECK(key.is_zero());
        }
    }

    TEST_CASE("IPv4Addr") {
        SUBCASE("Construction from octets") {
            IPv4Addr addr(192, 168, 1, 1);
            CHECK(addr.octets[0] == 192);
            CHECK(addr.octets[1] == 168);
            CHECK(addr.octets[2] == 1);
            CHECK(addr.octets[3] == 1);
        }

        SUBCASE("is_zero") {
            IPv4Addr zero;
            CHECK(zero.is_zero());

            IPv4Addr not_zero(192, 168, 1, 1);
            CHECK_FALSE(not_zero.is_zero());
        }

        SUBCASE("Comparison") {
            IPv4Addr a1(192, 168, 1, 1);
            IPv4Addr a2(192, 168, 1, 1);
            IPv4Addr a3(10, 0, 0, 1);

            CHECK(a1 == a2);
            CHECK_FALSE(a1 == a3);
        }
    }

    TEST_CASE("IPv6Addr") {
        SUBCASE("Default is zero") {
            IPv6Addr addr;
            CHECK(addr.is_zero());
        }

        SUBCASE("Non-zero") {
            IPv6Addr addr;
            addr.octets[15] = 1;
            CHECK_FALSE(addr.is_zero());
        }

        SUBCASE("Comparison") {
            IPv6Addr a1;
            a1.octets[15] = 1;
            IPv6Addr a2;
            a2.octets[15] = 1;
            IPv6Addr a3;
            a3.octets[15] = 2;

            CHECK(a1 == a2);
            CHECK_FALSE(a1 == a3);
        }
    }

    TEST_CASE("Endpoint") {
        SUBCASE("IPv4 endpoint") {
            Endpoint ep(IPv4Addr(192, 168, 1, 1), 51820);
            CHECK(ep.is_ipv4());
            CHECK_FALSE(ep.is_ipv6());
            CHECK(ep.port == 51820);
        }

        SUBCASE("IPv6 endpoint") {
            IPv6Addr addr;
            addr.octets[15] = 1;
            Endpoint ep(addr, 8080);
            CHECK(ep.is_ipv6());
            CHECK_FALSE(ep.is_ipv4());
            CHECK(ep.port == 8080);
        }

        SUBCASE("Endpoint comparison") {
            Endpoint ep1(IPv4Addr(192, 168, 1, 1), 51820);
            Endpoint ep2(IPv4Addr(192, 168, 1, 1), 51820);
            Endpoint ep3(IPv4Addr(192, 168, 1, 2), 51820);

            CHECK(ep1 == ep2);
            CHECK(ep1 != ep3);
        }
    }

    TEST_CASE("OverlayAddr") {
        SUBCASE("Default values") {
            OverlayAddr addr;
            CHECK(addr.addr.empty());
            CHECK(addr.prefix_len == 24);
        }

        SUBCASE("Custom values") {
            OverlayAddr addr;
            addr.addr = "10.42.0.1";
            addr.prefix_len = 16;
            CHECK(addr.addr == "10.42.0.1");
            CHECK(addr.prefix_len == 16);
        }
    }

    TEST_CASE("Timestamp") {
        SUBCASE("Construction") {
            Timestamp ts(1234567890);
            CHECK(ts.ms == 1234567890);
        }

        SUBCASE("Comparison") {
            Timestamp ts1(1000);
            Timestamp ts2(2000);
            Timestamp ts3(1000);

            CHECK(ts1 < ts2);
            CHECK(ts2 > ts1);
            CHECK(ts1 == ts3);
            CHECK(ts1 <= ts3);
            CHECK(ts1 >= ts3);
        }
    }

    TEST_CASE("MemberStatus enum") {
        CHECK(static_cast<u8>(MemberStatus::Unconfigured) == 0);
        CHECK(static_cast<u8>(MemberStatus::Configured) == 1);
        CHECK(static_cast<u8>(MemberStatus::Pending) == 2);
        CHECK(static_cast<u8>(MemberStatus::Approved) == 3);
        CHECK(static_cast<u8>(MemberStatus::Rejected) == 4);
        CHECK(static_cast<u8>(MemberStatus::Revoked) == 5);
    }

    TEST_CASE("Role enum") {
        CHECK(static_cast<u8>(Role::Member) == 0);
        CHECK(static_cast<u8>(Role::Relay) == 1);
    }

    TEST_CASE("Vote enum") {
        CHECK(static_cast<u8>(Vote::Yes) == 0);
        CHECK(static_cast<u8>(Vote::No) == 1);
        CHECK(static_cast<u8>(Vote::Abstain) == 2);
    }

}
