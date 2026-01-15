/* SPDX-License-Identifier: MIT */
/*
 * Botlink Network Tests
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Network - Endpoint Parsing") {

    TEST_CASE("Parse IPv4 endpoint") {
        auto result = net::parse_endpoint("192.168.1.1:51820");
        REQUIRE(result.is_ok());

        auto &ep = result.value();
        CHECK(ep.is_ipv4());
        CHECK(ep.port == 51820);
        CHECK(ep.ipv4.octets[0] == 192);
        CHECK(ep.ipv4.octets[1] == 168);
        CHECK(ep.ipv4.octets[2] == 1);
        CHECK(ep.ipv4.octets[3] == 1);
    }

    TEST_CASE("Parse IPv4 endpoint without port returns error") {
        // The current implementation requires explicit port
        auto result = net::parse_endpoint("10.0.0.1");
        CHECK(result.is_err());
    }

    TEST_CASE("Parse UDP URI") {
        auto result = net::parse_uri("udp://192.168.1.100:8080");
        REQUIRE(result.is_ok());

        auto &uri = result.value();
        CHECK(uri.scheme == net::Scheme::UDP);
        CHECK(uri.host == "192.168.1.100");
        CHECK(uri.port == 8080);
    }

    TEST_CASE("Parse endpoint list") {
        auto result = net::parse_endpoint_list("192.168.1.1:51820, 10.0.0.1:51821");
        REQUIRE(result.is_ok());
        CHECK(result.value().size() == 2);
    }

    TEST_CASE("Format endpoint") {
        Endpoint ep(IPv4Addr(192, 168, 1, 1), 51820);
        String formatted = net::format_endpoint(ep);
        CHECK(formatted == "192.168.1.1:51820");
    }

    TEST_CASE("Parse URI scheme") {
        auto result = net::parse_uri("udp://127.0.0.1:8000");
        REQUIRE(result.is_ok());
        CHECK(result.value().scheme == net::Scheme::UDP);
        CHECK(result.value().host == "127.0.0.1");
        CHECK(result.value().port == 8000);
    }

    TEST_CASE("Invalid endpoint returns error") {
        auto result = net::parse_endpoint("not-an-ip");
        CHECK(result.is_err());
    }

    TEST_CASE("Parse IPv6 endpoint with brackets") {
        auto result = net::parse_endpoint("[::1]:51820");
        REQUIRE(result.is_ok());

        auto &ep = result.value();
        CHECK(ep.is_ipv6());
        CHECK(ep.port == 51820);
        // ::1 has octet[15] = 1, rest = 0
        CHECK(ep.ipv6.octets[15] == 1);
        for (usize i = 0; i < 15; ++i) {
            CHECK(ep.ipv6.octets[i] == 0);
        }
    }

    TEST_CASE("Parse IPv6 endpoint full address") {
        auto result = net::parse_endpoint("[2001:db8::1]:8080");
        REQUIRE(result.is_ok());

        auto &ep = result.value();
        CHECK(ep.is_ipv6());
        CHECK(ep.port == 8080);
        // 2001:db8::1 = 2001:0db8:0000:0000:0000:0000:0000:0001
        CHECK(ep.ipv6.octets[0] == 0x20);
        CHECK(ep.ipv6.octets[1] == 0x01);
        CHECK(ep.ipv6.octets[2] == 0x0d);
        CHECK(ep.ipv6.octets[3] == 0xb8);
        CHECK(ep.ipv6.octets[15] == 0x01);
    }

    TEST_CASE("Parse IPv6 URI") {
        auto result = net::parse_uri("udp://[fe80::1]:51820");
        REQUIRE(result.is_ok());

        auto &uri = result.value();
        CHECK(uri.scheme == net::Scheme::UDP);
        CHECK(uri.host == "fe80::1");
        CHECK(uri.port == 51820);
        CHECK(uri.is_ipv6);
    }

    TEST_CASE("Format IPv6 endpoint") {
        IPv6Addr addr{};
        addr.octets[15] = 1; // ::1

        Endpoint ep(addr, 51820);
        String formatted = net::format_endpoint(ep);
        CHECK(formatted == "[::1]:51820");
    }

    TEST_CASE("IPv6 parsing :: (all zeros)") {
        auto result = net::parse_endpoint("[::]:8080");
        REQUIRE(result.is_ok());

        auto &ep = result.value();
        CHECK(ep.is_ipv6());
        CHECK(ep.port == 8080);
        for (usize i = 0; i < 16; ++i) {
            CHECK(ep.ipv6.octets[i] == 0);
        }
    }

    TEST_CASE("IPv6 without port returns error") {
        auto result = net::parse_endpoint("[::1]");
        CHECK(result.is_err());
    }

    TEST_CASE("Port 0 is rejected") {
        auto result = net::parse_endpoint("192.168.1.1:0");
        CHECK(result.is_err());
    }

    TEST_CASE("Invalid port characters are rejected") {
        auto result = net::parse_endpoint("192.168.1.1:abc");
        CHECK(result.is_err());
    }

    TEST_CASE("Port overflow is rejected") {
        auto result = net::parse_endpoint("192.168.1.1:99999");
        CHECK(result.is_err());
    }

    TEST_CASE("URI with port 0 is rejected") {
        auto result = net::parse_uri("udp://192.168.1.1:0");
        CHECK(result.is_err());
    }

}

TEST_SUITE("Network - Transport") {

    TEST_CASE("to_udp_endpoint creates UdpEndpoint") {
        Endpoint ep(IPv4Addr(127, 0, 0, 1), 8080);
        auto udp_ep = net::to_udp_endpoint(ep);

        CHECK(udp_ep.port == 8080);
        CHECK(udp_ep.host == "127.0.0.1");
    }

    TEST_CASE("from_udp_endpoint creates Endpoint") {
        net::UdpEndpoint udp_ep;
        udp_ep.host = "10.0.0.1";
        udp_ep.port = 51820;

        Endpoint ep = net::from_udp_endpoint(udp_ep);

        CHECK(ep.is_ipv4());
        CHECK(ep.port == 51820);
        CHECK(ep.ipv4.octets[0] == 10);
        CHECK(ep.ipv4.octets[1] == 0);
        CHECK(ep.ipv4.octets[2] == 0);
        CHECK(ep.ipv4.octets[3] == 1);
    }

}

TEST_SUITE("Network - DataPlane Messages") {

    TEST_CASE("HandshakeInit structure") {
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId initiator = crypto::node_id_from_pubkey(ed_pub);

        net::HandshakeInit init;
        init.initiator_id = initiator;
        init.initiator_x25519 = x_pub;
        init.timestamp_ms = time::now_ms();
        init.nonce = crypto::generate_nonce();

        CHECK(init.initiator_id == initiator);
        CHECK(init.initiator_x25519 == x_pub);
        CHECK(init.timestamp_ms > 0);
    }

    TEST_CASE("HandshakeResp structure") {
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId responder = crypto::node_id_from_pubkey(ed_pub);

        net::HandshakeResp resp;
        resp.responder_id = responder;
        resp.responder_x25519 = x_pub;
        resp.timestamp_ms = time::now_ms();
        resp.nonce = crypto::generate_nonce();

        CHECK(resp.responder_id == responder);
        CHECK(resp.responder_x25519 == x_pub);
    }

    TEST_CASE("KeepalivePacket structure") {
        net::KeepalivePacket ka;
        ka.key_id = 42;
        ka.timestamp_ms = time::now_ms();

        CHECK(ka.key_id == 42);
        CHECK(ka.timestamp_ms > 0);
    }

}

TEST_SUITE("Network - Relay") {

    TEST_CASE("RelayInfo stale check") {
        net::RelayInfo relay;
        relay.id = "relay1";
        relay.last_seen_ms = time::now_ms();
        relay.is_connected = true;

        CHECK_FALSE(relay.is_stale(30000));

        relay.last_seen_ms = time::now_ms() - 60000;
        CHECK(relay.is_stale(30000));
    }

    TEST_CASE("RelayRoute age calculation") {
        net::RelayRoute route;
        route.established_at_ms = time::now_ms() - 5000;

        CHECK(route.age_ms() >= 5000);
    }

    TEST_CASE("RelayConnectRequest members") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId requester = crypto::node_id_from_pubkey(ed_pub);

        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId target = crypto::node_id_from_pubkey(ed_pub2);

        net::RelayConnectRequest req;
        req.requester_id = requester;
        req.target_peer_id = target;
        req.timestamp_ms = time::now_ms();

        CHECK(req.requester_id == requester);
        CHECK(req.target_peer_id == target);
        CHECK(req.timestamp_ms > 0);
    }

    TEST_CASE("RelayForwardPacket members") {
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId source = crypto::node_id_from_pubkey(ed_pub1);
        NodeId target = crypto::node_id_from_pubkey(ed_pub2);

        net::RelayForwardPacket fwd;
        fwd.source_id = source;
        fwd.target_id = target;
        fwd.payload.push_back(0x01);
        fwd.payload.push_back(0x02);
        fwd.payload.push_back(0x03);
        fwd.timestamp_ms = time::now_ms();

        CHECK(fwd.source_id == source);
        CHECK(fwd.target_id == target);
        CHECK(fwd.payload.size() == 3);
    }

}
