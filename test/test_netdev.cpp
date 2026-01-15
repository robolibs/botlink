/* SPDX-License-Identifier: MIT */
/*
 * Botlink Netdev Tests
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Netdev - RouteTable") {

    TEST_CASE("Add direct route") {
        netdev::RouteTable table;

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(ed_pub);

        OverlayAddr dest;
        dest.addr = "10.42.0.2";
        dest.prefix_len = 32;

        auto result = table.add_direct_route(dest, peer_id);
        CHECK(result.is_ok());
        CHECK(table.route_count() == 1);
    }

    TEST_CASE("Add relay route") {
        netdev::RouteTable table;

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(ed_pub);

        OverlayAddr dest;
        dest.addr = "10.42.1.0";
        dest.prefix_len = 24;

        auto result = table.add_relay_route(dest, peer_id, "relay1", 100);
        CHECK(result.is_ok());

        auto routes = table.get_all_routes();
        CHECK(routes.size() == 1);
        CHECK_FALSE(routes[0].is_direct);
        CHECK(routes[0].relay_id == "relay1");
        CHECK(routes[0].metric == 100);
    }

    TEST_CASE("Lookup route by IP") {
        netdev::RouteTable table;

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(ed_pub);

        OverlayAddr dest;
        dest.addr = "10.42.0.0";
        dest.prefix_len = 24;

        table.add_direct_route(dest, peer_id);

        auto route = table.lookup("10.42.0.5");
        REQUIRE(route.has_value());
        CHECK(route->next_hop == peer_id);
    }

    TEST_CASE("Lookup prefers longer prefix match") {
        netdev::RouteTable table;

        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId peer1 = crypto::node_id_from_pubkey(ed_pub1);
        NodeId peer2 = crypto::node_id_from_pubkey(ed_pub2);

        // Add /24 route
        OverlayAddr dest1;
        dest1.addr = "10.42.0.0";
        dest1.prefix_len = 24;
        table.add_direct_route(dest1, peer1);

        // Add /32 route (more specific)
        OverlayAddr dest2;
        dest2.addr = "10.42.0.5";
        dest2.prefix_len = 32;
        table.add_direct_route(dest2, peer2);

        // Lookup should match /32
        auto route = table.lookup("10.42.0.5");
        REQUIRE(route.has_value());
        CHECK(route->next_hop == peer2);

        // Different IP should match /24
        auto route2 = table.lookup("10.42.0.10");
        REQUIRE(route2.has_value());
        CHECK(route2->next_hop == peer1);
    }

    TEST_CASE("Lookup prefers lower metric for same prefix") {
        netdev::RouteTable table;

        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId peer1 = crypto::node_id_from_pubkey(ed_pub1);
        NodeId peer2 = crypto::node_id_from_pubkey(ed_pub2);

        // Add route with higher metric
        OverlayAddr dest1;
        dest1.addr = "10.42.0.0";
        dest1.prefix_len = 24;

        netdev::RouteEntry entry1;
        entry1.dest = dest1;
        entry1.next_hop = peer1;
        entry1.metric = 100;
        entry1.added_at_ms = time::now_ms();
        entry1.last_used_ms = time::now_ms();
        table.add_route(entry1);

        // Try to add route with lower metric (should replace)
        netdev::RouteEntry entry2;
        entry2.dest = dest1;
        entry2.next_hop = peer2;
        entry2.metric = 10;
        entry2.added_at_ms = time::now_ms();
        entry2.last_used_ms = time::now_ms();
        table.add_route(entry2);

        auto route = table.lookup("10.42.0.1");
        REQUIRE(route.has_value());
        CHECK(route->next_hop == peer2);
        CHECK(route->metric == 10);
    }

    TEST_CASE("Remove routes to peer") {
        netdev::RouteTable table;

        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId peer1 = crypto::node_id_from_pubkey(ed_pub1);
        NodeId peer2 = crypto::node_id_from_pubkey(ed_pub2);

        OverlayAddr dest1;
        dest1.addr = "10.42.0.0";
        dest1.prefix_len = 24;
        table.add_direct_route(dest1, peer1);

        OverlayAddr dest2;
        dest2.addr = "10.42.1.0";
        dest2.prefix_len = 24;
        table.add_direct_route(dest2, peer1);

        OverlayAddr dest3;
        dest3.addr = "10.42.2.0";
        dest3.prefix_len = 24;
        table.add_direct_route(dest3, peer2);

        CHECK(table.route_count() == 3);

        usize removed = table.remove_routes_to_peer(peer1);
        CHECK(removed == 2);
        CHECK(table.route_count() == 1);
    }

    TEST_CASE("Lookup packet by IP header") {
        netdev::RouteTable table;

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(ed_pub);

        OverlayAddr dest;
        dest.addr = "10.42.0.0";
        dest.prefix_len = 24;
        table.add_direct_route(dest, peer_id);

        // Create a minimal IPv4 packet (20 bytes header)
        // Destination: 10.42.0.5
        Vector<u8> pkt(20, 0);
        pkt[0] = 0x45; // Version 4, IHL 5
        pkt[16] = 10;  // Dest IP
        pkt[17] = 42;
        pkt[18] = 0;
        pkt[19] = 5;

        auto route = table.lookup_packet(pkt);
        REQUIRE(route.has_value());
        CHECK(route->next_hop == peer_id);
    }

    TEST_CASE("Get routes to specific peer") {
        netdev::RouteTable table;

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(ed_pub);

        OverlayAddr dest1;
        dest1.addr = "10.42.0.0";
        dest1.prefix_len = 24;
        table.add_direct_route(dest1, peer_id);

        OverlayAddr dest2;
        dest2.addr = "10.42.1.0";
        dest2.prefix_len = 24;
        table.add_direct_route(dest2, peer_id);

        auto routes = table.get_routes_to_peer(peer_id);
        CHECK(routes.size() == 2);
    }

    TEST_CASE("Clear all routes") {
        netdev::RouteTable table;

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(ed_pub);

        OverlayAddr dest;
        dest.addr = "10.42.0.0";
        dest.prefix_len = 24;
        table.add_direct_route(dest, peer_id);

        CHECK(table.route_count() == 1);
        table.clear();
        CHECK(table.route_count() == 0);
    }

}

TEST_SUITE("Netdev - NullBackend") {

    TEST_CASE("Create interface") {
        netdev::NullBackend backend;

        InterfaceName name("bot0");
        auto result = backend.create_interface(name);
        CHECK(result.is_ok());

        CHECK(String(backend.info().name.c_str()) == String(name.c_str()));
        CHECK(backend.info().state == netdev::InterfaceState::Down);
    }

    TEST_CASE("Set MTU") {
        netdev::NullBackend backend;

        InterfaceName name("bot0");
        backend.create_interface(name);

        auto result = backend.set_mtu(name, 1400);
        CHECK(result.is_ok());
        CHECK(backend.info().mtu == 1400);
    }

    TEST_CASE("Assign address") {
        netdev::NullBackend backend;

        InterfaceName name("bot0");
        backend.create_interface(name);

        OverlayAddr addr;
        addr.addr = "10.42.0.1";
        addr.prefix_len = 24;

        auto result = backend.assign_addr(name, addr);
        CHECK(result.is_ok());
        CHECK(backend.info().addr.addr == "10.42.0.1");
    }

    TEST_CASE("Up and down interface") {
        netdev::NullBackend backend;

        InterfaceName name("bot0");
        backend.create_interface(name);

        CHECK(backend.info().state == netdev::InterfaceState::Down);

        backend.up(name);
        CHECK(backend.info().state == netdev::InterfaceState::Up);
        CHECK(backend.info().is_up());

        backend.down(name);
        CHECK(backend.info().state == netdev::InterfaceState::Down);
    }

    TEST_CASE("Inject and read packet") {
        netdev::NullBackend backend;

        InterfaceName name("bot0");
        backend.create_interface(name);
        backend.up(name);

        // Inject a packet
        netdev::IpPacket pkt;
        pkt.data = {0x45, 0x00, 0x00, 0x14};
        backend.inject_packet(pkt);

        CHECK(backend.can_read());

        auto read_result = backend.read_packet();
        REQUIRE(read_result.is_ok());
        CHECK(read_result.value().data.size() == 4);
    }

    TEST_CASE("Write packet") {
        netdev::NullBackend backend;

        InterfaceName name("bot0");
        backend.create_interface(name);
        backend.up(name);

        netdev::IpPacket pkt;
        pkt.data = {0x45, 0x00, 0x00, 0x14};

        auto result = backend.write_packet(pkt);
        CHECK(result.is_ok());

        auto &tx_queue = backend.get_tx_queue();
        CHECK(tx_queue.size() == 1);
        CHECK(tx_queue[0].data.size() == 4);
    }

}

TEST_SUITE("Netdev - IpPacket") {

    TEST_CASE("IPv4 packet detection") {
        netdev::IpPacket pkt;
        pkt.data = {0x45, 0x00}; // Version 4, IHL 5

        CHECK(pkt.ip_version() == 4);
        CHECK(pkt.is_ipv4());
        CHECK_FALSE(pkt.is_ipv6());
    }

    TEST_CASE("IPv6 packet detection") {
        netdev::IpPacket pkt;
        pkt.data = {0x60, 0x00}; // Version 6

        CHECK(pkt.ip_version() == 6);
        CHECK(pkt.is_ipv6());
        CHECK_FALSE(pkt.is_ipv4());
    }

    TEST_CASE("Empty packet") {
        netdev::IpPacket pkt;

        CHECK(pkt.empty());
        CHECK(pkt.size() == 0);
        CHECK(pkt.ip_version() == 0);
    }

}
