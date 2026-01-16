/* SPDX-License-Identifier: MIT */
/*
 * Botlink Route Table Tests
 * Tests for overlay route management
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>
#include <thread>

using namespace botlink;
using namespace dp;

TEST_SUITE("RouteTable - Basic Operations") {

    TEST_CASE("RouteEntry default values") {
        netdev::RouteEntry entry;
        CHECK(entry.added_at_ms == 0);
        CHECK(entry.last_used_ms == 0);
        CHECK(entry.metric == 0);
        CHECK(entry.is_direct == true);
        CHECK(entry.relay_id.empty());
    }

    TEST_CASE("RouteTable empty by default") {
        netdev::RouteTable table;
        CHECK(table.route_count() == 0);
        CHECK(table.get_all_routes().empty());
    }

    TEST_CASE("RouteTable with local address") {
        OverlayAddr local;
        local.addr = "10.42.0.1";
        local.prefix_len = 24;

        netdev::RouteTable table(local);
        CHECK(table.route_count() == 0);
    }

}

TEST_SUITE("RouteTable - Direct Routes") {

    TEST_CASE("Add direct route") {
        netdev::RouteTable table;

        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(pub);

        OverlayAddr dest;
        dest.addr = "10.42.0.2";
        dest.prefix_len = 32;

        auto result = table.add_direct_route(dest, peer_id);
        CHECK(result.is_ok());
        CHECK(table.route_count() == 1);

        auto routes = table.get_all_routes();
        CHECK(routes.size() == 1);
        CHECK(routes[0].dest.addr == "10.42.0.2");
        CHECK(routes[0].is_direct == true);
        CHECK(routes[0].next_hop == peer_id);
    }

    TEST_CASE("Add direct route with metric") {
        netdev::RouteTable table;

        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(pub);

        OverlayAddr dest;
        dest.addr = "10.42.0.3";
        dest.prefix_len = 32;

        auto result = table.add_direct_route(dest, peer_id, 10);
        CHECK(result.is_ok());

        auto routes = table.get_all_routes();
        CHECK(routes[0].metric == 10);
    }

    TEST_CASE("Update route with better metric") {
        netdev::RouteTable table;

        auto [priv1, pub1] = crypto::generate_ed25519_keypair();
        NodeId peer1 = crypto::node_id_from_pubkey(pub1);

        auto [priv2, pub2] = crypto::generate_ed25519_keypair();
        NodeId peer2 = crypto::node_id_from_pubkey(pub2);

        OverlayAddr dest;
        dest.addr = "10.42.0.4";
        dest.prefix_len = 32;

        // Add first route with metric 100
        (void)table.add_direct_route(dest, peer1, 100);
        CHECK(table.route_count() == 1);

        // Add same dest with better metric
        (void)table.add_direct_route(dest, peer2, 10);
        CHECK(table.route_count() == 1); // Should update, not add

        auto routes = table.get_all_routes();
        CHECK(routes[0].metric == 10);
        CHECK(routes[0].next_hop == peer2);
    }

}

TEST_SUITE("RouteTable - Relay Routes") {

    TEST_CASE("Add relay route") {
        netdev::RouteTable table;

        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(pub);

        OverlayAddr dest;
        dest.addr = "10.42.0.5";
        dest.prefix_len = 32;

        auto result = table.add_relay_route(dest, peer_id, "relay1", 100);
        CHECK(result.is_ok());
        CHECK(table.route_count() == 1);

        auto routes = table.get_all_routes();
        CHECK(routes[0].is_direct == false);
        CHECK(routes[0].relay_id == "relay1");
        CHECK(routes[0].metric == 100);
    }

}

TEST_SUITE("RouteTable - Route Lookup") {

    TEST_CASE("Lookup exact match") {
        netdev::RouteTable table;

        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(pub);

        OverlayAddr dest;
        dest.addr = "10.42.0.10";
        dest.prefix_len = 32;

        (void)table.add_direct_route(dest, peer_id);

        auto lookup = table.lookup("10.42.0.10");
        CHECK(lookup.has_value());
        CHECK(lookup->dest.addr == "10.42.0.10");
        CHECK(lookup->next_hop == peer_id);
    }

    TEST_CASE("Lookup subnet match") {
        netdev::RouteTable table;

        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(pub);

        OverlayAddr subnet;
        subnet.addr = "10.42.0.0";
        subnet.prefix_len = 24;

        (void)table.add_direct_route(subnet, peer_id);

        // Should match any IP in the subnet
        auto lookup1 = table.lookup("10.42.0.1");
        CHECK(lookup1.has_value());

        auto lookup2 = table.lookup("10.42.0.255");
        CHECK(lookup2.has_value());

        // Should not match outside subnet
        auto lookup3 = table.lookup("10.42.1.1");
        CHECK_FALSE(lookup3.has_value());
    }

    TEST_CASE("Lookup prefers longer prefix") {
        netdev::RouteTable table;

        auto [priv1, pub1] = crypto::generate_ed25519_keypair();
        NodeId peer1 = crypto::node_id_from_pubkey(pub1);

        auto [priv2, pub2] = crypto::generate_ed25519_keypair();
        NodeId peer2 = crypto::node_id_from_pubkey(pub2);

        // Add /24 subnet route
        OverlayAddr subnet;
        subnet.addr = "10.42.0.0";
        subnet.prefix_len = 24;
        (void)table.add_direct_route(subnet, peer1);

        // Add /32 host route
        OverlayAddr host;
        host.addr = "10.42.0.50";
        host.prefix_len = 32;
        (void)table.add_direct_route(host, peer2);

        // Lookup for host route should prefer /32
        auto lookup = table.lookup("10.42.0.50");
        CHECK(lookup.has_value());
        CHECK(lookup->next_hop == peer2);

        // Lookup for other IP should use /24
        auto lookup2 = table.lookup("10.42.0.100");
        CHECK(lookup2.has_value());
        CHECK(lookup2->next_hop == peer1);
    }

    TEST_CASE("Lookup no match") {
        netdev::RouteTable table;

        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(pub);

        OverlayAddr dest;
        dest.addr = "10.42.0.1";
        dest.prefix_len = 32;

        (void)table.add_direct_route(dest, peer_id);

        auto lookup = table.lookup("192.168.1.1");
        CHECK_FALSE(lookup.has_value());
    }

}

TEST_SUITE("RouteTable - Packet Lookup") {

    TEST_CASE("Lookup packet destination") {
        netdev::RouteTable table;

        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(pub);

        OverlayAddr dest;
        dest.addr = "10.42.0.0";
        dest.prefix_len = 24;

        (void)table.add_direct_route(dest, peer_id);

        // Create minimal IPv4 packet header (20 bytes)
        Vector<u8> pkt(20, 0);
        pkt[0] = 0x45; // IPv4, IHL=5
        // Destination IP at bytes 16-19: 10.42.0.5
        pkt[16] = 10;
        pkt[17] = 42;
        pkt[18] = 0;
        pkt[19] = 5;

        auto lookup = table.lookup_packet(pkt);
        CHECK(lookup.has_value());
        CHECK(lookup->next_hop == peer_id);
    }

    TEST_CASE("Lookup packet too short") {
        netdev::RouteTable table;

        Vector<u8> short_pkt(10, 0);
        auto lookup = table.lookup_packet(short_pkt);
        CHECK_FALSE(lookup.has_value());
    }

    TEST_CASE("Lookup packet IPv6 unsupported") {
        netdev::RouteTable table;

        Vector<u8> ipv6_pkt(40, 0);
        ipv6_pkt[0] = 0x60; // IPv6

        auto lookup = table.lookup_packet(ipv6_pkt);
        CHECK_FALSE(lookup.has_value());
    }

}

TEST_SUITE("RouteTable - Route Removal") {

    TEST_CASE("Remove routes to peer") {
        netdev::RouteTable table;

        auto [priv1, pub1] = crypto::generate_ed25519_keypair();
        NodeId peer1 = crypto::node_id_from_pubkey(pub1);

        auto [priv2, pub2] = crypto::generate_ed25519_keypair();
        NodeId peer2 = crypto::node_id_from_pubkey(pub2);

        OverlayAddr dest1;
        dest1.addr = "10.42.0.1";
        dest1.prefix_len = 32;

        OverlayAddr dest2;
        dest2.addr = "10.42.0.2";
        dest2.prefix_len = 32;

        OverlayAddr dest3;
        dest3.addr = "10.42.0.3";
        dest3.prefix_len = 32;

        (void)table.add_direct_route(dest1, peer1);
        (void)table.add_direct_route(dest2, peer1);
        (void)table.add_direct_route(dest3, peer2);

        CHECK(table.route_count() == 3);

        usize removed = table.remove_routes_to_peer(peer1);
        CHECK(removed == 2);
        CHECK(table.route_count() == 1);
    }

    TEST_CASE("Remove route by destination") {
        netdev::RouteTable table;

        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(pub);

        OverlayAddr dest;
        dest.addr = "10.42.0.1";
        dest.prefix_len = 32;

        (void)table.add_direct_route(dest, peer_id);
        CHECK(table.route_count() == 1);

        bool removed = table.remove_route(dest);
        CHECK(removed == true);
        CHECK(table.route_count() == 0);
    }

    TEST_CASE("Remove nonexistent route") {
        netdev::RouteTable table;

        OverlayAddr dest;
        dest.addr = "10.42.0.1";
        dest.prefix_len = 32;

        bool removed = table.remove_route(dest);
        CHECK(removed == false);
    }

    TEST_CASE("Clear all routes") {
        netdev::RouteTable table;

        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(pub);

        OverlayAddr dest1;
        dest1.addr = "10.42.0.1";
        dest1.prefix_len = 32;

        OverlayAddr dest2;
        dest2.addr = "10.42.0.2";
        dest2.prefix_len = 32;

        (void)table.add_direct_route(dest1, peer_id);
        (void)table.add_direct_route(dest2, peer_id);

        CHECK(table.route_count() == 2);

        table.clear();
        CHECK(table.route_count() == 0);
    }

}

TEST_SUITE("RouteTable - Maintenance") {

    TEST_CASE("Get routes to peer") {
        netdev::RouteTable table;

        auto [priv1, pub1] = crypto::generate_ed25519_keypair();
        NodeId peer1 = crypto::node_id_from_pubkey(pub1);

        auto [priv2, pub2] = crypto::generate_ed25519_keypair();
        NodeId peer2 = crypto::node_id_from_pubkey(pub2);

        OverlayAddr dest1;
        dest1.addr = "10.42.0.1";
        dest1.prefix_len = 32;

        OverlayAddr dest2;
        dest2.addr = "10.42.0.2";
        dest2.prefix_len = 32;

        OverlayAddr dest3;
        dest3.addr = "10.42.0.3";
        dest3.prefix_len = 32;

        (void)table.add_direct_route(dest1, peer1);
        (void)table.add_direct_route(dest2, peer1);
        (void)table.add_direct_route(dest3, peer2);

        auto peer1_routes = table.get_routes_to_peer(peer1);
        CHECK(peer1_routes.size() == 2);

        auto peer2_routes = table.get_routes_to_peer(peer2);
        CHECK(peer2_routes.size() == 1);
    }

    TEST_CASE("Mark route used") {
        netdev::RouteTable table;

        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(pub);

        OverlayAddr dest;
        dest.addr = "10.42.0.1";
        dest.prefix_len = 32;

        (void)table.add_direct_route(dest, peer_id);

        auto routes_before = table.get_all_routes();
        u64 last_used_before = routes_before[0].last_used_ms;

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        table.mark_used(dest);

        auto routes_after = table.get_all_routes();
        CHECK(routes_after[0].last_used_ms > last_used_before);
    }

}

TEST_SUITE("RouteTable - IPv4 Parsing") {

    TEST_CASE("Parse valid IPv4") {
        netdev::RouteTable table;

        // Using the subnet match function to indirectly test parsing
        OverlayAddr subnet;
        subnet.addr = "192.168.1.0";
        subnet.prefix_len = 24;

        // matches_subnet is private, but we can test via lookup
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(pub);

        (void)table.add_direct_route(subnet, peer_id);

        auto lookup = table.lookup("192.168.1.100");
        CHECK(lookup.has_value());
    }

}
