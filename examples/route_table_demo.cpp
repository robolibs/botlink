/* SPDX-License-Identifier: MIT */
/*
 * Route Table Demo
 * Demonstrates overlay route management and packet routing
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

// Helper to create a test NodeId
static NodeId make_node_id(u8 seed) {
    NodeId id;
    for (usize i = 0; i < NODE_ID_SIZE; ++i) {
        id.data[i] = static_cast<u8>(seed + i);
    }
    return id;
}

int main() {
    std::cout << "=== Route Table Demo ===\n\n";

    // ==========================================================================
    // Create route table
    // ==========================================================================
    std::cout << "1. Creating route table...\n";

    OverlayAddr local_addr;
    local_addr.addr = "10.42.0.1";
    local_addr.prefix_len = 24;

    netdev::RouteTable table(local_addr);
    std::cout << "   Local address: " << local_addr.addr.c_str() << "/" << local_addr.prefix_len << "\n";
    std::cout << "   Initial route count: " << table.route_count() << "\n\n";

    // ==========================================================================
    // Add direct routes to peers
    // ==========================================================================
    std::cout << "2. Adding direct routes...\n";

    NodeId peer1 = make_node_id(1);
    NodeId peer2 = make_node_id(2);
    NodeId peer3 = make_node_id(3);

    OverlayAddr dest1;
    dest1.addr = "10.42.0.10";
    dest1.prefix_len = 32;
    table.add_direct_route(dest1, peer1);
    std::cout << "   Added route to " << dest1.addr.c_str() << " via peer1\n";

    OverlayAddr dest2;
    dest2.addr = "10.42.0.20";
    dest2.prefix_len = 32;
    table.add_direct_route(dest2, peer2);
    std::cout << "   Added route to " << dest2.addr.c_str() << " via peer2\n";

    // Add a subnet route
    OverlayAddr subnet;
    subnet.addr = "10.42.1.0";
    subnet.prefix_len = 24;
    table.add_direct_route(subnet, peer3, 10);  // metric 10
    std::cout << "   Added route to " << subnet.addr.c_str() << "/24 via peer3 (metric 10)\n";

    std::cout << "   Route count: " << table.route_count() << "\n\n";

    // ==========================================================================
    // Add relay routes
    // ==========================================================================
    std::cout << "3. Adding relay routes...\n";

    OverlayAddr relay_dest;
    relay_dest.addr = "10.42.2.0";
    relay_dest.prefix_len = 24;
    table.add_relay_route(relay_dest, peer1, "relay-node-1", 100);
    std::cout << "   Added relay route to " << relay_dest.addr.c_str() << "/24 via relay-node-1\n";

    std::cout << "   Route count: " << table.route_count() << "\n\n";

    // ==========================================================================
    // Lookup routes
    // ==========================================================================
    std::cout << "4. Looking up routes...\n";

    auto route1 = table.lookup("10.42.0.10");
    if (route1.has_value()) {
        std::cout << "   10.42.0.10 -> " << (route1->is_direct ? "direct" : "relayed")
                  << " (metric " << route1->metric << ")\n";
    }

    auto route2 = table.lookup("10.42.1.50");
    if (route2.has_value()) {
        std::cout << "   10.42.1.50 -> " << (route2->is_direct ? "direct" : "relayed")
                  << " (metric " << route2->metric << ")\n";
    }

    auto route3 = table.lookup("10.42.2.100");
    if (route3.has_value()) {
        std::cout << "   10.42.2.100 -> " << (route3->is_direct ? "direct" : "relayed via " + route3->relay_id)
                  << " (metric " << route3->metric << ")\n";
    }

    auto no_route = table.lookup("192.168.1.1");
    std::cout << "   192.168.1.1 -> " << (no_route.has_value() ? "found" : "no route") << "\n\n";

    // ==========================================================================
    // Lookup from packet
    // ==========================================================================
    std::cout << "5. Looking up route from IP packet...\n";

    // Create a minimal IPv4 packet header (20 bytes)
    // Destination: 10.42.0.10
    Vector<u8> ip_packet(20, 0);
    ip_packet[0] = 0x45;  // Version 4, IHL 5 (20 bytes)
    ip_packet[16] = 10;   // Dest IP byte 1
    ip_packet[17] = 42;   // Dest IP byte 2
    ip_packet[18] = 0;    // Dest IP byte 3
    ip_packet[19] = 10;   // Dest IP byte 4

    auto pkt_route = table.lookup_packet(ip_packet);
    if (pkt_route.has_value()) {
        std::cout << "   Packet with dest 10.42.0.10 routed via peer\n";
    } else {
        std::cout << "   No route for packet\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Get routes to specific peer
    // ==========================================================================
    std::cout << "6. Getting routes to peer1...\n";

    auto peer1_routes = table.get_routes_to_peer(peer1);
    std::cout << "   Routes via peer1: " << peer1_routes.size() << "\n";
    for (const auto& r : peer1_routes) {
        std::cout << "   - " << r.dest.addr.c_str() << "/" << r.dest.prefix_len << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // List all routes
    // ==========================================================================
    std::cout << "7. All routes:\n";

    auto all_routes = table.get_all_routes();
    for (const auto& r : all_routes) {
        std::cout << "   " << r.dest.addr.c_str() << "/" << r.dest.prefix_len
                  << " -> " << (r.is_direct ? "direct" : "relay:" + r.relay_id)
                  << " (metric " << r.metric << ")\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Remove routes
    // ==========================================================================
    std::cout << "8. Removing routes to peer1...\n";

    usize removed = table.remove_routes_to_peer(peer1);
    std::cout << "   Removed " << removed << " routes\n";
    std::cout << "   Remaining route count: " << table.route_count() << "\n\n";

    // ==========================================================================
    // Route aging
    // ==========================================================================
    std::cout << "9. Route aging info:\n";

    auto remaining = table.get_all_routes();
    for (const auto& r : remaining) {
        std::cout << "   " << r.dest.addr.c_str() << "/" << r.dest.prefix_len
                  << " age: " << r.age_ms() << "ms"
                  << " idle: " << r.idle_ms() << "ms\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Clear all routes
    // ==========================================================================
    std::cout << "10. Clearing all routes...\n";

    table.clear();
    std::cout << "   Route count after clear: " << table.route_count() << "\n\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
