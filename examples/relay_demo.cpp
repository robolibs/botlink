/* SPDX-License-Identifier: MIT */
/*
 * Botlink Relay Demo
 * Demonstrates relay manager and relay routing functionality
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

// Helper to print separator
void print_separator() { std::cout << "----------------------------------------\n"; }

auto main() -> int {
    // Initialize the library
    auto init_result = botlink::init();
    if (init_result.is_err()) {
        std::cerr << "Failed to initialize botlink: " << init_result.error().message.c_str() << "\n";
        return 1;
    }

    std::cout << "Botlink Relay Demo\n";
    std::cout << "==================\n\n";

    // Create identities for local node and peers
    std::cout << "Creating node identities...\n";
    auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
    NodeId local_id = crypto::node_id_from_pubkey(ed_pub);

    auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
    NodeId peer_id = crypto::node_id_from_pubkey(ed_pub2);

    std::cout << "Local Node: " << crypto::node_id_to_hex(local_id).substr(0, 16).c_str() << "...\n";
    std::cout << "Peer Node:  " << crypto::node_id_to_hex(peer_id).substr(0, 16).c_str() << "...\n\n";

    print_separator();

    // Create RelayManager (without socket for demo)
    std::cout << "Creating Relay Manager...\n";
    net::RelayManager relay_manager(local_id, nullptr);

    // Add some relay servers
    std::cout << "\nAdding relay servers:\n";

    net::RelayInfo relay1;
    relay1.id = "relay-us-east-1";
    relay1.endpoint = Endpoint(IPv4Addr(52, 23, 100, 50), 51820);
    relay1.last_seen_ms = time::now_ms();
    relay1.latency_ms = 50;
    relay1.is_connected = true;
    relay_manager.add_relay(relay1);
    std::cout << "  - " << relay1.id.c_str() << " @ " << net::format_endpoint(relay1.endpoint).c_str()
              << " (latency: " << relay1.latency_ms << "ms)\n";

    net::RelayInfo relay2;
    relay2.id = "relay-eu-west-1";
    relay2.endpoint = Endpoint(IPv4Addr(54, 78, 200, 100), 51820);
    relay2.last_seen_ms = time::now_ms();
    relay2.latency_ms = 120;
    relay2.is_connected = true;
    relay_manager.add_relay(relay2);
    std::cout << "  - " << relay2.id.c_str() << " @ " << net::format_endpoint(relay2.endpoint).c_str()
              << " (latency: " << relay2.latency_ms << "ms)\n";

    net::RelayInfo relay3;
    relay3.id = "relay-asia-1";
    relay3.endpoint = Endpoint(IPv4Addr(13, 250, 50, 25), 51820);
    relay3.last_seen_ms = time::now_ms() - 60000; // Stale
    relay3.latency_ms = 200;
    relay3.is_connected = false;
    relay_manager.add_relay(relay3);
    std::cout << "  - " << relay3.id.c_str() << " @ " << net::format_endpoint(relay3.endpoint).c_str()
              << " (latency: " << relay3.latency_ms << "ms) [STALE]\n";

    std::cout << "\nTotal relays: " << relay_manager.get_relays().size() << "\n\n";

    print_separator();

    // Configure preferred relays
    std::cout << "Setting preferred relays...\n";
    Vector<String> preferred;
    preferred.push_back("relay-eu-west-1");
    relay_manager.set_preferred_relays(preferred);
    std::cout << "Preferred: relay-eu-west-1\n\n";

    print_separator();

    // Select best relay
    std::cout << "Selecting best relay...\n";
    auto selected = relay_manager.select_relay();
    if (selected.has_value()) {
        std::cout << "Selected: " << selected->id.c_str() << "\n";
        std::cout << "Endpoint: " << net::format_endpoint(selected->endpoint).c_str() << "\n";
        std::cout << "Latency:  " << selected->latency_ms << "ms\n";
    } else {
        std::cout << "No suitable relay found!\n";
    }
    std::cout << "\n";

    print_separator();

    // Check relay routes
    std::cout << "Checking relay routes to peer...\n";
    bool has_route = relay_manager.has_relay_route(peer_id);
    std::cout << "Has relay route to peer: " << (has_route ? "yes" : "no") << "\n\n";

    print_separator();

    // Demonstrate RelayRoute structure
    std::cout << "Creating example RelayRoute...\n";
    net::RelayRoute route;
    route.peer_id = peer_id;
    route.relay_id = "relay-us-east-1";
    route.relay_endpoint = Endpoint(IPv4Addr(52, 23, 100, 50), 51820);
    route.established_at_ms = time::now_ms();
    route.last_used_ms = time::now_ms();
    route.is_active = true;

    std::cout << "Route to peer via: " << route.relay_id.c_str() << "\n";
    std::cout << "Route active: " << (route.is_active ? "yes" : "no") << "\n";
    std::cout << "Route age: " << route.age_ms() << "ms\n\n";

    print_separator();

    // Demonstrate RelayConnectRequest
    std::cout << "Creating RelayConnectRequest...\n";
    net::RelayConnectRequest connect_req;
    connect_req.requester_id = local_id;
    connect_req.target_peer_id = peer_id;
    connect_req.timestamp_ms = time::now_ms();

    std::cout << "Requester: " << crypto::node_id_to_hex(connect_req.requester_id).substr(0, 16).c_str() << "...\n";
    std::cout << "Target:    " << crypto::node_id_to_hex(connect_req.target_peer_id).substr(0, 16).c_str() << "...\n\n";

    print_separator();

    // Demonstrate RelayForwardPacket
    std::cout << "Creating RelayForwardPacket...\n";
    net::RelayForwardPacket fwd_packet;
    fwd_packet.source_id = local_id;
    fwd_packet.target_id = peer_id;
    fwd_packet.timestamp_ms = time::now_ms();

    // Add some example encrypted payload
    const char *demo_data = "Encrypted tunnel data";
    for (const char *p = demo_data; *p; ++p) {
        fwd_packet.payload.push_back(static_cast<u8>(*p));
    }

    std::cout << "Forward packet from: " << crypto::node_id_to_hex(fwd_packet.source_id).substr(0, 16).c_str()
              << "...\n";
    std::cout << "Forward packet to:   " << crypto::node_id_to_hex(fwd_packet.target_id).substr(0, 16).c_str()
              << "...\n";
    std::cout << "Payload size: " << fwd_packet.payload.size() << " bytes\n\n";

    print_separator();

    // Update relay info
    std::cout << "Updating relay info...\n";
    std::cout << "Before: relay-us-east-1 latency = " << relay_manager.get_relays()[0].latency_ms << "ms\n";

    relay_manager.update_relay("relay-us-east-1", 30, true);

    std::cout << "After:  relay-us-east-1 latency = " << relay_manager.get_relays()[0].latency_ms << "ms\n\n";

    print_separator();

    // Stale check demonstration
    std::cout << "Relay stale check:\n";
    for (const auto &relay : relay_manager.get_relays()) {
        bool is_stale = relay.is_stale(30000);
        std::cout << "  - " << relay.id.c_str() << ": " << (is_stale ? "STALE" : "fresh") << "\n";
    }

    std::cout << "\nRelay demo completed successfully!\n";
    return 0;
}
