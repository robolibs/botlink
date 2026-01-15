/* SPDX-License-Identifier: MIT */
/*
 * Botlink Relay Server Example
 * A non-member relay that forwards encrypted packets between peers
 *
 * Key properties (from PLAN.md):
 * - Relays CANNOT vote
 * - Relays CANNOT introduce/sponsor
 * - Relays only forward opaque encrypted traffic
 * - Relays never terminate crypto (end-to-end between members)
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

// Simple relay routing table: maps node IDs to endpoints
struct RelayRoutingTable {
    Map<NodeId, Endpoint> routes;

    auto add_route(const NodeId& node_id, const Endpoint& endpoint) -> void {
        routes[node_id] = endpoint;
        echo::debug("Added route for node: ", crypto::node_id_to_hex(node_id).substr(0, 16).c_str());
    }

    auto get_route(const NodeId& node_id) -> Optional<Endpoint> {
        auto it = routes.find(node_id);
        if (it != routes.end()) {
            return it->second;
        }
        return Optional<Endpoint>();
    }

    auto remove_route(const NodeId& node_id) -> void {
        routes.erase(node_id);
    }
};

int main() {
    // Initialize libsodium
    if (botlink::init().is_err()) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    echo::info("=== Botlink Relay Server ===").cyan();
    echo::info("");

    // Relay identity (for relay control channel, not for voting)
    auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
    NodeId relay_id = crypto::node_id_from_pubkey(ed_pub);

    echo::info("Relay ID: ", crypto::node_id_to_hex(relay_id).substr(0, 16).c_str(), "...");

    // Relay configuration
    String listen_addr = "0.0.0.0:51900";
    echo::info("Listen: ", listen_addr.c_str());

    // Routing table for connected peers
    RelayRoutingTable routing;

    // Statistics
    u64 packets_forwarded = 0;
    u64 bytes_forwarded = 0;
    u64 connections = 0;

    echo::info("");
    echo::info("Relay Properties:").yellow();
    echo::info("  - Cannot vote on membership");
    echo::info("  - Cannot introduce/sponsor candidates");
    echo::info("  - Only forwards opaque encrypted packets");
    echo::info("  - Never decrypts traffic (end-to-end between members)");

    // Simulate relay operations
    echo::info("");
    echo::info("Simulating relay operations...").yellow();

    // Simulate two peers connecting through relay
    auto [peer_a_ed_priv, peer_a_ed_pub] = crypto::generate_ed25519_keypair();
    auto [peer_b_ed_priv, peer_b_ed_pub] = crypto::generate_ed25519_keypair();
    NodeId peer_a_id = crypto::node_id_from_pubkey(peer_a_ed_pub);
    NodeId peer_b_id = crypto::node_id_from_pubkey(peer_b_ed_pub);

    // Simulate RelayConnect from peer A
    net::RelayConnectRequest connect_a;
    connect_a.requester_id = peer_a_id;
    connect_a.target_peer_id = peer_b_id;
    connect_a.timestamp_ms = time::now_ms();

    echo::info("[Peer A] RelayConnect request to reach Peer B");

    // Register peer A's route
    Endpoint peer_a_endpoint;
    peer_a_endpoint.family = AddrFamily::IPv4;
    peer_a_endpoint.ipv4.octets = {192, 168, 1, 10};
    peer_a_endpoint.port = 51820;
    routing.add_route(peer_a_id, peer_a_endpoint);
    connections++;

    // Simulate RelayConnect from peer B
    net::RelayConnectRequest connect_b;
    connect_b.requester_id = peer_b_id;
    connect_b.target_peer_id = peer_a_id;
    connect_b.timestamp_ms = time::now_ms();

    echo::info("[Peer B] RelayConnect request to reach Peer A");

    // Register peer B's route
    Endpoint peer_b_endpoint;
    peer_b_endpoint.family = AddrFamily::IPv4;
    peer_b_endpoint.ipv4.octets = {192, 168, 2, 20};
    peer_b_endpoint.port = 51820;
    routing.add_route(peer_b_id, peer_b_endpoint);
    connections++;

    echo::info("Both peers connected through relay").green();

    // Simulate forwarding an encrypted packet from A to B
    echo::info("");
    echo::info("Simulating packet forwarding...").yellow();

    net::RelayForwardPacket fwd_packet;
    fwd_packet.source_id = peer_a_id;
    fwd_packet.target_id = peer_b_id;
    fwd_packet.timestamp_ms = time::now_ms();

    // Simulate encrypted payload (relay cannot decrypt this)
    for (int i = 0; i < 100; ++i) {
        fwd_packet.payload.push_back(static_cast<u8>(i));
    }

    echo::info("[Relay] Received packet from Peer A (", fwd_packet.payload.size(), " bytes)");

    // Look up route for target
    auto target_route = routing.get_route(fwd_packet.target_id);
    if (target_route.has_value()) {
        echo::info("[Relay] Forwarding to Peer B at ",
                   target_route.value().ipv4.octets[0], ".",
                   target_route.value().ipv4.octets[1], ".",
                   target_route.value().ipv4.octets[2], ".",
                   target_route.value().ipv4.octets[3], ":",
                   target_route.value().port);
        packets_forwarded++;
        bytes_forwarded += fwd_packet.payload.size();
    } else {
        echo::warn("[Relay] No route for target peer");
    }

    // Show statistics
    echo::info("");
    echo::info("Relay Statistics:").yellow();
    echo::info("  Connections:       ", connections);
    echo::info("  Packets forwarded: ", packets_forwarded);
    echo::info("  Bytes forwarded:   ", bytes_forwarded);

    echo::info("");
    echo::info("=== Relay Server Ready ===").cyan();
    echo::info("(In production, run event loop to handle real UDP traffic)");

    return 0;
}
