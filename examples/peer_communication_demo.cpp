/* SPDX-License-Identifier: MIT */
/*
 * Botlink Peer Communication Demo
 * Demonstrates peer table management, session establishment, and scheduling
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

// Helper to create a peer identity
struct PeerIdentity {
    PrivateKey ed_priv;
    PublicKey ed_pub;
    PrivateKey x_priv;
    PublicKey x_pub;
    NodeId node_id;
    String name;

    static PeerIdentity generate(const String &name) {
        PeerIdentity id;
        id.name = name;
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        id.ed_priv = ed_priv;
        id.ed_pub = ed_pub;
        id.x_priv = x_priv;
        id.x_pub = x_pub;
        id.node_id = crypto::node_id_from_pubkey(ed_pub);
        return id;
    }

    String short_id() const {
        return crypto::node_id_to_hex(node_id).substr(0, 8);
    }
};

void print_divider(const char *title) {
    std::cout << "\n════════════════════════════════════════════════════════════════\n";
    std::cout << "  " << title << "\n";
    std::cout << "════════════════════════════════════════════════════════════════\n\n";
}

void demo_peer_table() {
    print_divider("PeerTable Demo: Managing Known Peers");

    // Create peer table with timing parameters
    // keepalive_interval_ms, handshake_timeout_ms, session_lifetime_ms
    PeerTable peers(25000, 120000, 180000);

    std::cout << "Created PeerTable with:\n";
    std::cout << "  - Keepalive interval: 25 seconds\n";
    std::cout << "  - Handshake timeout: 120 seconds\n";
    std::cout << "  - Session lifetime: 180 seconds\n\n";

    // Generate peer identities
    PeerIdentity local = PeerIdentity::generate("LocalNode");
    PeerIdentity peer1 = PeerIdentity::generate("Peer1");
    PeerIdentity peer2 = PeerIdentity::generate("Peer2");
    PeerIdentity peer3 = PeerIdentity::generate("Peer3");

    std::cout << "Local node: " << local.short_id().c_str() << "\n\n";

    // Add peers to table
    std::cout << "Adding peers to table:\n";
    peers.add_peer(peer1.node_id, peer1.ed_pub, peer1.x_pub);
    std::cout << "  + " << peer1.short_id().c_str() << " (Peer1)\n";

    peers.add_peer(peer2.node_id, peer2.ed_pub, peer2.x_pub);
    std::cout << "  + " << peer2.short_id().c_str() << " (Peer2)\n";

    peers.add_peer(peer3.node_id, peer3.ed_pub, peer3.x_pub);
    std::cout << "  + " << peer3.short_id().c_str() << " (Peer3)\n";

    std::cout << "\nPeer count: " << peers.peer_count() << "\n";
    std::cout << "Connected count: " << peers.connected_count() << "\n";

    // Update endpoints for a peer
    print_divider("Updating Peer Endpoints");

    Vector<Endpoint> peer1_endpoints;
    peer1_endpoints.push_back(Endpoint(IPv4Addr(192, 168, 1, 10), 51820));
    peer1_endpoints.push_back(Endpoint(IPv4Addr(10, 0, 0, 10), 51820));
    peers.update_endpoints(peer1.node_id, peer1_endpoints);

    std::cout << "Updated " << peer1.short_id().c_str() << " with endpoints:\n";
    std::cout << "  - " << net::format_endpoint(peer1_endpoints[0]).c_str() << "\n";
    std::cout << "  - " << net::format_endpoint(peer1_endpoints[1]).c_str() << "\n";

    // Retrieve peer info
    auto peer_info = peers.get_peer(peer1.node_id);
    if (peer_info.has_value()) {
        std::cout << "\nPeer info for " << peer1.short_id().c_str() << ":\n";
        std::cout << "  - Status: " << ((*peer_info)->is_connected() ? "Connected" : "Not connected") << "\n";
        std::cout << "  - Endpoints: " << (*peer_info)->endpoints.size() << "\n";
    }

    // Establish session with peer1
    print_divider("Establishing Encrypted Session");

    std::cout << "Simulating key exchange with " << peer1.short_id().c_str() << "...\n";

    // Compute shared secret
    auto shared = crypto::x25519_shared_secret(local.x_priv, peer1.x_pub);
    if (shared.is_err()) {
        std::cout << "Key exchange failed!\n";
        return;
    }

    // Derive session keys
    auto [send_key, recv_key] = crypto::derive_initiator_keys(shared.value(), local.node_id, peer1.node_id, 1);

    std::cout << "Session keys derived:\n";
    std::cout << "  - Key ID: " << send_key.key_id << "\n";

    // Create session in peer table
    peers.create_session(peer1.node_id, send_key, recv_key);

    std::cout << "\nSession established!\n";
    std::cout << "Connected count: " << peers.connected_count() << "\n";

    // Check connection status
    auto connected_peers = peers.get_connected_peers();
    std::cout << "\nConnected peers:\n";
    for (auto *p : connected_peers) {
        std::cout << "  - " << crypto::node_id_to_hex(p->node_id).substr(0, 8).c_str() << "\n";
    }

    // Check if peer is connected
    std::cout << "\nConnection status:\n";
    std::cout << "  - " << peer1.short_id().c_str() << ": " << (peers.has_peer(peer1.node_id) ? "known" : "unknown");
    auto p1_info = peers.get_peer(peer1.node_id);
    if (p1_info.has_value()) {
        std::cout << ", " << ((*p1_info)->is_connected() ? "connected" : "not connected");
    }
    std::cout << "\n";

    std::cout << "  - " << peer2.short_id().c_str() << ": " << (peers.has_peer(peer2.node_id) ? "known" : "unknown");
    auto p2_info = peers.get_peer(peer2.node_id);
    if (p2_info.has_value()) {
        std::cout << ", " << ((*p2_info)->is_connected() ? "connected" : "not connected");
    }
    std::cout << "\n";

    // Remove a peer
    print_divider("Removing Peer");

    std::cout << "Removing " << peer3.short_id().c_str() << " from peer table...\n";
    peers.remove_peer(peer3.node_id);
    std::cout << "Peer count: " << peers.peer_count() << "\n";
}

void demo_scheduler() {
    print_divider("Scheduler Demo: Timer Management");

    runtime::Scheduler scheduler;

    std::cout << "Created scheduler\n";
    std::cout << "Initial timer count: " << scheduler.timer_count() << "\n\n";

    // Create timers with callbacks
    int keepalive_count = 0;
    int cleanup_count = 0;

    std::cout << "Creating timers:\n";

    auto keepalive_id = scheduler.create_repeating("keepalive", 50, [&keepalive_count]() {
        keepalive_count++;
        std::cout << "  [keepalive] Tick #" << keepalive_count << "\n";
    });
    std::cout << "  + Keepalive timer (50ms repeating) - ID: " << keepalive_id << "\n";

    auto cleanup_id = scheduler.create_oneshot("cleanup", 150, [&cleanup_count]() {
        cleanup_count++;
        std::cout << "  [cleanup] Executed!\n";
    });
    std::cout << "  + Cleanup timer (150ms oneshot) - ID: " << cleanup_id << "\n";

    std::cout << "\nActive timers: " << scheduler.active_timer_count() << "\n";
    std::cout << "Time until next: " << scheduler.time_until_next_ms() << " ms\n";

    // Process timers in a loop
    std::cout << "\nRunning scheduler loop (300ms):\n";

    u64 start = time::now_ms();
    while (time::now_ms() - start < 300) {
        scheduler.process();
        time::sleep_ms(10);
    }

    std::cout << "\nAfter 300ms:\n";
    std::cout << "  - Keepalive fired: " << keepalive_count << " times\n";
    std::cout << "  - Cleanup fired: " << cleanup_count << " times\n";
    std::cout << "  - Active timers: " << scheduler.active_timer_count() << "\n";

    // Cancel repeating timer
    std::cout << "\nCancelling keepalive timer...\n";
    bool cancelled = scheduler.cancel(keepalive_id);
    std::cout << "Cancelled: " << (cancelled ? "yes" : "no") << "\n";
    std::cout << "Active timers: " << scheduler.active_timer_count() << "\n";

    // Cleanup inactive timers
    usize removed = scheduler.cleanup();
    std::cout << "\nCleaned up " << removed << " inactive timer(s)\n";
    std::cout << "Total timers: " << scheduler.timer_count() << "\n";
}

void demo_endpoints() {
    print_divider("Endpoint Handling Demo");

    // Parse different endpoint formats
    std::cout << "Parsing endpoints:\n";

    auto ep1 = net::parse_endpoint("192.168.1.1:51820");
    if (ep1.is_ok()) {
        std::cout << "  \"192.168.1.1:51820\" -> " << net::format_endpoint(ep1.value()).c_str() << "\n";
    }

    auto ep2 = net::parse_endpoint("10.0.0.5:8080");
    if (ep2.is_ok()) {
        std::cout << "  \"10.0.0.5:8080\" -> " << net::format_endpoint(ep2.value()).c_str() << "\n";
    }

    // Create endpoints programmatically
    std::cout << "\nCreating endpoints programmatically:\n";

    Endpoint local_ep(IPv4Addr(127, 0, 0, 1), 51820);
    std::cout << "  Localhost: " << net::format_endpoint(local_ep).c_str() << "\n";

    Endpoint any_ep(IPv4Addr(0, 0, 0, 0), 51820);
    std::cout << "  Any address: " << net::format_endpoint(any_ep).c_str() << "\n";

    // Parse endpoint list
    std::cout << "\nParsing endpoint list:\n";
    auto ep_list = net::parse_endpoint_list("192.168.1.1:51820, 10.0.0.1:51821, 172.16.0.1:51822");
    if (ep_list.is_ok()) {
        std::cout << "  Parsed " << ep_list.value().size() << " endpoints:\n";
        for (const auto &ep : ep_list.value()) {
            std::cout << "    - " << net::format_endpoint(ep).c_str() << "\n";
        }
    }

    // Convert to/from UDP endpoint
    std::cout << "\nConverting to UdpEndpoint:\n";
    Endpoint orig(IPv4Addr(192, 168, 1, 100), 8080);
    auto udp_ep = net::to_udp_endpoint(orig);
    std::cout << "  Original: " << net::format_endpoint(orig).c_str() << "\n";
    std::cout << "  UdpEndpoint: " << udp_ep.host.c_str() << ":" << udp_ep.port << "\n";

    Endpoint back = net::from_udp_endpoint(udp_ep);
    std::cout << "  Converted back: " << net::format_endpoint(back).c_str() << "\n";
}

void demo_route_table() {
    print_divider("RouteTable Demo: Overlay Network Routing");

    // Create overlay address
    OverlayAddr overlay("10.42.0.1", 24);

    std::cout << "Local overlay address: " << overlay.addr.c_str() << "/" << static_cast<int>(overlay.prefix_len)
              << "\n\n";

    // Create route table
    netdev::RouteTable routes(overlay);

    // Add routes
    PeerIdentity peer1 = PeerIdentity::generate("Peer1");
    PeerIdentity peer2 = PeerIdentity::generate("Peer2");

    std::cout << "Adding routes:\n";

    netdev::RouteEntry route1;
    route1.dest = OverlayAddr("10.42.0.2", 32);
    route1.next_hop = peer1.node_id;
    routes.add_route(route1);
    std::cout << "  10.42.0.2/32 -> " << peer1.short_id().c_str() << "\n";

    netdev::RouteEntry route2;
    route2.dest = OverlayAddr("10.42.1.0", 24);
    route2.next_hop = peer2.node_id;
    routes.add_route(route2);
    std::cout << "  10.42.1.0/24 -> " << peer2.short_id().c_str() << "\n";

    std::cout << "\nRoute count: " << routes.route_count() << "\n";

    // Lookup routes
    std::cout << "\nRoute lookups:\n";

    auto r1 = routes.lookup("10.42.0.2");
    if (r1.has_value()) {
        std::cout << "  10.42.0.2 -> " << crypto::node_id_to_hex(r1->next_hop).substr(0, 8).c_str() << "\n";
    }

    auto r2 = routes.lookup("10.42.1.50");
    if (r2.has_value()) {
        std::cout << "  10.42.1.50 -> " << crypto::node_id_to_hex(r2->next_hop).substr(0, 8).c_str() << "\n";
    }

    auto r3 = routes.lookup("10.42.0.1");
    std::cout << "  10.42.0.1 -> " << (r3.has_value() ? "found" : "local (no route needed)") << "\n";
}

auto main() -> int {
    // Initialize botlink
    auto init_result = botlink::init();
    if (init_result.is_err()) {
        std::cerr << "Failed to initialize: " << init_result.error().message.c_str() << "\n";
        return 1;
    }

    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║          Botlink Peer Communication Demo                       ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";

    demo_peer_table();
    demo_scheduler();
    demo_endpoints();
    demo_route_table();

    std::cout << "\n=== Demo Complete ===\n";
    return 0;
}
