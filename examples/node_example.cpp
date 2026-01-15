/* SPDX-License-Identifier: MIT */
/*
 * Botlink Node Example
 * Demonstrates creating and configuring a BotlinkNode
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

auto main() -> int {
    // Initialize the library
    auto init_result = botlink::init();
    if (init_result.is_err()) {
        std::cerr << "Failed to initialize botlink: " << init_result.error().message.c_str() << "\n";
        return 1;
    }

    std::cout << "Botlink Node Configuration Example\n";
    std::cout << "===================================\n\n";

    // Generate identity keypairs
    std::cout << "Generating identity keypairs...\n";
    auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

    NodeId node_id = crypto::node_id_from_pubkey(ed_pub);
    std::cout << "Node ID: " << crypto::node_id_to_hex(node_id).substr(0, 16).c_str() << "...\n\n";

    // Demonstrate PeerTable usage
    std::cout << "Setting up peer table...\n";
    PeerTable peers(25000, 120000, 180000); // keepalive, handshake timeout, session lifetime

    // Generate keys for a peer
    auto [peer_ed_priv, peer_ed_pub] = crypto::generate_ed25519_keypair();
    auto [peer_x_priv, peer_x_pub] = crypto::generate_x25519_keypair();
    NodeId peer_id = crypto::node_id_from_pubkey(peer_ed_pub);

    // Add peer
    peers.add_peer(peer_id, peer_ed_pub, peer_x_pub);
    std::cout << "Added peer: " << crypto::node_id_to_hex(peer_id).substr(0, 16).c_str() << "...\n";
    std::cout << "Peer count: " << peers.peer_count() << "\n";
    std::cout << "Connected count: " << peers.connected_count() << "\n\n";

    // Create session keys
    std::cout << "Creating session with peer...\n";
    crypto::SessionKey send_key, recv_key;
    auto rnd1 = keylock::utils::Common::generate_random_bytes(32);
    auto rnd2 = keylock::utils::Common::generate_random_bytes(32);
    for (usize i = 0; i < 32; ++i) {
        send_key.data[i] = rnd1[i];
        recv_key.data[i] = rnd2[i];
    }
    send_key.key_id = 1;
    recv_key.key_id = 1;

    peers.create_session(peer_id, send_key, recv_key);
    std::cout << "Session created!\n";
    std::cout << "Connected count: " << peers.connected_count() << "\n\n";

    // Demonstrate scheduler
    std::cout << "Setting up scheduler...\n";
    runtime::Scheduler scheduler;

    bool timer_fired = false;
    auto timer_id = scheduler.create_oneshot("example_timer", 100, [&timer_fired]() {
        timer_fired = true;
    });
    std::cout << "Created timer with ID: " << timer_id << "\n";
    std::cout << "Active timers: " << scheduler.active_timer_count() << "\n";

    // Wait and process
    time::sleep_ms(150);
    usize processed = scheduler.process();
    std::cout << "Processed " << processed << " timer(s)\n";
    std::cout << "Timer fired: " << (timer_fired ? "yes" : "no") << "\n\n";

    // Demonstrate TrustChain
    std::cout << "Creating trust chain...\n";
    TrustChain chain("example_swarm", node_id, ed_pub, x_pub);
    std::cout << "Chain ID: " << chain.chain_id().c_str() << "\n";
    std::cout << "Chain length: " << chain.length() << "\n";
    std::cout << "Genesis member: " << (chain.is_member(node_id) ? "yes" : "no") << "\n\n";

    std::cout << "Example completed successfully!\n";
    return 0;
}
