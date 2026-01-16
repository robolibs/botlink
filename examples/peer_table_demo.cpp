/* SPDX-License-Identifier: MIT */
/*
 * Peer Table Demo
 * Demonstrates runtime peer connection tracking and session management
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

// Helper to create a test node identity
struct NodeIdentity {
    PrivateKey ed_priv;
    PublicKey ed_pub;
    PrivateKey x_priv;
    PublicKey x_pub;
    NodeId id;
};

static NodeIdentity create_identity() {
    NodeIdentity ident;
    auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

    ident.ed_priv = ed_priv;
    ident.ed_pub = ed_pub;
    ident.x_priv = x_priv;
    ident.x_pub = x_pub;
    ident.id = crypto::node_id_from_pubkey(ed_pub);

    return ident;
}

int main() {
    std::cout << "=== Peer Table Demo ===\n\n";

    // ==========================================================================
    // Create peer table
    // ==========================================================================
    std::cout << "1. Creating peer table...\n";

    // Custom intervals: keepalive=5s, session_timeout=30s, handshake_timeout=10s
    PeerTable table(5000, 30000, 10000);

    std::cout << "   Peer count: " << table.peer_count() << "\n";
    std::cout << "   Connected count: " << table.connected_count() << "\n\n";

    // ==========================================================================
    // Add peers
    // ==========================================================================
    std::cout << "2. Adding peers...\n";

    auto peer1 = create_identity();
    auto peer2 = create_identity();
    auto peer3 = create_identity();

    table.add_peer(peer1.id, peer1.ed_pub, peer1.x_pub);
    table.add_peer(peer2.id, peer2.ed_pub, peer2.x_pub);
    table.add_peer(peer3.id, peer3.ed_pub, peer3.x_pub);

    std::cout << "   Added peer 1: " << crypto::node_id_to_hex(peer1.id).substr(0, 16).c_str() << "...\n";
    std::cout << "   Added peer 2: " << crypto::node_id_to_hex(peer2.id).substr(0, 16).c_str() << "...\n";
    std::cout << "   Added peer 3: " << crypto::node_id_to_hex(peer3.id).substr(0, 16).c_str() << "...\n";
    std::cout << "   Total peers: " << table.peer_count() << "\n\n";

    // ==========================================================================
    // Add endpoints to peers
    // ==========================================================================
    std::cout << "3. Setting peer endpoints...\n";

    Vector<Endpoint> peer1_endpoints;
    auto ep1_result = net::parse_endpoint("192.168.1.10:51820");
    if (ep1_result.is_ok()) {
        peer1_endpoints.push_back(ep1_result.value());
    }
    auto ep2_result = net::parse_endpoint("10.0.0.10:51820");
    if (ep2_result.is_ok()) {
        peer1_endpoints.push_back(ep2_result.value());
    }
    table.update_endpoints(peer1.id, peer1_endpoints);

    auto peer = table.get_peer(peer1.id);
    if (peer.has_value()) {
        std::cout << "   Peer 1 endpoints: " << peer.value()->endpoints.size() << "\n";
        auto pref = peer.value()->preferred_endpoint();
        if (pref.has_value()) {
            std::cout << "   Preferred endpoint port: " << pref->port << "\n";
        }
    }
    std::cout << "\n";

    // ==========================================================================
    // Create sessions
    // ==========================================================================
    std::cout << "4. Creating secure sessions...\n";

    // Simulate key exchange result
    crypto::SessionKey send_key, recv_key;
    auto rand1 = keylock::utils::Common::generate_random_bytes(32);
    auto rand2 = keylock::utils::Common::generate_random_bytes(32);
    for (usize i = 0; i < 32; ++i) {
        send_key.data[i] = rand1[i];
        recv_key.data[i] = rand2[i];
    }
    send_key.key_id = 1;
    recv_key.key_id = 1;

    boolean created = table.create_session(peer1.id, send_key, recv_key);
    std::cout << "   Session created for peer 1: " << (created ? "yes" : "no") << "\n";

    peer = table.get_peer(peer1.id);
    if (peer.has_value()) {
        std::cout << "   Peer 1 has session: " << (peer.value()->has_session() ? "yes" : "no") << "\n";
        std::cout << "   Peer 1 status: "
                  << (peer.value()->status == PeerStatus::Direct ? "Direct" :
                      peer.value()->status == PeerStatus::Relayed ? "Relayed" : "Unknown") << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Record data transfer
    // ==========================================================================
    std::cout << "5. Recording data transfer...\n";

    table.record_send(peer1.id, 1500);  // Sent 1500 bytes
    table.record_send(peer1.id, 2000);  // Sent 2000 more bytes
    table.record_recv(peer1.id, 1000);  // Received 1000 bytes

    peer = table.get_peer(peer1.id);
    if (peer.has_value()) {
        std::cout << "   Peer 1 TX bytes: " << peer.value()->tx_bytes << "\n";
        std::cout << "   Peer 1 RX bytes: " << peer.value()->rx_bytes << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Session rekey
    // ==========================================================================
    std::cout << "6. Rekeying session...\n";

    peer = table.get_peer(peer1.id);
    if (peer.has_value() && peer.value()->has_session()) {
        std::cout << "   Before rekey:\n";
        std::cout << "   - Key ID: " << peer.value()->session->send_key.key_id << "\n";
        std::cout << "   - Rekey count: " << peer.value()->session->rekey_count << "\n";
    }

    boolean rekeyed = table.rekey_session(peer1.id);
    std::cout << "\n   Rekey successful: " << (rekeyed ? "yes" : "no") << "\n";

    peer = table.get_peer(peer1.id);
    if (peer.has_value() && peer.value()->has_session()) {
        std::cout << "   After rekey:\n";
        std::cout << "   - Key ID: " << peer.value()->session->send_key.key_id << "\n";
        std::cout << "   - Rekey count: " << peer.value()->session->rekey_count << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Query peer lists
    // ==========================================================================
    std::cout << "7. Querying peer lists...\n";

    auto all_peers = table.get_all_peers();
    std::cout << "   All peers: " << all_peers.size() << "\n";

    auto connected = table.get_connected_peers();
    std::cout << "   Connected peers: " << connected.size() << "\n";

    std::cout << "   Connected count: " << table.connected_count() << "\n\n";

    // ==========================================================================
    // Check connection status
    // ==========================================================================
    std::cout << "8. Checking peer status...\n";

    std::cout << "   Has peer 1: " << (table.has_peer(peer1.id) ? "yes" : "no") << "\n";
    std::cout << "   Has peer 2: " << (table.has_peer(peer2.id) ? "yes" : "no") << "\n";

    NodeId unknown_id;
    for (usize i = 0; i < NODE_ID_SIZE; ++i) {
        unknown_id.data[i] = static_cast<u8>(i + 100);
    }
    std::cout << "   Has unknown peer: " << (table.has_peer(unknown_id) ? "yes" : "no") << "\n\n";

    // ==========================================================================
    // Clear session and remove peer
    // ==========================================================================
    std::cout << "9. Clearing session and removing peer...\n";

    table.clear_session(peer1.id);
    peer = table.get_peer(peer1.id);
    if (peer.has_value()) {
        std::cout << "   Peer 1 has session after clear: " << (peer.value()->has_session() ? "yes" : "no") << "\n";
        std::cout << "   Peer 1 status after clear: "
                  << (peer.value()->status == PeerStatus::Unknown ? "Unknown" : "Connected") << "\n";
    }

    boolean removed = table.remove_peer(peer3.id);
    std::cout << "\n   Removed peer 3: " << (removed ? "yes" : "no") << "\n";
    std::cout << "   Peer count after removal: " << table.peer_count() << "\n\n";

    // ==========================================================================
    // Session timing
    // ==========================================================================
    std::cout << "10. Session timing info...\n";

    // Create a new session for timing demo
    table.create_session(peer2.id, send_key, recv_key);
    peer = table.get_peer(peer2.id);

    if (peer.has_value() && peer.value()->has_session()) {
        auto& session = peer.value()->session.value();
        std::cout << "   Session age: " << session.age_ms() << " ms\n";
        std::cout << "   Idle send: " << session.idle_send_ms() << " ms\n";
        std::cout << "   Idle recv: " << session.idle_recv_ms() << " ms\n";

        // Get next nonce
        u64 nonce1 = session.next_send_nonce();
        u64 nonce2 = session.next_send_nonce();
        std::cout << "   Nonce sequence: " << nonce1 << ", " << nonce2 << ", ...\n";
    }
    std::cout << "\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
