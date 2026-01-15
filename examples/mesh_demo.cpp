/* SPDX-License-Identifier: MIT */
/*
 * Botlink Mesh Demo
 *
 * Demonstrates two nodes establishing an encrypted connection:
 * 1. Both nodes generate cryptographic identities
 * 2. They perform a Noise-like handshake
 * 3. They exchange encrypted messages
 *
 * This is a simulation without actual network I/O.
 * For real networking, use BotlinkNode with a UDP socket.
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

// =============================================================================
// Simulated Node
// =============================================================================

struct SimNode {
    String name;
    NodeId id;
    PrivateKey ed25519_priv;
    PublicKey ed25519_pub;
    PrivateKey x25519_priv;
    PublicKey x25519_pub;

    // Ephemeral keys for handshake
    PrivateKey eph_priv;
    PublicKey eph_pub;

    // Session keys after handshake
    crypto::SessionKey send_key;
    crypto::SessionKey recv_key;
    crypto::ReplayWindow replay_window;
    u64 nonce_counter = 0;

    SimNode(const String &node_name) : name(node_name) {
        // Generate long-term identity keys
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

        ed25519_priv = ed_priv;
        ed25519_pub = ed_pub;
        x25519_priv = x_priv;
        x25519_pub = x_pub;
        id = crypto::node_id_from_pubkey(ed_pub);

        echo::info("[", name.c_str(), "] Generated identity: ", crypto::node_id_to_hex(id).substr(0, 16).c_str(), "...");
    }

    // Generate ephemeral keys for handshake
    auto generate_ephemeral() -> void {
        auto [priv, pub] = crypto::generate_x25519_keypair();
        eph_priv = priv;
        eph_pub = pub;
    }

    // Compute shared secret with peer's ephemeral
    auto compute_shared(const PublicKey &peer_eph) -> Array<u8, 32> {
        auto res = crypto::x25519_shared_secret(eph_priv, peer_eph);
        if (res.is_err()) {
            echo::error("[", name.c_str(), "] Failed to compute shared secret");
            return {};
        }
        return res.value();
    }

    // Derive session keys as initiator
    auto derive_initiator_keys(const Array<u8, 32> &shared, const NodeId &peer_id) -> void {
        auto [send, recv] = crypto::derive_initiator_keys(shared, id, peer_id, 1);
        send_key = send;
        recv_key = recv;
    }

    // Derive session keys as responder
    auto derive_responder_keys(const Array<u8, 32> &shared, const NodeId &peer_id) -> void {
        auto [send, recv] = crypto::derive_responder_keys(shared, peer_id, id, 1);
        send_key = send;
        recv_key = recv;
    }

    // Encrypt a message
    auto encrypt(const String &plaintext) -> Vector<u8> {
        Vector<u8> data(plaintext.begin(), plaintext.end());
        auto nonce = crypto::nonce_from_counter(++nonce_counter);
        auto res = crypto::aead_encrypt(send_key, nonce, data);
        if (res.is_err()) {
            echo::error("[", name.c_str(), "] Encryption failed");
            return {};
        }
        // Prepend nonce counter
        Vector<u8> packet;
        for (int i = 0; i < 8; ++i) {
            packet.push_back(static_cast<u8>((nonce_counter >> (i * 8)) & 0xFF));
        }
        for (auto b : res.value()) {
            packet.push_back(b);
        }
        return packet;
    }

    // Decrypt a message
    auto decrypt(const Vector<u8> &packet) -> String {
        if (packet.size() < 8) {
            echo::error("[", name.c_str(), "] Packet too short");
            return "";
        }

        // Extract nonce counter
        u64 counter = 0;
        for (int i = 0; i < 8; ++i) {
            counter |= static_cast<u64>(packet[i]) << (i * 8);
        }

        // Replay check
        if (!replay_window.check_and_update(counter)) {
            echo::warn("[", name.c_str(), "] Replay detected! Packet rejected.");
            metrics::inc_packets_dropped_replay();
            return "";
        }

        // Decrypt
        Vector<u8> ciphertext(packet.begin() + 8, packet.end());
        auto nonce = crypto::nonce_from_counter(counter);
        auto res = crypto::aead_decrypt(recv_key, nonce, ciphertext);
        if (res.is_err()) {
            echo::error("[", name.c_str(), "] Decryption failed");
            return "";
        }

        auto &decrypted = res.value();
        String result;
        result.reserve(decrypted.size());
        for (auto c : decrypted) {
            result.push_back(static_cast<char>(c));
        }
        return result;
    }
};

// =============================================================================
// Main Demo
// =============================================================================

int main() {
    // Initialize libsodium
    if (botlink::init().is_err()) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    echo::info("=== Botlink Mesh Demo ===").cyan();
    echo::info("");

    // Reset metrics
    metrics::global().reset();

    // ==========================================================================
    // Step 1: Create two nodes
    // ==========================================================================
    echo::info("Step 1: Creating nodes...").yellow();

    SimNode alice("Alice");
    SimNode bob("Bob");

    echo::info("");

    // ==========================================================================
    // Step 2: Handshake
    // ==========================================================================
    echo::info("Step 2: Performing handshake...").yellow();

    // Alice initiates: generates ephemeral key
    alice.generate_ephemeral();
    echo::info("[Alice] Generated ephemeral key, sending to Bob...");
    metrics::inc_handshakes_initiated();

    // "Send" Alice's ephemeral to Bob (simulated)
    PublicKey alice_eph_to_bob = alice.eph_pub;

    // Bob receives, generates his ephemeral
    bob.generate_ephemeral();
    echo::info("[Bob] Received Alice's ephemeral, generating response...");

    // Bob computes shared secret and derives keys
    auto bob_shared = bob.compute_shared(alice_eph_to_bob);
    bob.derive_responder_keys(bob_shared, alice.id);

    // "Send" Bob's ephemeral to Alice (simulated)
    PublicKey bob_eph_to_alice = bob.eph_pub;

    // Alice receives Bob's response
    auto alice_shared = alice.compute_shared(bob_eph_to_alice);
    alice.derive_initiator_keys(alice_shared, bob.id);

    metrics::inc_handshakes_completed();
    metrics::inc_sessions_created();
    echo::info("[Both] Handshake complete! Session established.").green();
    echo::info("");

    // Verify keys match
    if (alice.send_key.data == bob.recv_key.data && alice.recv_key.data == bob.send_key.data) {
        echo::info("[Verify] Session keys match correctly!").green();
    } else {
        echo::error("[Verify] Session key mismatch!");
        return 1;
    }
    echo::info("");

    // ==========================================================================
    // Step 3: Exchange encrypted messages
    // ==========================================================================
    echo::info("Step 3: Exchanging encrypted messages...").yellow();

    // Alice sends to Bob
    String msg1 = "Hello Bob! This is Alice.";
    echo::info("[Alice] Sending: \"", msg1.c_str(), "\"");
    auto encrypted1 = alice.encrypt(msg1);
    metrics::inc_packets_sent();
    metrics::add_bytes_sent(encrypted1.size());

    // Bob receives and decrypts
    auto decrypted1 = bob.decrypt(encrypted1);
    metrics::inc_packets_received();
    echo::info("[Bob] Received: \"", decrypted1.c_str(), "\"");

    if (decrypted1 == msg1) {
        echo::info("[Verify] Message 1 decrypted correctly!").green();
    }
    echo::info("");

    // Bob sends to Alice
    String msg2 = "Hi Alice! Nice to meet you.";
    echo::info("[Bob] Sending: \"", msg2.c_str(), "\"");
    auto encrypted2 = bob.encrypt(msg2);
    metrics::inc_packets_sent();
    metrics::add_bytes_sent(encrypted2.size());

    // Alice receives and decrypts
    auto decrypted2 = alice.decrypt(encrypted2);
    metrics::inc_packets_received();
    echo::info("[Alice] Received: \"", decrypted2.c_str(), "\"");

    if (decrypted2 == msg2) {
        echo::info("[Verify] Message 2 decrypted correctly!").green();
    }
    echo::info("");

    // ==========================================================================
    // Step 4: Demonstrate replay protection
    // ==========================================================================
    echo::info("Step 4: Testing replay protection...").yellow();

    // Try to replay the first message
    echo::info("[Attacker] Replaying Alice's first message...");
    auto replay_result = bob.decrypt(encrypted1);

    if (replay_result.empty()) {
        echo::info("[Bob] Replay attack blocked!").green();
    } else {
        echo::error("[Bob] Replay attack succeeded (this is bad!)");
    }
    echo::info("");

    // ==========================================================================
    // Step 5: Demonstrate relayed connection fallback
    // ==========================================================================
    echo::info("Step 5: Simulating relayed connection fallback...").yellow();

    // Scenario: Dave can't reach Eve directly (NAT), uses relay
    SimNode dave("Dave");
    SimNode eve("Eve");

    // Simulate relay info
    net::RelayInfo relay_info;
    relay_info.id = "relay-1";
    relay_info.endpoint.family = AddrFamily::IPv4;
    relay_info.endpoint.ipv4.octets = {192, 168, 1, 100};
    relay_info.endpoint.port = 51821;
    relay_info.is_connected = true;
    relay_info.latency_ms = 50;

    echo::info("[Dave] Cannot reach Eve directly (behind NAT)");
    echo::info("[Dave] Using relay: ", relay_info.id.c_str(), " at ",
               relay_info.endpoint.ipv4.octets[0], ".",
               relay_info.endpoint.ipv4.octets[1], ".",
               relay_info.endpoint.ipv4.octets[2], ".",
               relay_info.endpoint.ipv4.octets[3], ":",
               relay_info.endpoint.port);

    // Dave and Eve do handshake (keys exchanged out-of-band or via relay)
    dave.generate_ephemeral();
    eve.generate_ephemeral();

    auto dave_shared = dave.compute_shared(eve.eph_pub);
    auto eve_shared = eve.compute_shared(dave.eph_pub);

    dave.derive_initiator_keys(dave_shared, eve.id);
    eve.derive_responder_keys(eve_shared, dave.id);

    // Dave creates a relayed message
    String relay_msg = "Hello via relay!";
    auto encrypted_relay = dave.encrypt(relay_msg);

    // Simulate relay forwarding
    net::RelayForwardPacket fwd_pkt;
    fwd_pkt.source_id = dave.id;
    fwd_pkt.target_id = eve.id;
    for (auto b : encrypted_relay) {
        fwd_pkt.payload.push_back(b);
    }
    fwd_pkt.timestamp_ms = time::now_ms();

    echo::info("[Dave] Sending via relay: \"", relay_msg.c_str(), "\"");
    echo::info("[Relay] Forwarding packet from Dave to Eve (", fwd_pkt.payload.size(), " bytes)");

    // Eve receives from relay and decrypts
    Vector<u8> received_payload;
    for (auto b : fwd_pkt.payload) {
        received_payload.push_back(b);
    }
    auto decrypted_relay = eve.decrypt(received_payload);
    echo::info("[Eve] Received via relay: \"", decrypted_relay.c_str(), "\"");

    if (decrypted_relay == relay_msg) {
        echo::info("[Verify] Relayed message decrypted correctly!").green();
    }
    echo::info("");

    // ==========================================================================
    // Step 6: Show metrics
    // ==========================================================================
    echo::info("Step 6: Session metrics...").yellow();

    auto &m = metrics::global();
    echo::info("  Handshakes initiated: ", m.handshakes_initiated.load());
    echo::info("  Handshakes completed: ", m.handshakes_completed.load());
    echo::info("  Sessions created:     ", m.sessions_created.load());
    echo::info("  Packets sent:         ", m.packets_sent.load());
    echo::info("  Packets received:     ", m.packets_received.load());
    echo::info("  Bytes sent:           ", m.bytes_sent.load());
    echo::info("  Replays blocked:      ", m.packets_dropped_replay.load());
    echo::info("");

    echo::info("=== Demo Complete ===").cyan();

    return 0;
}
