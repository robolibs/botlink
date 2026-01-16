/* SPDX-License-Identifier: MIT */
/*
 * Handshake Demo
 * Demonstrates the full key exchange handshake between two nodes
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>

using namespace botlink;
using namespace dp;

// Helper to print bytes as hex
void print_hex(const char* label, const u8* data, usize len, usize max_bytes = 16) {
    std::cout << label << ": ";
    for (usize i = 0; i < std::min(len, max_bytes); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    if (len > max_bytes) {
        std::cout << "...";
    }
    std::cout << std::dec << "\n";
}

// Node structure to hold identity and keys
struct Node {
    String name;
    PrivateKey ed_priv;
    PublicKey ed_pub;
    PrivateKey x_priv;
    PublicKey x_pub;
    NodeId id;

    // Session keys (after handshake)
    crypto::SessionKey send_key;
    crypto::SessionKey recv_key;

    static Node create(const char* name) {
        Node n;
        n.name = name;
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        n.ed_priv = ed_priv;
        n.ed_pub = ed_pub;
        n.x_priv = x_priv;
        n.x_pub = x_pub;
        n.id = crypto::node_id_from_pubkey(ed_pub);
        return n;
    }
};

int main() {
    std::cout << "=== Handshake Demo ===\n\n";

    // ==========================================================================
    // Step 1: Create two nodes
    // ==========================================================================
    std::cout << "1. Creating nodes...\n";

    Node alice = Node::create("Alice");
    Node bob = Node::create("Bob");

    std::cout << "   Alice ID: " << crypto::node_id_to_hex(alice.id).substr(0, 16).c_str() << "...\n";
    std::cout << "   Bob ID:   " << crypto::node_id_to_hex(bob.id).substr(0, 16).c_str() << "...\n\n";

    // ==========================================================================
    // Step 2: Alice creates HandshakeInit
    // ==========================================================================
    std::cout << "2. Alice creates HandshakeInit message...\n";

    net::HandshakeInit init_msg;
    init_msg.initiator_id = alice.id;
    init_msg.initiator_x25519 = alice.x_pub;
    init_msg.timestamp_ms = time::now_ms();
    init_msg.nonce = crypto::generate_nonce();

    std::cout << "   Initiator ID: " << crypto::node_id_to_hex(init_msg.initiator_id).substr(0, 16).c_str() << "...\n";
    std::cout << "   Timestamp: " << init_msg.timestamp_ms << " ms\n";
    print_hex("   Ephemeral X25519", init_msg.initiator_x25519.data.data(), 32);

    // Serialize the init message
    auto init_bytes = serial::serialize(init_msg);
    std::cout << "   Serialized size: " << init_bytes.size() << " bytes\n\n";

    // ==========================================================================
    // Step 3: Alice wraps in signed envelope
    // ==========================================================================
    std::cout << "3. Alice signs the message in an envelope...\n";

    Envelope init_env = crypto::create_signed_envelope(MsgType::HandshakeInit, alice.id, alice.ed_priv, init_bytes);

    std::cout << "   Envelope version: " << static_cast<int>(init_env.version) << "\n";
    std::cout << "   Message type: HandshakeInit\n";
    print_hex("   Signature", init_env.signature.data.data(), SIGNATURE_SIZE);

    // Serialize envelope for "transmission"
    auto env_bytes = crypto::serialize_envelope(init_env);
    std::cout << "   Total envelope size: " << env_bytes.size() << " bytes\n\n";

    // ==========================================================================
    // Step 4: Bob receives and verifies envelope
    // ==========================================================================
    std::cout << "4. Bob receives and verifies the envelope...\n";

    auto recv_result = crypto::deserialize_envelope(env_bytes);
    if (recv_result.is_err()) {
        std::cerr << "   Failed to deserialize envelope!\n";
        return 1;
    }

    Envelope& recv_env = recv_result.value();
    std::cout << "   Deserialized envelope successfully\n";
    std::cout << "   Sender ID: " << crypto::node_id_to_hex(recv_env.sender_id).substr(0, 16).c_str() << "...\n";

    // Note: In real implementation, Bob would look up Alice's public key from trust store
    // For demo, we use alice.ed_pub directly
    bool sig_valid = crypto::verify_envelope(recv_env, alice.ed_pub);
    std::cout << "   Signature valid: " << (sig_valid ? "YES" : "NO") << "\n";

    // Deserialize the HandshakeInit
    auto init_result = serial::deserialize<net::HandshakeInit>(recv_env.payload);
    if (init_result.is_err()) {
        std::cerr << "   Failed to deserialize HandshakeInit!\n";
        return 1;
    }

    net::HandshakeInit& recv_init = init_result.value();
    std::cout << "   Parsed HandshakeInit successfully\n\n";

    // ==========================================================================
    // Step 5: Bob computes shared secret
    // ==========================================================================
    std::cout << "5. Bob computes shared secret...\n";

    auto bob_shared = crypto::x25519_shared_secret(bob.x_priv, recv_init.initiator_x25519);
    if (bob_shared.is_err()) {
        std::cerr << "   Failed to compute shared secret!\n";
        return 1;
    }

    print_hex("   Shared secret", bob_shared.value().data(), 32);
    std::cout << "\n";

    // ==========================================================================
    // Step 6: Bob creates HandshakeResp
    // ==========================================================================
    std::cout << "6. Bob creates HandshakeResp message...\n";

    net::HandshakeResp resp_msg;
    resp_msg.responder_id = bob.id;
    resp_msg.responder_x25519 = bob.x_pub;
    resp_msg.timestamp_ms = time::now_ms();
    resp_msg.nonce = crypto::generate_nonce();

    auto resp_bytes = serial::serialize(resp_msg);
    Envelope resp_env = crypto::create_signed_envelope(MsgType::HandshakeResp, bob.id, bob.ed_priv, resp_bytes);

    auto resp_env_bytes = crypto::serialize_envelope(resp_env);
    std::cout << "   Response envelope size: " << resp_env_bytes.size() << " bytes\n\n";

    // ==========================================================================
    // Step 7: Alice receives response and computes shared secret
    // ==========================================================================
    std::cout << "7. Alice receives response and computes shared secret...\n";

    auto alice_recv_result = crypto::deserialize_envelope(resp_env_bytes);
    if (alice_recv_result.is_err()) {
        std::cerr << "   Failed to deserialize response!\n";
        return 1;
    }

    auto resp_result = serial::deserialize<net::HandshakeResp>(alice_recv_result.value().payload);
    if (resp_result.is_err()) {
        std::cerr << "   Failed to deserialize HandshakeResp!\n";
        return 1;
    }

    net::HandshakeResp& recv_resp = resp_result.value();

    auto alice_shared = crypto::x25519_shared_secret(alice.x_priv, recv_resp.responder_x25519);
    if (alice_shared.is_err()) {
        std::cerr << "   Failed to compute shared secret!\n";
        return 1;
    }

    std::cout << "   Shared secrets match: " << (alice_shared.value() == bob_shared.value() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 8: Both derive session keys
    // ==========================================================================
    std::cout << "8. Both nodes derive session keys...\n";

    u32 key_id = 1;
    auto [alice_send, alice_recv] = crypto::derive_initiator_keys(alice_shared.value(), alice.id, bob.id, key_id);
    auto [bob_send, bob_recv] = crypto::derive_responder_keys(bob_shared.value(), alice.id, bob.id, key_id);

    alice.send_key = alice_send;
    alice.recv_key = alice_recv;
    bob.send_key = bob_send;
    bob.recv_key = bob_recv;

    std::cout << "   Key ID: " << key_id << "\n";
    std::cout << "   Keys symmetric: " << ((alice_send.data == bob_recv.data && alice_recv.data == bob_send.data) ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 9: Test encrypted communication
    // ==========================================================================
    std::cout << "9. Testing encrypted communication...\n\n";

    // Alice sends to Bob
    std::cout << "   Alice -> Bob:\n";
    String alice_msg = "Hello Bob! This is Alice.";
    Vector<u8> alice_plaintext;
    for (char c : alice_msg) {
        alice_plaintext.push_back(static_cast<u8>(c));
    }

    auto alice_pkt = crypto::encrypt_packet(alice.send_key, 0, alice_plaintext);
    if (alice_pkt.is_err()) {
        std::cerr << "   Encryption failed!\n";
        return 1;
    }

    std::cout << "   Original: \"" << alice_msg.c_str() << "\"\n";
    std::cout << "   Encrypted packet size: " << alice_pkt.value().ciphertext.size() << " bytes\n";

    // Bob decrypts
    auto bob_decrypted = crypto::decrypt_packet(bob.recv_key, alice_pkt.value());
    if (bob_decrypted.is_err()) {
        std::cerr << "   Decryption failed!\n";
        return 1;
    }

    String bob_received;
    for (u8 b : bob_decrypted.value()) {
        bob_received += static_cast<char>(b);
    }
    std::cout << "   Decrypted: \"" << bob_received.c_str() << "\"\n\n";

    // Bob replies
    std::cout << "   Bob -> Alice:\n";
    String bob_msg = "Hi Alice! Nice to meet you!";
    Vector<u8> bob_plaintext;
    for (char c : bob_msg) {
        bob_plaintext.push_back(static_cast<u8>(c));
    }

    auto bob_pkt = crypto::encrypt_packet(bob.send_key, 0, bob_plaintext);
    if (bob_pkt.is_err()) {
        std::cerr << "   Encryption failed!\n";
        return 1;
    }

    std::cout << "   Original: \"" << bob_msg.c_str() << "\"\n";

    auto alice_decrypted = crypto::decrypt_packet(alice.recv_key, bob_pkt.value());
    if (alice_decrypted.is_err()) {
        std::cerr << "   Decryption failed!\n";
        return 1;
    }

    String alice_received;
    for (u8 b : alice_decrypted.value()) {
        alice_received += static_cast<char>(b);
    }
    std::cout << "   Decrypted: \"" << alice_received.c_str() << "\"\n\n";

    std::cout << "=== Handshake Complete ===\n";

    return 0;
}
