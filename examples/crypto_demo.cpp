/* SPDX-License-Identifier: MIT */
/*
 * Botlink Crypto Demo
 * Demonstrates cryptographic operations: key generation, signing, encryption
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>

using namespace botlink;
using namespace dp;

// Helper to print bytes as hex
void print_hex(const char *label, const u8 *data, usize len, usize max_bytes = 16) {
    std::cout << label << ": ";
    for (usize i = 0; i < std::min(len, max_bytes); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    if (len > max_bytes) {
        std::cout << "...";
    }
    std::cout << std::dec << " (" << len << " bytes)\n";
}

void demo_key_generation() {
    std::cout << "\n=== Key Generation Demo ===\n\n";

    // Generate Ed25519 keypair (for signing)
    std::cout << "Generating Ed25519 keypair (signing key)...\n";
    auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
    print_hex("  Private key", ed_priv.data.data(), ed_priv.data.size());
    print_hex("  Public key ", ed_pub.data.data(), ed_pub.data.size());

    // Generate X25519 keypair (for key exchange)
    std::cout << "\nGenerating X25519 keypair (key exchange)...\n";
    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
    print_hex("  Private key", x_priv.data.data(), x_priv.data.size());
    print_hex("  Public key ", x_pub.data.data(), x_pub.data.size());

    // Derive NodeId from Ed25519 public key
    NodeId node_id = crypto::node_id_from_pubkey(ed_pub);
    std::cout << "\nDerived Node ID: " << crypto::node_id_to_hex(node_id).c_str() << "\n";

    // Base64 encoding
    KeyB64 b64 = crypto::key_to_base64(ed_pub);
    std::cout << "Public key (base64): " << b64.c_str() << "\n";
}

void demo_signing() {
    std::cout << "\n=== Digital Signature Demo ===\n\n";

    // Generate keypair
    auto [priv, pub] = crypto::generate_ed25519_keypair();
    NodeId signer_id = crypto::node_id_from_pubkey(pub);
    std::cout << "Signer ID: " << crypto::node_id_to_hex(signer_id).substr(0, 16).c_str() << "...\n\n";

    // Create a message
    Vector<u8> message;
    const char *msg = "This is a secure message from Robot A to Robot B";
    for (const char *p = msg; *p; ++p) {
        message.push_back(static_cast<u8>(*p));
    }
    std::cout << "Message: \"" << msg << "\"\n";
    std::cout << "Message length: " << message.size() << " bytes\n\n";

    // Sign the message
    Signature sig = crypto::ed25519_sign(priv, message);
    print_hex("Signature", sig.data.data(), sig.data.size(), 32);

    // Verify the signature
    bool valid = crypto::ed25519_verify(pub, message, sig);
    std::cout << "\nSignature verification: " << (valid ? "VALID" : "INVALID") << "\n";

    // Tamper with the message
    std::cout << "\n--- Tampering with message ---\n";
    message[10] = 'X';
    valid = crypto::ed25519_verify(pub, message, sig);
    std::cout << "Verification after tampering: " << (valid ? "VALID" : "INVALID") << "\n";
}

void demo_key_exchange() {
    std::cout << "\n=== Key Exchange Demo (X25519 DH) ===\n\n";

    // Alice generates her keypair
    std::cout << "Alice generates keypair...\n";
    auto [alice_priv, alice_pub] = crypto::generate_x25519_keypair();

    // Bob generates his keypair
    std::cout << "Bob generates keypair...\n";
    auto [bob_priv, bob_pub] = crypto::generate_x25519_keypair();

    // Alice computes shared secret using Bob's public key
    std::cout << "\nAlice computes shared secret...\n";
    auto alice_secret = crypto::x25519_shared_secret(alice_priv, bob_pub);

    // Bob computes shared secret using Alice's public key
    std::cout << "Bob computes shared secret...\n";
    auto bob_secret = crypto::x25519_shared_secret(bob_priv, alice_pub);

    if (alice_secret.is_ok() && bob_secret.is_ok()) {
        print_hex("Alice's shared secret", alice_secret.value().data(), 32);
        print_hex("Bob's shared secret  ", bob_secret.value().data(), 32);

        bool match = (alice_secret.value() == bob_secret.value());
        std::cout << "\nSecrets match: " << (match ? "YES" : "NO") << "\n";

        if (match) {
            std::cout << "Key exchange successful! Both parties have the same secret.\n";
        }
    }
}

void demo_aead_encryption() {
    std::cout << "\n=== AEAD Encryption Demo ===\n\n";

    // Create a session key
    crypto::SessionKey key;
    auto random = keylock::crypto::Common::generate_random_bytes(32);
    for (usize i = 0; i < 32; ++i) {
        key.data[i] = random[i];
    }
    key.key_id = 1;
    print_hex("Session key", key.data.data(), 32);

    // Create plaintext
    Vector<u8> plaintext;
    const char *msg = "Secret robot coordinates: X=42.5, Y=17.3";
    for (const char *p = msg; *p; ++p) {
        plaintext.push_back(static_cast<u8>(*p));
    }
    std::cout << "\nPlaintext: \"" << msg << "\"\n";
    std::cout << "Plaintext size: " << plaintext.size() << " bytes\n";

    // Generate nonce
    auto nonce = crypto::generate_nonce();
    print_hex("Nonce", nonce.data.data(), nonce.data.size());

    // Encrypt
    auto ct_result = crypto::aead_encrypt(key, nonce, plaintext);
    if (ct_result.is_err()) {
        std::cerr << "Encryption failed!\n";
        return;
    }
    print_hex("\nCiphertext", ct_result.value().data(), ct_result.value().size(), 32);
    std::cout << "Ciphertext size: " << ct_result.value().size() << " bytes (includes "
              << crypto::TAG_SIZE << "-byte auth tag)\n";

    // Decrypt
    auto pt_result = crypto::aead_decrypt(key, nonce, ct_result.value());
    if (pt_result.is_err()) {
        std::cerr << "Decryption failed!\n";
        return;
    }

    std::string decrypted(pt_result.value().begin(), pt_result.value().end());
    std::cout << "\nDecrypted: \"" << decrypted << "\"\n";
    std::cout << "Decryption successful: " << (pt_result.value() == plaintext ? "YES" : "NO") << "\n";

    // Try decryption with wrong key
    std::cout << "\n--- Trying with wrong key ---\n";
    crypto::SessionKey wrong_key;
    auto wrong_random = keylock::crypto::Common::generate_random_bytes(32);
    for (usize i = 0; i < 32; ++i) {
        wrong_key.data[i] = wrong_random[i];
    }
    auto wrong_result = crypto::aead_decrypt(wrong_key, nonce, ct_result.value());
    std::cout << "Decryption with wrong key: " << (wrong_result.is_err() ? "FAILED (expected)" : "SUCCEEDED") << "\n";
}

void demo_packet_encryption() {
    std::cout << "\n=== Packet Encryption Demo ===\n\n";

    // Simulate two peers establishing session keys
    std::cout << "Simulating key exchange between Peer A and Peer B...\n\n";

    auto [a_x_priv, a_x_pub] = crypto::generate_x25519_keypair();
    auto [b_x_priv, b_x_pub] = crypto::generate_x25519_keypair();
    auto [a_ed_priv, a_ed_pub] = crypto::generate_ed25519_keypair();
    auto [b_ed_priv, b_ed_pub] = crypto::generate_ed25519_keypair();

    NodeId peer_a = crypto::node_id_from_pubkey(a_ed_pub);
    NodeId peer_b = crypto::node_id_from_pubkey(b_ed_pub);

    std::cout << "Peer A: " << crypto::node_id_to_hex(peer_a).substr(0, 16).c_str() << "...\n";
    std::cout << "Peer B: " << crypto::node_id_to_hex(peer_b).substr(0, 16).c_str() << "...\n";

    // Compute shared secret
    auto shared = crypto::x25519_shared_secret(a_x_priv, b_x_pub);
    if (shared.is_err()) {
        std::cerr << "Key exchange failed!\n";
        return;
    }

    // Derive session keys
    auto [a_send, a_recv] = crypto::derive_initiator_keys(shared.value(), peer_a, peer_b, 1);
    auto [b_send, b_recv] = crypto::derive_responder_keys(shared.value(), peer_a, peer_b, 1);

    std::cout << "\nSession keys derived.\n";
    std::cout << "Key ID: " << a_send.key_id << "\n";

    // Peer A sends encrypted packet to Peer B
    Vector<u8> data;
    const char *sensor_data = "SENSOR:temp=25.3,humidity=60%";
    for (const char *p = sensor_data; *p; ++p) {
        data.push_back(static_cast<u8>(*p));
    }

    std::cout << "\nPeer A sends: \"" << sensor_data << "\"\n";

    auto pkt_result = crypto::encrypt_packet(a_send, 1, data);
    if (pkt_result.is_err()) {
        std::cerr << "Packet encryption failed!\n";
        return;
    }

    auto &pkt = pkt_result.value();
    std::cout << "Encrypted packet: version=" << static_cast<int>(pkt.version)
              << ", key_id=" << pkt.key_id
              << ", nonce=" << pkt.nonce_counter
              << ", size=" << pkt.ciphertext.size() << "\n";

    // Peer B decrypts
    auto decrypt_result = crypto::decrypt_packet(b_recv, pkt);
    if (decrypt_result.is_err()) {
        std::cerr << "Packet decryption failed!\n";
        return;
    }

    std::string received(decrypt_result.value().begin(), decrypt_result.value().end());
    std::cout << "Peer B received: \"" << received << "\"\n";
}

void demo_envelope() {
    std::cout << "\n=== Signed Envelope Demo ===\n\n";

    // Generate identity
    auto [priv, pub] = crypto::generate_ed25519_keypair();
    NodeId sender = crypto::node_id_from_pubkey(pub);

    std::cout << "Sender: " << crypto::node_id_to_hex(sender).substr(0, 16).c_str() << "...\n";

    // Create payload
    Vector<u8> payload;
    const char *cmd = "MOVE:x=10,y=20,speed=5";
    for (const char *p = cmd; *p; ++p) {
        payload.push_back(static_cast<u8>(*p));
    }

    std::cout << "Payload: \"" << cmd << "\"\n";

    // Create signed envelope
    Envelope env = crypto::create_signed_envelope(MsgType::Data, sender, priv, payload);
    std::cout << "\nEnvelope created:\n";
    std::cout << "  Version: " << static_cast<int>(env.version) << "\n";
    std::cout << "  Type: " << static_cast<int>(env.msg_type) << "\n";
    std::cout << "  Sender: " << crypto::node_id_to_hex(env.sender_id).substr(0, 16).c_str() << "...\n";
    std::cout << "  Payload size: " << env.payload.size() << " bytes\n";

    // Verify signature
    bool valid = crypto::verify_envelope(env, pub);
    std::cout << "\nSignature verification: " << (valid ? "VALID" : "INVALID") << "\n";

    // Serialize and deserialize
    Vector<u8> serialized = crypto::serialize_envelope(env);
    std::cout << "\nSerialized size: " << serialized.size() << " bytes\n";

    auto deserialized = crypto::deserialize_envelope(serialized);
    if (deserialized.is_ok()) {
        std::cout << "Deserialization: SUCCESS\n";
        std::cout << "Payload matches: " << (deserialized.value().payload == payload ? "YES" : "NO") << "\n";
    }
}

auto main() -> int {
    // Initialize botlink
    auto init_result = botlink::init();
    if (init_result.is_err()) {
        std::cerr << "Failed to initialize: " << init_result.error().message.c_str() << "\n";
        return 1;
    }

    std::cout << "╔════════════════════════════════════════════╗\n";
    std::cout << "║       Botlink Cryptography Demo            ║\n";
    std::cout << "╚════════════════════════════════════════════╝\n";

    demo_key_generation();
    demo_signing();
    demo_key_exchange();
    demo_aead_encryption();
    demo_packet_encryption();
    demo_envelope();

    std::cout << "\n=== Demo Complete ===\n";
    return 0;
}
