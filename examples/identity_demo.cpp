/* SPDX-License-Identifier: MIT */
/*
 * Identity Demo
 * Demonstrates key generation, encoding, and identity operations
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>

using namespace botlink;
using namespace dp;

int main() {
    std::cout << "=== Identity Demo ===\n\n";

    // ==========================================================================
    // Step 1: Generate Ed25519 keypair (for signing)
    // ==========================================================================
    std::cout << "1. Generating Ed25519 keypair for signing...\n";

    auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();

    std::cout << "   Private key (first 8 bytes): ";
    for (int i = 0; i < 8; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ed_priv.data[i]);
    }
    std::cout << "...\n" << std::dec;

    std::cout << "   Public key (first 8 bytes):  ";
    for (int i = 0; i < 8; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ed_pub.data[i]);
    }
    std::cout << "...\n\n" << std::dec;

    // ==========================================================================
    // Step 2: Generate X25519 keypair (for key exchange)
    // ==========================================================================
    std::cout << "2. Generating X25519 keypair for key exchange...\n";

    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

    std::cout << "   Private key (first 8 bytes): ";
    for (int i = 0; i < 8; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(x_priv.data[i]);
    }
    std::cout << "...\n" << std::dec;

    std::cout << "   Public key (first 8 bytes):  ";
    for (int i = 0; i < 8; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(x_pub.data[i]);
    }
    std::cout << "...\n\n" << std::dec;

    // ==========================================================================
    // Step 3: Derive NodeId from public key
    // ==========================================================================
    std::cout << "3. Deriving NodeId from Ed25519 public key...\n";

    NodeId node_id = crypto::node_id_from_pubkey(ed_pub);
    String node_id_hex = crypto::node_id_to_hex(node_id);

    std::cout << "   NodeId (hex): " << node_id_hex.substr(0, 32).c_str() << "...\n";
    std::cout << "   NodeId is zero: " << (node_id.is_zero() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 4: Base64 encoding/decoding
    // ==========================================================================
    std::cout << "4. Base64 encoding and decoding...\n";

    KeyB64 pub_b64 = crypto::key_to_base64(ed_pub);
    std::cout << "   Public key (Base64): " << pub_b64.c_str() << "\n";

    auto decoded_pub = crypto::public_key_from_base64(pub_b64);
    if (decoded_pub.is_ok()) {
        std::cout << "   Decoded matches original: " << (decoded_pub.value() == ed_pub ? "YES" : "NO") << "\n";
    }

    KeyB64 priv_b64 = crypto::key_to_base64(ed_priv);
    std::cout << "   Private key (Base64): " << priv_b64.c_str() << "\n\n";

    // ==========================================================================
    // Step 5: Hex encoding/decoding
    // ==========================================================================
    std::cout << "5. Hex encoding and decoding...\n";

    String pub_hex = crypto::to_hex(ed_pub.raw(), KEY_SIZE);
    std::cout << "   Public key (hex): " << pub_hex.substr(0, 32).c_str() << "...\n";

    auto decoded_from_hex = crypto::public_key_from_hex(pub_hex);
    if (decoded_from_hex.is_ok()) {
        std::cout << "   Decoded matches original: " << (decoded_from_hex.value() == ed_pub ? "YES" : "NO") << "\n\n";
    }

    // ==========================================================================
    // Step 6: Derive public key from private
    // ==========================================================================
    std::cout << "6. Deriving public key from private key...\n";

    PublicKey derived_ed_pub = crypto::ed25519_public_from_private(ed_priv);
    std::cout << "   Ed25519 derived matches: " << (derived_ed_pub == ed_pub ? "YES" : "NO") << "\n";

    PublicKey derived_x_pub = crypto::x25519_public_from_private(x_priv);
    std::cout << "   X25519 derived matches: " << (derived_x_pub == x_pub ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 7: Key to Vector conversion
    // ==========================================================================
    std::cout << "7. Converting keys to/from Vector...\n";

    Vector<u8> pub_vec = crypto::to_vector(ed_pub);
    std::cout << "   Vector size: " << pub_vec.size() << " bytes\n";

    auto from_vec = crypto::public_key_from_vector(pub_vec);
    if (from_vec.is_ok()) {
        std::cout << "   Roundtrip successful: " << (from_vec.value() == ed_pub ? "YES" : "NO") << "\n\n";
    }

    // ==========================================================================
    // Step 8: Ed25519 signing and verification
    // ==========================================================================
    std::cout << "8. Signing and verifying a message...\n";

    Vector<u8> message;
    const char* msg = "Hello, Botlink!";
    for (const char* p = msg; *p; ++p) {
        message.push_back(static_cast<u8>(*p));
    }

    Signature sig = crypto::ed25519_sign(ed_priv, message);
    std::cout << "   Message: \"" << msg << "\"\n";
    std::cout << "   Signature (first 16 bytes): ";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(sig.data[i]);
    }
    std::cout << "...\n" << std::dec;

    bool valid = crypto::ed25519_verify(ed_pub, message, sig);
    std::cout << "   Signature valid: " << (valid ? "YES" : "NO") << "\n";

    // Try with wrong key
    auto [other_priv, other_pub] = crypto::generate_ed25519_keypair();
    bool invalid = crypto::ed25519_verify(other_pub, message, sig);
    std::cout << "   Signature valid with wrong key: " << (invalid ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 9: X25519 key exchange
    // ==========================================================================
    std::cout << "9. X25519 key exchange (Diffie-Hellman)...\n";

    // Alice and Bob each have X25519 keypairs
    auto [alice_priv, alice_pub] = crypto::generate_x25519_keypair();
    auto [bob_priv, bob_pub] = crypto::generate_x25519_keypair();

    // Each computes shared secret using their private key and other's public key
    auto alice_shared = crypto::x25519_shared_secret(alice_priv, bob_pub);
    auto bob_shared = crypto::x25519_shared_secret(bob_priv, alice_pub);

    if (alice_shared.is_ok() && bob_shared.is_ok()) {
        std::cout << "   Alice's shared secret (first 8 bytes): ";
        for (int i = 0; i < 8; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(alice_shared.value()[i]);
        }
        std::cout << "...\n" << std::dec;

        std::cout << "   Bob's shared secret (first 8 bytes):   ";
        for (int i = 0; i < 8; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bob_shared.value()[i]);
        }
        std::cout << "...\n" << std::dec;

        std::cout << "   Shared secrets match: " << (alice_shared.value() == bob_shared.value() ? "YES" : "NO") << "\n\n";
    }

    // ==========================================================================
    // Step 10: Clear sensitive data
    // ==========================================================================
    std::cout << "10. Clearing sensitive data...\n";

    std::cout << "   Private key before clear is zero: " << (ed_priv.is_zero() ? "YES" : "NO") << "\n";
    ed_priv.clear();
    std::cout << "   Private key after clear is zero: " << (ed_priv.is_zero() ? "YES" : "NO") << "\n\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
