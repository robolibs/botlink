/* SPDX-License-Identifier: MIT */
/*
 * Signing Demo
 * Demonstrates Ed25519 signing and verification operations
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>

namespace bl = botlink;

int main() {
    std::cout << "=== Signing Demo ===\n\n";

    std::cout << "This demo shows Ed25519 digital signature operations\n";
    std::cout << "for authenticating messages in botlink.\n\n";

    // ==========================================================================
    // Step 1: Generate signing keypair
    // ==========================================================================
    std::cout << "1. Generating Ed25519 keypair...\n";

    auto [priv_key, pub_key] = bl::crypto::generate_ed25519_keypair();

    std::cout << "   Private key size: " << sizeof(priv_key.data) << " bytes\n";
    std::cout << "   Public key size: " << sizeof(pub_key.data) << " bytes\n";
    std::cout << "   Keys generated: YES\n\n";

    // ==========================================================================
    // Step 2: Create message and sign
    // ==========================================================================
    std::cout << "2. Signing a message...\n";

    dp::Vector<dp::u8> message;
    const char* msg = "Hello, this is a test message!";
    for (const char* p = msg; *p; ++p) {
        message.push_back(static_cast<dp::u8>(*p));
    }

    std::cout << "   Message: \"" << msg << "\"\n";
    std::cout << "   Message size: " << message.size() << " bytes\n";

    bl::Signature sig = bl::crypto::ed25519_sign(priv_key, message);

    std::cout << "   Signature size: " << bl::SIGNATURE_SIZE << " bytes\n";
    std::cout << "   Signature (first 16 bytes): ";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(sig.data[i]);
    }
    std::cout << "...\n\n" << std::dec;

    // ==========================================================================
    // Step 3: Verify signature
    // ==========================================================================
    std::cout << "3. Verifying signature...\n";

    bool valid = bl::crypto::ed25519_verify(pub_key, message, sig);
    std::cout << "   Verification with correct key: " << (valid ? "VALID" : "INVALID") << "\n";

    // Try with wrong key
    auto [other_priv, other_pub] = bl::crypto::generate_ed25519_keypair();
    bool invalid = bl::crypto::ed25519_verify(other_pub, message, sig);
    std::cout << "   Verification with wrong key: " << (invalid ? "VALID" : "INVALID") << "\n\n";

    // ==========================================================================
    // Step 4: Tamper detection
    // ==========================================================================
    std::cout << "4. Tamper detection...\n";

    // Modify the message
    dp::Vector<dp::u8> tampered_msg = message;
    tampered_msg[0] ^= 0xFF;

    bool tampered_valid = bl::crypto::ed25519_verify(pub_key, tampered_msg, sig);
    std::cout << "   Modified message verification: " << (tampered_valid ? "VALID (BAD!)" : "INVALID (tamper detected)") << "\n";

    // Modify the signature
    bl::Signature tampered_sig = sig;
    tampered_sig.data[0] ^= 0xFF;

    bool sig_tampered = bl::crypto::ed25519_verify(pub_key, message, tampered_sig);
    std::cout << "   Modified signature verification: " << (sig_tampered ? "VALID (BAD!)" : "INVALID (tamper detected)") << "\n\n";

    // ==========================================================================
    // Step 5: Sign different messages
    // ==========================================================================
    std::cout << "5. Different messages produce different signatures...\n";

    dp::Vector<dp::u8> msg1;
    msg1.push_back('A');
    msg1.push_back('B');
    msg1.push_back('C');

    dp::Vector<dp::u8> msg2;
    msg2.push_back('A');
    msg2.push_back('B');
    msg2.push_back('D');

    bl::Signature sig1 = bl::crypto::ed25519_sign(priv_key, msg1);
    bl::Signature sig2 = bl::crypto::ed25519_sign(priv_key, msg2);

    bool same_sig = (sig1.data == sig2.data);
    std::cout << "   Signatures are equal: " << (same_sig ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 6: NodeId from public key
    // ==========================================================================
    std::cout << "6. Deriving NodeId from public key...\n";

    bl::NodeId node_id = bl::crypto::node_id_from_pubkey(pub_key);
    dp::String id_hex = bl::crypto::node_id_to_hex(node_id);

    std::cout << "   NodeId: " << id_hex.substr(0, 16).c_str() << "...\n";
    std::cout << "   NodeId size: " << bl::NODE_ID_SIZE << " bytes\n";

    // Same public key produces same NodeId
    bl::NodeId node_id2 = bl::crypto::node_id_from_pubkey(pub_key);
    std::cout << "   NodeId deterministic: " << (node_id == node_id2 ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 7: Key hex encoding/decoding
    // ==========================================================================
    std::cout << "7. Key hex encoding/decoding...\n";

    dp::String pub_hex = bl::crypto::to_hex(pub_key.data.begin(), bl::KEY_SIZE);
    std::cout << "   Public key hex length: " << pub_hex.size() << " chars\n";
    std::cout << "   Public key hex: " << pub_hex.substr(0, 32).c_str() << "...\n";

    auto decoded_result = bl::crypto::public_key_from_hex(pub_hex);
    if (decoded_result.is_ok()) {
        bool matches = (decoded_result.value() == pub_key);
        std::cout << "   Decoded matches original: " << (matches ? "YES" : "NO") << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 8: Signature struct operations
    // ==========================================================================
    std::cout << "8. Signature struct operations...\n";

    bl::Signature zero_sig;
    std::cout << "   Default signature is zero: " << (zero_sig.is_zero() ? "YES" : "NO") << "\n";
    std::cout << "   Our signature is zero: " << (sig.is_zero() ? "YES" : "NO") << "\n";

    // Copy signature
    bl::Signature sig_copy = sig;
    std::cout << "   Signature copy equals original: " << (sig_copy.data == sig.data ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 9: Empty message signing
    // ==========================================================================
    std::cout << "9. Empty message signing...\n";

    dp::Vector<dp::u8> empty_msg;
    bl::Signature empty_sig = bl::crypto::ed25519_sign(priv_key, empty_msg);

    std::cout << "   Empty message signature generated: YES\n";

    bool empty_valid = bl::crypto::ed25519_verify(pub_key, empty_msg, empty_sig);
    std::cout << "   Empty message signature valid: " << (empty_valid ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 10: Multiple keypairs
    // ==========================================================================
    std::cout << "10. Multiple keypairs...\n";

    auto [alice_priv, alice_pub] = bl::crypto::generate_ed25519_keypair();
    auto [bob_priv, bob_pub] = bl::crypto::generate_ed25519_keypair();

    bl::NodeId alice_id = bl::crypto::node_id_from_pubkey(alice_pub);
    bl::NodeId bob_id = bl::crypto::node_id_from_pubkey(bob_pub);

    std::cout << "   Alice and Bob have different NodeIds: " << (alice_id != bob_id ? "YES" : "NO") << "\n";

    // Alice signs, Bob cannot verify with his key
    bl::Signature alice_sig = bl::crypto::ed25519_sign(alice_priv, message);
    bool bob_verify = bl::crypto::ed25519_verify(bob_pub, message, alice_sig);
    std::cout << "   Bob can verify Alice's signature: " << (bob_verify ? "YES (BAD!)" : "NO (correct)") << "\n";

    // Alice can verify her own signature
    bool alice_verify = bl::crypto::ed25519_verify(alice_pub, message, alice_sig);
    std::cout << "   Alice can verify her signature: " << (alice_verify ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 11: Summary
    // ==========================================================================
    std::cout << "11. Summary...\n";
    std::cout << "   generate_ed25519_keypair() - Generate signing keypair\n";
    std::cout << "   ed25519_sign(priv, msg)    - Sign a message\n";
    std::cout << "   ed25519_verify(pub, msg, sig) - Verify a signature\n";
    std::cout << "   node_id_from_pubkey(pub)   - Derive NodeId from pubkey\n";
    std::cout << "   public_key_to_hex(key)     - Encode key as hex\n";
    std::cout << "   public_key_from_hex(hex)   - Decode key from hex\n\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
