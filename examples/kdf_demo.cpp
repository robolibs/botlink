/* SPDX-License-Identifier: MIT */
/*
 * Key Derivation Demo
 * Demonstrates HKDF and session key derivation functions
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
    std::cout << std::dec << " (" << len << " bytes)\n";
}

int main() {
    std::cout << "=== Key Derivation Demo ===\n\n";

    // ==========================================================================
    // Generate identities for Alice and Bob
    // ==========================================================================
    std::cout << "1. Generating identities for Alice and Bob...\n";

    auto [alice_ed_priv, alice_ed_pub] = crypto::generate_ed25519_keypair();
    auto [alice_x_priv, alice_x_pub] = crypto::generate_x25519_keypair();
    NodeId alice_id = crypto::node_id_from_pubkey(alice_ed_pub);

    auto [bob_ed_priv, bob_ed_pub] = crypto::generate_ed25519_keypair();
    auto [bob_x_priv, bob_x_pub] = crypto::generate_x25519_keypair();
    NodeId bob_id = crypto::node_id_from_pubkey(bob_ed_pub);

    std::cout << "   Alice ID: " << crypto::node_id_to_hex(alice_id).substr(0, 16).c_str() << "...\n";
    std::cout << "   Bob ID:   " << crypto::node_id_to_hex(bob_id).substr(0, 16).c_str() << "...\n\n";

    // ==========================================================================
    // X25519 Key Exchange
    // ==========================================================================
    std::cout << "2. Performing X25519 key exchange...\n";

    auto alice_shared = crypto::x25519_shared_secret(alice_x_priv, bob_x_pub);
    auto bob_shared = crypto::x25519_shared_secret(bob_x_priv, alice_x_pub);

    if (alice_shared.is_err() || bob_shared.is_err()) {
        std::cerr << "   Key exchange failed!\n";
        return 1;
    }

    std::cout << "   Alice computed shared secret\n";
    std::cout << "   Bob computed shared secret\n";
    std::cout << "   Secrets match: " << (alice_shared.value() == bob_shared.value() ? "YES" : "NO") << "\n";
    print_hex("   Shared secret", alice_shared.value().data(), 32);
    std::cout << "\n";

    // ==========================================================================
    // Derive session keys
    // ==========================================================================
    std::cout << "3. Deriving session keys...\n";

    u32 key_id = 1;
    auto [alice_send, alice_recv] = crypto::derive_initiator_keys(alice_shared.value(), alice_id, bob_id, key_id);
    auto [bob_send, bob_recv] = crypto::derive_responder_keys(bob_shared.value(), alice_id, bob_id, key_id);

    std::cout << "   Alice (initiator) keys:\n";
    print_hex("     Send key", alice_send.raw(), crypto::SESSION_KEY_SIZE);
    print_hex("     Recv key", alice_recv.raw(), crypto::SESSION_KEY_SIZE);

    std::cout << "   Bob (responder) keys:\n";
    print_hex("     Send key", bob_send.raw(), crypto::SESSION_KEY_SIZE);
    print_hex("     Recv key", bob_recv.raw(), crypto::SESSION_KEY_SIZE);

    std::cout << "   Key symmetry check:\n";
    std::cout << "     Alice send == Bob recv: " << (alice_send.data == bob_recv.data ? "YES" : "NO") << "\n";
    std::cout << "     Alice recv == Bob send: " << (alice_recv.data == bob_send.data ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Test encryption with derived keys
    // ==========================================================================
    std::cout << "4. Testing encryption with derived keys...\n";

    Vector<u8> message;
    const char* msg = "Secret message from Alice to Bob";
    for (const char* p = msg; *p; ++p) {
        message.push_back(static_cast<u8>(*p));
    }

    // Alice encrypts with her send key
    auto nonce = crypto::nonce_from_counter(0);
    auto ciphertext = crypto::aead_encrypt(alice_send, nonce, message);

    if (ciphertext.is_err()) {
        std::cerr << "   Encryption failed!\n";
        return 1;
    }

    std::cout << "   Original: \"" << msg << "\"\n";
    std::cout << "   Encrypted size: " << ciphertext.value().size() << " bytes\n";

    // Bob decrypts with his recv key (should be same as Alice's send key)
    auto plaintext = crypto::aead_decrypt(bob_recv, nonce, ciphertext.value());

    if (plaintext.is_err()) {
        std::cerr << "   Decryption failed!\n";
        return 1;
    }

    String decrypted;
    for (u8 b : plaintext.value()) {
        decrypted += static_cast<char>(b);
    }
    std::cout << "   Decrypted: \"" << decrypted.c_str() << "\"\n\n";

    // ==========================================================================
    // Session key rekeying
    // ==========================================================================
    std::cout << "5. Demonstrating key rekeying...\n";

    std::cout << "   Original key ID: " << alice_send.key_id << "\n";
    print_hex("   Original key", alice_send.raw(), crypto::SESSION_KEY_SIZE);

    crypto::SessionKey rekeyed = crypto::rekey(alice_send);
    std::cout << "   After rekey:\n";
    std::cout << "   New key ID: " << rekeyed.key_id << "\n";
    print_hex("   Rekeyed key", rekeyed.raw(), crypto::SESSION_KEY_SIZE);

    // Rekey again
    crypto::SessionKey rekeyed2 = crypto::rekey(rekeyed);
    std::cout << "   After second rekey:\n";
    std::cout << "   Key ID: " << rekeyed2.key_id << "\n";
    print_hex("   Rekeyed key", rekeyed2.raw(), crypto::SESSION_KEY_SIZE);
    std::cout << "\n";

    // ==========================================================================
    // Nonce derivation
    // ==========================================================================
    std::cout << "6. Nonce derivation from counters...\n";

    for (u64 counter = 0; counter < 5; ++counter) {
        auto n = crypto::nonce_from_counter(counter);
        std::cout << "   Counter " << counter << ": ";
        for (usize i = 0; i < 8; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(n.data[i]);
        }
        std::cout << "...\n" << std::dec;
    }
    std::cout << "\n";

    // ==========================================================================
    // Random nonce generation
    // ==========================================================================
    std::cout << "7. Random nonce generation...\n";

    for (int i = 0; i < 3; ++i) {
        auto n = crypto::generate_nonce();
        std::cout << "   Nonce " << (i + 1) << ": ";
        for (usize j = 0; j < 12; ++j) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(n.data[j]);
        }
        std::cout << "...\n" << std::dec;
    }
    std::cout << "\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
