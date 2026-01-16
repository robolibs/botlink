/* SPDX-License-Identifier: MIT */
/*
 * AEAD Encryption Demo
 * Demonstrates symmetric encryption/decryption using XChaCha20-Poly1305
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>

using namespace botlink;
using namespace dp;

int main() {
    std::cout << "=== AEAD Encryption Demo ===\n\n";

    // ==========================================================================
    // Generate a session key
    // ==========================================================================
    std::cout << "1. Generating session key...\n";

    crypto::SessionKey key;
    auto random_bytes = keylock::utils::Common::generate_random_bytes(crypto::SESSION_KEY_SIZE);
    for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
        key.data[i] = random_bytes[i];
    }
    key.key_id = 1;

    std::cout << "   Key ID: " << key.key_id << "\n";
    std::cout << "   Key size: " << crypto::SESSION_KEY_SIZE << " bytes\n\n";

    // ==========================================================================
    // Encrypt a message
    // ==========================================================================
    std::cout << "2. Encrypting a message...\n";

    String message = "Hello, secure world! This is a secret message.";
    Vector<u8> plaintext;
    for (char c : message) {
        plaintext.push_back(static_cast<u8>(c));
    }

    std::cout << "   Original message: \"" << message.c_str() << "\"\n";
    std::cout << "   Plaintext size: " << plaintext.size() << " bytes\n";

    auto nonce = crypto::generate_nonce();
    auto ct_result = crypto::aead_encrypt(key, nonce, plaintext);

    if (ct_result.is_err()) {
        std::cerr << "   Encryption failed!\n";
        return 1;
    }

    auto& ciphertext = ct_result.value();
    std::cout << "   Ciphertext size: " << ciphertext.size() << " bytes\n";
    std::cout << "   Overhead: " << (ciphertext.size() - plaintext.size()) << " bytes (auth tag)\n\n";

    // ==========================================================================
    // Decrypt the message
    // ==========================================================================
    std::cout << "3. Decrypting the message...\n";

    auto pt_result = crypto::aead_decrypt(key, nonce, ciphertext);

    if (pt_result.is_err()) {
        std::cerr << "   Decryption failed!\n";
        return 1;
    }

    auto& decrypted = pt_result.value();
    String decrypted_msg;
    for (u8 b : decrypted) {
        decrypted_msg += static_cast<char>(b);
    }

    std::cout << "   Decrypted message: \"" << decrypted_msg.c_str() << "\"\n";
    std::cout << "   Match: " << (decrypted == plaintext ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Demonstrate wrong key failure
    // ==========================================================================
    std::cout << "4. Demonstrating authentication failure with wrong key...\n";

    crypto::SessionKey wrong_key;
    auto wrong_random = keylock::utils::Common::generate_random_bytes(crypto::SESSION_KEY_SIZE);
    for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
        wrong_key.data[i] = wrong_random[i];
    }

    auto wrong_result = crypto::aead_decrypt(wrong_key, nonce, ciphertext);

    if (wrong_result.is_err()) {
        std::cout << "   Decryption with wrong key failed (expected!)\n\n";
    } else {
        std::cerr << "   UNEXPECTED: Decryption succeeded with wrong key!\n\n";
    }

    // ==========================================================================
    // Data packet encryption (with headers)
    // ==========================================================================
    std::cout << "5. Using data packet encryption...\n";

    u64 nonce_counter = 42;
    auto pkt_result = crypto::encrypt_packet(key, nonce_counter, plaintext);

    if (pkt_result.is_err()) {
        std::cerr << "   Packet encryption failed!\n";
        return 1;
    }

    auto& packet = pkt_result.value();
    std::cout << "   Packet version: " << static_cast<int>(packet.version) << "\n";
    std::cout << "   Packet type: " << static_cast<int>(packet.packet_type) << "\n";
    std::cout << "   Key ID: " << packet.key_id << "\n";
    std::cout << "   Nonce counter: " << packet.nonce_counter << "\n";
    std::cout << "   Ciphertext size: " << packet.ciphertext.size() << " bytes\n";

    // Serialize and deserialize
    auto serialized = crypto::serialize_data_packet(packet);
    std::cout << "   Serialized packet size: " << serialized.size() << " bytes\n";

    auto deser_result = crypto::deserialize_data_packet(serialized);
    if (deser_result.is_ok()) {
        auto& deser_pkt = deser_result.value();
        auto decrypt_result = crypto::decrypt_packet(key, deser_pkt);
        if (decrypt_result.is_ok()) {
            std::cout << "   Packet decryption: SUCCESS\n";
        }
    }
    std::cout << "\n";

    // ==========================================================================
    // Replay window demonstration
    // ==========================================================================
    std::cout << "6. Demonstrating replay protection...\n";

    crypto::ReplayWindow window;

    std::cout << "   Accepting nonce 1: " << (window.check_and_update(1) ? "YES" : "NO") << "\n";
    std::cout << "   Accepting nonce 2: " << (window.check_and_update(2) ? "YES" : "NO") << "\n";
    std::cout << "   Accepting nonce 1 again: " << (window.check_and_update(1) ? "YES (replay!)" : "NO (blocked)") << "\n";
    std::cout << "   Accepting nonce 5 (skip): " << (window.check_and_update(5) ? "YES" : "NO") << "\n";
    std::cout << "   Accepting nonce 3 (old but unseen): " << (window.check_and_update(3) ? "YES" : "NO") << "\n";
    std::cout << "   Accepting nonce 3 again: " << (window.check_and_update(3) ? "YES (replay!)" : "NO (blocked)") << "\n\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
