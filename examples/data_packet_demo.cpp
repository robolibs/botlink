/* SPDX-License-Identifier: MIT */
/*
 * Data Packet Demo
 * Demonstrates AEAD encryption/decryption and packet serialization
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>

using namespace botlink;
using namespace dp;

int main() {
    std::cout << "=== Data Packet Demo ===\n\n";

    std::cout << "This demo shows XChaCha20-Poly1305 AEAD encryption and\n";
    std::cout << "the DataPacket structure for secure network communication.\n\n";

    // ==========================================================================
    // Step 1: Create a session key
    // ==========================================================================
    std::cout << "1. Creating session key...\n";

    crypto::SessionKey key;
    auto random = keylock::crypto::Common::generate_random_bytes(32);
    for (usize i = 0; i < 32; ++i) {
        key.data[i] = random[i];
    }
    key.key_id = 1;

    std::cout << "   Key ID: " << key.key_id << "\n";
    std::cout << "   Key (first 8 bytes): ";
    for (int i = 0; i < 8; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key.data[i]);
    }
    std::cout << "...\n\n" << std::dec;

    // ==========================================================================
    // Step 2: Encrypt a simple message
    // ==========================================================================
    std::cout << "2. Encrypting a simple message...\n";

    const char* message = "Hello, secure world!";
    Vector<u8> plaintext;
    for (const char* p = message; *p; ++p) {
        plaintext.push_back(static_cast<u8>(*p));
    }

    std::cout << "   Plaintext: \"" << message << "\"\n";
    std::cout << "   Plaintext size: " << plaintext.size() << " bytes\n";

    auto pkt_result = crypto::encrypt_packet(key, 1, plaintext);
    if (pkt_result.is_ok()) {
        auto& pkt = pkt_result.value();
        std::cout << "   Encrypted packet created:\n";
        std::cout << "     Version: " << static_cast<int>(pkt.version) << "\n";
        std::cout << "     Packet type: " << static_cast<int>(pkt.packet_type) << " (DATA)\n";
        std::cout << "     Key ID: " << pkt.key_id << "\n";
        std::cout << "     Nonce counter: " << pkt.nonce_counter << "\n";
        std::cout << "     Ciphertext size: " << pkt.ciphertext.size() << " bytes (plaintext + 16 byte tag)\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 3: Decrypt the message
    // ==========================================================================
    std::cout << "3. Decrypting the message...\n";

    if (pkt_result.is_ok()) {
        auto decrypted = crypto::decrypt_packet(key, pkt_result.value());
        if (decrypted.is_ok()) {
            std::cout << "   Decrypted: \"";
            for (const auto& byte : decrypted.value()) {
                std::cout << static_cast<char>(byte);
            }
            std::cout << "\"\n";
            std::cout << "   Match: " << (decrypted.value() == plaintext ? "YES" : "NO") << "\n";
        }
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 4: Different packet types
    // ==========================================================================
    std::cout << "4. Different packet types...\n";

    Vector<u8> empty_payload;
    empty_payload.push_back(0x00);

    auto keepalive = crypto::encrypt_packet(key, 2, empty_payload, crypto::PACKET_TYPE_KEEPALIVE);
    if (keepalive.is_ok()) {
        std::cout << "   KEEPALIVE packet (type " << static_cast<int>(keepalive.value().packet_type) << ")\n";
    }

    auto rekey = crypto::encrypt_packet(key, 3, empty_payload, crypto::PACKET_TYPE_REKEY);
    if (rekey.is_ok()) {
        std::cout << "   REKEY packet (type " << static_cast<int>(rekey.value().packet_type) << ")\n";
    }

    auto data = crypto::encrypt_packet(key, 4, plaintext, crypto::PACKET_TYPE_DATA);
    if (data.is_ok()) {
        std::cout << "   DATA packet (type " << static_cast<int>(data.value().packet_type) << ")\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 5: Packet serialization
    // ==========================================================================
    std::cout << "5. Packet serialization...\n";

    if (pkt_result.is_ok()) {
        Vector<u8> serialized = crypto::serialize_data_packet(pkt_result.value());
        std::cout << "   Serialized packet size: " << serialized.size() << " bytes\n";
        std::cout << "     Header: 18 bytes (version, type, key_id, nonce, length)\n";
        std::cout << "     Ciphertext: " << pkt_result.value().ciphertext.size() << " bytes\n";

        // Deserialize
        auto deserialized = crypto::deserialize_data_packet(serialized);
        if (deserialized.is_ok()) {
            std::cout << "   Deserialized successfully\n";
            std::cout << "   Fields match: ";
            auto& orig = pkt_result.value();
            auto& deser = deserialized.value();
            bool match = (orig.version == deser.version &&
                         orig.packet_type == deser.packet_type &&
                         orig.key_id == deser.key_id &&
                         orig.nonce_counter == deser.nonce_counter &&
                         orig.ciphertext == deser.ciphertext);
            std::cout << (match ? "YES" : "NO") << "\n";
        }
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 6: Low-level AEAD encryption
    // ==========================================================================
    std::cout << "6. Low-level AEAD encryption with associated data...\n";

    crypto::Nonce nonce = crypto::nonce_from_counter(100);
    std::cout << "   Nonce from counter 100 (first 8 bytes): ";
    for (int i = 0; i < 8; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(nonce.data[i]);
    }
    std::cout << "...\n" << std::dec;

    // Associated data (authenticated but not encrypted)
    Vector<u8> associated_data;
    const char* ad_str = "header-info";
    for (const char* p = ad_str; *p; ++p) {
        associated_data.push_back(static_cast<u8>(*p));
    }

    auto aead_result = crypto::aead_encrypt(key, nonce, plaintext, associated_data);
    if (aead_result.is_ok()) {
        std::cout << "   AEAD ciphertext size: " << aead_result.value().size() << " bytes\n";

        // Decrypt with correct AD
        auto decrypted = crypto::aead_decrypt(key, nonce, aead_result.value(), associated_data);
        std::cout << "   Decrypt with correct AD: " << (decrypted.is_ok() ? "SUCCESS" : "FAILED") << "\n";

        // Decrypt with wrong AD
        Vector<u8> wrong_ad;
        wrong_ad.push_back('x');
        auto bad_decrypt = crypto::aead_decrypt(key, nonce, aead_result.value(), wrong_ad);
        std::cout << "   Decrypt with wrong AD: " << (bad_decrypt.is_ok() ? "SUCCESS" : "FAILED (expected)") << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 7: Tampering detection
    // ==========================================================================
    std::cout << "7. Tampering detection...\n";

    if (pkt_result.is_ok()) {
        // Make a copy and tamper with ciphertext
        crypto::DataPacket tampered = pkt_result.value();
        if (!tampered.ciphertext.empty()) {
            tampered.ciphertext[0] ^= 0xFF; // Flip bits
        }

        auto tampered_result = crypto::decrypt_packet(key, tampered);
        std::cout << "   Decrypt tampered packet: " << (tampered_result.is_ok() ? "SUCCESS (BAD!)" : "FAILED (tamper detected)") << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 8: Wrong key detection
    // ==========================================================================
    std::cout << "8. Wrong key detection...\n";

    crypto::SessionKey wrong_key;
    auto wrong_random = keylock::crypto::Common::generate_random_bytes(32);
    for (usize i = 0; i < 32; ++i) {
        wrong_key.data[i] = wrong_random[i];
    }
    wrong_key.key_id = 2; // Different key ID

    if (pkt_result.is_ok()) {
        auto wrong_key_result = crypto::decrypt_packet(wrong_key, pkt_result.value());
        std::cout << "   Decrypt with wrong key ID: " << (wrong_key_result.is_ok() ? "SUCCESS (BAD!)" : "FAILED (key ID mismatch)") << "\n";

        // Same key ID but different key material
        wrong_key.key_id = 1;
        auto wrong_material = crypto::decrypt_packet(wrong_key, pkt_result.value());
        std::cout << "   Decrypt with wrong key material: " << (wrong_material.is_ok() ? "SUCCESS (BAD!)" : "FAILED (authentication failed)") << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 9: Multiple packets with increasing nonces
    // ==========================================================================
    std::cout << "9. Multiple packets with increasing nonces...\n";

    for (u64 counter = 1; counter <= 5; ++counter) {
        Vector<u8> msg;
        char buf[32];
        int len = std::snprintf(buf, sizeof(buf), "Message %lu", static_cast<unsigned long>(counter));
        for (int i = 0; i < len; ++i) {
            msg.push_back(static_cast<u8>(buf[i]));
        }

        auto encrypted = crypto::encrypt_packet(key, counter, msg);
        if (encrypted.is_ok()) {
            auto decrypted = crypto::decrypt_packet(key, encrypted.value());
            if (decrypted.is_ok()) {
                std::cout << "   Packet " << counter << ": \"";
                for (const auto& byte : decrypted.value()) {
                    std::cout << static_cast<char>(byte);
                }
                std::cout << "\"\n";
            }
        }
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 10: Deserialization error handling
    // ==========================================================================
    std::cout << "10. Deserialization error handling...\n";

    // Too small
    Vector<u8> too_small;
    too_small.push_back(0x01);
    auto small_result = crypto::deserialize_data_packet(too_small);
    std::cout << "   Parse too-small packet: " << (small_result.is_ok() ? "SUCCESS" : "FAILED (expected)") << "\n";

    // Wrong version
    Vector<u8> wrong_version;
    for (int i = 0; i < 20; ++i) {
        wrong_version.push_back(0);
    }
    wrong_version[0] = 99; // Invalid version
    auto version_result = crypto::deserialize_data_packet(wrong_version);
    std::cout << "   Parse wrong-version packet: " << (version_result.is_ok() ? "SUCCESS" : "FAILED (expected)") << "\n";

    std::cout << "\n=== Demo Complete ===\n";

    return 0;
}
