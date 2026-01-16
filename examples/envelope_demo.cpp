/* SPDX-License-Identifier: MIT */
/*
 * Envelope Demo
 * Demonstrates message envelope signing, verification, and serialization
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>

using namespace botlink;
using namespace dp;

int main() {
    std::cout << "=== Envelope Demo ===\n\n";

    std::cout << "Envelopes are signed message wrappers used for all control\n";
    std::cout << "plane communication in botlink. They provide authentication\n";
    std::cout << "and integrity protection using Ed25519 signatures.\n\n";

    // ==========================================================================
    // Step 1: Generate sender identity
    // ==========================================================================
    std::cout << "1. Generating sender identity...\n";

    auto [sender_priv, sender_pub] = crypto::generate_ed25519_keypair();
    NodeId sender_id = crypto::node_id_from_pubkey(sender_pub);

    String sender_hex = crypto::node_id_to_hex(sender_id);
    std::cout << "   Sender ID: " << sender_hex.substr(0, 16).c_str() << "...\n\n";

    // ==========================================================================
    // Step 2: Create a simple envelope
    // ==========================================================================
    std::cout << "2. Creating envelope...\n";

    Vector<u8> payload;
    const char* msg = "Hello from botlink!";
    for (const char* p = msg; *p; ++p) {
        payload.push_back(static_cast<u8>(*p));
    }

    Envelope env(MsgType::Data, sender_id, payload);

    std::cout << "   Version: " << static_cast<int>(env.version) << "\n";
    std::cout << "   Message type: " << static_cast<int>(env.msg_type) << " (Data)\n";
    std::cout << "   Flags: " << env.flags << "\n";
    std::cout << "   Timestamp: " << env.timestamp_ms << " ms\n";
    std::cout << "   Payload size: " << env.payload.size() << " bytes\n\n";

    // ==========================================================================
    // Step 3: Sign the envelope
    // ==========================================================================
    std::cout << "3. Signing envelope...\n";

    crypto::sign_envelope(env, sender_priv);

    std::cout << "   Signature (first 16 bytes): ";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(env.signature.data[i]);
    }
    std::cout << "...\n\n" << std::dec;

    // ==========================================================================
    // Step 4: Verify the signature
    // ==========================================================================
    std::cout << "4. Verifying signature...\n";

    bool valid = crypto::verify_envelope(env, sender_pub);
    std::cout << "   Verification with correct key: " << (valid ? "VALID" : "INVALID") << "\n";

    // Try with wrong key
    auto [other_priv, other_pub] = crypto::generate_ed25519_keypair();
    bool invalid = crypto::verify_envelope(env, other_pub);
    std::cout << "   Verification with wrong key: " << (invalid ? "VALID" : "INVALID") << "\n\n";

    // ==========================================================================
    // Step 5: Serialize envelope
    // ==========================================================================
    std::cout << "5. Serializing envelope...\n";

    Vector<u8> serialized = crypto::serialize_envelope(env);
    std::cout << "   Serialized size: " << serialized.size() << " bytes\n";
    std::cout << "   Header overhead: " << (serialized.size() - env.payload.size()) << " bytes\n";
    std::cout << "   (version + type + flags + timestamp + sender_id + signature + length)\n\n";

    // ==========================================================================
    // Step 6: Deserialize envelope
    // ==========================================================================
    std::cout << "6. Deserializing envelope...\n";

    auto deser_result = crypto::deserialize_envelope(serialized);
    if (deser_result.is_ok()) {
        auto& deser = deser_result.value();
        std::cout << "   Deserialization: SUCCESS\n";
        std::cout << "   Version matches: " << (deser.version == env.version ? "YES" : "NO") << "\n";
        std::cout << "   Type matches: " << (deser.msg_type == env.msg_type ? "YES" : "NO") << "\n";
        std::cout << "   Timestamp matches: " << (deser.timestamp_ms == env.timestamp_ms ? "YES" : "NO") << "\n";
        std::cout << "   Sender matches: " << (deser.sender_id == env.sender_id ? "YES" : "NO") << "\n";
        std::cout << "   Payload matches: " << (deser.payload == env.payload ? "YES" : "NO") << "\n";

        // Verify deserialized signature still works
        bool deser_valid = crypto::verify_envelope(deser, sender_pub);
        std::cout << "   Signature still valid: " << (deser_valid ? "YES" : "NO") << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 7: Create signed envelope helper
    // ==========================================================================
    std::cout << "7. Using create_signed_envelope helper...\n";

    Vector<u8> payload2;
    const char* msg2 = "Signed message";
    for (const char* p = msg2; *p; ++p) {
        payload2.push_back(static_cast<u8>(*p));
    }

    Envelope signed_env = crypto::create_signed_envelope(
        MsgType::JoinRequest, sender_id, sender_priv, payload2);

    std::cout << "   Created and signed in one call\n";
    std::cout << "   Message type: " << static_cast<int>(signed_env.msg_type) << " (JoinRequest)\n";

    bool helper_valid = crypto::verify_envelope(signed_env, sender_pub);
    std::cout << "   Signature valid: " << (helper_valid ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 8: Timestamp validation
    // ==========================================================================
    std::cout << "8. Timestamp validation...\n";

    // Current timestamp should be valid
    bool ts_valid = crypto::validate_envelope_timestamp(env);
    std::cout << "   Current envelope timestamp: " << (ts_valid ? "VALID" : "INVALID") << "\n";

    // Create envelope with old timestamp
    Envelope old_env = env;
    old_env.timestamp_ms = time::now_ms() - 120000; // 2 minutes ago
    bool old_valid = crypto::validate_envelope_timestamp(old_env);
    std::cout << "   2-minute old timestamp: " << (old_valid ? "VALID" : "INVALID (too old)") << "\n";

    // Create envelope with future timestamp
    Envelope future_env = env;
    future_env.timestamp_ms = time::now_ms() + 60000; // 1 minute in future
    bool future_valid = crypto::validate_envelope_timestamp(future_env);
    std::cout << "   1-minute future timestamp: " << (future_valid ? "VALID" : "INVALID (too far ahead)") << "\n\n";

    // ==========================================================================
    // Step 9: Full envelope validation
    // ==========================================================================
    std::cout << "9. Full envelope validation...\n";

    auto full_valid = crypto::validate_envelope(env, sender_pub);
    std::cout << "   Full validation (timestamp + signature): "
              << (full_valid.is_ok() ? "PASSED" : "FAILED") << "\n";

    // Tamper with payload
    Envelope tampered = env;
    if (!tampered.payload.empty()) {
        tampered.payload[0] ^= 0xFF;
    }
    auto tamper_valid = crypto::validate_envelope(tampered, sender_pub);
    std::cout << "   Tampered payload validation: "
              << (tamper_valid.is_ok() ? "PASSED (BAD!)" : "FAILED (tamper detected)") << "\n\n";

    // ==========================================================================
    // Step 10: Different message types
    // ==========================================================================
    std::cout << "10. Different message types...\n";

    Vector<u8> empty_payload;
    empty_payload.push_back(0x00);

    Envelope data_env = crypto::create_signed_envelope(
        MsgType::Data, sender_id, sender_priv, empty_payload);
    std::cout << "   Data message type: " << static_cast<int>(data_env.msg_type) << "\n";

    Envelope join_env = crypto::create_signed_envelope(
        MsgType::JoinRequest, sender_id, sender_priv, empty_payload);
    std::cout << "   JoinRequest message type: " << static_cast<int>(join_env.msg_type) << "\n";

    Envelope ka_env = crypto::create_signed_envelope(
        MsgType::Keepalive, sender_id, sender_priv, empty_payload);
    std::cout << "   Keepalive message type: " << static_cast<int>(ka_env.msg_type) << "\n\n";

    // ==========================================================================
    // Step 11: Deserialization error cases
    // ==========================================================================
    std::cout << "11. Deserialization error handling...\n";

    // Too small
    Vector<u8> too_small;
    too_small.push_back(0x01);
    auto small_result = crypto::deserialize_envelope(too_small);
    std::cout << "   Parse too-small data: " << (small_result.is_ok() ? "SUCCESS" : "FAILED (expected)") << "\n";

    // Wrong version
    Vector<u8> wrong_version = serialized;
    wrong_version[0] = 99;
    auto version_result = crypto::deserialize_envelope(wrong_version);
    std::cout << "   Parse wrong version: " << (version_result.is_ok() ? "SUCCESS" : "FAILED (expected)") << "\n";

    std::cout << "\n=== Demo Complete ===\n";

    return 0;
}
