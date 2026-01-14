/* SPDX-License-Identifier: MIT */
/*
 * Botlink Signing
 * Message envelope signing and verification
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/time.hpp>
#include <botlink/core/types.hpp>
#include <botlink/crypto/identity.hpp>
#include <datapod/datapod.hpp>

namespace botlink {

    using namespace dp;

    // =============================================================================
    // Message Envelope - Signed wrapper for all control messages
    // =============================================================================

    struct Envelope {
        u8 version = 1;
        MsgType msg_type = MsgType::Data;
        u32 flags = 0;
        u64 timestamp_ms = 0;
        NodeId sender_id;
        Signature signature;
        Vector<u8> payload;

        Envelope() = default;

        Envelope(MsgType type, NodeId sender, Vector<u8> data)
            : version(1), msg_type(type), flags(0), timestamp_ms(time::now_ms()), sender_id(sender),
              payload(std::move(data)) {}

        auto members() noexcept {
            return std::tie(version, msg_type, flags, timestamp_ms, sender_id, signature, payload);
        }
        auto members() const noexcept {
            return std::tie(version, msg_type, flags, timestamp_ms, sender_id, signature, payload);
        }
    };

    namespace crypto {

        // =============================================================================
        // Envelope Serialization
        // =============================================================================

        // Serialize envelope header (excluding signature) for signing
        inline auto serialize_for_signing(const Envelope &env) -> Vector<u8> {
            Vector<u8> data;
            data.reserve(1 + 1 + 4 + 8 + NODE_ID_SIZE + env.payload.size());

            // Version
            data.push_back(env.version);

            // Message type
            data.push_back(static_cast<u8>(env.msg_type));

            // Flags (little endian)
            data.push_back(static_cast<u8>(env.flags & 0xFF));
            data.push_back(static_cast<u8>((env.flags >> 8) & 0xFF));
            data.push_back(static_cast<u8>((env.flags >> 16) & 0xFF));
            data.push_back(static_cast<u8>((env.flags >> 24) & 0xFF));

            // Timestamp (little endian)
            for (usize i = 0; i < 8; ++i) {
                data.push_back(static_cast<u8>((env.timestamp_ms >> (i * 8)) & 0xFF));
            }

            // Sender ID
            for (usize i = 0; i < NODE_ID_SIZE; ++i) {
                data.push_back(env.sender_id.data[i]);
            }

            // Payload
            for (const auto &byte : env.payload) {
                data.push_back(byte);
            }

            return data;
        }

        // Serialize complete envelope (including signature)
        inline auto serialize_envelope(const Envelope &env) -> Vector<u8> {
            Vector<u8> data;
            data.reserve(1 + 1 + 4 + 8 + NODE_ID_SIZE + SIGNATURE_SIZE + 4 + env.payload.size());

            // Version
            data.push_back(env.version);

            // Message type
            data.push_back(static_cast<u8>(env.msg_type));

            // Flags (little endian)
            data.push_back(static_cast<u8>(env.flags & 0xFF));
            data.push_back(static_cast<u8>((env.flags >> 8) & 0xFF));
            data.push_back(static_cast<u8>((env.flags >> 16) & 0xFF));
            data.push_back(static_cast<u8>((env.flags >> 24) & 0xFF));

            // Timestamp (little endian)
            for (usize i = 0; i < 8; ++i) {
                data.push_back(static_cast<u8>((env.timestamp_ms >> (i * 8)) & 0xFF));
            }

            // Sender ID
            for (usize i = 0; i < NODE_ID_SIZE; ++i) {
                data.push_back(env.sender_id.data[i]);
            }

            // Signature
            for (usize i = 0; i < SIGNATURE_SIZE; ++i) {
                data.push_back(env.signature.data[i]);
            }

            // Payload length (little endian u32)
            u32 payload_len = static_cast<u32>(env.payload.size());
            data.push_back(static_cast<u8>(payload_len & 0xFF));
            data.push_back(static_cast<u8>((payload_len >> 8) & 0xFF));
            data.push_back(static_cast<u8>((payload_len >> 16) & 0xFF));
            data.push_back(static_cast<u8>((payload_len >> 24) & 0xFF));

            // Payload
            for (const auto &byte : env.payload) {
                data.push_back(byte);
            }

            return data;
        }

        // Deserialize envelope from bytes
        inline auto deserialize_envelope(const Vector<u8> &data) -> Res<Envelope> {
            constexpr usize MIN_SIZE = 1 + 1 + 4 + 8 + NODE_ID_SIZE + SIGNATURE_SIZE + 4;
            if (data.size() < MIN_SIZE) {
                return result::err(err::invalid("Envelope too small"));
            }

            Envelope env;
            usize offset = 0;

            // Version
            env.version = data[offset++];
            if (env.version != 1) {
                return result::err(err::invalid("Unsupported envelope version"));
            }

            // Message type
            env.msg_type = static_cast<MsgType>(data[offset++]);

            // Flags
            env.flags = static_cast<u32>(data[offset]) | (static_cast<u32>(data[offset + 1]) << 8) |
                        (static_cast<u32>(data[offset + 2]) << 16) | (static_cast<u32>(data[offset + 3]) << 24);
            offset += 4;

            // Timestamp
            env.timestamp_ms = 0;
            for (usize i = 0; i < 8; ++i) {
                env.timestamp_ms |= static_cast<u64>(data[offset + i]) << (i * 8);
            }
            offset += 8;

            // Sender ID
            for (usize i = 0; i < NODE_ID_SIZE; ++i) {
                env.sender_id.data[i] = data[offset++];
            }

            // Signature
            for (usize i = 0; i < SIGNATURE_SIZE; ++i) {
                env.signature.data[i] = data[offset++];
            }

            // Payload length
            u32 payload_len = static_cast<u32>(data[offset]) | (static_cast<u32>(data[offset + 1]) << 8) |
                              (static_cast<u32>(data[offset + 2]) << 16) | (static_cast<u32>(data[offset + 3]) << 24);
            offset += 4;

            if (data.size() < offset + payload_len) {
                return result::err(err::invalid("Envelope payload truncated"));
            }

            // Payload
            env.payload.resize(payload_len);
            for (usize i = 0; i < payload_len; ++i) {
                env.payload[i] = data[offset++];
            }

            return result::ok(env);
        }

        // =============================================================================
        // Envelope Signing and Verification
        // =============================================================================

        // Sign an envelope with Ed25519 private key
        inline auto sign_envelope(Envelope &env, const PrivateKey &private_key) -> void {
            auto data_to_sign = serialize_for_signing(env);
            env.signature = ed25519_sign(private_key, data_to_sign);
        }

        // Verify envelope signature with sender's public key
        inline auto verify_envelope(const Envelope &env, const PublicKey &sender_pubkey) -> boolean {
            auto data_to_verify = serialize_for_signing(env);
            return ed25519_verify(sender_pubkey, data_to_verify, env.signature);
        }

        // Create and sign a new envelope
        inline auto create_signed_envelope(MsgType type, const NodeId &sender_id, const PrivateKey &private_key,
                                           Vector<u8> payload) -> Envelope {
            Envelope env(type, sender_id, std::move(payload));
            sign_envelope(env, private_key);
            return env;
        }

        // =============================================================================
        // Envelope Validation
        // =============================================================================

        // Check if envelope timestamp is within acceptable range
        inline auto validate_envelope_timestamp(const Envelope &env, u64 max_age_ms = 60000, u64 max_future_ms = 5000)
            -> boolean {
            u64 now = time::now_ms();

            // Check if too old
            if (env.timestamp_ms + max_age_ms < now) {
                return false;
            }

            // Check if too far in the future
            if (env.timestamp_ms > now + max_future_ms) {
                return false;
            }

            return true;
        }

        // Full envelope validation (signature + timestamp)
        inline auto validate_envelope(const Envelope &env, const PublicKey &sender_pubkey, u64 max_age_ms = 60000)
            -> VoidRes {
            if (!validate_envelope_timestamp(env, max_age_ms)) {
                return result::err(err::invalid("Envelope timestamp out of range"));
            }

            if (!verify_envelope(env, sender_pubkey)) {
                return result::err(err::crypto("Envelope signature verification failed"));
            }

            return result::ok();
        }

    } // namespace crypto

} // namespace botlink
