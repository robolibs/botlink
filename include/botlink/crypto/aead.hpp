/* SPDX-License-Identifier: MIT */
/*
 * Botlink AEAD
 * Authenticated Encryption with Associated Data using XChaCha20-Poly1305
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/types.hpp>
#include <botlink/crypto/kdf.hpp>
#include <datapod/datapod.hpp>
#include <keylock/crypto/aead_xchacha20poly1305_ietf/aead.hpp>
#include <keylock/keylock.hpp>

namespace botlink {

    using namespace dp;

    namespace crypto {

        // =============================================================================
        // Constants
        // =============================================================================

        inline constexpr usize TAG_SIZE = keylock::crypto::aead_xchacha20poly1305::ABYTES; // 16 bytes

        // =============================================================================
        // AEAD Encryption
        // =============================================================================

        // Encrypt plaintext with XChaCha20-Poly1305
        inline auto aead_encrypt(const SessionKey &key, const Nonce &nonce, const u8 *plaintext, usize plaintext_len,
                                 const u8 *ad = nullptr, usize ad_len = 0) -> Res<Vector<u8>> {

            Vector<u8> ciphertext;
            ciphertext.resize(plaintext_len + TAG_SIZE);

            unsigned long long ciphertext_len;

            int result = keylock::crypto::aead_xchacha20poly1305::encrypt(ciphertext.data(), &ciphertext_len, plaintext,
                                                                          plaintext_len, ad, ad_len, nullptr,
                                                                          nonce.raw(), key.raw());

            if (result != 0) {
                return result::err(err::crypto("AEAD encryption failed"));
            }

            ciphertext.resize(static_cast<usize>(ciphertext_len));
            return result::ok(std::move(ciphertext));
        }

        // Encrypt with Vector input
        inline auto aead_encrypt(const SessionKey &key, const Nonce &nonce, const Vector<u8> &plaintext,
                                 const Vector<u8> &ad = {}) -> Res<Vector<u8>> {
            return aead_encrypt(key, nonce, plaintext.data(), plaintext.size(), ad.empty() ? nullptr : ad.data(),
                                ad.size());
        }

        // =============================================================================
        // AEAD Decryption
        // =============================================================================

        // Decrypt ciphertext with XChaCha20-Poly1305
        inline auto aead_decrypt(const SessionKey &key, const Nonce &nonce, const u8 *ciphertext, usize ciphertext_len,
                                 const u8 *ad = nullptr, usize ad_len = 0) -> Res<Vector<u8>> {

            if (ciphertext_len < TAG_SIZE) {
                return result::err(err::invalid("Ciphertext too short"));
            }

            Vector<u8> plaintext;
            plaintext.resize(ciphertext_len - TAG_SIZE);

            unsigned long long plaintext_len;

            int result =
                keylock::crypto::aead_xchacha20poly1305::decrypt(plaintext.data(), &plaintext_len, nullptr, ciphertext,
                                                                 ciphertext_len, ad, ad_len, nonce.raw(), key.raw());

            if (result != 0) {
                return result::err(err::crypto("AEAD decryption failed (authentication)"));
            }

            plaintext.resize(static_cast<usize>(plaintext_len));
            return result::ok(std::move(plaintext));
        }

        // Decrypt with Vector input
        inline auto aead_decrypt(const SessionKey &key, const Nonce &nonce, const Vector<u8> &ciphertext,
                                 const Vector<u8> &ad = {}) -> Res<Vector<u8>> {
            return aead_decrypt(key, nonce, ciphertext.data(), ciphertext.size(), ad.empty() ? nullptr : ad.data(),
                                ad.size());
        }

        // =============================================================================
        // Data Packet Structure
        // =============================================================================

        struct DataPacket {
            u8 version = 1;
            u8 packet_type = 0; // 0 = data, 1 = keepalive, 2 = rekey
            u32 key_id = 0;
            u64 nonce_counter = 0;
            Vector<u8> ciphertext;

            DataPacket() = default;

            auto members() noexcept { return std::tie(version, packet_type, key_id, nonce_counter, ciphertext); }
            auto members() const noexcept { return std::tie(version, packet_type, key_id, nonce_counter, ciphertext); }
        };

        // Packet types
        inline constexpr u8 PACKET_TYPE_DATA = 0;
        inline constexpr u8 PACKET_TYPE_KEEPALIVE = 1;
        inline constexpr u8 PACKET_TYPE_REKEY = 2;

        // =============================================================================
        // Data Packet Serialization
        // =============================================================================

        inline auto serialize_data_packet(const DataPacket &pkt) -> Vector<u8> {
            Vector<u8> data;
            data.reserve(1 + 1 + 4 + 8 + 4 + pkt.ciphertext.size());

            // Version
            data.push_back(pkt.version);

            // Packet type
            data.push_back(pkt.packet_type);

            // Key ID (little endian)
            data.push_back(static_cast<u8>(pkt.key_id & 0xFF));
            data.push_back(static_cast<u8>((pkt.key_id >> 8) & 0xFF));
            data.push_back(static_cast<u8>((pkt.key_id >> 16) & 0xFF));
            data.push_back(static_cast<u8>((pkt.key_id >> 24) & 0xFF));

            // Nonce counter (little endian)
            for (usize i = 0; i < 8; ++i) {
                data.push_back(static_cast<u8>((pkt.nonce_counter >> (i * 8)) & 0xFF));
            }

            // Ciphertext length (little endian u32)
            u32 ct_len = static_cast<u32>(pkt.ciphertext.size());
            data.push_back(static_cast<u8>(ct_len & 0xFF));
            data.push_back(static_cast<u8>((ct_len >> 8) & 0xFF));
            data.push_back(static_cast<u8>((ct_len >> 16) & 0xFF));
            data.push_back(static_cast<u8>((ct_len >> 24) & 0xFF));

            // Ciphertext
            for (const auto &byte : pkt.ciphertext) {
                data.push_back(byte);
            }

            return data;
        }

        inline auto deserialize_data_packet(const Vector<u8> &data) -> Res<DataPacket> {
            constexpr usize MIN_SIZE = 1 + 1 + 4 + 8 + 4;
            if (data.size() < MIN_SIZE) {
                return result::err(err::invalid("Data packet too small"));
            }

            DataPacket pkt;
            usize offset = 0;

            // Version
            pkt.version = data[offset++];
            if (pkt.version != 1) {
                return result::err(err::invalid("Unsupported packet version"));
            }

            // Packet type
            pkt.packet_type = data[offset++];

            // Key ID
            pkt.key_id = static_cast<u32>(data[offset]) | (static_cast<u32>(data[offset + 1]) << 8) |
                         (static_cast<u32>(data[offset + 2]) << 16) | (static_cast<u32>(data[offset + 3]) << 24);
            offset += 4;

            // Nonce counter
            pkt.nonce_counter = 0;
            for (usize i = 0; i < 8; ++i) {
                pkt.nonce_counter |= static_cast<u64>(data[offset + i]) << (i * 8);
            }
            offset += 8;

            // Ciphertext length
            u32 ct_len = static_cast<u32>(data[offset]) | (static_cast<u32>(data[offset + 1]) << 8) |
                         (static_cast<u32>(data[offset + 2]) << 16) | (static_cast<u32>(data[offset + 3]) << 24);
            offset += 4;

            if (data.size() < offset + ct_len) {
                return result::err(err::invalid("Data packet ciphertext truncated"));
            }

            // Ciphertext
            pkt.ciphertext.resize(ct_len);
            for (usize i = 0; i < ct_len; ++i) {
                pkt.ciphertext[i] = data[offset++];
            }

            return result::ok(pkt);
        }

        // =============================================================================
        // High-Level Encrypt/Decrypt Functions
        // =============================================================================

        // Encrypt data into a DataPacket
        inline auto encrypt_packet(const SessionKey &key, u64 nonce_counter, const Vector<u8> &plaintext,
                                   u8 packet_type = PACKET_TYPE_DATA) -> Res<DataPacket> {
            DataPacket pkt;
            pkt.version = 1;
            pkt.packet_type = packet_type;
            pkt.key_id = key.key_id;
            pkt.nonce_counter = nonce_counter;

            // Create nonce from counter
            Nonce nonce = nonce_from_counter(nonce_counter);

            // Encrypt
            auto ct_result = aead_encrypt(key, nonce, plaintext);
            if (ct_result.is_err()) {
                return result::err(ct_result.error());
            }

            pkt.ciphertext = std::move(ct_result.value());
            return result::ok(pkt);
        }

        // Decrypt data from a DataPacket
        inline auto decrypt_packet(const SessionKey &key, const DataPacket &pkt) -> Res<Vector<u8>> {
            if (pkt.key_id != key.key_id) {
                return result::err(err::invalid("Key ID mismatch"));
            }

            // Create nonce from counter
            Nonce nonce = nonce_from_counter(pkt.nonce_counter);

            // Decrypt
            return aead_decrypt(key, nonce, pkt.ciphertext);
        }

        // =============================================================================
        // Replay Protection
        // =============================================================================

        // Simple sliding window replay protection
        struct ReplayWindow {
            u64 last_seen = 0;
            u64 window_bitmap = 0; // Tracks 64 nonces before last_seen
            static constexpr u64 WINDOW_SIZE = 64;

            // Check if nonce is valid (not replayed) and update window
            [[nodiscard]] auto check_and_update(u64 nonce) -> boolean {
                if (nonce > last_seen) {
                    // New highest nonce
                    u64 shift = nonce - last_seen;
                    if (shift >= WINDOW_SIZE) {
                        window_bitmap = 0;
                    } else {
                        window_bitmap <<= shift;
                    }
                    window_bitmap |= 1;
                    last_seen = nonce;
                    return true;
                } else if (nonce == last_seen) {
                    // Replay of last seen
                    return false;
                } else {
                    // Within window
                    u64 diff = last_seen - nonce;
                    if (diff >= WINDOW_SIZE) {
                        // Too old
                        return false;
                    }
                    u64 mask = 1ULL << diff;
                    if (window_bitmap & mask) {
                        // Already seen
                        return false;
                    }
                    window_bitmap |= mask;
                    return true;
                }
            }

            auto members() noexcept { return std::tie(last_seen, window_bitmap); }
            auto members() const noexcept { return std::tie(last_seen, window_bitmap); }
        };

    } // namespace crypto

} // namespace botlink
