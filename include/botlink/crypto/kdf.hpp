/* SPDX-License-Identifier: MIT */
/*
 * Botlink Key Derivation
 * Session key derivation and rekey management
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/types.hpp>
#include <botlink/crypto/identity.hpp>
#include <datapod/datapod.hpp>
#include <keylock/keylock.hpp>

#include <sodium.h>

namespace botlink {

    using namespace dp;

    namespace crypto {

        // =============================================================================
        // Constants
        // =============================================================================

        inline constexpr usize SESSION_KEY_SIZE = 32;
        inline constexpr usize NONCE_SIZE = 24; // XChaCha20-Poly1305
        inline constexpr usize HKDF_SALT_SIZE = 32;
        inline constexpr usize HANDSHAKE_HASH_SIZE = 32;

        // =============================================================================
        // Session Key
        // =============================================================================

        struct SessionKey {
            Array<u8, SESSION_KEY_SIZE> data{};
            u32 key_id = 0;

            SessionKey() = default;

            // Copy constructor
            SessionKey(const SessionKey &other) : key_id(other.key_id) {
                for (usize i = 0; i < SESSION_KEY_SIZE; ++i) {
                    data[i] = other.data[i];
                }
            }

            // Copy assignment
            auto operator=(const SessionKey &other) -> SessionKey & {
                if (this != &other) {
                    for (usize i = 0; i < SESSION_KEY_SIZE; ++i) {
                        data[i] = other.data[i];
                    }
                    key_id = other.key_id;
                }
                return *this;
            }

            // Move constructor - zeros the source after move
            SessionKey(SessionKey &&other) noexcept : key_id(other.key_id) {
                for (usize i = 0; i < SESSION_KEY_SIZE; ++i) {
                    data[i] = other.data[i];
                }
                other.clear();
            }

            // Move assignment - zeros the source after move
            auto operator=(SessionKey &&other) noexcept -> SessionKey & {
                if (this != &other) {
                    clear(); // Clear current data first
                    for (usize i = 0; i < SESSION_KEY_SIZE; ++i) {
                        data[i] = other.data[i];
                    }
                    key_id = other.key_id;
                    other.clear();
                }
                return *this;
            }

            // RAII: Securely clear key material on destruction
            ~SessionKey() { clear(); }

            auto clear() -> void {
                keylock::utils::Common::secure_clear(data.data(), data.size());
                key_id = 0;
            }

            [[nodiscard]] auto is_zero() const -> boolean {
                for (usize i = 0; i < SESSION_KEY_SIZE; ++i) {
                    if (data[i] != 0)
                        return false;
                }
                return true;
            }

            [[nodiscard]] auto raw() -> u8 * { return data.data(); }
            [[nodiscard]] auto raw() const -> const u8 * { return data.data(); }

            auto members() noexcept { return std::tie(data, key_id); }
            auto members() const noexcept { return std::tie(data, key_id); }
        };

        // =============================================================================
        // Nonce
        // =============================================================================

        struct Nonce {
            Array<u8, NONCE_SIZE> data{};

            Nonce() = default;

            // Increment nonce (for counter mode)
            auto increment() -> void {
                for (usize i = 0; i < NONCE_SIZE; ++i) {
                    if (++data[i] != 0)
                        break;
                }
            }

            [[nodiscard]] auto raw() -> u8 * { return data.data(); }
            [[nodiscard]] auto raw() const -> const u8 * { return data.data(); }

            auto members() noexcept { return std::tie(data); }
            auto members() const noexcept { return std::tie(data); }
        };

        // =============================================================================
        // Key Derivation Functions
        // =============================================================================

        // HKDF-Extract: Extract pseudorandom key from input key material
        inline auto hkdf_extract(const u8 *salt, usize salt_len, const u8 *ikm, usize ikm_len)
            -> Array<u8, HANDSHAKE_HASH_SIZE> {
            Array<u8, HANDSHAKE_HASH_SIZE> prk{};

            // HMAC-SHA256(salt, ikm)
            crypto_auth_hmacsha256_state state;
            crypto_auth_hmacsha256_init(&state, salt, salt_len);
            crypto_auth_hmacsha256_update(&state, ikm, ikm_len);
            crypto_auth_hmacsha256_final(&state, prk.data());

            return prk;
        }

        // HKDF-Expand: Expand pseudorandom key to desired length
        inline auto hkdf_expand(const Array<u8, HANDSHAKE_HASH_SIZE> &prk, const u8 *info, usize info_len,
                                usize output_len) -> Vector<u8> {
            Vector<u8> output;
            output.reserve(output_len);

            Array<u8, HANDSHAKE_HASH_SIZE> t{};
            u8 counter = 1;

            while (output.size() < output_len) {
                crypto_auth_hmacsha256_state state;
                crypto_auth_hmacsha256_init(&state, prk.data(), prk.size());

                if (counter > 1) {
                    crypto_auth_hmacsha256_update(&state, t.data(), t.size());
                }

                crypto_auth_hmacsha256_update(&state, info, info_len);
                crypto_auth_hmacsha256_update(&state, &counter, 1);
                crypto_auth_hmacsha256_final(&state, t.data());

                for (usize i = 0; i < t.size() && output.size() < output_len; ++i) {
                    output.push_back(t[i]);
                }

                ++counter;
            }

            return output;
        }

        // Full HKDF (Extract + Expand)
        inline auto hkdf(const u8 *salt, usize salt_len, const u8 *ikm, usize ikm_len, const u8 *info, usize info_len,
                         usize output_len) -> Vector<u8> {
            auto prk = hkdf_extract(salt, salt_len, ikm, ikm_len);
            return hkdf_expand(prk, info, info_len, output_len);
        }

        // =============================================================================
        // Session Key Derivation
        // =============================================================================

        // Derive session keys from X25519 shared secret
        inline auto derive_session_keys(const Array<u8, 32> &shared_secret, const NodeId &initiator_id,
                                        const NodeId &responder_id, u32 key_id) -> Pair<SessionKey, SessionKey> {
            // Build info string: "botlink-session" || initiator_id || responder_id
            Vector<u8> info;
            info.reserve(15 + NODE_ID_SIZE * 2);

            const char *label = "botlink-session";
            for (usize i = 0; label[i] != '\0'; ++i) {
                info.push_back(static_cast<u8>(label[i]));
            }

            for (usize i = 0; i < NODE_ID_SIZE; ++i) {
                info.push_back(initiator_id.data[i]);
            }

            for (usize i = 0; i < NODE_ID_SIZE; ++i) {
                info.push_back(responder_id.data[i]);
            }

            // Derive 64 bytes: 32 for send key, 32 for receive key
            auto derived = hkdf(nullptr, 0, shared_secret.data(), shared_secret.size(), info.data(), info.size(), 64);

            SessionKey send_key, recv_key;
            send_key.key_id = key_id;
            recv_key.key_id = key_id;

            for (usize i = 0; i < SESSION_KEY_SIZE; ++i) {
                send_key.data[i] = derived[i];
                recv_key.data[i] = derived[SESSION_KEY_SIZE + i];
            }

            // Secure clear
            keylock::utils::Common::secure_clear(derived.data(), derived.size());

            return {send_key, recv_key};
        }

        // Derive session keys for initiator (send = first 32 bytes, recv = last 32 bytes)
        inline auto derive_initiator_keys(const Array<u8, 32> &shared_secret, const NodeId &my_id,
                                          const NodeId &peer_id, u32 key_id) -> Pair<SessionKey, SessionKey> {
            return derive_session_keys(shared_secret, my_id, peer_id, key_id);
        }

        // Derive session keys for responder (send = last 32 bytes, recv = first 32 bytes)
        inline auto derive_responder_keys(const Array<u8, 32> &shared_secret, const NodeId &initiator_id,
                                          const NodeId &my_id, u32 key_id) -> Pair<SessionKey, SessionKey> {
            auto [init_send, init_recv] = derive_session_keys(shared_secret, initiator_id, my_id, key_id);
            // Responder's send = initiator's recv, responder's recv = initiator's send
            return {init_recv, init_send};
        }

        // =============================================================================
        // Rekey Functions
        // =============================================================================

        // Derive new session key from existing key (for rekeying)
        inline auto rekey(const SessionKey &old_key) -> SessionKey {
            SessionKey new_key;
            new_key.key_id = old_key.key_id + 1;

            // Use HKDF with label "botlink-rekey"
            const char *label = "botlink-rekey";
            auto derived = hkdf(nullptr, 0, old_key.raw(), SESSION_KEY_SIZE, reinterpret_cast<const u8 *>(label), 13,
                                SESSION_KEY_SIZE);

            for (usize i = 0; i < SESSION_KEY_SIZE; ++i) {
                new_key.data[i] = derived[i];
            }

            keylock::utils::Common::secure_clear(derived.data(), derived.size());

            return new_key;
        }

        // =============================================================================
        // Nonce Generation
        // =============================================================================

        // Generate random nonce
        inline auto generate_nonce() -> Nonce {
            Nonce nonce;
            auto random = keylock::utils::Common::generate_random_bytes(NONCE_SIZE);
            for (usize i = 0; i < NONCE_SIZE; ++i) {
                nonce.data[i] = random[i];
            }
            keylock::utils::Common::secure_clear(random.data(), random.size());
            return nonce;
        }

        // Generate nonce from counter (for deterministic nonces)
        inline auto nonce_from_counter(u64 counter) -> Nonce {
            Nonce nonce;
            // Put counter in first 8 bytes (little endian)
            for (usize i = 0; i < 8; ++i) {
                nonce.data[i] = static_cast<u8>((counter >> (i * 8)) & 0xFF);
            }
            return nonce;
        }

        // =============================================================================
        // Key ID Management
        // =============================================================================

        // Generate a random key ID
        inline auto generate_key_id() -> u32 {
            auto random = keylock::utils::Common::generate_random_bytes(4);
            u32 id = static_cast<u32>(random[0]) | (static_cast<u32>(random[1]) << 8) |
                     (static_cast<u32>(random[2]) << 16) | (static_cast<u32>(random[3]) << 24);
            return id;
        }

    } // namespace crypto

} // namespace botlink
