/* SPDX-License-Identifier: MIT */
/*
 * Botlink Identity
 * Ed25519/X25519 key management using Keylock
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/types.hpp>
#include <datapod/datapod.hpp>
#include <keylock/crypto/box_seal_x25519/x25519.hpp>
#include <keylock/crypto/sign_ed25519/ed25519.hpp>
#include <keylock/hash/sha256/sha256.hpp>
#include <keylock/keylock.hpp>

namespace botlink {

    using namespace dp;

    namespace crypto {

        // =============================================================================
        // Constants
        // =============================================================================

        inline constexpr usize ED25519_SEED_SIZE = 32;
        inline constexpr usize ED25519_PUBLIC_SIZE = 32;
        inline constexpr usize ED25519_SECRET_SIZE = 64;
        inline constexpr usize ED25519_SIGNATURE_SIZE = 64;

        inline constexpr usize X25519_PUBLIC_SIZE = 32;
        inline constexpr usize X25519_SECRET_SIZE = 32;

        // =============================================================================
        // Key Generation
        // =============================================================================

        // Generate a new Ed25519 signing key pair
        inline auto generate_ed25519_keypair() -> Pair<PrivateKey, PublicKey> {
            PrivateKey private_key;
            PublicKey public_key;

            // Generate seed
            auto seed = keylock::crypto::Common::generate_random_bytes(ED25519_SEED_SIZE);

            // Derive keypair from seed
            Array<u8, ED25519_SECRET_SIZE> secret_key{};
            keylock::crypto::ed25519::seed_keypair(public_key.raw(), secret_key.data(), seed.data());

            // Store only the seed portion (first 32 bytes) for our PrivateKey
            for (usize i = 0; i < KEY_SIZE; ++i) {
                private_key.data[i] = seed[i];
            }

            // Secure clear
            keylock::crypto::Common::secure_clear(seed.data(), seed.size());
            keylock::crypto::Common::secure_clear(secret_key.data(), secret_key.size());

            return {private_key, public_key};
        }

        // Derive Ed25519 public key from private key (seed)
        inline auto ed25519_public_from_private(const PrivateKey &private_key) -> PublicKey {
            PublicKey public_key;
            Array<u8, ED25519_SECRET_SIZE> secret_key{};

            keylock::crypto::ed25519::seed_keypair(public_key.raw(), secret_key.data(), private_key.raw());

            keylock::crypto::Common::secure_clear(secret_key.data(), secret_key.size());

            return public_key;
        }

        // Generate a new X25519 key exchange key pair
        inline auto generate_x25519_keypair() -> Pair<PrivateKey, PublicKey> {
            PrivateKey private_key;
            PublicKey public_key;

            // Generate random private key
            auto random = keylock::crypto::Common::generate_random_bytes(X25519_SECRET_SIZE);
            for (usize i = 0; i < KEY_SIZE; ++i) {
                private_key.data[i] = random[i];
            }

            // Derive public key
            keylock::crypto::x25519::public_key(public_key.raw(), private_key.raw());

            keylock::crypto::Common::secure_clear(random.data(), random.size());

            return {private_key, public_key};
        }

        // Derive X25519 public key from private key
        inline auto x25519_public_from_private(const PrivateKey &private_key) -> PublicKey {
            PublicKey public_key;
            keylock::crypto::x25519::public_key(public_key.raw(), private_key.raw());
            return public_key;
        }

        // =============================================================================
        // Node ID Derivation
        // =============================================================================

        // Derive NodeId from Ed25519 public key (SHA-256 hash)
        inline auto node_id_from_pubkey(const PublicKey &pubkey) -> NodeId {
            NodeId id;

            // Use SHA-256 hash of public key
            keylock::hash::sha256::hash(id.raw(), pubkey.raw(), KEY_SIZE);

            return id;
        }

        // =============================================================================
        // Ed25519 Signing
        // =============================================================================

        // Sign data with Ed25519 private key (seed format)
        inline auto ed25519_sign(const PrivateKey &private_key, const u8 *data, usize len) -> Signature {
            Signature sig;

            // Reconstruct full secret key from seed
            Array<u8, ED25519_SECRET_SIZE> secret_key{};
            Array<u8, ED25519_PUBLIC_SIZE> public_key{};
            keylock::crypto::ed25519::seed_keypair(public_key.data(), secret_key.data(), private_key.raw());

            // Sign
            crypto_sign_detached(sig.raw(), nullptr, data, len, secret_key.data());

            keylock::crypto::Common::secure_clear(secret_key.data(), secret_key.size());

            return sig;
        }

        // Verify Ed25519 signature
        inline auto ed25519_verify(const PublicKey &public_key, const u8 *data, usize len, const Signature &sig)
            -> boolean {
            return crypto_sign_verify_detached(sig.raw(), data, len, public_key.raw()) == 0;
        }

        // Sign a Vector of bytes
        inline auto ed25519_sign(const PrivateKey &private_key, const Vector<u8> &data) -> Signature {
            return ed25519_sign(private_key, data.data(), data.size());
        }

        // Verify with Vector of bytes
        inline auto ed25519_verify(const PublicKey &public_key, const Vector<u8> &data, const Signature &sig)
            -> boolean {
            return ed25519_verify(public_key, data.data(), data.size(), sig);
        }

        // =============================================================================
        // X25519 Key Exchange (Diffie-Hellman)
        // =============================================================================

        // Perform X25519 scalar multiplication (shared secret)
        inline auto x25519_shared_secret(const PrivateKey &my_private, const PublicKey &their_public)
            -> Res<Array<u8, 32>> {
            Array<u8, 32> shared;

            keylock::crypto::x25519::scalarmult(shared.data(), my_private.raw(), their_public.raw());

            return result::ok(shared);
        }

        // =============================================================================
        // Key Conversion Utilities
        // =============================================================================

        // Convert PublicKey to Vector<u8>
        inline auto to_vector(const PublicKey &key) -> Vector<u8> {
            Vector<u8> result;
            result.reserve(KEY_SIZE);
            for (usize i = 0; i < KEY_SIZE; ++i) {
                result.push_back(key.data[i]);
            }
            return result;
        }

        // Convert PrivateKey to Vector<u8>
        inline auto to_vector(const PrivateKey &key) -> Vector<u8> {
            Vector<u8> result;
            result.reserve(KEY_SIZE);
            for (usize i = 0; i < KEY_SIZE; ++i) {
                result.push_back(key.data[i]);
            }
            return result;
        }

        // Convert Vector<u8> to PublicKey
        inline auto public_key_from_vector(const Vector<u8> &vec) -> Res<PublicKey> {
            if (vec.size() < KEY_SIZE) {
                return result::err(err::invalid("Invalid key size"));
            }
            PublicKey key;
            for (usize i = 0; i < KEY_SIZE; ++i) {
                key.data[i] = vec[i];
            }
            return result::ok(key);
        }

        // Convert Vector<u8> to PrivateKey
        inline auto private_key_from_vector(const Vector<u8> &vec) -> Res<PrivateKey> {
            if (vec.size() < KEY_SIZE) {
                return result::err(err::invalid("Invalid key size"));
            }
            PrivateKey key;
            for (usize i = 0; i < KEY_SIZE; ++i) {
                key.data[i] = vec[i];
            }
            return result::ok(key);
        }

        // =============================================================================
        // Base64 Encoding/Decoding (for config files)
        // =============================================================================

        namespace detail {

            inline constexpr char B64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

            inline auto b64_encode(const u8 *data, usize len) -> String {
                String result;
                result.reserve(((len + 2) / 3) * 4);

                for (usize i = 0; i < len; i += 3) {
                    u32 n = static_cast<u32>(data[i]) << 16;
                    if (i + 1 < len)
                        n |= static_cast<u32>(data[i + 1]) << 8;
                    if (i + 2 < len)
                        n |= static_cast<u32>(data[i + 2]);

                    result.push_back(B64_CHARS[(n >> 18) & 0x3F]);
                    result.push_back(B64_CHARS[(n >> 12) & 0x3F]);
                    result.push_back(i + 1 < len ? B64_CHARS[(n >> 6) & 0x3F] : '=');
                    result.push_back(i + 2 < len ? B64_CHARS[n & 0x3F] : '=');
                }

                return result;
            }

            inline auto b64_decode_char(char c) -> i8 {
                if (c >= 'A' && c <= 'Z')
                    return c - 'A';
                if (c >= 'a' && c <= 'z')
                    return c - 'a' + 26;
                if (c >= '0' && c <= '9')
                    return c - '0' + 52;
                if (c == '+')
                    return 62;
                if (c == '/')
                    return 63;
                return -1;
            }

            inline auto b64_decode(const char *data, usize len) -> Res<Vector<u8>> {
                if (len % 4 != 0) {
                    return result::err(err::invalid("Invalid base64 length"));
                }

                Vector<u8> result;
                result.reserve((len / 4) * 3);

                for (usize i = 0; i < len; i += 4) {
                    i8 a = b64_decode_char(data[i]);
                    i8 b = b64_decode_char(data[i + 1]);
                    i8 c = data[i + 2] == '=' ? 0 : b64_decode_char(data[i + 2]);
                    i8 d = data[i + 3] == '=' ? 0 : b64_decode_char(data[i + 3]);

                    if (a < 0 || b < 0 || (data[i + 2] != '=' && c < 0) || (data[i + 3] != '=' && d < 0)) {
                        return result::err(err::invalid("Invalid base64 character"));
                    }

                    u32 n = (static_cast<u32>(a) << 18) | (static_cast<u32>(b) << 12) | (static_cast<u32>(c) << 6) |
                            static_cast<u32>(d);

                    result.push_back(static_cast<u8>((n >> 16) & 0xFF));
                    if (data[i + 2] != '=')
                        result.push_back(static_cast<u8>((n >> 8) & 0xFF));
                    if (data[i + 3] != '=')
                        result.push_back(static_cast<u8>(n & 0xFF));
                }

                return result::ok(result);
            }

        } // namespace detail

        // Encode key to base64
        inline auto key_to_base64(const PublicKey &key) -> KeyB64 {
            KeyB64 b64;
            String encoded = detail::b64_encode(key.raw(), KEY_SIZE);
            usize i = 0;
            for (; i < encoded.size() && i < KEY_B64_SIZE - 1; ++i) {
                b64.data[i] = encoded[i];
            }
            b64.data[i] = '\0';
            return b64;
        }

        inline auto key_to_base64(const PrivateKey &key) -> KeyB64 {
            KeyB64 b64;
            String encoded = detail::b64_encode(key.raw(), KEY_SIZE);
            usize i = 0;
            for (; i < encoded.size() && i < KEY_B64_SIZE - 1; ++i) {
                b64.data[i] = encoded[i];
            }
            b64.data[i] = '\0';
            return b64;
        }

        // Decode public key from base64
        inline auto public_key_from_base64(const KeyB64 &b64) -> Res<PublicKey> {
            usize len = 0;
            while (len < KEY_B64_SIZE && b64.data[len] != '\0')
                ++len;

            auto decoded = detail::b64_decode(b64.c_str(), len);
            if (decoded.is_err()) {
                return result::err(decoded.error());
            }

            if (decoded.value().size() != KEY_SIZE) {
                return result::err(err::invalid("Invalid key size after decoding"));
            }

            PublicKey key;
            for (usize i = 0; i < KEY_SIZE; ++i) {
                key.data[i] = decoded.value()[i];
            }
            return result::ok(key);
        }

        // Decode private key from base64
        inline auto private_key_from_base64(const KeyB64 &b64) -> Res<PrivateKey> {
            usize len = 0;
            while (len < KEY_B64_SIZE && b64.data[len] != '\0')
                ++len;

            auto decoded = detail::b64_decode(b64.c_str(), len);
            if (decoded.is_err()) {
                return result::err(decoded.error());
            }

            if (decoded.value().size() != KEY_SIZE) {
                return result::err(err::invalid("Invalid key size after decoding"));
            }

            PrivateKey key;
            for (usize i = 0; i < KEY_SIZE; ++i) {
                key.data[i] = decoded.value()[i];
            }
            return result::ok(key);
        }

        // Convert NodeId to hex string
        inline auto node_id_to_hex(const NodeId &id) -> String {
            static constexpr char HEX_CHARS[] = "0123456789abcdef";
            String result;
            result.reserve(NODE_ID_SIZE * 2);
            for (usize i = 0; i < NODE_ID_SIZE; ++i) {
                result.push_back(HEX_CHARS[(id.data[i] >> 4) & 0x0F]);
                result.push_back(HEX_CHARS[id.data[i] & 0x0F]);
            }
            return result;
        }

        // =============================================================================
        // Hex Encoding/Decoding for Keys
        // =============================================================================

        // Convert bytes to hex string
        inline auto to_hex(const u8 *data, usize len) -> String {
            static constexpr char HEX_CHARS[] = "0123456789abcdef";
            String result;
            result.reserve(len * 2);
            for (usize i = 0; i < len; ++i) {
                result.push_back(HEX_CHARS[(data[i] >> 4) & 0x0F]);
                result.push_back(HEX_CHARS[data[i] & 0x0F]);
            }
            return result;
        }

        // Parse hex character to nibble
        inline auto hex_char_to_nibble(char c) -> Res<u8> {
            if (c >= '0' && c <= '9')
                return result::ok(static_cast<u8>(c - '0'));
            if (c >= 'a' && c <= 'f')
                return result::ok(static_cast<u8>(c - 'a' + 10));
            if (c >= 'A' && c <= 'F')
                return result::ok(static_cast<u8>(c - 'A' + 10));
            return result::err(err::invalid("Invalid hex character"));
        }

        // Convert hex string to bytes
        inline auto from_hex(const String &hex) -> Res<Vector<u8>> {
            if (hex.size() % 2 != 0) {
                return result::err(err::invalid("Hex string must have even length"));
            }

            Vector<u8> result;
            result.reserve(hex.size() / 2);

            for (usize i = 0; i < hex.size(); i += 2) {
                auto high = hex_char_to_nibble(hex[i]);
                if (high.is_err())
                    return result::err(high.error());
                auto low = hex_char_to_nibble(hex[i + 1]);
                if (low.is_err())
                    return result::err(low.error());
                result.push_back(static_cast<u8>((high.value() << 4) | low.value()));
            }

            return result::ok(result);
        }

        // Convert hex string to PublicKey
        inline auto public_key_from_hex(const String &hex) -> Res<PublicKey> {
            if (hex.size() != KEY_SIZE * 2) {
                return result::err(err::invalid("Invalid hex key length"));
            }

            auto bytes = from_hex(hex);
            if (bytes.is_err()) {
                return result::err(bytes.error());
            }

            PublicKey key;
            for (usize i = 0; i < KEY_SIZE; ++i) {
                key.data[i] = bytes.value()[i];
            }
            return result::ok(key);
        }

        // Convert hex string to PrivateKey
        inline auto private_key_from_hex(const String &hex) -> Res<PrivateKey> {
            if (hex.size() != KEY_SIZE * 2) {
                return result::err(err::invalid("Invalid hex key length"));
            }

            auto bytes = from_hex(hex);
            if (bytes.is_err()) {
                return result::err(bytes.error());
            }

            PrivateKey key;
            for (usize i = 0; i < KEY_SIZE; ++i) {
                key.data[i] = bytes.value()[i];
            }
            return result::ok(key);
        }

    } // namespace crypto

} // namespace botlink
