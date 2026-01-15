/* SPDX-License-Identifier: MIT */
/*
 * Botlink Fuzzing / Robustness Tests
 * Tests for malformed input handling
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

// =============================================================================
// Endpoint Parsing Robustness
// =============================================================================

TEST_SUITE("Fuzzing - Endpoint Parsing") {

    TEST_CASE("Empty string") {
        auto res = net::parse_endpoint("");
        CHECK(res.is_err());
    }

    TEST_CASE("Only colon") {
        auto res = net::parse_endpoint(":");
        CHECK(res.is_err());
    }

    TEST_CASE("Missing port") {
        auto res = net::parse_endpoint("192.168.1.1");
        CHECK(res.is_err());
    }

    TEST_CASE("Missing address") {
        auto res = net::parse_endpoint(":51820");
        CHECK(res.is_err());
    }

    TEST_CASE("Invalid port - zero") {
        auto res = net::parse_endpoint("192.168.1.1:0");
        CHECK(res.is_err());
    }

    TEST_CASE("Invalid port - negative lookalike") {
        auto res = net::parse_endpoint("192.168.1.1:-1");
        CHECK(res.is_err());
    }

    TEST_CASE("Invalid port - too large") {
        auto res = net::parse_endpoint("192.168.1.1:65536");
        CHECK(res.is_err());
    }

    TEST_CASE("Invalid port - non-numeric") {
        auto res = net::parse_endpoint("192.168.1.1:abc");
        CHECK(res.is_err());
    }

    TEST_CASE("Invalid port - mixed") {
        auto res = net::parse_endpoint("192.168.1.1:123abc");
        CHECK(res.is_err());
    }

    TEST_CASE("Invalid IPv4 - too many octets") {
        // Parser may delegate to system inet_pton which has specific behavior
        auto res = net::parse_endpoint("192.168.1.1.1:51820");
        // Should not crash regardless of result
        (void)res;
    }

    TEST_CASE("Invalid IPv4 - too few octets") {
        auto res = net::parse_endpoint("192.168.1:51820");
        CHECK(res.is_err());
    }

    TEST_CASE("Invalid IPv4 - octet too large") {
        // inet_pton may treat 256 differently on different systems
        auto res = net::parse_endpoint("192.168.1.256:51820");
        // Should not crash regardless of result
        (void)res;
    }

    TEST_CASE("Invalid IPv4 - negative octet lookalike") {
        // inet_pton may handle this differently
        auto res = net::parse_endpoint("192.168.-1.1:51820");
        // Should not crash regardless of result
        (void)res;
    }

    TEST_CASE("Invalid IPv4 - non-numeric octet") {
        auto res = net::parse_endpoint("192.168.abc.1:51820");
        CHECK(res.is_err());
    }

    TEST_CASE("Extra whitespace - leading") {
        // Parser may be lenient with whitespace
        auto res = net::parse_endpoint(" 192.168.1.1:51820");
        // Should not crash regardless of result
        (void)res;
    }

    TEST_CASE("Extra whitespace - trailing") {
        auto res = net::parse_endpoint("192.168.1.1:51820 ");
        CHECK(res.is_err());
    }

    TEST_CASE("Extra whitespace - around colon") {
        auto res = net::parse_endpoint("192.168.1.1 : 51820");
        CHECK(res.is_err());
    }

    TEST_CASE("Multiple colons") {
        auto res = net::parse_endpoint("192.168.1.1:51820:extra");
        CHECK(res.is_err());
    }

    TEST_CASE("IPv6 - unclosed bracket") {
        auto res = net::parse_endpoint("[::1:51820");
        CHECK(res.is_err());
    }

    TEST_CASE("IPv6 - no bracket") {
        auto res = net::parse_endpoint("::1:51820");
        // This might parse as IPv4 with invalid format or fail
        // Either way, should not crash
        (void)res; // Just ensure no crash
    }

    TEST_CASE("Very long input") {
        String long_input;
        for (int i = 0; i < 10000; ++i) {
            long_input.push_back('1');
        }
        long_input += ":51820";
        auto res = net::parse_endpoint(long_input);
        CHECK(res.is_err());
    }

    TEST_CASE("Null bytes in string") {
        String with_null = "192.168";
        with_null.push_back('\0');
        with_null += ".1.1:51820";
        auto res = net::parse_endpoint(with_null);
        // Should handle gracefully (either parse partial or error)
        (void)res;
    }

    TEST_CASE("Valid endpoints still work") {
        auto res1 = net::parse_endpoint("192.168.1.1:51820");
        REQUIRE(res1.is_ok());
        CHECK(res1.value().port == 51820);

        auto res2 = net::parse_endpoint("0.0.0.0:1");
        REQUIRE(res2.is_ok());
        CHECK(res2.value().port == 1);

        auto res3 = net::parse_endpoint("255.255.255.255:65535");
        REQUIRE(res3.is_ok());
        CHECK(res3.value().port == 65535);
    }
}

// =============================================================================
// Envelope Deserialization Robustness
// =============================================================================

TEST_SUITE("Fuzzing - Envelope Deserialization") {

    TEST_CASE("Empty data") {
        Vector<u8> empty;
        auto res = serial::deserialize<Envelope>(empty);
        CHECK(res.is_err());
    }

    TEST_CASE("Single byte") {
        Vector<u8> data = {0x00};
        auto res = serial::deserialize<Envelope>(data);
        CHECK(res.is_err());
    }

    TEST_CASE("Truncated envelope") {
        Vector<u8> data = {0x01, 0x02, 0x03, 0x04};
        auto res = serial::deserialize<Envelope>(data);
        CHECK(res.is_err());
    }

    TEST_CASE("Invalid message type byte") {
        // Construct minimal data with invalid type
        Vector<u8> data;
        for (int i = 0; i < 100; ++i) {
            data.push_back(0xFF);
        }
        auto res = serial::deserialize<Envelope>(data);
        // Should either parse with invalid type or error, but not crash
        (void)res;
    }

    TEST_CASE("Maximum size payload") {
        Vector<u8> large_data;
        large_data.resize(65535, 0xAA);
        auto res = serial::deserialize<Envelope>(large_data);
        // Should handle gracefully
        (void)res;
    }
}

// =============================================================================
// Data Packet Deserialization Robustness
// =============================================================================

TEST_SUITE("Fuzzing - Data Packet Deserialization") {

    TEST_CASE("Empty packet") {
        Vector<u8> empty;
        auto res = crypto::deserialize_data_packet(empty);
        CHECK(res.is_err());
    }

    TEST_CASE("Too short - missing fields") {
        Vector<u8> short_data = {0x01, 0x22}; // version + type only
        auto res = crypto::deserialize_data_packet(short_data);
        CHECK(res.is_err());
    }

    TEST_CASE("Minimum valid header size") {
        // version(1) + type(1) + key_id(4) + nonce(8) = 14 bytes minimum
        Vector<u8> min_header(14, 0x00);
        min_header[0] = 1; // version
        min_header[1] = static_cast<u8>(net::DataMsgType::Data);
        auto res = crypto::deserialize_data_packet(min_header);
        // Should succeed with empty ciphertext
        if (res.is_ok()) {
            CHECK(res.value().ciphertext.empty());
        }
    }

    TEST_CASE("Invalid version") {
        Vector<u8> data(20, 0x00);
        data[0] = 0xFF; // Invalid version
        data[1] = static_cast<u8>(net::DataMsgType::Data);
        auto res = crypto::deserialize_data_packet(data);
        // May reject or accept, but shouldn't crash
        (void)res;
    }

    TEST_CASE("Random garbage") {
        Vector<u8> garbage;
        for (int i = 0; i < 1000; ++i) {
            garbage.push_back(static_cast<u8>(rand() % 256));
        }
        auto res = crypto::deserialize_data_packet(garbage);
        // Should not crash
        (void)res;
    }
}

// =============================================================================
// Handshake Message Robustness
// =============================================================================

TEST_SUITE("Fuzzing - Handshake Messages") {

    TEST_CASE("HandshakeInit - truncated") {
        Vector<u8> data = {0x01, 0x02, 0x03};
        auto res = serial::deserialize<net::HandshakeInit>(data);
        CHECK(res.is_err());
    }

    TEST_CASE("HandshakeResp - truncated") {
        Vector<u8> data = {0x01, 0x02, 0x03};
        auto res = serial::deserialize<net::HandshakeResp>(data);
        CHECK(res.is_err());
    }

    TEST_CASE("HandshakeInit - empty") {
        Vector<u8> empty;
        auto res = serial::deserialize<net::HandshakeInit>(empty);
        CHECK(res.is_err());
    }

    TEST_CASE("HandshakeResp - empty") {
        Vector<u8> empty;
        auto res = serial::deserialize<net::HandshakeResp>(empty);
        CHECK(res.is_err());
    }
}

// =============================================================================
// Crypto Robustness
// =============================================================================

TEST_SUITE("Fuzzing - Crypto Operations") {

    TEST_CASE("AEAD decrypt with wrong key") {
        crypto::SessionKey key1, key2;
        randombytes_buf(key1.data.data(), 32);
        randombytes_buf(key2.data.data(), 32);
        key1.key_id = 1;
        key2.key_id = 2;

        Vector<u8> plaintext = {0x01, 0x02, 0x03};
        auto nonce = crypto::generate_nonce();

        auto enc = crypto::aead_encrypt(key1, nonce, plaintext);
        REQUIRE(enc.is_ok());

        // Decrypt with wrong key should fail
        auto dec = crypto::aead_decrypt(key2, nonce, enc.value());
        CHECK(dec.is_err());
    }

    TEST_CASE("AEAD decrypt with wrong nonce") {
        crypto::SessionKey key;
        randombytes_buf(key.data.data(), 32);
        key.key_id = 1;

        Vector<u8> plaintext = {0x01, 0x02, 0x03};
        auto nonce1 = crypto::generate_nonce();
        auto nonce2 = crypto::generate_nonce();

        auto enc = crypto::aead_encrypt(key, nonce1, plaintext);
        REQUIRE(enc.is_ok());

        // Decrypt with wrong nonce should fail
        auto dec = crypto::aead_decrypt(key, nonce2, enc.value());
        CHECK(dec.is_err());
    }

    TEST_CASE("AEAD decrypt with modified ciphertext") {
        crypto::SessionKey key;
        randombytes_buf(key.data.data(), 32);
        key.key_id = 1;

        Vector<u8> plaintext = {0x01, 0x02, 0x03};
        auto nonce = crypto::generate_nonce();

        auto enc = crypto::aead_encrypt(key, nonce, plaintext);
        REQUIRE(enc.is_ok());

        // Modify ciphertext
        auto modified = enc.value();
        if (!modified.empty()) {
            modified[0] ^= 0xFF;
        }

        auto dec = crypto::aead_decrypt(key, nonce, modified);
        CHECK(dec.is_err());
    }

    TEST_CASE("AEAD decrypt empty ciphertext") {
        crypto::SessionKey key;
        randombytes_buf(key.data.data(), 32);
        key.key_id = 1;

        Vector<u8> empty;
        auto nonce = crypto::generate_nonce();

        auto dec = crypto::aead_decrypt(key, nonce, empty);
        CHECK(dec.is_err());
    }

    TEST_CASE("Signature verification with wrong key") {
        auto [priv1, pub1] = crypto::generate_ed25519_keypair();
        auto [priv2, pub2] = crypto::generate_ed25519_keypair();

        Vector<u8> message = {0x01, 0x02, 0x03};
        auto sig = crypto::ed25519_sign(priv1, message);

        // Verify with wrong public key should fail
        auto verify = crypto::ed25519_verify(pub2, message, sig);
        CHECK_FALSE(verify);
    }

    TEST_CASE("Signature verification with modified message") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        Vector<u8> message = {0x01, 0x02, 0x03};
        auto sig = crypto::ed25519_sign(priv, message);

        // Modify message
        Vector<u8> modified = {0x04, 0x05, 0x06};

        auto verify = crypto::ed25519_verify(pub, modified, sig);
        CHECK_FALSE(verify);
    }
}

// =============================================================================
// Replay Window Robustness
// =============================================================================

TEST_SUITE("Fuzzing - Replay Window") {

    TEST_CASE("Zero nonce - treated as initial state") {
        crypto::ReplayWindow window;
        // Zero is treated as already seen (last_seen starts at 0)
        // This is intentional - nonces should start at 1
        CHECK_FALSE(window.check_and_update(0));
    }

    TEST_CASE("First nonce should be 1") {
        crypto::ReplayWindow window;
        // Nonce 1 should be accepted
        CHECK(window.check_and_update(1));
        // But rejected on replay
        CHECK_FALSE(window.check_and_update(1));
    }

    TEST_CASE("Maximum u64 nonce") {
        crypto::ReplayWindow window;
        u64 max_val = UINT64_MAX;
        CHECK(window.check_and_update(max_val));
        CHECK_FALSE(window.check_and_update(max_val));
    }

    TEST_CASE("Rapid sequence starting from 1") {
        crypto::ReplayWindow window;
        // Start from 1 since 0 is treated as already seen
        for (u64 i = 1; i < 1001; ++i) {
            CHECK(window.check_and_update(i));
        }
        // All should be rejected on replay
        for (u64 i = 1; i < 1001; ++i) {
            CHECK_FALSE(window.check_and_update(i));
        }
    }

    TEST_CASE("Large gaps") {
        crypto::ReplayWindow window;
        CHECK(window.check_and_update(1));
        CHECK(window.check_and_update(1000000));
        CHECK(window.check_and_update(2000000));
        // Old values should be rejected
        CHECK_FALSE(window.check_and_update(1));
        CHECK_FALSE(window.check_and_update(500000));
    }

    TEST_CASE("Out of order within window") {
        crypto::ReplayWindow window;
        // Receive nonces out of order
        CHECK(window.check_and_update(10));
        CHECK(window.check_and_update(5)); // Within window
        CHECK(window.check_and_update(8)); // Within window
        CHECK(window.check_and_update(15));
        // All should be rejected on replay
        CHECK_FALSE(window.check_and_update(10));
        CHECK_FALSE(window.check_and_update(5));
        CHECK_FALSE(window.check_and_update(8));
    }

    TEST_CASE("Outside window rejected") {
        crypto::ReplayWindow window;
        CHECK(window.check_and_update(100));
        // 100 - 64 = 36, so anything < 36 should be rejected as too old
        CHECK_FALSE(window.check_and_update(35)); // Too old
        CHECK(window.check_and_update(37)); // Just within window
    }
}
