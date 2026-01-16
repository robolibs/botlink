/* SPDX-License-Identifier: MIT */
/*
 * Botlink AEAD Tests
 * Tests for authenticated encryption
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("AEAD - Constants") {

    TEST_CASE("TAG_SIZE is correct") {
        CHECK(crypto::TAG_SIZE == 16);
    }

}

TEST_SUITE("AEAD - Encryption/Decryption") {

    TEST_CASE("Basic encrypt/decrypt roundtrip") {
        // Generate session key
        crypto::SessionKey key;
        key.key_id = 1;
        auto random = crypto::generate_nonce();
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            key.data[i] = random.data[i % crypto::NONCE_SIZE];
        }

        // Generate nonce
        crypto::Nonce nonce = crypto::generate_nonce();

        // Plaintext
        Vector<u8> plaintext;
        const char* msg = "Hello, botlink!";
        for (usize i = 0; msg[i]; ++i) {
            plaintext.push_back(static_cast<u8>(msg[i]));
        }

        // Encrypt
        auto enc_result = crypto::aead_encrypt(key, nonce, plaintext);
        REQUIRE(enc_result.is_ok());
        Vector<u8> ciphertext = enc_result.value();

        // Ciphertext should be plaintext + TAG_SIZE
        CHECK(ciphertext.size() == plaintext.size() + crypto::TAG_SIZE);

        // Decrypt
        auto dec_result = crypto::aead_decrypt(key, nonce, ciphertext);
        REQUIRE(dec_result.is_ok());
        Vector<u8> decrypted = dec_result.value();

        // Should match original
        CHECK(decrypted.size() == plaintext.size());
        for (usize i = 0; i < plaintext.size(); ++i) {
            CHECK(decrypted[i] == plaintext[i]);
        }
    }

    TEST_CASE("Encrypt with associated data") {
        crypto::SessionKey key;
        key.key_id = 2;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            key.data[i] = static_cast<u8>(i + 1);
        }

        crypto::Nonce nonce = crypto::nonce_from_counter(123);

        Vector<u8> plaintext;
        plaintext.push_back('D');
        plaintext.push_back('A');
        plaintext.push_back('T');
        plaintext.push_back('A');

        Vector<u8> ad;
        ad.push_back('H');
        ad.push_back('D');
        ad.push_back('R');

        // Encrypt with AD
        auto enc_result = crypto::aead_encrypt(key, nonce, plaintext, ad);
        REQUIRE(enc_result.is_ok());

        // Decrypt with same AD
        auto dec_result = crypto::aead_decrypt(key, nonce, enc_result.value(), ad);
        REQUIRE(dec_result.is_ok());
        CHECK(dec_result.value().size() == plaintext.size());
    }

    TEST_CASE("Decryption fails with wrong key") {
        crypto::SessionKey key1, key2;
        key1.key_id = 1;
        key2.key_id = 2;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            key1.data[i] = static_cast<u8>(i);
            key2.data[i] = static_cast<u8>(i + 100);
        }

        crypto::Nonce nonce = crypto::nonce_from_counter(1);

        Vector<u8> plaintext;
        plaintext.push_back('X');

        auto enc_result = crypto::aead_encrypt(key1, nonce, plaintext);
        REQUIRE(enc_result.is_ok());

        auto dec_result = crypto::aead_decrypt(key2, nonce, enc_result.value());
        CHECK(dec_result.is_err());
    }

    TEST_CASE("Decryption fails with wrong nonce") {
        crypto::SessionKey key;
        key.key_id = 1;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            key.data[i] = static_cast<u8>(i);
        }

        crypto::Nonce nonce1 = crypto::nonce_from_counter(1);
        crypto::Nonce nonce2 = crypto::nonce_from_counter(2);

        Vector<u8> plaintext;
        plaintext.push_back('X');

        auto enc_result = crypto::aead_encrypt(key, nonce1, plaintext);
        REQUIRE(enc_result.is_ok());

        auto dec_result = crypto::aead_decrypt(key, nonce2, enc_result.value());
        CHECK(dec_result.is_err());
    }

    TEST_CASE("Decryption fails with wrong AD") {
        crypto::SessionKey key;
        key.key_id = 1;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            key.data[i] = static_cast<u8>(i);
        }

        crypto::Nonce nonce = crypto::nonce_from_counter(1);

        Vector<u8> plaintext;
        plaintext.push_back('X');

        Vector<u8> ad1, ad2;
        ad1.push_back('A');
        ad2.push_back('B');

        auto enc_result = crypto::aead_encrypt(key, nonce, plaintext, ad1);
        REQUIRE(enc_result.is_ok());

        auto dec_result = crypto::aead_decrypt(key, nonce, enc_result.value(), ad2);
        CHECK(dec_result.is_err());
    }

    TEST_CASE("Empty plaintext encryption") {
        crypto::SessionKey key;
        key.key_id = 1;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            key.data[i] = static_cast<u8>(i);
        }

        crypto::Nonce nonce = crypto::generate_nonce();
        Vector<u8> plaintext;  // Empty

        auto enc_result = crypto::aead_encrypt(key, nonce, plaintext);
        REQUIRE(enc_result.is_ok());
        CHECK(enc_result.value().size() == crypto::TAG_SIZE);

        auto dec_result = crypto::aead_decrypt(key, nonce, enc_result.value());
        REQUIRE(dec_result.is_ok());
        CHECK(dec_result.value().empty());
    }

    TEST_CASE("Ciphertext too short fails") {
        crypto::SessionKey key;
        key.key_id = 1;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            key.data[i] = static_cast<u8>(i);
        }

        crypto::Nonce nonce = crypto::generate_nonce();

        Vector<u8> short_ciphertext;
        for (usize i = 0; i < crypto::TAG_SIZE - 1; ++i) {
            short_ciphertext.push_back(0);
        }

        auto dec_result = crypto::aead_decrypt(key, nonce, short_ciphertext);
        CHECK(dec_result.is_err());
    }

}

TEST_SUITE("AEAD - DataPacket") {

    TEST_CASE("DataPacket default values") {
        crypto::DataPacket pkt;
        CHECK(pkt.version == 1);
        CHECK(pkt.packet_type == 0);
        CHECK(pkt.key_id == 0);
        CHECK(pkt.nonce_counter == 0);
        CHECK(pkt.ciphertext.empty());
    }

    TEST_CASE("DataPacket serialize/deserialize roundtrip") {
        crypto::DataPacket pkt;
        pkt.version = 1;
        pkt.packet_type = crypto::PACKET_TYPE_DATA;
        pkt.key_id = 0x12345678;
        pkt.nonce_counter = 0xDEADBEEFCAFE;
        pkt.ciphertext.push_back(0xAA);
        pkt.ciphertext.push_back(0xBB);
        pkt.ciphertext.push_back(0xCC);

        auto serialized = crypto::serialize_data_packet(pkt);
        CHECK(serialized.size() > 0);

        auto des_result = crypto::deserialize_data_packet(serialized);
        REQUIRE(des_result.is_ok());
        auto pkt2 = des_result.value();

        CHECK(pkt2.version == pkt.version);
        CHECK(pkt2.packet_type == pkt.packet_type);
        CHECK(pkt2.key_id == pkt.key_id);
        CHECK(pkt2.nonce_counter == pkt.nonce_counter);
        CHECK(pkt2.ciphertext.size() == pkt.ciphertext.size());
    }

    TEST_CASE("Deserialize rejects unsupported version") {
        Vector<u8> data;
        data.push_back(2);  // Version 2 (unsupported)
        for (usize i = 0; i < 17; ++i) {
            data.push_back(0);
        }

        auto result = crypto::deserialize_data_packet(data);
        CHECK(result.is_err());
    }

    TEST_CASE("Deserialize rejects truncated packet") {
        Vector<u8> data;
        data.push_back(1);  // Version
        data.push_back(0);  // Packet type
        // Missing rest of header

        auto result = crypto::deserialize_data_packet(data);
        CHECK(result.is_err());
    }

}

TEST_SUITE("AEAD - High-Level Packet Functions") {

    TEST_CASE("encrypt_packet/decrypt_packet roundtrip") {
        crypto::SessionKey key;
        key.key_id = 42;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            key.data[i] = static_cast<u8>(i * 2);
        }

        Vector<u8> plaintext;
        const char* msg = "Test packet data";
        for (usize i = 0; msg[i]; ++i) {
            plaintext.push_back(static_cast<u8>(msg[i]));
        }

        u64 counter = 100;

        auto enc_result = crypto::encrypt_packet(key, counter, plaintext);
        REQUIRE(enc_result.is_ok());
        auto pkt = enc_result.value();

        CHECK(pkt.version == 1);
        CHECK(pkt.packet_type == crypto::PACKET_TYPE_DATA);
        CHECK(pkt.key_id == 42);
        CHECK(pkt.nonce_counter == counter);

        auto dec_result = crypto::decrypt_packet(key, pkt);
        REQUIRE(dec_result.is_ok());

        CHECK(dec_result.value().size() == plaintext.size());
        for (usize i = 0; i < plaintext.size(); ++i) {
            CHECK(dec_result.value()[i] == plaintext[i]);
        }
    }

    TEST_CASE("decrypt_packet fails with wrong key_id") {
        crypto::SessionKey key;
        key.key_id = 42;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            key.data[i] = static_cast<u8>(i);
        }

        Vector<u8> plaintext;
        plaintext.push_back('X');

        auto enc_result = crypto::encrypt_packet(key, 1, plaintext);
        REQUIRE(enc_result.is_ok());
        auto pkt = enc_result.value();

        // Change key_id
        key.key_id = 99;

        auto dec_result = crypto::decrypt_packet(key, pkt);
        CHECK(dec_result.is_err());
    }

    TEST_CASE("Keepalive packet type") {
        crypto::SessionKey key;
        key.key_id = 1;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            key.data[i] = static_cast<u8>(i);
        }

        Vector<u8> empty;
        auto result = crypto::encrypt_packet(key, 1, empty, crypto::PACKET_TYPE_KEEPALIVE);
        REQUIRE(result.is_ok());
        CHECK(result.value().packet_type == crypto::PACKET_TYPE_KEEPALIVE);
    }

}

TEST_SUITE("AEAD - ReplayWindow") {

    TEST_CASE("ReplayWindow allows sequential nonces") {
        crypto::ReplayWindow window;

        CHECK(window.check_and_update(1) == true);
        CHECK(window.check_and_update(2) == true);
        CHECK(window.check_and_update(3) == true);
        CHECK(window.last_seen == 3);
    }

    TEST_CASE("ReplayWindow rejects duplicate nonces") {
        crypto::ReplayWindow window;

        CHECK(window.check_and_update(5) == true);
        CHECK(window.check_and_update(5) == false);  // Duplicate
    }

    TEST_CASE("ReplayWindow allows out-of-order within window") {
        crypto::ReplayWindow window;

        CHECK(window.check_and_update(10) == true);
        CHECK(window.check_and_update(8) == true);   // Within window
        CHECK(window.check_and_update(9) == true);   // Within window
        CHECK(window.check_and_update(8) == false);  // Duplicate
    }

    TEST_CASE("ReplayWindow rejects nonces too old") {
        crypto::ReplayWindow window;

        CHECK(window.check_and_update(100) == true);
        // Nonce 1 is too old (100 - 1 > 64)
        CHECK(window.check_and_update(1) == false);
    }

    TEST_CASE("ReplayWindow handles large jumps") {
        crypto::ReplayWindow window;

        CHECK(window.check_and_update(1) == true);
        CHECK(window.check_and_update(1000) == true);  // Big jump
        CHECK(window.last_seen == 1000);
        // Old nonces now outside window
        CHECK(window.check_and_update(1) == false);
    }

    TEST_CASE("ReplayWindow boundary at WINDOW_SIZE") {
        crypto::ReplayWindow window;

        CHECK(window.check_and_update(64) == true);
        // Exactly at window boundary
        CHECK(window.check_and_update(1) == true);   // diff = 63, just inside window
        CHECK(window.check_and_update(0) == false);  // diff = 64, outside window
    }

}
