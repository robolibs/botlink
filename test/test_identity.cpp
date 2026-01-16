/* SPDX-License-Identifier: MIT */
/*
 * Botlink Identity Tests
 * Tests for key conversion, hex encoding, and identity utilities
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Identity - Key Conversion") {

    TEST_CASE("PublicKey to Vector roundtrip") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        Vector<u8> vec = crypto::to_vector(pub);
        CHECK(vec.size() == KEY_SIZE);

        auto result = crypto::public_key_from_vector(vec);
        REQUIRE(result.is_ok());
        CHECK(result.value() == pub);
    }

    TEST_CASE("PrivateKey to Vector roundtrip") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        Vector<u8> vec = crypto::to_vector(priv);
        CHECK(vec.size() == KEY_SIZE);

        auto result = crypto::private_key_from_vector(vec);
        REQUIRE(result.is_ok());
        CHECK(result.value().data == priv.data);
    }

    TEST_CASE("public_key_from_vector fails on short input") {
        Vector<u8> short_vec;
        short_vec.push_back(0x01);
        short_vec.push_back(0x02);

        auto result = crypto::public_key_from_vector(short_vec);
        CHECK(result.is_err());
    }

    TEST_CASE("private_key_from_vector fails on short input") {
        Vector<u8> short_vec;
        short_vec.push_back(0x01);

        auto result = crypto::private_key_from_vector(short_vec);
        CHECK(result.is_err());
    }

}

TEST_SUITE("Identity - Hex Encoding") {

    TEST_CASE("to_hex produces correct length") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        String hex = crypto::to_hex(pub.raw(), KEY_SIZE);
        CHECK(hex.size() == KEY_SIZE * 2);
    }

    TEST_CASE("to_hex produces valid hex characters") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        String hex = crypto::to_hex(pub.raw(), KEY_SIZE);
        for (usize i = 0; i < hex.size(); ++i) {
            char c = hex[i];
            bool is_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            CHECK(is_hex);
        }
    }

    TEST_CASE("from_hex roundtrip") {
        Vector<u8> original;
        for (u8 i = 0; i < 32; ++i) {
            original.push_back(i);
        }

        String hex = crypto::to_hex(original.data(), original.size());
        auto result = crypto::from_hex(hex);

        REQUIRE(result.is_ok());
        CHECK(result.value() == original);
    }

    TEST_CASE("from_hex fails on odd length") {
        String odd_hex = "abc";
        auto result = crypto::from_hex(odd_hex);
        CHECK(result.is_err());
    }

    TEST_CASE("from_hex fails on invalid characters") {
        String invalid_hex = "xyz123";
        auto result = crypto::from_hex(invalid_hex);
        CHECK(result.is_err());
    }

    TEST_CASE("public_key_from_hex roundtrip") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        String hex = crypto::to_hex(pub.raw(), KEY_SIZE);
        auto result = crypto::public_key_from_hex(hex);

        REQUIRE(result.is_ok());
        CHECK(result.value() == pub);
    }

    TEST_CASE("private_key_from_hex roundtrip") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        String hex = crypto::to_hex(priv.raw(), KEY_SIZE);
        auto result = crypto::private_key_from_hex(hex);

        REQUIRE(result.is_ok());
        CHECK(result.value().data == priv.data);
    }

    TEST_CASE("public_key_from_hex fails on wrong length") {
        String short_hex = "0102030405";
        auto result = crypto::public_key_from_hex(short_hex);
        CHECK(result.is_err());
    }

    TEST_CASE("private_key_from_hex fails on wrong length") {
        String short_hex = "abcd";
        auto result = crypto::private_key_from_hex(short_hex);
        CHECK(result.is_err());
    }

}

TEST_SUITE("Identity - Key Derivation") {

    TEST_CASE("ed25519_public_from_private produces correct public key") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        PublicKey derived = crypto::ed25519_public_from_private(priv);
        CHECK(derived == pub);
    }

    TEST_CASE("x25519_public_from_private produces correct public key") {
        auto [priv, pub] = crypto::generate_x25519_keypair();

        PublicKey derived = crypto::x25519_public_from_private(priv);
        CHECK(derived == pub);
    }

    TEST_CASE("ed25519_public_from_private is deterministic") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        PublicKey derived1 = crypto::ed25519_public_from_private(priv);
        PublicKey derived2 = crypto::ed25519_public_from_private(priv);
        CHECK(derived1 == derived2);
    }

    TEST_CASE("x25519_public_from_private is deterministic") {
        auto [priv, pub] = crypto::generate_x25519_keypair();

        PublicKey derived1 = crypto::x25519_public_from_private(priv);
        PublicKey derived2 = crypto::x25519_public_from_private(priv);
        CHECK(derived1 == derived2);
    }

}

TEST_SUITE("Identity - NodeId") {

    TEST_CASE("NodeId from different keys are different") {
        auto [priv1, pub1] = crypto::generate_ed25519_keypair();
        auto [priv2, pub2] = crypto::generate_ed25519_keypair();

        NodeId id1 = crypto::node_id_from_pubkey(pub1);
        NodeId id2 = crypto::node_id_from_pubkey(pub2);

        CHECK(id1 != id2);
    }

    TEST_CASE("NodeId is deterministic for same key") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        NodeId id1 = crypto::node_id_from_pubkey(pub);
        NodeId id2 = crypto::node_id_from_pubkey(pub);

        CHECK(id1 == id2);
    }

    TEST_CASE("NodeId hex encoding is 64 characters") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId id = crypto::node_id_from_pubkey(pub);

        String hex = crypto::node_id_to_hex(id);
        CHECK(hex.size() == NODE_ID_SIZE * 2);
    }

    TEST_CASE("NodeId is_zero on default") {
        NodeId id;
        CHECK(id.is_zero());
    }

    TEST_CASE("NodeId is_zero false after derivation") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId id = crypto::node_id_from_pubkey(pub);
        CHECK_FALSE(id.is_zero());
    }

}

TEST_SUITE("Identity - Base64") {

    TEST_CASE("Base64 encoding produces non-empty string") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        KeyB64 b64 = crypto::key_to_base64(pub);
        CHECK(b64.data[0] != '\0');
    }

    TEST_CASE("Base64 encoding is deterministic") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        KeyB64 b64_1 = crypto::key_to_base64(pub);
        KeyB64 b64_2 = crypto::key_to_base64(pub);

        CHECK(String(b64_1.c_str()) == String(b64_2.c_str()));
    }

    TEST_CASE("Invalid base64 fails gracefully") {
        KeyB64 invalid;
        invalid.data[0] = '!';
        invalid.data[1] = '@';
        invalid.data[2] = '#';
        invalid.data[3] = '$';
        invalid.data[4] = '\0';

        auto result = crypto::public_key_from_base64(invalid);
        CHECK(result.is_err());
    }

    TEST_CASE("Empty base64 fails gracefully") {
        KeyB64 empty;
        empty.data[0] = '\0';

        auto result = crypto::public_key_from_base64(empty);
        CHECK(result.is_err());
    }

}

