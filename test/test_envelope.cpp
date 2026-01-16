/* SPDX-License-Identifier: MIT */
/*
 * Botlink Envelope Tests
 * Tests for signed envelope creation and verification
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Envelope - Basic Structure") {

    TEST_CASE("Envelope default values") {
        Envelope env;
        CHECK(env.version == 1);
        CHECK(env.msg_type == MsgType::Data);
        CHECK(env.flags == 0);
        CHECK(env.timestamp_ms == 0);
        CHECK(env.sender_id.is_zero());
        CHECK(env.payload.empty());
    }

    TEST_CASE("Envelope constructor with type and sender") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(ed_pub);

        Vector<u8> payload;
        payload.push_back(0x01);
        payload.push_back(0x02);

        Envelope env(MsgType::HandshakeInit, sender, payload);

        CHECK(env.version == 1);
        CHECK(env.msg_type == MsgType::HandshakeInit);
        CHECK(env.sender_id == sender);
        CHECK(env.payload.size() == 2);
        CHECK(env.timestamp_ms > 0);
    }

}

TEST_SUITE("Envelope - Signing") {

    TEST_CASE("create_signed_envelope produces valid signature") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(ed_pub);

        Vector<u8> payload;
        payload.push_back(0xAB);
        payload.push_back(0xCD);

        Envelope env = crypto::create_signed_envelope(MsgType::Data, sender, ed_priv, payload);

        CHECK(env.version == 1);
        CHECK(env.msg_type == MsgType::Data);
        CHECK(env.sender_id == sender);
        CHECK(env.payload == payload);
        CHECK_FALSE(env.signature.is_zero());
    }

    TEST_CASE("verify_envelope with correct key succeeds") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(ed_pub);

        Vector<u8> payload;
        payload.push_back(0x01);

        Envelope env = crypto::create_signed_envelope(MsgType::Data, sender, ed_priv, payload);

        bool valid = crypto::verify_envelope(env, ed_pub);
        CHECK(valid);
    }

    TEST_CASE("verify_envelope with wrong key fails") {
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(ed_pub1);

        Vector<u8> payload;
        payload.push_back(0x01);

        Envelope env = crypto::create_signed_envelope(MsgType::Data, sender, ed_priv1, payload);

        // Try to verify with wrong key
        bool valid = crypto::verify_envelope(env, ed_pub2);
        CHECK_FALSE(valid);
    }

    TEST_CASE("verify_envelope fails on modified payload") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(ed_pub);

        Vector<u8> payload;
        payload.push_back(0x01);

        Envelope env = crypto::create_signed_envelope(MsgType::Data, sender, ed_priv, payload);

        // Modify payload
        env.payload[0] = 0xFF;

        bool valid = crypto::verify_envelope(env, ed_pub);
        CHECK_FALSE(valid);
    }

    TEST_CASE("verify_envelope fails on modified timestamp") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(ed_pub);

        Vector<u8> payload;
        payload.push_back(0x01);

        Envelope env = crypto::create_signed_envelope(MsgType::Data, sender, ed_priv, payload);

        // Modify timestamp
        env.timestamp_ms += 1000;

        bool valid = crypto::verify_envelope(env, ed_pub);
        CHECK_FALSE(valid);
    }

}

TEST_SUITE("Envelope - Serialization") {

    TEST_CASE("serialize_envelope produces non-empty bytes") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(ed_pub);

        Vector<u8> payload;
        payload.push_back(0xDE);
        payload.push_back(0xAD);

        Envelope env = crypto::create_signed_envelope(MsgType::Data, sender, ed_priv, payload);

        Vector<u8> serialized = crypto::serialize_envelope(env);
        CHECK_FALSE(serialized.empty());
        CHECK(serialized.size() > payload.size());  // Should include header
    }

    TEST_CASE("deserialize_envelope roundtrip") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(ed_pub);

        Vector<u8> payload;
        payload.push_back(0xBE);
        payload.push_back(0xEF);

        Envelope original = crypto::create_signed_envelope(MsgType::HandshakeInit, sender, ed_priv, payload);

        Vector<u8> serialized = crypto::serialize_envelope(original);
        auto result = crypto::deserialize_envelope(serialized);

        REQUIRE(result.is_ok());

        Envelope& parsed = result.value();
        CHECK(parsed.version == original.version);
        CHECK(parsed.msg_type == original.msg_type);
        CHECK(parsed.flags == original.flags);
        CHECK(parsed.timestamp_ms == original.timestamp_ms);
        CHECK(parsed.sender_id == original.sender_id);
        CHECK(parsed.payload == original.payload);
        CHECK(parsed.signature.data == original.signature.data);
    }

    TEST_CASE("deserialize_envelope fails on invalid data") {
        Vector<u8> garbage;
        garbage.push_back(0xFF);
        garbage.push_back(0xFF);

        auto result = crypto::deserialize_envelope(garbage);
        CHECK(result.is_err());
    }

    TEST_CASE("deserialize_envelope fails on empty data") {
        Vector<u8> empty;

        auto result = crypto::deserialize_envelope(empty);
        CHECK(result.is_err());
    }

}

TEST_SUITE("Envelope - serialize_for_signing") {

    TEST_CASE("serialize_for_signing excludes signature") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(ed_pub);

        Envelope env;
        env.version = 1;
        env.msg_type = MsgType::Data;
        env.flags = 0;
        env.timestamp_ms = time::now_ms();
        env.sender_id = sender;
        env.payload.push_back(0x42);

        auto data1 = crypto::serialize_for_signing(env);

        // Add a signature
        env.signature = crypto::ed25519_sign(ed_priv, data1);

        auto data2 = crypto::serialize_for_signing(env);

        // serialize_for_signing should produce same output regardless of signature
        CHECK(data1 == data2);
    }

    TEST_CASE("serialize_for_signing produces deterministic output") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(ed_pub);

        Envelope env;
        env.version = 1;
        env.msg_type = MsgType::Data;
        env.timestamp_ms = 1234567890;
        env.sender_id = sender;
        env.payload.push_back(0x01);

        auto data1 = crypto::serialize_for_signing(env);
        auto data2 = crypto::serialize_for_signing(env);

        CHECK(data1 == data2);
    }

}

TEST_SUITE("Envelope - MsgType") {

    TEST_CASE("Different message types") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(ed_pub);
        Vector<u8> payload;

        Envelope data_env = crypto::create_signed_envelope(MsgType::Data, sender, ed_priv, payload);
        CHECK(data_env.msg_type == MsgType::Data);

        Envelope init_env = crypto::create_signed_envelope(MsgType::HandshakeInit, sender, ed_priv, payload);
        CHECK(init_env.msg_type == MsgType::HandshakeInit);

        Envelope resp_env = crypto::create_signed_envelope(MsgType::HandshakeResp, sender, ed_priv, payload);
        CHECK(resp_env.msg_type == MsgType::HandshakeResp);
    }

}
