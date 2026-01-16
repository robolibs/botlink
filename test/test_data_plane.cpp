/* SPDX-License-Identifier: MIT */
/*
 * Botlink Data Plane Tests
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("DataPlane - Message Structures") {

    TEST_CASE("HandshakeInit structure") {
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId initiator = crypto::node_id_from_pubkey(ed_pub);

        net::HandshakeInit init;
        init.initiator_id = initiator;
        init.initiator_x25519 = x_pub;
        init.timestamp_ms = time::now_ms();
        init.nonce = crypto::generate_nonce();

        CHECK(init.initiator_id == initiator);
        CHECK(init.initiator_x25519 == x_pub);
        CHECK(init.timestamp_ms > 0);
    }

    TEST_CASE("HandshakeResp structure") {
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId responder = crypto::node_id_from_pubkey(ed_pub);

        net::HandshakeResp resp;
        resp.responder_id = responder;
        resp.responder_x25519 = x_pub;
        resp.timestamp_ms = time::now_ms();
        resp.nonce = crypto::generate_nonce();
        resp.encrypted_ack = {0x01, 0x02, 0x03};

        CHECK(resp.responder_id == responder);
        CHECK(resp.responder_x25519 == x_pub);
        CHECK(resp.encrypted_ack.size() == 3);
    }

    TEST_CASE("KeepalivePacket structure") {
        net::KeepalivePacket ka;
        ka.key_id = 42;
        ka.timestamp_ms = time::now_ms();

        CHECK(ka.key_id == 42);
        CHECK(ka.timestamp_ms > 0);
    }

    TEST_CASE("RekeyRequest structure") {
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(ed_pub);

        net::RekeyRequest rekey;
        rekey.sender_id = sender;
        rekey.new_x25519 = x_pub;
        rekey.new_key_id = 100;
        rekey.timestamp_ms = time::now_ms();

        CHECK(rekey.sender_id == sender);
        CHECK(rekey.new_x25519 == x_pub);
        CHECK(rekey.new_key_id == 100);
    }

}

TEST_SUITE("DataPlane - HandshakeSession") {

    TEST_CASE("HandshakeSession default state") {
        net::HandshakeSession session;

        CHECK(session.state == net::HandshakeState::None);
        CHECK(session.started_at_ms == 0);
        CHECK(session.retries == 0);
        CHECK(session.max_retries == 3);
        CHECK(session.timeout_ms == 5000);
    }

    TEST_CASE("HandshakeSession timeout check") {
        net::HandshakeSession session;
        session.started_at_ms = time::now_ms();
        session.timeout_ms = 100;

        CHECK_FALSE(session.is_timed_out());

        // Simulate timeout
        session.started_at_ms = time::now_ms() - 200;
        CHECK(session.is_timed_out());
    }

    TEST_CASE("HandshakeSession can_retry check") {
        net::HandshakeSession session;
        session.max_retries = 3;

        session.retries = 0;
        CHECK(session.can_retry());

        session.retries = 2;
        CHECK(session.can_retry());

        session.retries = 3;
        CHECK_FALSE(session.can_retry());

        session.retries = 4;
        CHECK_FALSE(session.can_retry());
    }

    TEST_CASE("HandshakeSession with keys") {
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId peer = crypto::node_id_from_pubkey(ed_pub);

        net::HandshakeSession session;
        session.peer_id = peer;
        session.state = net::HandshakeState::InitSent;
        session.local_ephemeral_priv = x_priv;
        session.local_ephemeral_pub = x_pub;
        session.started_at_ms = time::now_ms();

        CHECK(session.peer_id == peer);
        CHECK(session.state == net::HandshakeState::InitSent);
    }

}

TEST_SUITE("DataPlane - Serialization") {

    TEST_CASE("HandshakeInit serialization roundtrip") {
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId initiator = crypto::node_id_from_pubkey(ed_pub);

        net::HandshakeInit original;
        original.initiator_id = initiator;
        original.initiator_x25519 = x_pub;
        original.timestamp_ms = time::now_ms();
        original.nonce = crypto::generate_nonce();

        // Serialize
        auto buf = dp::serialize<dp::Mode::WITH_VERSION>(original);
        Vector<u8> payload;
        for (const auto &b : buf) {
            payload.push_back(b);
        }

        // Deserialize
        auto result = serial::deserialize<net::HandshakeInit>(payload);
        REQUIRE(result.is_ok());

        auto &deserialized = result.value();
        CHECK(deserialized.initiator_id == original.initiator_id);
        CHECK(deserialized.initiator_x25519 == original.initiator_x25519);
        CHECK(deserialized.timestamp_ms == original.timestamp_ms);
    }

    TEST_CASE("HandshakeResp serialization roundtrip") {
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId responder = crypto::node_id_from_pubkey(ed_pub);

        net::HandshakeResp original;
        original.responder_id = responder;
        original.responder_x25519 = x_pub;
        original.timestamp_ms = time::now_ms();
        original.nonce = crypto::generate_nonce();
        original.encrypted_ack = {0xAA, 0xBB, 0xCC, 0xDD};

        // Serialize
        auto buf = dp::serialize<dp::Mode::WITH_VERSION>(original);
        Vector<u8> payload;
        for (const auto &b : buf) {
            payload.push_back(b);
        }

        // Deserialize
        auto result = serial::deserialize<net::HandshakeResp>(payload);
        REQUIRE(result.is_ok());

        auto &deserialized = result.value();
        CHECK(deserialized.responder_id == original.responder_id);
        CHECK(deserialized.encrypted_ack.size() == 4);
    }

    TEST_CASE("KeepalivePacket serialization roundtrip") {
        net::KeepalivePacket original;
        original.key_id = 12345;
        original.timestamp_ms = time::now_ms();

        // Serialize
        auto buf = dp::serialize<dp::Mode::WITH_VERSION>(original);
        Vector<u8> payload;
        for (const auto &b : buf) {
            payload.push_back(b);
        }

        // Deserialize
        auto result = serial::deserialize<net::KeepalivePacket>(payload);
        REQUIRE(result.is_ok());

        auto &deserialized = result.value();
        CHECK(deserialized.key_id == 12345);
        CHECK(deserialized.timestamp_ms == original.timestamp_ms);
    }

    TEST_CASE("RekeyRequest serialization roundtrip") {
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId sender = crypto::node_id_from_pubkey(ed_pub);

        net::RekeyRequest original;
        original.sender_id = sender;
        original.new_x25519 = x_pub;
        original.new_key_id = 999;
        original.timestamp_ms = time::now_ms();

        // Serialize
        auto buf = dp::serialize<dp::Mode::WITH_VERSION>(original);
        Vector<u8> payload;
        for (const auto &b : buf) {
            payload.push_back(b);
        }

        // Deserialize
        auto result = serial::deserialize<net::RekeyRequest>(payload);
        REQUIRE(result.is_ok());

        auto &deserialized = result.value();
        CHECK(deserialized.sender_id == original.sender_id);
        CHECK(deserialized.new_key_id == 999);
    }

}

TEST_SUITE("DataPlane - DataMsgType") {

    TEST_CASE("DataMsgType enum values") {
        CHECK(static_cast<u8>(net::DataMsgType::HandshakeInit) == 0x20);
        CHECK(static_cast<u8>(net::DataMsgType::HandshakeResp) == 0x21);
        CHECK(static_cast<u8>(net::DataMsgType::Data) == 0x22);
        CHECK(static_cast<u8>(net::DataMsgType::Keepalive) == 0x23);
        CHECK(static_cast<u8>(net::DataMsgType::Rekey) == 0x24);
    }

}

TEST_SUITE("DataPlane - HandshakeState") {

    TEST_CASE("HandshakeState enum values") {
        CHECK(static_cast<u8>(net::HandshakeState::None) == 0);
        CHECK(static_cast<u8>(net::HandshakeState::InitSent) == 1);
        CHECK(static_cast<u8>(net::HandshakeState::InitReceived) == 2);
        CHECK(static_cast<u8>(net::HandshakeState::Complete) == 3);
        CHECK(static_cast<u8>(net::HandshakeState::Failed) == 4);
    }

}
