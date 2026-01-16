/* SPDX-License-Identifier: MIT */
/*
 * Botlink Handshake Tests
 * Tests for handshake message serialization and verification
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Handshake - Init Message") {

    TEST_CASE("HandshakeInit default values") {
        net::HandshakeInit init;
        CHECK(init.timestamp_ms == 0);
    }

    TEST_CASE("HandshakeInit with generated keys") {
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId initiator = crypto::node_id_from_pubkey(ed_pub);

        net::HandshakeInit init;
        init.initiator_id = initiator;
        init.initiator_x25519 = x_pub;
        init.timestamp_ms = time::now_ms();
        init.nonce = crypto::generate_nonce();

        CHECK_FALSE(init.initiator_id.is_zero());
        CHECK_FALSE(init.initiator_x25519.is_zero());
        CHECK(init.timestamp_ms > 0);
        // Nonce data should have some non-zero bytes
        CHECK(init.nonce.data.size() == crypto::NONCE_SIZE);
    }

    TEST_CASE("HandshakeInit serialization roundtrip") {
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId initiator = crypto::node_id_from_pubkey(ed_pub);

        net::HandshakeInit original;
        original.initiator_id = initiator;
        original.initiator_x25519 = x_pub;
        original.timestamp_ms = time::now_ms();
        original.nonce = crypto::generate_nonce();

        auto bytes = serial::serialize(original);
        CHECK(bytes.size() > 0);

        auto result = serial::deserialize<net::HandshakeInit>(bytes);
        REQUIRE(result.is_ok());

        auto& parsed = result.value();
        CHECK(parsed.initiator_id == original.initiator_id);
        CHECK(parsed.initiator_x25519 == original.initiator_x25519);
        CHECK(parsed.timestamp_ms == original.timestamp_ms);
    }

}

TEST_SUITE("Handshake - Response Message") {

    TEST_CASE("HandshakeResp default values") {
        net::HandshakeResp resp;
        CHECK(resp.timestamp_ms == 0);
    }

    TEST_CASE("HandshakeResp with generated keys") {
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId responder = crypto::node_id_from_pubkey(ed_pub);

        net::HandshakeResp resp;
        resp.responder_id = responder;
        resp.responder_x25519 = x_pub;
        resp.timestamp_ms = time::now_ms();
        resp.nonce = crypto::generate_nonce();

        CHECK_FALSE(resp.responder_id.is_zero());
        CHECK_FALSE(resp.responder_x25519.is_zero());
        CHECK(resp.timestamp_ms > 0);
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

        auto bytes = serial::serialize(original);
        CHECK(bytes.size() > 0);

        auto result = serial::deserialize<net::HandshakeResp>(bytes);
        REQUIRE(result.is_ok());

        auto& parsed = result.value();
        CHECK(parsed.responder_id == original.responder_id);
        CHECK(parsed.responder_x25519 == original.responder_x25519);
        CHECK(parsed.timestamp_ms == original.timestamp_ms);
    }

}

TEST_SUITE("Handshake - Key Exchange") {

    TEST_CASE("X25519 shared secret is symmetric") {
        auto [priv_a, pub_a] = crypto::generate_x25519_keypair();
        auto [priv_b, pub_b] = crypto::generate_x25519_keypair();

        auto secret_a = crypto::x25519_shared_secret(priv_a, pub_b);
        auto secret_b = crypto::x25519_shared_secret(priv_b, pub_a);

        REQUIRE(secret_a.is_ok());
        REQUIRE(secret_b.is_ok());

        CHECK(secret_a.value() == secret_b.value());
    }

    TEST_CASE("Initiator and responder keys are complementary") {
        auto [priv_a, pub_a] = crypto::generate_x25519_keypair();
        auto [priv_b, pub_b] = crypto::generate_x25519_keypair();

        auto shared = crypto::x25519_shared_secret(priv_a, pub_b);
        REQUIRE(shared.is_ok());

        auto [ed_priv_a, ed_pub_a] = crypto::generate_ed25519_keypair();
        auto [ed_priv_b, ed_pub_b] = crypto::generate_ed25519_keypair();
        NodeId id_a = crypto::node_id_from_pubkey(ed_pub_a);
        NodeId id_b = crypto::node_id_from_pubkey(ed_pub_b);

        auto [init_send, init_recv] = crypto::derive_initiator_keys(shared.value(), id_a, id_b, 1);
        auto [resp_send, resp_recv] = crypto::derive_responder_keys(shared.value(), id_a, id_b, 1);

        // Initiator's send == Responder's recv
        CHECK(init_send.data == resp_recv.data);
        // Initiator's recv == Responder's send
        CHECK(init_recv.data == resp_send.data);
    }

    TEST_CASE("Different shared secrets produce different keys") {
        auto [priv_a1, pub_a1] = crypto::generate_x25519_keypair();
        auto [priv_b1, pub_b1] = crypto::generate_x25519_keypair();
        auto [priv_a2, pub_a2] = crypto::generate_x25519_keypair();
        auto [priv_b2, pub_b2] = crypto::generate_x25519_keypair();

        auto shared1 = crypto::x25519_shared_secret(priv_a1, pub_b1);
        auto shared2 = crypto::x25519_shared_secret(priv_a2, pub_b2);

        REQUIRE(shared1.is_ok());
        REQUIRE(shared2.is_ok());

        CHECK(shared1.value() != shared2.value());
    }

}

TEST_SUITE("Handshake - Keepalive") {

    TEST_CASE("KeepalivePacket default values") {
        net::KeepalivePacket ka;
        CHECK(ka.key_id == 0);
        CHECK(ka.timestamp_ms == 0);
    }

    TEST_CASE("KeepalivePacket serialization") {
        net::KeepalivePacket original;
        original.key_id = 42;
        original.timestamp_ms = time::now_ms();

        auto bytes = serial::serialize(original);
        CHECK(bytes.size() > 0);

        auto result = serial::deserialize<net::KeepalivePacket>(bytes);
        REQUIRE(result.is_ok());

        auto& parsed = result.value();
        CHECK(parsed.key_id == original.key_id);
        CHECK(parsed.timestamp_ms == original.timestamp_ms);
    }

}

TEST_SUITE("Handshake - Session Establishment") {

    TEST_CASE("Full handshake simulation") {
        // Generate identities for Alice and Bob
        auto [alice_x_priv, alice_x_pub] = crypto::generate_x25519_keypair();
        auto [alice_ed_priv, alice_ed_pub] = crypto::generate_ed25519_keypair();
        NodeId alice_id = crypto::node_id_from_pubkey(alice_ed_pub);

        auto [bob_x_priv, bob_x_pub] = crypto::generate_x25519_keypair();
        auto [bob_ed_priv, bob_ed_pub] = crypto::generate_ed25519_keypair();
        NodeId bob_id = crypto::node_id_from_pubkey(bob_ed_pub);

        // Alice creates HandshakeInit
        net::HandshakeInit init;
        init.initiator_id = alice_id;
        init.initiator_x25519 = alice_x_pub;
        init.timestamp_ms = time::now_ms();
        init.nonce = crypto::generate_nonce();

        // Bob receives init and creates response
        net::HandshakeResp resp;
        resp.responder_id = bob_id;
        resp.responder_x25519 = bob_x_pub;
        resp.timestamp_ms = time::now_ms();
        resp.nonce = crypto::generate_nonce();

        // Both derive shared secret
        auto alice_shared = crypto::x25519_shared_secret(alice_x_priv, bob_x_pub);
        auto bob_shared = crypto::x25519_shared_secret(bob_x_priv, alice_x_pub);

        REQUIRE(alice_shared.is_ok());
        REQUIRE(bob_shared.is_ok());
        CHECK(alice_shared.value() == bob_shared.value());

        // Derive session keys
        auto [alice_send, alice_recv] = crypto::derive_initiator_keys(alice_shared.value(), alice_id, bob_id, 1);
        auto [bob_send, bob_recv] = crypto::derive_responder_keys(bob_shared.value(), alice_id, bob_id, 1);

        // Verify key symmetry
        CHECK(alice_send.data == bob_recv.data);
        CHECK(alice_recv.data == bob_send.data);

        // Test encryption/decryption
        Vector<u8> message;
        const char* msg = "Hello from Alice!";
        for (const char* p = msg; *p; ++p) {
            message.push_back(static_cast<u8>(*p));
        }

        auto alice_ct = crypto::aead_encrypt(alice_send, crypto::nonce_from_counter(0), message);
        REQUIRE(alice_ct.is_ok());

        auto bob_pt = crypto::aead_decrypt(bob_recv, crypto::nonce_from_counter(0), alice_ct.value());
        REQUIRE(bob_pt.is_ok());
        CHECK(bob_pt.value() == message);
    }

}
