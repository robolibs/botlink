/* SPDX-License-Identifier: MIT */
/*
 * Botlink Crypto Tests
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Crypto - Identity") {

    TEST_CASE("Ed25519 keypair generation") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        CHECK_FALSE(priv.is_zero());
        CHECK_FALSE(pub.is_zero());
    }

    TEST_CASE("Ed25519 keypairs are unique") {
        auto [priv1, pub1] = crypto::generate_ed25519_keypair();
        auto [priv2, pub2] = crypto::generate_ed25519_keypair();

        CHECK(priv1.data != priv2.data);
        CHECK(pub1 != pub2);
    }

    TEST_CASE("X25519 keypair generation") {
        auto [priv, pub] = crypto::generate_x25519_keypair();

        CHECK_FALSE(priv.is_zero());
        CHECK_FALSE(pub.is_zero());
    }

    TEST_CASE("X25519 keypairs are unique") {
        auto [priv1, pub1] = crypto::generate_x25519_keypair();
        auto [priv2, pub2] = crypto::generate_x25519_keypair();

        CHECK(priv1.data != priv2.data);
        CHECK(pub1 != pub2);
    }

    TEST_CASE("NodeId derivation from public key") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId id = crypto::node_id_from_pubkey(pub);

        CHECK_FALSE(id.is_zero());

        // Same key should produce same ID
        NodeId id2 = crypto::node_id_from_pubkey(pub);
        CHECK(id == id2);
    }

    TEST_CASE("Different keys produce different NodeIds") {
        auto [priv1, pub1] = crypto::generate_ed25519_keypair();
        auto [priv2, pub2] = crypto::generate_ed25519_keypair();

        NodeId id1 = crypto::node_id_from_pubkey(pub1);
        NodeId id2 = crypto::node_id_from_pubkey(pub2);

        CHECK(id1 != id2);
    }

    TEST_CASE("NodeId hex encoding") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId id = crypto::node_id_from_pubkey(pub);

        String hex = crypto::node_id_to_hex(id);
        CHECK(hex.size() == NODE_ID_SIZE * 2);

        // Verify hex is consistent
        String hex2 = crypto::node_id_to_hex(id);
        CHECK(hex == hex2);
    }

    TEST_CASE("NodeId hex contains valid hex characters") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId id = crypto::node_id_from_pubkey(pub);

        String hex = crypto::node_id_to_hex(id);
        for (usize i = 0; i < hex.size(); ++i) {
            char c = hex[i];
            bool is_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            CHECK(is_hex);
        }
    }

    TEST_CASE("Key base64 encoding/decoding") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        KeyB64 b64 = crypto::key_to_base64(pub);
        CHECK(b64.data[0] != '\0'); // Not empty

        auto decoded = crypto::public_key_from_base64(b64);
        CHECK(decoded.is_ok());
        CHECK(decoded.value() == pub);
    }

    TEST_CASE("Private key base64 encoding/decoding") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        KeyB64 b64 = crypto::key_to_base64(priv);
        CHECK(b64.data[0] != '\0'); // Not empty

        auto decoded = crypto::private_key_from_base64(b64);
        CHECK(decoded.is_ok());
        CHECK(decoded.value().data == priv.data);
    }

    TEST_CASE("X25519 shared secret") {
        auto [priv1, pub1] = crypto::generate_x25519_keypair();
        auto [priv2, pub2] = crypto::generate_x25519_keypair();

        auto secret1 = crypto::x25519_shared_secret(priv1, pub2);
        CHECK(secret1.is_ok());

        auto secret2 = crypto::x25519_shared_secret(priv2, pub1);
        CHECK(secret2.is_ok());

        // Both parties should derive same shared secret
        CHECK(secret1.value() == secret2.value());
    }

    TEST_CASE("X25519 shared secret is not zero") {
        auto [priv1, pub1] = crypto::generate_x25519_keypair();
        auto [priv2, pub2] = crypto::generate_x25519_keypair();

        auto secret = crypto::x25519_shared_secret(priv1, pub2);
        REQUIRE(secret.is_ok());

        bool all_zero = true;
        for (usize i = 0; i < 32; ++i) {
            if (secret.value()[i] != 0) {
                all_zero = false;
                break;
            }
        }
        CHECK_FALSE(all_zero);
    }

    TEST_CASE("Different key pairs produce different shared secrets") {
        auto [priv1, pub1] = crypto::generate_x25519_keypair();
        auto [priv2, pub2] = crypto::generate_x25519_keypair();
        auto [priv3, pub3] = crypto::generate_x25519_keypair();

        auto secret12 = crypto::x25519_shared_secret(priv1, pub2);
        auto secret13 = crypto::x25519_shared_secret(priv1, pub3);
        auto secret23 = crypto::x25519_shared_secret(priv2, pub3);

        REQUIRE(secret12.is_ok());
        REQUIRE(secret13.is_ok());
        REQUIRE(secret23.is_ok());

        CHECK(secret12.value() != secret13.value());
        CHECK(secret12.value() != secret23.value());
        CHECK(secret13.value() != secret23.value());
    }

    TEST_CASE("PrivateKey clear zeros the data") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        CHECK_FALSE(priv.is_zero());

        priv.clear();
        CHECK(priv.is_zero());
    }

    TEST_CASE("Nonce generation produces unique nonces") {
        auto n1 = crypto::generate_nonce();
        auto n2 = crypto::generate_nonce();
        auto n3 = crypto::generate_nonce();

        CHECK(n1.data != n2.data);
        CHECK(n1.data != n3.data);
        CHECK(n2.data != n3.data);
    }

}

TEST_SUITE("Crypto - Signing") {

    TEST_CASE("Ed25519 sign and verify") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        Vector<u8> message;
        message.push_back('H');
        message.push_back('e');
        message.push_back('l');
        message.push_back('l');
        message.push_back('o');

        Signature sig = crypto::ed25519_sign(priv, message);
        CHECK_FALSE(sig.is_zero());

        bool valid = crypto::ed25519_verify(pub, message, sig);
        CHECK(valid);
    }

    TEST_CASE("Sign empty message") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        Vector<u8> message; // Empty

        Signature sig = crypto::ed25519_sign(priv, message);
        CHECK_FALSE(sig.is_zero());

        bool valid = crypto::ed25519_verify(pub, message, sig);
        CHECK(valid);
    }

    TEST_CASE("Sign large message") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        Vector<u8> message;
        for (int i = 0; i < 10000; ++i) {
            message.push_back(static_cast<u8>(i % 256));
        }

        Signature sig = crypto::ed25519_sign(priv, message);
        CHECK_FALSE(sig.is_zero());

        bool valid = crypto::ed25519_verify(pub, message, sig);
        CHECK(valid);
    }

    TEST_CASE("Same message produces different signatures with different keys") {
        auto [priv1, pub1] = crypto::generate_ed25519_keypair();
        auto [priv2, pub2] = crypto::generate_ed25519_keypair();

        Vector<u8> message;
        message.push_back('T');
        message.push_back('e');
        message.push_back('s');
        message.push_back('t');

        Signature sig1 = crypto::ed25519_sign(priv1, message);
        Signature sig2 = crypto::ed25519_sign(priv2, message);

        CHECK(sig1.data != sig2.data);
    }

    TEST_CASE("Signature verification fails with wrong message") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        Vector<u8> message;
        message.push_back('A');

        Signature sig = crypto::ed25519_sign(priv, message);

        Vector<u8> wrong_message;
        wrong_message.push_back('B');

        bool valid = crypto::ed25519_verify(pub, wrong_message, sig);
        CHECK_FALSE(valid);
    }

    TEST_CASE("Signature verification fails with modified message") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        Vector<u8> message;
        message.push_back('O');
        message.push_back('r');
        message.push_back('i');
        message.push_back('g');

        Signature sig = crypto::ed25519_sign(priv, message);

        // Modify one byte
        message[2] = 'X';

        bool valid = crypto::ed25519_verify(pub, message, sig);
        CHECK_FALSE(valid);
    }

    TEST_CASE("Signature verification fails with wrong key") {
        auto [priv1, pub1] = crypto::generate_ed25519_keypair();
        auto [priv2, pub2] = crypto::generate_ed25519_keypair();

        Vector<u8> message;
        message.push_back('X');

        Signature sig = crypto::ed25519_sign(priv1, message);

        bool valid = crypto::ed25519_verify(pub2, message, sig);
        CHECK_FALSE(valid);
    }

    TEST_CASE("Signature is deterministic for same key and message") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();

        Vector<u8> message;
        message.push_back('D');
        message.push_back('e');
        message.push_back('t');

        Signature sig1 = crypto::ed25519_sign(priv, message);
        Signature sig2 = crypto::ed25519_sign(priv, message);

        CHECK(sig1.data == sig2.data);
    }

}

TEST_SUITE("Crypto - Envelope") {

    TEST_CASE("Create and verify signed envelope") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(pub);

        Vector<u8> payload;
        payload.push_back(0x01);
        payload.push_back(0x02);
        payload.push_back(0x03);

        Envelope env = crypto::create_signed_envelope(MsgType::Data, node_id, priv, payload);

        CHECK(env.version == 1);
        CHECK(env.msg_type == MsgType::Data);
        CHECK(env.sender_id == node_id);
        CHECK(env.payload == payload);

        bool valid = crypto::verify_envelope(env, pub);
        CHECK(valid);
    }

    TEST_CASE("Envelope serialization round-trip") {
        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(pub);

        Vector<u8> payload;
        payload.push_back(0xAB);
        payload.push_back(0xCD);

        Envelope env = crypto::create_signed_envelope(MsgType::HandshakeInit, node_id, priv, payload);

        Vector<u8> serialized = crypto::serialize_envelope(env);
        CHECK_FALSE(serialized.empty());

        auto deserialized = crypto::deserialize_envelope(serialized);
        CHECK(deserialized.is_ok());
        CHECK(deserialized.value().version == env.version);
        CHECK(deserialized.value().msg_type == env.msg_type);
        CHECK(deserialized.value().sender_id == env.sender_id);
        CHECK(deserialized.value().payload == env.payload);
    }

}

TEST_SUITE("Crypto - KDF") {

    TEST_CASE("Session key derivation") {
        auto [priv1, pub1] = crypto::generate_x25519_keypair();
        auto [priv2, pub2] = crypto::generate_x25519_keypair();

        auto secret = crypto::x25519_shared_secret(priv1, pub2);
        REQUIRE(secret.is_ok());

        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId id1 = crypto::node_id_from_pubkey(ed_pub1);
        NodeId id2 = crypto::node_id_from_pubkey(ed_pub2);

        auto [send_key, recv_key] = crypto::derive_initiator_keys(secret.value(), id1, id2, 1);

        CHECK_FALSE(send_key.is_zero());
        CHECK_FALSE(recv_key.is_zero());
        CHECK(send_key.key_id == 1);
        CHECK(recv_key.key_id == 1);
    }

    TEST_CASE("Initiator and responder keys are symmetric") {
        auto [priv1, pub1] = crypto::generate_x25519_keypair();
        auto [priv2, pub2] = crypto::generate_x25519_keypair();

        auto secret = crypto::x25519_shared_secret(priv1, pub2);
        REQUIRE(secret.is_ok());

        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId id1 = crypto::node_id_from_pubkey(ed_pub1);
        NodeId id2 = crypto::node_id_from_pubkey(ed_pub2);

        auto [init_send, init_recv] = crypto::derive_initiator_keys(secret.value(), id1, id2, 1);
        auto [resp_send, resp_recv] = crypto::derive_responder_keys(secret.value(), id1, id2, 1);

        // Initiator's send = Responder's recv
        CHECK(init_send.data == resp_recv.data);
        // Initiator's recv = Responder's send
        CHECK(init_recv.data == resp_send.data);
    }

    TEST_CASE("Rekey produces different key") {
        crypto::SessionKey key;
        auto random = keylock::crypto::Common::generate_random_bytes(32);
        for (usize i = 0; i < 32; ++i) {
            key.data[i] = random[i];
        }
        key.key_id = 1;

        crypto::SessionKey new_key = crypto::rekey(key);

        CHECK(new_key.key_id == 2);
        CHECK(new_key.data != key.data);
    }

    TEST_CASE("Nonce from counter") {
        crypto::Nonce n1 = crypto::nonce_from_counter(0);
        crypto::Nonce n2 = crypto::nonce_from_counter(1);
        crypto::Nonce n3 = crypto::nonce_from_counter(0);

        CHECK(n1.data != n2.data);
        CHECK(n1.data == n3.data);
    }

}

TEST_SUITE("Crypto - AEAD") {

    TEST_CASE("AEAD encrypt and decrypt") {
        crypto::SessionKey key;
        auto random = keylock::crypto::Common::generate_random_bytes(32);
        for (usize i = 0; i < 32; ++i) {
            key.data[i] = random[i];
        }
        key.key_id = 1;

        Vector<u8> plaintext;
        const char *msg = "Hello, World!";
        for (const char *p = msg; *p; ++p) {
            plaintext.push_back(static_cast<u8>(*p));
        }

        auto nonce = crypto::generate_nonce();
        auto ct_result = crypto::aead_encrypt(key, nonce, plaintext);
        REQUIRE(ct_result.is_ok());

        // Ciphertext should be larger due to auth tag
        CHECK(ct_result.value().size() == plaintext.size() + crypto::TAG_SIZE);

        auto pt_result = crypto::aead_decrypt(key, nonce, ct_result.value());
        REQUIRE(pt_result.is_ok());
        CHECK(pt_result.value() == plaintext);
    }

    TEST_CASE("AEAD fails with wrong key") {
        crypto::SessionKey key1, key2;
        auto r1 = keylock::crypto::Common::generate_random_bytes(32);
        auto r2 = keylock::crypto::Common::generate_random_bytes(32);
        for (usize i = 0; i < 32; ++i) {
            key1.data[i] = r1[i];
            key2.data[i] = r2[i];
        }

        Vector<u8> plaintext;
        plaintext.push_back(0x42);

        auto nonce = crypto::generate_nonce();
        auto ct_result = crypto::aead_encrypt(key1, nonce, plaintext);
        REQUIRE(ct_result.is_ok());

        auto pt_result = crypto::aead_decrypt(key2, nonce, ct_result.value());
        CHECK(pt_result.is_err());
    }

    TEST_CASE("AEAD fails with wrong nonce") {
        crypto::SessionKey key;
        auto random = keylock::crypto::Common::generate_random_bytes(32);
        for (usize i = 0; i < 32; ++i) {
            key.data[i] = random[i];
        }

        Vector<u8> plaintext;
        plaintext.push_back(0x42);

        auto nonce1 = crypto::generate_nonce();
        auto nonce2 = crypto::generate_nonce();

        auto ct_result = crypto::aead_encrypt(key, nonce1, plaintext);
        REQUIRE(ct_result.is_ok());

        auto pt_result = crypto::aead_decrypt(key, nonce2, ct_result.value());
        CHECK(pt_result.is_err());
    }

    TEST_CASE("Data packet encrypt and decrypt") {
        crypto::SessionKey key;
        auto random = keylock::crypto::Common::generate_random_bytes(32);
        for (usize i = 0; i < 32; ++i) {
            key.data[i] = random[i];
        }
        key.key_id = 42;

        Vector<u8> plaintext;
        plaintext.push_back(0xDE);
        plaintext.push_back(0xAD);
        plaintext.push_back(0xBE);
        plaintext.push_back(0xEF);

        auto pkt_result = crypto::encrypt_packet(key, 123, plaintext);
        REQUIRE(pkt_result.is_ok());

        auto &pkt = pkt_result.value();
        CHECK(pkt.version == 1);
        CHECK(pkt.packet_type == crypto::PACKET_TYPE_DATA);
        CHECK(pkt.key_id == 42);
        CHECK(pkt.nonce_counter == 123);

        auto decrypted = crypto::decrypt_packet(key, pkt);
        REQUIRE(decrypted.is_ok());
        CHECK(decrypted.value() == plaintext);
    }

    TEST_CASE("Data packet serialization") {
        crypto::DataPacket pkt;
        pkt.version = 1;
        pkt.packet_type = crypto::PACKET_TYPE_KEEPALIVE;
        pkt.key_id = 100;
        pkt.nonce_counter = 999;
        pkt.ciphertext = {0x01, 0x02, 0x03};

        Vector<u8> serialized = crypto::serialize_data_packet(pkt);
        CHECK_FALSE(serialized.empty());

        auto deserialized = crypto::deserialize_data_packet(serialized);
        REQUIRE(deserialized.is_ok());
        CHECK(deserialized.value().version == pkt.version);
        CHECK(deserialized.value().packet_type == pkt.packet_type);
        CHECK(deserialized.value().key_id == pkt.key_id);
        CHECK(deserialized.value().nonce_counter == pkt.nonce_counter);
        CHECK(deserialized.value().ciphertext == pkt.ciphertext);
    }

    TEST_CASE("Replay window") {
        crypto::ReplayWindow window;

        // First nonce should be accepted
        CHECK(window.check_and_update(1));
        CHECK(window.last_seen == 1);

        // Same nonce should be rejected
        CHECK_FALSE(window.check_and_update(1));

        // Higher nonce should be accepted
        CHECK(window.check_and_update(5));
        CHECK(window.last_seen == 5);

        // Nonce within window should be accepted (if not seen)
        CHECK(window.check_and_update(3));

        // Same nonce should be rejected
        CHECK_FALSE(window.check_and_update(3));

        // Very old nonce (beyond window) should be rejected
        // Window size is 64, so nonce 100+ behind last_seen should be rejected
        crypto::ReplayWindow window2;
        (void)window2.check_and_update(100);
        CHECK_FALSE(window2.check_and_update(1)); // 99 behind, beyond window
    }

}
