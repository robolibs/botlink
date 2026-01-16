/* SPDX-License-Identifier: MIT */
/*
 * Botlink KDF Tests
 * Tests for key derivation functions
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("KDF - Constants") {

    TEST_CASE("Key sizes are correct") {
        CHECK(crypto::SESSION_KEY_SIZE == 32);
        CHECK(crypto::NONCE_SIZE == 24);
        CHECK(crypto::HKDF_SALT_SIZE == 32);
        CHECK(crypto::HANDSHAKE_HASH_SIZE == 32);
    }

}

TEST_SUITE("KDF - SessionKey") {

    TEST_CASE("SessionKey default construction") {
        crypto::SessionKey key;
        CHECK(key.key_id == 0);
        CHECK(key.is_zero() == true);
    }

    TEST_CASE("SessionKey is_zero after setting data") {
        crypto::SessionKey key;
        key.data[0] = 1;
        CHECK(key.is_zero() == false);
    }

    TEST_CASE("SessionKey clear") {
        crypto::SessionKey key;
        key.key_id = 42;
        key.data[0] = 0xFF;
        key.data[15] = 0xAB;

        key.clear();

        CHECK(key.key_id == 0);
        CHECK(key.is_zero() == true);
    }

    TEST_CASE("SessionKey copy constructor") {
        crypto::SessionKey key1;
        key1.key_id = 123;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            key1.data[i] = static_cast<u8>(i);
        }

        crypto::SessionKey key2 = key1;

        CHECK(key2.key_id == 123);
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            CHECK(key2.data[i] == static_cast<u8>(i));
        }
    }

    TEST_CASE("SessionKey copy assignment") {
        crypto::SessionKey key1;
        key1.key_id = 456;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            key1.data[i] = static_cast<u8>(i + 10);
        }

        crypto::SessionKey key2;
        key2 = key1;

        CHECK(key2.key_id == 456);
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            CHECK(key2.data[i] == static_cast<u8>(i + 10));
        }
    }

    TEST_CASE("SessionKey move constructor clears source") {
        crypto::SessionKey key1;
        key1.key_id = 789;
        key1.data[0] = 0xFF;

        crypto::SessionKey key2 = std::move(key1);

        CHECK(key2.key_id == 789);
        CHECK(key2.data[0] == 0xFF);
        // Source should be cleared
        CHECK(key1.key_id == 0);
        CHECK(key1.is_zero() == true);
    }

    TEST_CASE("SessionKey move assignment clears source") {
        crypto::SessionKey key1;
        key1.key_id = 111;
        key1.data[0] = 0xAA;

        crypto::SessionKey key2;
        key2 = std::move(key1);

        CHECK(key2.key_id == 111);
        CHECK(key2.data[0] == 0xAA);
        CHECK(key1.key_id == 0);
        CHECK(key1.is_zero() == true);
    }

    TEST_CASE("SessionKey raw accessors") {
        crypto::SessionKey key;
        key.data[0] = 0x42;

        CHECK(key.raw()[0] == 0x42);

        const crypto::SessionKey& const_key = key;
        CHECK(const_key.raw()[0] == 0x42);
    }

}

TEST_SUITE("KDF - Nonce") {

    TEST_CASE("Nonce default construction") {
        crypto::Nonce nonce;
        for (usize i = 0; i < crypto::NONCE_SIZE; ++i) {
            CHECK(nonce.data[i] == 0);
        }
    }

    TEST_CASE("Nonce increment") {
        crypto::Nonce nonce;
        nonce.increment();

        CHECK(nonce.data[0] == 1);
        for (usize i = 1; i < crypto::NONCE_SIZE; ++i) {
            CHECK(nonce.data[i] == 0);
        }
    }

    TEST_CASE("Nonce increment with carry") {
        crypto::Nonce nonce;
        nonce.data[0] = 0xFF;

        nonce.increment();

        CHECK(nonce.data[0] == 0);
        CHECK(nonce.data[1] == 1);
    }

    TEST_CASE("Nonce raw accessors") {
        crypto::Nonce nonce;
        nonce.data[5] = 0x99;

        CHECK(nonce.raw()[5] == 0x99);
    }

}

TEST_SUITE("KDF - HKDF Functions") {

    TEST_CASE("hkdf_extract produces non-zero output") {
        u8 salt[] = {0x01, 0x02, 0x03, 0x04};
        u8 ikm[] = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e};

        auto prk = crypto::hkdf_extract(salt, 4, ikm, 5);

        // Should produce non-zero output
        bool all_zero = true;
        for (usize i = 0; i < prk.size(); ++i) {
            if (prk[i] != 0) {
                all_zero = false;
                break;
            }
        }
        CHECK(all_zero == false);
    }

    TEST_CASE("hkdf_extract is deterministic") {
        u8 salt[] = {0x01, 0x02};
        u8 ikm[] = {0x0a, 0x0b};

        auto prk1 = crypto::hkdf_extract(salt, 2, ikm, 2);
        auto prk2 = crypto::hkdf_extract(salt, 2, ikm, 2);

        for (usize i = 0; i < crypto::HANDSHAKE_HASH_SIZE; ++i) {
            CHECK(prk1[i] == prk2[i]);
        }
    }

    TEST_CASE("hkdf produces requested output length") {
        u8 salt[] = {0x01};
        u8 ikm[] = {0x02};
        u8 info[] = {0x03};

        auto out32 = crypto::hkdf(salt, 1, ikm, 1, info, 1, 32);
        CHECK(out32.size() == 32);

        auto out64 = crypto::hkdf(salt, 1, ikm, 1, info, 1, 64);
        CHECK(out64.size() == 64);

        auto out100 = crypto::hkdf(salt, 1, ikm, 1, info, 1, 100);
        CHECK(out100.size() == 100);
    }

    TEST_CASE("hkdf different info produces different output") {
        u8 salt[] = {0x01};
        u8 ikm[] = {0x02};
        u8 info1[] = {0x03};
        u8 info2[] = {0x04};

        auto out1 = crypto::hkdf(salt, 1, ikm, 1, info1, 1, 32);
        auto out2 = crypto::hkdf(salt, 1, ikm, 1, info2, 1, 32);

        bool differ = false;
        for (usize i = 0; i < 32; ++i) {
            if (out1[i] != out2[i]) {
                differ = true;
                break;
            }
        }
        CHECK(differ == true);
    }

}

TEST_SUITE("KDF - Session Key Derivation") {

    TEST_CASE("derive_session_keys produces different send/recv keys") {
        Array<u8, 32> shared_secret{};
        for (usize i = 0; i < 32; ++i) {
            shared_secret[i] = static_cast<u8>(i);
        }

        NodeId initiator, responder;
        for (usize i = 0; i < NODE_ID_SIZE; ++i) {
            initiator.data[i] = static_cast<u8>(i);
            responder.data[i] = static_cast<u8>(i + 100);
        }

        auto [send_key, recv_key] = crypto::derive_session_keys(shared_secret, initiator, responder, 1);

        // Keys should be different
        bool differ = false;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            if (send_key.data[i] != recv_key.data[i]) {
                differ = true;
                break;
            }
        }
        CHECK(differ == true);
        CHECK(send_key.key_id == 1);
        CHECK(recv_key.key_id == 1);
    }

    TEST_CASE("derive_initiator_keys and derive_responder_keys are compatible") {
        Array<u8, 32> shared_secret{};
        for (usize i = 0; i < 32; ++i) {
            shared_secret[i] = static_cast<u8>(i * 2);
        }

        NodeId alice, bob;
        for (usize i = 0; i < NODE_ID_SIZE; ++i) {
            alice.data[i] = static_cast<u8>(i);
            bob.data[i] = static_cast<u8>(i + 50);
        }

        // Alice (initiator) derives keys
        auto [alice_send, alice_recv] = crypto::derive_initiator_keys(shared_secret, alice, bob, 1);

        // Bob (responder) derives keys
        auto [bob_send, bob_recv] = crypto::derive_responder_keys(shared_secret, alice, bob, 1);

        // Alice's send should equal Bob's recv
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            CHECK(alice_send.data[i] == bob_recv.data[i]);
        }

        // Alice's recv should equal Bob's send
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            CHECK(alice_recv.data[i] == bob_send.data[i]);
        }
    }

}

TEST_SUITE("KDF - Rekey") {

    TEST_CASE("rekey produces different key") {
        crypto::SessionKey old_key;
        old_key.key_id = 5;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            old_key.data[i] = static_cast<u8>(i);
        }

        crypto::SessionKey new_key = crypto::rekey(old_key);

        // Key ID should increment
        CHECK(new_key.key_id == 6);

        // Key material should be different
        bool differ = false;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            if (new_key.data[i] != old_key.data[i]) {
                differ = true;
                break;
            }
        }
        CHECK(differ == true);
    }

    TEST_CASE("rekey is deterministic") {
        crypto::SessionKey old_key;
        old_key.key_id = 10;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            old_key.data[i] = static_cast<u8>(i + 20);
        }

        crypto::SessionKey new_key1 = crypto::rekey(old_key);
        crypto::SessionKey new_key2 = crypto::rekey(old_key);

        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            CHECK(new_key1.data[i] == new_key2.data[i]);
        }
    }

    TEST_CASE("Multiple rekeys produce chain of keys") {
        crypto::SessionKey key;
        key.key_id = 0;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            key.data[i] = static_cast<u8>(i);
        }

        for (int round = 1; round <= 5; ++round) {
            key = crypto::rekey(key);
            CHECK(key.key_id == static_cast<u32>(round));
            CHECK(key.is_zero() == false);
        }
    }

}

TEST_SUITE("KDF - Nonce Generation") {

    TEST_CASE("generate_nonce produces non-zero nonce") {
        crypto::Nonce nonce = crypto::generate_nonce();

        bool all_zero = true;
        for (usize i = 0; i < crypto::NONCE_SIZE; ++i) {
            if (nonce.data[i] != 0) {
                all_zero = false;
                break;
            }
        }
        // Should be extremely unlikely to generate all zeros
        CHECK(all_zero == false);
    }

    TEST_CASE("generate_nonce produces different nonces") {
        crypto::Nonce n1 = crypto::generate_nonce();
        crypto::Nonce n2 = crypto::generate_nonce();

        bool differ = false;
        for (usize i = 0; i < crypto::NONCE_SIZE; ++i) {
            if (n1.data[i] != n2.data[i]) {
                differ = true;
                break;
            }
        }
        CHECK(differ == true);
    }

    TEST_CASE("nonce_from_counter creates deterministic nonces") {
        crypto::Nonce n1 = crypto::nonce_from_counter(12345);
        crypto::Nonce n2 = crypto::nonce_from_counter(12345);

        for (usize i = 0; i < crypto::NONCE_SIZE; ++i) {
            CHECK(n1.data[i] == n2.data[i]);
        }
    }

    TEST_CASE("nonce_from_counter encodes counter correctly") {
        crypto::Nonce nonce = crypto::nonce_from_counter(0x0102030405060708ULL);

        // Little endian encoding
        CHECK(nonce.data[0] == 0x08);
        CHECK(nonce.data[1] == 0x07);
        CHECK(nonce.data[2] == 0x06);
        CHECK(nonce.data[3] == 0x05);
        CHECK(nonce.data[4] == 0x04);
        CHECK(nonce.data[5] == 0x03);
        CHECK(nonce.data[6] == 0x02);
        CHECK(nonce.data[7] == 0x01);

        // Rest should be zero
        for (usize i = 8; i < crypto::NONCE_SIZE; ++i) {
            CHECK(nonce.data[i] == 0);
        }
    }

    TEST_CASE("Different counters produce different nonces") {
        crypto::Nonce n1 = crypto::nonce_from_counter(1);
        crypto::Nonce n2 = crypto::nonce_from_counter(2);

        bool differ = false;
        for (usize i = 0; i < crypto::NONCE_SIZE; ++i) {
            if (n1.data[i] != n2.data[i]) {
                differ = true;
                break;
            }
        }
        CHECK(differ == true);
    }

}

TEST_SUITE("KDF - Key ID Generation") {

    TEST_CASE("generate_key_id produces non-zero ID") {
        // Run multiple times since random could technically produce 0
        bool found_nonzero = false;
        for (int i = 0; i < 10; ++i) {
            u32 id = crypto::generate_key_id();
            if (id != 0) {
                found_nonzero = true;
                break;
            }
        }
        CHECK(found_nonzero == true);
    }

    TEST_CASE("generate_key_id produces different IDs") {
        u32 id1 = crypto::generate_key_id();
        u32 id2 = crypto::generate_key_id();

        // Should be extremely unlikely to get same random ID
        CHECK(id1 != id2);
    }

}
