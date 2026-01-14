/* Botlink library test program */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

void test_types() {
    echo::info("=== Testing Types ===");

    // Test NodeId
    NodeId id;
    echo::info("NodeId is_zero: ", id.is_zero() ? "true" : "false");

    // Test Endpoint
    Endpoint ep(IPv4Addr(192, 168, 1, 1), 51820);
    echo::info("Endpoint is_ipv4: ", ep.is_ipv4() ? "true" : "false");
    echo::info("Endpoint port: ", ep.port);

    // Test Timestamp
    Timestamp ts(time::now_ms());
    echo::info("Timestamp ms: ", ts.ms);

    echo::info("Types test passed!");
}

void test_crypto() {
    echo::info("=== Testing Crypto ===");

    // Generate Ed25519 keypair
    auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
    echo::info("Generated Ed25519 keypair");

    // Generate X25519 keypair
    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
    echo::info("Generated X25519 keypair");

    // Derive NodeId
    NodeId node_id = crypto::node_id_from_pubkey(ed_pub);
    echo::info("Derived NodeId: ", crypto::node_id_to_hex(node_id).substr(0, 16).c_str(), "...");

    // Sign and verify
    Vector<u8> message;
    message.push_back('H');
    message.push_back('e');
    message.push_back('l');
    message.push_back('l');
    message.push_back('o');

    Signature sig = crypto::ed25519_sign(ed_priv, message);
    bool valid = crypto::ed25519_verify(ed_pub, message, sig);
    echo::info("Signature verification: ", valid ? "PASSED" : "FAILED");

    // Test base64 encoding/decoding
    KeyB64 b64 = crypto::key_to_base64(ed_pub);
    echo::info("Base64 encoded key: ", b64.c_str());

    auto decoded = crypto::public_key_from_base64(b64);
    if (decoded.is_ok() && decoded.value() == ed_pub) {
        echo::info("Base64 round-trip: PASSED");
    } else {
        echo::error("Base64 round-trip: FAILED");
    }

    echo::info("Crypto test passed!");
}

void test_envelope() {
    echo::info("=== Testing Envelope ===");

    // Generate keypair
    auto [priv_key, pub_key] = crypto::generate_ed25519_keypair();
    NodeId node_id = crypto::node_id_from_pubkey(pub_key);

    // Create payload
    Vector<u8> payload;
    payload.push_back(0x01);
    payload.push_back(0x02);
    payload.push_back(0x03);

    // Create and sign envelope
    Envelope env = crypto::create_signed_envelope(MsgType::Data, node_id, priv_key, payload);
    echo::info("Created envelope with type: ", static_cast<int>(env.msg_type));

    // Verify envelope
    bool valid = crypto::verify_envelope(env, pub_key);
    echo::info("Envelope verification: ", valid ? "PASSED" : "FAILED");

    // Serialize and deserialize
    Vector<u8> serialized = crypto::serialize_envelope(env);
    echo::info("Serialized envelope size: ", serialized.size());

    auto deserialized = crypto::deserialize_envelope(serialized);
    if (deserialized.is_ok()) {
        echo::info("Envelope deserialization: PASSED");
    } else {
        echo::error("Envelope deserialization: FAILED");
    }

    echo::info("Envelope test passed!");
}

void test_aead() {
    echo::info("=== Testing AEAD ===");

    // Create session key
    crypto::SessionKey key;
    auto random = keylock::utils::Common::generate_random_bytes(32);
    for (usize i = 0; i < 32; ++i) {
        key.data[i] = random[i];
    }
    key.key_id = 1;

    // Create plaintext
    Vector<u8> plaintext;
    const char *msg = "Hello, World!";
    for (const char *p = msg; *p; ++p) {
        plaintext.push_back(static_cast<u8>(*p));
    }

    // Encrypt
    auto nonce = crypto::generate_nonce();
    auto ct_result = crypto::aead_encrypt(key, nonce, plaintext);
    if (ct_result.is_err()) {
        echo::error("AEAD encryption failed: ", ct_result.error().message.c_str());
        return;
    }
    echo::info("Encrypted ciphertext size: ", ct_result.value().size());

    // Decrypt
    auto pt_result = crypto::aead_decrypt(key, nonce, ct_result.value());
    if (pt_result.is_err()) {
        echo::error("AEAD decryption failed: ", pt_result.error().message.c_str());
        return;
    }

    if (pt_result.value() == plaintext) {
        echo::info("AEAD round-trip: PASSED");
    } else {
        echo::error("AEAD round-trip: FAILED");
    }

    echo::info("AEAD test passed!");
}

void test_trust_view() {
    echo::info("=== Testing Trust View ===");

    TrustView view(2, 15000); // min 2 yes votes, 15s timeout

    // Generate some keys
    auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
    auto [x_priv1, x_pub1] = crypto::generate_x25519_keypair();
    NodeId node1 = crypto::node_id_from_pubkey(ed_pub1);

    auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
    auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();
    NodeId node2 = crypto::node_id_from_pubkey(ed_pub2);

    // Add first member (genesis-like)
    MemberEntry entry1;
    entry1.node_id = node1;
    entry1.ed25519_pubkey = ed_pub1;
    entry1.x25519_pubkey = x_pub1;
    entry1.status = MemberStatus::Approved;
    entry1.joined_at_ms = time::now_ms();
    view.add_member(entry1);

    echo::info("Added genesis member");
    echo::info("Member count: ", view.member_count());
    echo::info("Is node1 member: ", view.is_member(node1) ? "true" : "false");
    echo::info("Is node2 member: ", view.is_member(node2) ? "true" : "false");

    echo::info("Trust View test passed!");
}

void test_network() {
    echo::info("=== Testing Network ===");

    // Test endpoint parsing
    auto ep_result = net::parse_endpoint("192.168.1.1:51820");
    if (ep_result.is_ok()) {
        auto &ep = ep_result.value();
        echo::info("Parsed endpoint: ", net::format_endpoint(ep).c_str());
    } else {
        echo::error("Failed to parse endpoint");
    }

    // Test IPv6 endpoint parsing
    auto ep6_result = net::parse_endpoint("[::1]:8080");
    if (ep6_result.is_ok()) {
        auto &ep = ep6_result.value();
        echo::info("Parsed IPv6 endpoint: ", net::format_endpoint(ep).c_str());
    } else {
        echo::error("Failed to parse IPv6 endpoint");
    }

    echo::info("Network test passed!");
}

void test_peer_table() {
    echo::info("=== Testing Peer Table ===");

    PeerTable table(25000, 120000, 180000);

    // Generate keys for two peers
    auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
    auto [x_priv1, x_pub1] = crypto::generate_x25519_keypair();
    NodeId node1 = crypto::node_id_from_pubkey(ed_pub1);

    auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
    auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();
    NodeId node2 = crypto::node_id_from_pubkey(ed_pub2);

    // Add peers
    table.add_peer(node1, ed_pub1, x_pub1);
    table.add_peer(node2, ed_pub2, x_pub2);

    echo::info("Peer count: ", table.peer_count());
    echo::info("Connected count: ", table.connected_count());

    // Create a session
    crypto::SessionKey send_key, recv_key;
    auto rnd1 = keylock::utils::Common::generate_random_bytes(32);
    auto rnd2 = keylock::utils::Common::generate_random_bytes(32);
    for (usize i = 0; i < 32; ++i) {
        send_key.data[i] = rnd1[i];
        recv_key.data[i] = rnd2[i];
    }
    send_key.key_id = 1;
    recv_key.key_id = 1;

    table.create_session(node1, send_key, recv_key);
    echo::info("Connected count after session: ", table.connected_count());

    auto peer = table.get_peer(node1);
    if (peer.has_value() && (*peer)->is_connected()) {
        echo::info("Peer 1 is connected: true");
    }

    echo::info("Peer Table test passed!");
}

auto main() -> int {
    echo::info("Botlink Library Test");
    echo::info("====================\n");

    // Initialize libsodium
    auto init_result = botlink::init();
    if (init_result.is_err()) {
        echo::error("Failed to initialize: ", init_result.error().message.c_str());
        return 1;
    }
    echo::info("Botlink initialized (libsodium ready)\n");

    test_types();
    echo::info("");

    test_crypto();
    echo::info("");

    test_envelope();
    echo::info("");

    test_aead();
    echo::info("");

    test_trust_view();
    echo::info("");

    test_network();
    echo::info("");

    test_peer_table();
    echo::info("");

    echo::info("All tests passed!");
    return 0;
}
