/* SPDX-License-Identifier: MIT */
/*
 * Botlink Encrypted Messaging Demo
 * Demonstrates secure message exchange between robots
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <sstream>

using namespace botlink;

// Simulated robot node
class RobotNode {
  public:
    dp::String name;
    PrivateKey ed_priv;
    PublicKey ed_pub;
    PrivateKey x_priv;
    PublicKey x_pub;
    NodeId node_id;

    // Session with another peer
    struct Session {
        NodeId peer_id;
        crypto::SessionKey send_key;
        crypto::SessionKey recv_key;
        dp::u64 send_counter = 0;
        crypto::ReplayWindow replay_window;
    };

    dp::Map<NodeId, Session> sessions;

    RobotNode(const dp::String &name) : name(name) {
        auto [ed_priv_, ed_pub_] = crypto::generate_ed25519_keypair();
        auto [x_priv_, x_pub_] = crypto::generate_x25519_keypair();
        ed_priv = ed_priv_;
        ed_pub = ed_pub_;
        x_priv = x_priv_;
        x_pub = x_pub_;
        node_id = crypto::node_id_from_pubkey(ed_pub);
    }

    dp::String short_id() const { return crypto::node_id_to_hex(node_id).substr(0, 8); }

    // Establish session with another node
    bool establish_session(RobotNode &peer, bool is_initiator) {
        // Compute shared secret
        auto shared = crypto::x25519_shared_secret(x_priv, peer.x_pub);
        if (shared.is_err()) {
            return false;
        }

        // Derive session keys
        Session session;
        session.peer_id = peer.node_id;

        if (is_initiator) {
            auto [send, recv] = crypto::derive_initiator_keys(shared.value(), node_id, peer.node_id, 1);
            session.send_key = send;
            session.recv_key = recv;
        } else {
            auto [send, recv] = crypto::derive_responder_keys(shared.value(), peer.node_id, node_id, 1);
            session.send_key = send;
            session.recv_key = recv;
        }

        sessions[peer.node_id] = session;
        return true;
    }

    // Encrypt and send a message
    botlink::Res<crypto::DataPacket> encrypt_message(const NodeId &peer_id, const dp::String &message) {
        auto it = sessions.find(peer_id);
        if (it == sessions.end()) {
            return botlink::result::err(botlink::err::not_found("No session with peer"));
        }

        auto &session = it->second;

        // Convert message to bytes
        dp::Vector<dp::u8> plaintext;
        for (dp::usize i = 0; i < message.size(); ++i) {
            plaintext.push_back(static_cast<dp::u8>(message[i]));
        }

        // Encrypt with counter
        auto pkt_result = crypto::encrypt_packet(session.send_key, session.send_counter++, plaintext);
        return pkt_result;
    }

    // Decrypt a received message
    botlink::Res<dp::String> decrypt_message(const NodeId &peer_id, const crypto::DataPacket &packet) {
        auto it = sessions.find(peer_id);
        if (it == sessions.end()) {
            return botlink::result::err(botlink::err::not_found("No session with peer"));
        }

        auto &session = it->second;

        // Check replay protection
        if (!session.replay_window.check_and_update(packet.nonce_counter)) {
            return botlink::result::err(botlink::err::permission("Replay detected"));
        }

        // Decrypt
        auto pt_result = crypto::decrypt_packet(session.recv_key, packet);
        if (pt_result.is_err()) {
            return botlink::result::err(pt_result.error());
        }

        // Convert to string
        dp::String message;
        for (dp::u8 b : pt_result.value()) {
            message += static_cast<char>(b);
        }

        return botlink::result::ok(message);
    }

    // Create signed envelope
    Envelope create_envelope(MsgType type, const dp::Vector<dp::u8> &payload) {
        return crypto::create_signed_envelope(type, node_id, ed_priv, payload);
    }

    // Verify received envelope
    bool verify_envelope(const Envelope &env, const PublicKey &sender_pub) {
        return crypto::verify_envelope(env, sender_pub);
    }
};

void print_divider(const char *title) {
    std::cout << "\n════════════════════════════════════════════════════════════════\n";
    std::cout << "  " << title << "\n";
    std::cout << "════════════════════════════════════════════════════════════════\n\n";
}

void demo_basic_messaging() {
    print_divider("Basic Encrypted Messaging");

    // Create two robot nodes
    RobotNode alice("Alice");
    RobotNode bob("Bob");

    std::cout << "Created robots:\n";
    std::cout << "  Alice: " << alice.short_id().c_str() << "\n";
    std::cout << "  Bob:   " << bob.short_id().c_str() << "\n\n";

    // Establish sessions
    std::cout << "Establishing encrypted session...\n";
    alice.establish_session(bob, true);  // Alice is initiator
    bob.establish_session(alice, false); // Bob is responder
    std::cout << "Session established!\n\n";

    // Alice sends message to Bob
    std::cout << "Alice sends message to Bob:\n";
    dp::String msg1 = "Hello Bob! This is a secret command.";
    std::cout << "  Plaintext: \"" << msg1.c_str() << "\"\n";

    auto pkt1 = alice.encrypt_message(bob.node_id, msg1);
    if (pkt1.is_ok()) {
        std::cout << "  Encrypted: " << pkt1.value().ciphertext.size() << " bytes\n";
        std::cout << "  Nonce: " << pkt1.value().nonce_counter << "\n";

        // Bob decrypts
        auto decrypted1 = bob.decrypt_message(alice.node_id, pkt1.value());
        if (decrypted1.is_ok()) {
            std::cout << "  Bob received: \"" << decrypted1.value().c_str() << "\"\n";
        }
    }

    // Bob sends reply
    std::cout << "\nBob sends reply to Alice:\n";
    dp::String msg2 = "Roger that, Alice! Command acknowledged.";
    std::cout << "  Plaintext: \"" << msg2.c_str() << "\"\n";

    auto pkt2 = bob.encrypt_message(alice.node_id, msg2);
    if (pkt2.is_ok()) {
        std::cout << "  Encrypted: " << pkt2.value().ciphertext.size() << " bytes\n";

        auto decrypted2 = alice.decrypt_message(bob.node_id, pkt2.value());
        if (decrypted2.is_ok()) {
            std::cout << "  Alice received: \"" << decrypted2.value().c_str() << "\"\n";
        }
    }
}

void demo_replay_protection() {
    print_divider("Replay Protection Demo");

    RobotNode alice("Alice");
    RobotNode bob("Bob");

    alice.establish_session(bob, true);
    bob.establish_session(alice, false);

    // Alice sends a message
    dp::String msg = "Transfer $1000 to account XYZ";
    std::cout << "Alice sends: \"" << msg.c_str() << "\"\n";

    auto pkt = alice.encrypt_message(bob.node_id, msg);
    if (pkt.is_err()) {
        return;
    }

    // Bob receives and decrypts
    auto first = bob.decrypt_message(alice.node_id, pkt.value());
    std::cout << "Bob first receive: " << (first.is_ok() ? "SUCCESS" : "FAILED") << "\n";

    // Attacker replays the same packet
    std::cout << "\n[ATTACKER] Replaying the same packet...\n";
    auto replay = bob.decrypt_message(alice.node_id, pkt.value());
    std::cout << "Bob replay receive: " << (replay.is_ok() ? "SUCCESS (BAD!)" : "REJECTED (GOOD!)") << "\n";

    if (replay.is_err()) {
        std::cout << "Reason: " << replay.error().message.c_str() << "\n";
    }
}

void demo_multi_party() {
    print_divider("Multi-Party Communication");

    // Create a small swarm of robots
    RobotNode leader("Leader");
    RobotNode drone1("Drone1");
    RobotNode drone2("Drone2");
    RobotNode drone3("Drone3");

    std::cout << "Robot swarm:\n";
    std::cout << "  Leader: " << leader.short_id().c_str() << "\n";
    std::cout << "  Drone1: " << drone1.short_id().c_str() << "\n";
    std::cout << "  Drone2: " << drone2.short_id().c_str() << "\n";
    std::cout << "  Drone3: " << drone3.short_id().c_str() << "\n\n";

    // Leader establishes sessions with all drones
    std::cout << "Leader establishing sessions with all drones...\n";
    leader.establish_session(drone1, true);
    drone1.establish_session(leader, false);

    leader.establish_session(drone2, true);
    drone2.establish_session(leader, false);

    leader.establish_session(drone3, true);
    drone3.establish_session(leader, false);

    std::cout << "All sessions established!\n\n";

    // Leader broadcasts command to all drones
    std::cout << "Leader broadcasts command to all drones:\n";
    dp::String command = "MOVE:formation=triangle,speed=5";
    std::cout << "  Command: \"" << command.c_str() << "\"\n\n";

    dp::Vector<RobotNode *> drones = {&drone1, &drone2, &drone3};
    for (auto *drone : drones) {
        auto pkt = leader.encrypt_message(drone->node_id, command);
        if (pkt.is_ok()) {
            auto received = drone->decrypt_message(leader.node_id, pkt.value());
            if (received.is_ok()) {
                std::cout << "  " << drone->name.c_str() << " received: \"" << received.value().c_str() << "\"\n";
            }
        }
    }

    // Drones send status back
    std::cout << "\nDrones send status updates:\n";
    dp::Vector<dp::String> statuses = {"STATUS:pos=10,20,battery=85%", "STATUS:pos=15,25,battery=72%",
                               "STATUS:pos=12,18,battery=91%"};

    for (dp::usize i = 0; i < drones.size(); ++i) {
        auto pkt = drones[i]->encrypt_message(leader.node_id, statuses[i]);
        if (pkt.is_ok()) {
            auto received = leader.decrypt_message(drones[i]->node_id, pkt.value());
            if (received.is_ok()) {
                std::cout << "  From " << drones[i]->name.c_str() << ": \"" << received.value().c_str() << "\"\n";
            }
        }
    }
}

void demo_signed_messages() {
    print_divider("Signed Message Demo (Non-Repudiation)");

    RobotNode commander("Commander");
    RobotNode soldier("Soldier");

    std::cout << "Commander: " << commander.short_id().c_str() << "\n";
    std::cout << "Soldier:   " << soldier.short_id().c_str() << "\n\n";

    // Commander sends a signed order
    std::cout << "Commander sends signed order:\n";

    dp::Vector<dp::u8> order_payload;
    const char *order = "FIRE:target=enemy_base,authorization=ALPHA";
    for (const char *p = order; *p; ++p) {
        order_payload.push_back(static_cast<dp::u8>(*p));
    }

    Envelope env = commander.create_envelope(MsgType::Data, order_payload);
    std::cout << "  Order: \"" << order << "\"\n";
    std::cout << "  Envelope type: " << static_cast<int>(env.msg_type) << "\n";
    std::cout << "  Sender: " << crypto::node_id_to_hex(env.sender_id).substr(0, 8).c_str() << "\n";

    // Serialize for transmission
    dp::Vector<dp::u8> wire_data = crypto::serialize_envelope(env);
    std::cout << "  Wire size: " << wire_data.size() << " bytes\n\n";

    // Soldier receives and verifies
    std::cout << "Soldier receives and verifies:\n";

    auto received = crypto::deserialize_envelope(wire_data);
    if (received.is_ok()) {
        std::cout << "  Deserialized: SUCCESS\n";

        bool valid = soldier.verify_envelope(received.value(), commander.ed_pub);
        std::cout << "  Signature verification: " << (valid ? "VALID" : "INVALID") << "\n";

        if (valid) {
            dp::String order_str;
            for (dp::u8 b : received.value().payload) {
                order_str += static_cast<char>(b);
            }
            std::cout << "  Order content: \"" << order_str.c_str() << "\"\n";
            std::cout << "  Commander confirmed: " << crypto::node_id_to_hex(received.value().sender_id).substr(0, 8).c_str()
                      << "\n";
        }
    }

    // Try to forge a message
    std::cout << "\n[ATTACKER] Attempting to forge commander's signature...\n";
    RobotNode attacker("Attacker");

    Envelope fake_env = attacker.create_envelope(MsgType::Data, order_payload);
    // Attacker tries to claim it's from commander
    fake_env.sender_id = commander.node_id;

    bool fake_valid = soldier.verify_envelope(fake_env, commander.ed_pub);
    std::cout << "  Forged signature verification: " << (fake_valid ? "VALID (BAD!)" : "INVALID (GOOD!)") << "\n";
}

auto main() -> int {
    // Initialize botlink
    auto init_result = botlink::init();
    if (init_result.is_err()) {
        std::cerr << "Failed to initialize: " << init_result.error().message.c_str() << "\n";
        return 1;
    }

    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║          Botlink Encrypted Messaging Demo                      ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";

    demo_basic_messaging();
    demo_replay_protection();
    demo_multi_party();
    demo_signed_messages();

    std::cout << "\n=== Demo Complete ===\n";
    return 0;
}
