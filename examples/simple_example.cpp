/* SPDX-License-Identifier: MIT */
/*
 * Botlink Simple Example
 * Demonstrates basic usage of the botlink library
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

auto main() -> int {
    // Initialize the library (sets up libsodium)
    auto init_result = botlink::init();
    if (init_result.is_err()) {
        std::cerr << "Failed to initialize botlink: " << init_result.error().message.c_str() << "\n";
        return 1;
    }

    std::cout << "Botlink Library - Simple Example\n";
    std::cout << "================================\n\n";

    // Generate identity keypairs
    std::cout << "Generating identity keypairs...\n";
    auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

    // Derive NodeId from Ed25519 public key
    NodeId node_id = crypto::node_id_from_pubkey(ed_pub);
    std::cout << "Node ID: " << crypto::node_id_to_hex(node_id).substr(0, 16).c_str() << "...\n\n";

    // Create a simple message and sign it
    std::cout << "Signing a message...\n";
    Vector<u8> message;
    const char *msg = "Hello, Botlink!";
    for (const char *p = msg; *p; ++p) {
        message.push_back(static_cast<u8>(*p));
    }

    Signature sig = crypto::ed25519_sign(ed_priv, message);
    bool valid = crypto::ed25519_verify(ed_pub, message, sig);
    std::cout << "Signature valid: " << (valid ? "yes" : "no") << "\n\n";

    // Create an endpoint
    std::cout << "Creating network endpoint...\n";
    Endpoint ep(IPv4Addr(192, 168, 1, 1), 51820);
    std::cout << "Endpoint: " << net::format_endpoint(ep).c_str() << "\n\n";

    // Create a TrustView with ourselves as the only member
    std::cout << "Setting up trust view...\n";
    TrustView trust_view(2, 15000);

    MemberEntry self_entry;
    self_entry.node_id = node_id;
    self_entry.ed25519_pubkey = ed_pub;
    self_entry.x25519_pubkey = x_pub;
    self_entry.status = MemberStatus::Approved;
    self_entry.joined_at_ms = time::now_ms();

    trust_view.add_member(self_entry);
    std::cout << "Member count: " << trust_view.member_count() << "\n";
    std::cout << "We are a member: " << (trust_view.is_member(node_id) ? "yes" : "no") << "\n\n";

    std::cout << "Example completed successfully!\n";
    return 0;
}
