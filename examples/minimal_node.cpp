/* SPDX-License-Identifier: MIT */
/*
 * Botlink Minimal Node Example
 * Brings up botlink0 with static peers
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

int main() {
    // Initialize libsodium
    if (botlink::init().is_err()) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    echo::info("=== Botlink Minimal Node ===").cyan();

    // Generate identity keys
    auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
    NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

    String node_hex = crypto::node_id_to_hex(node_id);
    echo::info("Generated node ID: ", node_hex.substr(0, 16).c_str(), "...");

    // Create configuration
    Config config = cfg::default_config();
    config.node.name = "minimal_node";
    config.node.interface = InterfaceName("botlink0");
    config.node.mtu = 1420;
    config.node.overlay.addr = OverlayAddr("10.42.0.1", 24);

    // Parse listen endpoint
    auto listen_res = net::parse_endpoint("0.0.0.0:51820");
    if (listen_res.is_ok()) {
        config.node.overlay.listen.push_back(listen_res.value());
    }

    // Set identity
    config.identity.ed25519_private = ed_priv;
    config.identity.ed25519_public = ed_pub;
    config.identity.x25519_private = x_priv;
    config.identity.x25519_public = x_pub;
    config.identity.ed25519_id = node_hex;

    echo::info("Configuration created").green();

    // Create and configure node
    runtime::BotlinkNode node;
    auto configure_res = node.configure(config);
    if (configure_res.is_err()) {
        echo::error("Failed to configure node: ", configure_res.error().message.c_str());
        return 1;
    }

    echo::info("Node configured:").yellow();
    echo::info("  Interface: botlink0");
    echo::info("  Overlay:   10.42.0.1/24");
    echo::info("  Listen:    0.0.0.0:51820");

    // In a real application, you would start the node and run the event loop:
    // node.start();
    // node.run(); // blocking event loop

    echo::info("=== Minimal Node Ready ===").cyan();
    echo::info("(In production, call node.start() and node.run())");

    return 0;
}
