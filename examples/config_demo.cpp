/* SPDX-License-Identifier: MIT */
/*
 * Config Demo
 * Demonstrates configuration structures, parsing, and validation
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>

using namespace botlink;
using namespace dp;

int main() {
    std::cout << "=== Config Demo ===\n\n";

    std::cout << "This demo shows botlink configuration structures,\n";
    std::cout << "file parsing, validation, and serialization.\n\n";

    // ==========================================================================
    // Step 1: Create default config
    // ==========================================================================
    std::cout << "1. Creating default config...\n";

    Config config = cfg::default_config();

    std::cout << "   Version: " << config.version << "\n";
    std::cout << "   Node name: " << config.node.name.c_str() << "\n";
    std::cout << "   Interface: " << config.node.interface.c_str() << "\n";
    std::cout << "   MTU: " << config.node.mtu << "\n";
    std::cout << "   Log level: " << config.logging.level.c_str() << "\n";
    std::cout << "   Role: " << (config.node.is_member() ? "Member" : "Relay") << "\n\n";

    // ==========================================================================
    // Step 2: Configure identity
    // ==========================================================================
    std::cout << "2. Configuring identity with fresh keys...\n";

    auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

    config.identity.ed25519_private = ed_priv;
    config.identity.ed25519_public = ed_pub;
    config.identity.ed25519_id = crypto::to_hex(ed_pub.data.begin(), 32).substr(0, 16);
    config.identity.x25519_private = x_priv;
    config.identity.x25519_public = x_pub;

    std::cout << "   Ed25519 ID: " << config.identity.ed25519_id.c_str() << "...\n";
    std::cout << "   Has Ed25519: " << (config.identity.has_ed25519() ? "YES" : "NO") << "\n";
    std::cout << "   Has X25519: " << (config.identity.has_x25519() ? "YES" : "NO") << "\n";
    std::cout << "   Identity valid: " << (config.identity.is_valid() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 3: Configure overlay network
    // ==========================================================================
    std::cout << "3. Configuring overlay network...\n";

    config.node.overlay.addr.addr = "10.42.0.1";
    config.node.overlay.addr.prefix_len = 24;

    auto ep_result = net::parse_endpoint("0.0.0.0:51820");
    if (ep_result.is_ok()) {
        config.node.overlay.listen.push_back(ep_result.value());
    }

    std::cout << "   Overlay address: " << config.node.overlay.addr.addr.c_str()
              << "/" << static_cast<int>(config.node.overlay.addr.prefix_len) << "\n";
    std::cout << "   Listen endpoints: " << config.node.overlay.listen.size() << "\n";
    std::cout << "   Overlay valid: " << (config.node.overlay.is_valid() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 4: Configure trust settings
    // ==========================================================================
    std::cout << "4. Configuring trust settings...\n";

    config.trust.chain.path = "./data/chain";
    config.trust.chain.chain_name = "demo_mesh";
    config.trust.policy.min_yes_votes = 2;
    config.trust.policy.vote_timeout_ms = 15000;
    config.trust.policy.require_sponsor = true;

    std::cout << "   Chain path: " << config.trust.chain.path.c_str() << "\n";
    std::cout << "   Chain name: " << config.trust.chain.chain_name.c_str() << "\n";
    std::cout << "   Min yes votes: " << config.trust.policy.min_yes_votes << "\n";
    std::cout << "   Vote timeout: " << config.trust.policy.vote_timeout_ms << " ms\n";
    std::cout << "   Require sponsor: " << (config.trust.policy.require_sponsor ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 5: Add bootstrap peer
    // ==========================================================================
    std::cout << "5. Adding bootstrap peer...\n";

    auto [boot_priv, boot_pub] = crypto::generate_ed25519_keypair();
    auto boot_ep = net::parse_endpoint("192.168.1.1:51820");

    BootstrapEntry bootstrap;
    bootstrap.type = BootstrapType::Member;
    bootstrap.id = "genesis";
    if (boot_ep.is_ok()) {
        bootstrap.endpoint = boot_ep.value();
    }
    bootstrap.pubkey = boot_pub;

    config.trust.bootstraps.push_back(bootstrap);

    std::cout << "   Bootstrap type: " << (bootstrap.is_member() ? "Member" : "Relay") << "\n";
    std::cout << "   Bootstrap ID: " << bootstrap.id.c_str() << "\n";
    std::cout << "   Total bootstraps: " << config.trust.bootstraps.size() << "\n\n";

    // ==========================================================================
    // Step 6: Validate config
    // ==========================================================================
    std::cout << "6. Validating config...\n";

    auto validate_result = cfg::validate(config);
    std::cout << "   Validation: " << (validate_result.is_ok() ? "PASSED" : "FAILED") << "\n";
    std::cout << "   Config is_valid: " << (config.is_valid() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 7: Generate config template
    // ==========================================================================
    std::cout << "7. Generating config template...\n";

    String template_content = cfg::generate_config_template(true);
    std::cout << "   Template size: " << template_content.size() << " bytes\n";
    std::cout << "   First 100 chars:\n";
    std::cout << "   ---\n";
    std::string preview(template_content.c_str(), std::min(static_cast<usize>(100), template_content.size()));
    std::cout << "   " << preview << "...\n";
    std::cout << "   ---\n\n";

    // ==========================================================================
    // Step 8: Serialize config
    // ==========================================================================
    std::cout << "8. Serializing config...\n";

    String serialized = cfg::serialize_config(config);
    std::cout << "   Serialized size: " << serialized.size() << " bytes\n";
    std::cout << "   Contains [node]: " << (serialized.find("[node]") != String::npos ? "YES" : "NO") << "\n";
    std::cout << "   Contains [overlay]: " << (serialized.find("[overlay]") != String::npos ? "YES" : "NO") << "\n";
    std::cout << "   Contains [identity]: " << (serialized.find("[identity]") != String::npos ? "YES" : "NO") << "\n";
    std::cout << "   Contains [trust]: " << (serialized.find("[trust]") != String::npos ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 9: Parse config from string
    // ==========================================================================
    std::cout << "9. Parsing config from string...\n";

    String test_config = R"(
[node]
name = "test_node"
role = "member"
interface = "botlink1"
mtu = 1400

[overlay]
addr = "10.100.0.1/16"
listen = "0.0.0.0:51821"

[trust]
chain_path = "./test/chain"
chain_name = "test_chain"
min_yes_votes = 3
vote_timeout_ms = 30000

[logging]
level = "debug"
)";

    cfg::ConfigParser parser;
    auto parse_result = parser.parse(test_config);
    std::cout << "   Parse result: " << (parse_result.is_ok() ? "SUCCESS" : "FAILED") << "\n";

    if (parse_result.is_ok()) {
        std::cout << "   node.name: " << parser.get_or("node", "name", "").c_str() << "\n";
        std::cout << "   node.role: " << parser.get_or("node", "role", "").c_str() << "\n";
        std::cout << "   overlay.addr: " << parser.get_or("overlay", "addr", "").c_str() << "\n";
        std::cout << "   trust.min_yes_votes: " << parser.get_or("trust", "min_yes_votes", "").c_str() << "\n";
        std::cout << "   logging.level: " << parser.get_or("logging", "level", "").c_str() << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 10: Generate config with fresh keys
    // ==========================================================================
    std::cout << "10. Generating config with fresh keys...\n";

    auto fresh_config = cfg::generate_config_with_keys("fresh_node", "10.50.0.1/24", "0.0.0.0:51822");
    if (fresh_config.is_ok()) {
        auto& cfg = fresh_config.value();
        std::cout << "   Node name: " << cfg.node.name.c_str() << "\n";
        std::cout << "   Overlay: " << cfg.node.overlay.addr.addr.c_str()
                  << "/" << static_cast<int>(cfg.node.overlay.addr.prefix_len) << "\n";
        std::cout << "   Has keys: " << (cfg.identity.is_valid() ? "YES" : "NO") << "\n";
        std::cout << "   Ed25519 ID: " << cfg.identity.ed25519_id.c_str() << "...\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 11: Log level conversion
    // ==========================================================================
    std::cout << "11. Log level conversion...\n";

    LoggingConfig log_cfg;
    log_cfg.level = "trace";
    std::cout << "   'trace' -> " << static_cast<int>(log_cfg.get_log_level()) << " (Trace)\n";
    log_cfg.level = "debug";
    std::cout << "   'debug' -> " << static_cast<int>(log_cfg.get_log_level()) << " (Debug)\n";
    log_cfg.level = "info";
    std::cout << "   'info' -> " << static_cast<int>(log_cfg.get_log_level()) << " (Info)\n";
    log_cfg.level = "warn";
    std::cout << "   'warn' -> " << static_cast<int>(log_cfg.get_log_level()) << " (Warn)\n";
    log_cfg.level = "error";
    std::cout << "   'error' -> " << static_cast<int>(log_cfg.get_log_level()) << " (Error)\n";
    log_cfg.level = "critical";
    std::cout << "   'critical' -> " << static_cast<int>(log_cfg.get_log_level()) << " (Critical)\n\n";

    // ==========================================================================
    // Step 12: Relay config
    // ==========================================================================
    std::cout << "12. Relay configuration...\n";

    config.relays.allow.push_back("relay1");
    config.relays.allow.push_back("relay2");
    config.relays.prefer.push_back("relay1");

    std::cout << "   Allowed relays: " << config.relays.allow.size() << "\n";
    std::cout << "   Preferred relays: " << config.relays.prefer.size() << "\n";
    for (const auto& relay : config.relays.allow) {
        std::cout << "   - " << relay.c_str() << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 13: Validation errors
    // ==========================================================================
    std::cout << "13. Validation error cases...\n";

    // Empty node name
    Config bad_config = cfg::default_config();
    bad_config.node.name = "";
    auto bad_result = cfg::validate(bad_config);
    std::cout << "   Empty node name: " << (bad_result.is_err() ? "REJECTED" : "ACCEPTED") << "\n";

    // Zero min_yes_votes
    bad_config = config;
    bad_config.trust.policy.min_yes_votes = 0;
    bad_result = cfg::validate(bad_config);
    std::cout << "   Zero min_yes_votes: " << (bad_result.is_err() ? "REJECTED" : "ACCEPTED") << "\n";

    // Empty bootstraps
    bad_config = config;
    bad_config.trust.bootstraps.clear();
    bad_result = cfg::validate(bad_config);
    std::cout << "   Empty bootstraps: " << (bad_result.is_err() ? "REJECTED" : "ACCEPTED") << "\n";

    std::cout << "\n=== Demo Complete ===\n";

    return 0;
}
