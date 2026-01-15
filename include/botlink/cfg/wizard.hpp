/* SPDX-License-Identifier: MIT */
/*
 * Botlink Config Wizard
 * Interactive configuration builder
 */

#pragma once

#include <botlink/cfg/config.hpp>
#include <botlink/core/result.hpp>
#include <botlink/crypto/identity.hpp>
#include <botlink/net/endpoint.hpp>
#include <datapod/datapod.hpp>
#include <echo/echo.hpp>

#include <fstream>
#include <iostream>
#include <string>

namespace botlink {

    using namespace dp;

    namespace cfg {

        // =============================================================================
        // Wizard Options
        // =============================================================================

        struct WizardOptions {
            boolean generate_keys = true;
            boolean interactive = true;
            String default_interface = "botlink0";
            u16 default_port = DEFAULT_PORT;
            String default_overlay = "10.42.0.1/24";

            WizardOptions() = default;

            auto members() noexcept {
                return std::tie(generate_keys, interactive, default_interface, default_port, default_overlay);
            }
            auto members() const noexcept {
                return std::tie(generate_keys, interactive, default_interface, default_port, default_overlay);
            }
        };

        // =============================================================================
        // Config Wizard
        // =============================================================================

        class ConfigWizard {
          private:
            WizardOptions options_;
            Config config_;

          public:
            explicit ConfigWizard(const WizardOptions &options = {}) : options_(options) { config_ = default_config(); }

            // =============================================================================
            // Interactive Prompts
            // =============================================================================

            // Prompt for string input
            [[nodiscard]] auto prompt_string(const String &prompt, const String &default_val) -> String {
                if (!options_.interactive) {
                    return default_val;
                }

                std::cout << prompt.c_str();
                if (!default_val.empty()) {
                    std::cout << " [" << default_val.c_str() << "]";
                }
                std::cout << ": ";

                std::string input;
                std::getline(std::cin, input);

                if (input.empty()) {
                    return default_val;
                }
                return String(input.c_str());
            }

            // Prompt for yes/no
            [[nodiscard]] auto prompt_bool(const String &prompt, boolean default_val) -> boolean {
                if (!options_.interactive) {
                    return default_val;
                }

                std::cout << prompt.c_str() << " [" << (default_val ? "Y/n" : "y/N") << "]: ";

                std::string input;
                std::getline(std::cin, input);

                if (input.empty()) {
                    return default_val;
                }

                return (input[0] == 'y' || input[0] == 'Y');
            }

            // Prompt for number
            [[nodiscard]] auto prompt_number(const String &prompt, u32 default_val) -> u32 {
                if (!options_.interactive) {
                    return default_val;
                }

                std::cout << prompt.c_str() << " [" << default_val << "]: ";

                std::string input;
                std::getline(std::cin, input);

                if (input.empty()) {
                    return default_val;
                }

                try {
                    return static_cast<u32>(std::stoul(input));
                } catch (...) {
                    return default_val;
                }
            }

            // Prompt for choice
            [[nodiscard]] auto prompt_choice(const String &prompt, const Vector<String> &choices, usize default_idx)
                -> usize {
                if (!options_.interactive) {
                    return default_idx;
                }

                std::cout << prompt.c_str() << ":\n";
                for (usize i = 0; i < choices.size(); ++i) {
                    std::cout << "  " << (i + 1) << ") " << choices[i].c_str();
                    if (i == default_idx) {
                        std::cout << " (default)";
                    }
                    std::cout << "\n";
                }
                std::cout << "Choice [" << (default_idx + 1) << "]: ";

                std::string input;
                std::getline(std::cin, input);

                if (input.empty()) {
                    return default_idx;
                }

                try {
                    usize choice = std::stoul(input) - 1;
                    if (choice < choices.size()) {
                        return choice;
                    }
                } catch (...) {
                }
                return default_idx;
            }

            // =============================================================================
            // Wizard Steps
            // =============================================================================

            // Step 1: Basic node configuration
            auto configure_node() -> void {
                echo::info("=== Node Configuration ===");

                config_.node.name = prompt_string("Node name", "botlink_node");

                Vector<String> roles;
                roles.push_back("member");
                roles.push_back("relay");
                usize role_choice = prompt_choice("Node role", roles, 0);
                config_.node.role = (role_choice == 0) ? Role::Member : Role::Relay;

                config_.node.interface =
                    InterfaceName(prompt_string("Interface name", options_.default_interface).c_str());

                config_.node.mtu = static_cast<u16>(prompt_number("MTU", DEFAULT_MTU));
            }

            // Step 2: Network configuration
            auto configure_network() -> void {
                echo::info("=== Network Configuration ===");

                config_.node.overlay.addr.addr = prompt_string("Overlay IP address", "10.42.0.1");
                config_.node.overlay.addr.prefix_len = static_cast<u8>(prompt_number("Overlay prefix length", 24));

                String listen_addr = prompt_string("Listen address", "0.0.0.0");
                u32 listen_port = prompt_number("Listen port", options_.default_port);

                Endpoint ep(IPv4Addr(0, 0, 0, 0), // Will be parsed
                            static_cast<u16>(listen_port));

                // Parse listen address
                auto ep_res = net::parse_endpoint(listen_addr + ":" + String(std::to_string(listen_port).c_str()));
                if (ep_res.is_ok()) {
                    config_.node.overlay.listen.push_back(ep_res.value());
                } else {
                    // Default to any
                    config_.node.overlay.listen.push_back(
                        Endpoint(IPv4Addr(0, 0, 0, 0), static_cast<u16>(listen_port)));
                }
            }

            // Step 3: Identity configuration
            auto configure_identity() -> void {
                echo::info("=== Identity Configuration ===");

                boolean gen_keys = prompt_bool("Generate new keys", options_.generate_keys);

                if (gen_keys) {
                    // Generate Ed25519 keypair
                    auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
                    config_.identity.ed25519_private = ed_priv;
                    config_.identity.ed25519_public = ed_pub;

                    // Generate X25519 keypair
                    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
                    config_.identity.x25519_private = x_priv;
                    config_.identity.x25519_public = x_pub;

                    // Derive NodeId
                    NodeId node_id = crypto::node_id_from_pubkey(ed_pub);
                    config_.identity.ed25519_id = crypto::node_id_to_hex(node_id);

                    echo::info("Generated new identity: ", config_.identity.ed25519_id.substr(0, 16).c_str(), "...");
                } else {
                    // Import existing keys
                    Vector<String> import_methods;
                    import_methods.push_back("Load from file");
                    import_methods.push_back("Paste base64");
                    import_methods.push_back("Paste hex");
                    usize method = prompt_choice("Key import method", import_methods, 0);

                    boolean import_success = false;

                    if (method == 0) {
                        // Load from file
                        import_success = import_keys_from_file();
                    } else if (method == 1) {
                        // Paste base64
                        import_success = import_keys_base64();
                    } else {
                        // Paste hex
                        import_success = import_keys_hex();
                    }

                    if (!import_success) {
                        echo::warn("Key import failed, generating new keys instead");
                        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
                        config_.identity.ed25519_private = ed_priv;
                        config_.identity.ed25519_public = ed_pub;

                        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
                        config_.identity.x25519_private = x_priv;
                        config_.identity.x25519_public = x_pub;

                        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);
                        config_.identity.ed25519_id = crypto::node_id_to_hex(node_id);
                    }
                }
            }

            // Import keys from file
            auto import_keys_from_file() -> boolean {
                String ed_priv_path = prompt_string("Ed25519 private key file path", "");
                if (ed_priv_path.empty()) {
                    echo::warn("No file path provided");
                    return false;
                }

                // Read Ed25519 private key
                std::ifstream ed_file(ed_priv_path.c_str());
                if (!ed_file.is_open()) {
                    echo::warn("Failed to open Ed25519 key file");
                    return false;
                }

                std::string ed_content;
                std::getline(ed_file, ed_content);
                ed_file.close();

                // Try base64 first, then hex
                auto ed_priv_res = crypto::private_key_from_base64(KeyB64(ed_content.c_str()));
                if (ed_priv_res.is_err()) {
                    ed_priv_res = crypto::private_key_from_hex(String(ed_content.c_str()));
                }

                if (ed_priv_res.is_err()) {
                    echo::warn("Failed to parse Ed25519 private key");
                    return false;
                }

                config_.identity.ed25519_private = ed_priv_res.value();
                config_.identity.ed25519_public = crypto::ed25519_public_from_private(config_.identity.ed25519_private);

                // Ask for X25519 key or derive from Ed25519
                boolean derive_x25519 = prompt_bool("Derive X25519 key from Ed25519 (or enter separately)", true);
                if (derive_x25519) {
                    // Generate X25519 keypair (independent from Ed25519)
                    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
                    config_.identity.x25519_private = x_priv;
                    config_.identity.x25519_public = x_pub;
                } else {
                    String x_priv_path = prompt_string("X25519 private key file path", "");
                    if (!x_priv_path.empty()) {
                        std::ifstream x_file(x_priv_path.c_str());
                        if (x_file.is_open()) {
                            std::string x_content;
                            std::getline(x_file, x_content);
                            x_file.close();

                            auto x_priv_res = crypto::private_key_from_base64(KeyB64(x_content.c_str()));
                            if (x_priv_res.is_err()) {
                                x_priv_res = crypto::private_key_from_hex(String(x_content.c_str()));
                            }

                            if (x_priv_res.is_ok()) {
                                config_.identity.x25519_private = x_priv_res.value();
                                config_.identity.x25519_public =
                                    crypto::x25519_public_from_private(config_.identity.x25519_private);
                            }
                        }
                    }
                }

                // Derive NodeId
                NodeId node_id = crypto::node_id_from_pubkey(config_.identity.ed25519_public);
                config_.identity.ed25519_id = crypto::node_id_to_hex(node_id);

                echo::info("Imported identity: ", config_.identity.ed25519_id.substr(0, 16).c_str(), "...");
                return true;
            }

            // Import keys from pasted base64
            auto import_keys_base64() -> boolean {
                String ed_b64 = prompt_string("Ed25519 private key (base64)", "");
                if (ed_b64.empty()) {
                    return false;
                }

                auto ed_priv_res = crypto::private_key_from_base64(KeyB64(ed_b64.c_str()));
                if (ed_priv_res.is_err()) {
                    echo::warn("Invalid base64 Ed25519 key");
                    return false;
                }

                config_.identity.ed25519_private = ed_priv_res.value();
                config_.identity.ed25519_public = crypto::ed25519_public_from_private(config_.identity.ed25519_private);

                // X25519 key
                String x_b64 = prompt_string("X25519 private key (base64, or empty to generate)", "");
                if (!x_b64.empty()) {
                    auto x_priv_res = crypto::private_key_from_base64(KeyB64(x_b64.c_str()));
                    if (x_priv_res.is_ok()) {
                        config_.identity.x25519_private = x_priv_res.value();
                        config_.identity.x25519_public =
                            crypto::x25519_public_from_private(config_.identity.x25519_private);
                    } else {
                        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
                        config_.identity.x25519_private = x_priv;
                        config_.identity.x25519_public = x_pub;
                    }
                } else {
                    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
                    config_.identity.x25519_private = x_priv;
                    config_.identity.x25519_public = x_pub;
                }

                // Derive NodeId
                NodeId node_id = crypto::node_id_from_pubkey(config_.identity.ed25519_public);
                config_.identity.ed25519_id = crypto::node_id_to_hex(node_id);

                echo::info("Imported identity: ", config_.identity.ed25519_id.substr(0, 16).c_str(), "...");
                return true;
            }

            // Import keys from pasted hex
            auto import_keys_hex() -> boolean {
                String ed_hex = prompt_string("Ed25519 private key (hex)", "");
                if (ed_hex.empty()) {
                    return false;
                }

                auto ed_priv_res = crypto::private_key_from_hex(ed_hex);
                if (ed_priv_res.is_err()) {
                    echo::warn("Invalid hex Ed25519 key");
                    return false;
                }

                config_.identity.ed25519_private = ed_priv_res.value();
                config_.identity.ed25519_public = crypto::ed25519_public_from_private(config_.identity.ed25519_private);

                // X25519 key
                String x_hex = prompt_string("X25519 private key (hex, or empty to generate)", "");
                if (!x_hex.empty()) {
                    auto x_priv_res = crypto::private_key_from_hex(x_hex);
                    if (x_priv_res.is_ok()) {
                        config_.identity.x25519_private = x_priv_res.value();
                        config_.identity.x25519_public =
                            crypto::x25519_public_from_private(config_.identity.x25519_private);
                    } else {
                        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
                        config_.identity.x25519_private = x_priv;
                        config_.identity.x25519_public = x_pub;
                    }
                } else {
                    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
                    config_.identity.x25519_private = x_priv;
                    config_.identity.x25519_public = x_pub;
                }

                // Derive NodeId
                NodeId node_id = crypto::node_id_from_pubkey(config_.identity.ed25519_public);
                config_.identity.ed25519_id = crypto::node_id_to_hex(node_id);

                echo::info("Imported identity: ", config_.identity.ed25519_id.substr(0, 16).c_str(), "...");
                return true;
            }

            // Step 4: Trust configuration
            auto configure_trust() -> void {
                echo::info("=== Trust Configuration ===");

                config_.trust.chain.chain_name = prompt_string("Trust chain name", "swarm_trust");
                config_.trust.chain.path = prompt_string("Trust chain path", "./botlink_trust");

                config_.trust.policy.min_yes_votes = prompt_number("Minimum yes votes", 2);
                config_.trust.policy.vote_timeout_ms = prompt_number("Vote timeout (ms)", 15000);
                config_.trust.policy.require_sponsor = prompt_bool("Require sponsor", true);
            }

            // Step 5: Bootstrap configuration
            auto configure_bootstraps() -> void {
                echo::info("=== Bootstrap Configuration ===");

                boolean add_bootstrap = prompt_bool("Add bootstrap peer", true);

                while (add_bootstrap) {
                    BootstrapEntry entry;

                    Vector<String> types;
                    types.push_back("member");
                    types.push_back("relay");
                    usize type_choice = prompt_choice("Bootstrap type", types, 0);
                    entry.type = (type_choice == 0) ? BootstrapType::Member : BootstrapType::Relay;

                    entry.id = prompt_string("Bootstrap ID", "bootstrap_1");

                    String ep_str = prompt_string("Bootstrap endpoint (ip:port)", "192.168.1.1:51820");
                    auto ep_res = net::parse_endpoint(ep_str);
                    if (ep_res.is_ok()) {
                        entry.endpoint = ep_res.value();
                    }

                    // Bootstrap public key entry
                    Vector<String> key_formats;
                    key_formats.push_back("Base64");
                    key_formats.push_back("Hex");
                    usize key_format = prompt_choice("Public key format", key_formats, 0);

                    if (key_format == 0) {
                        String pubkey_b64 = prompt_string("Bootstrap public key (base64)", "");
                        if (!pubkey_b64.empty()) {
                            auto pubkey_res = crypto::public_key_from_base64(KeyB64(pubkey_b64.c_str()));
                            if (pubkey_res.is_ok()) {
                                entry.pubkey = pubkey_res.value();
                                echo::info("Bootstrap public key accepted");
                            } else {
                                echo::warn("Invalid base64 public key - bootstrap entry may not work");
                            }
                        } else {
                            echo::warn("No public key provided - bootstrap entry may not work");
                        }
                    } else {
                        String pubkey_hex = prompt_string("Bootstrap public key (hex)", "");
                        if (!pubkey_hex.empty()) {
                            auto pubkey_res = crypto::public_key_from_hex(pubkey_hex);
                            if (pubkey_res.is_ok()) {
                                entry.pubkey = pubkey_res.value();
                                echo::info("Bootstrap public key accepted");
                            } else {
                                echo::warn("Invalid hex public key - bootstrap entry may not work");
                            }
                        } else {
                            echo::warn("No public key provided - bootstrap entry may not work");
                        }
                    }

                    config_.trust.bootstraps.push_back(entry);

                    add_bootstrap = prompt_bool("Add another bootstrap", false);
                }
            }

            // =============================================================================
            // Main Wizard Flow
            // =============================================================================

            // Run the full wizard
            auto run() -> Config {
                echo::info("Botlink Configuration Wizard").cyan();
                echo::info("============================\n");

                configure_node();
                echo::info("");

                configure_network();
                echo::info("");

                configure_identity();
                echo::info("");

                configure_trust();
                echo::info("");

                configure_bootstraps();
                echo::info("");

                echo::info("Configuration complete!").green();
                return config_;
            }

            // Run wizard with defaults (non-interactive)
            auto run_defaults() -> Config {
                options_.interactive = false;
                return run();
            }

            // Get the generated config
            [[nodiscard]] auto config() const -> const Config & { return config_; }
        };

        // =============================================================================
        // Convenience Functions
        // =============================================================================

        // Run interactive wizard and return config
        [[nodiscard]] inline auto run_wizard(const WizardOptions &options = {}) -> Config {
            ConfigWizard wizard(options);
            return wizard.run();
        }

        // Generate config with defaults
        [[nodiscard]] inline auto generate_default_config() -> Config {
            WizardOptions options;
            options.interactive = false;
            options.generate_keys = true;

            ConfigWizard wizard(options);
            return wizard.run_defaults();
        }

    } // namespace cfg

} // namespace botlink
