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
                    // TODO: Load from file or paste
                    echo::warn("Manual key entry not implemented, generating new keys");
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

                    // Note: In real usage, pubkey would be entered as base64
                    // For now, generate placeholder
                    echo::warn("Bootstrap pubkey should be entered manually in the config file");

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
