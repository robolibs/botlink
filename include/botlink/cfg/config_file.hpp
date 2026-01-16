/* SPDX-License-Identifier: MIT */
/*
 * Botlink Config File Parser
 * Simple TOML-like config file parser and generator
 */

#pragma once

#include <botlink/cfg/config.hpp>
#include <botlink/core/result.hpp>
#include <botlink/core/types.hpp>
#include <botlink/crypto/identity.hpp>
#include <botlink/net/endpoint.hpp>
#include <botlink/net/transport.hpp>
#include <datapod/datapod.hpp>
#include <fstream>
#include <sstream>

namespace botlink {

    using namespace dp;

    namespace cfg {

        // =============================================================================
        // Config File Parser - Simple key=value with [sections]
        // =============================================================================

        class ConfigParser {
          private:
            Map<String, Map<String, String>> sections_;
            String current_section_;
            Vector<String> errors_;

          public:
            ConfigParser() = default;

            // Parse a config file
            auto parse(const String &content) -> VoidRes {
                errors_.clear();
                sections_.clear();
                current_section_ = "global";

                std::istringstream stream(std::string(content.c_str()));
                std::string line;
                usize line_num = 0;

                while (std::getline(stream, line)) {
                    ++line_num;
                    parse_line(line, line_num);
                }

                if (!errors_.empty()) {
                    String err_msg = "Config parse errors:\n";
                    for (const auto &e : errors_) {
                        err_msg = err_msg + "  " + e + "\n";
                    }
                    return result::err(err::config(err_msg.c_str()));
                }

                return result::ok();
            }

            // Get a value from a section
            [[nodiscard]] auto get(const String &section, const String &key) const -> Optional<String> {
                auto sec_it = sections_.find(section);
                if (sec_it == sections_.end()) {
                    return nullopt;
                }
                auto key_it = sec_it->second.find(key);
                if (key_it == sec_it->second.end()) {
                    return nullopt;
                }
                return key_it->second;
            }

            // Get a value with default
            [[nodiscard]] auto get_or(const String &section, const String &key, const String &def) const -> String {
                auto val = get(section, key);
                return val.has_value() ? val.value() : def;
            }

            // Check if section exists
            [[nodiscard]] auto has_section(const String &section) const -> boolean {
                return sections_.find(section) != sections_.end();
            }

            // Get all keys in a section
            [[nodiscard]] auto keys(const String &section) const -> Vector<String> {
                Vector<String> result;
                auto sec_it = sections_.find(section);
                if (sec_it != sections_.end()) {
                    for (const auto &[key, _] : sec_it->second) {
                        result.push_back(key);
                    }
                }
                return result;
            }

          private:
            auto parse_line(const std::string &line, usize line_num) -> void {
                // Trim whitespace
                auto start = line.find_first_not_of(" \t\r\n");
                if (start == std::string::npos) {
                    return; // Empty line
                }
                auto end = line.find_last_not_of(" \t\r\n");
                std::string trimmed = line.substr(start, end - start + 1);

                // Skip comments
                if (trimmed[0] == '#' || trimmed[0] == ';') {
                    return;
                }

                // Section header
                if (trimmed[0] == '[') {
                    auto close = trimmed.find(']');
                    if (close == std::string::npos) {
                        errors_.push_back(String("Line ") + to_str(static_cast<u64>(line_num)) +
                                          ": Unclosed section bracket");
                        return;
                    }
                    current_section_ = String(trimmed.substr(1, close - 1).c_str());
                    return;
                }

                // Key-value pair
                auto eq_pos = trimmed.find('=');
                if (eq_pos == std::string::npos) {
                    errors_.push_back(String("Line ") + to_str(static_cast<u64>(line_num)) +
                                      ": Expected '=' in key=value");
                    return;
                }

                std::string key = trimmed.substr(0, eq_pos);
                std::string value = trimmed.substr(eq_pos + 1);

                // Trim key
                auto key_end = key.find_last_not_of(" \t");
                if (key_end != std::string::npos) {
                    key = key.substr(0, key_end + 1);
                }

                // Trim value
                auto val_start = value.find_first_not_of(" \t");
                if (val_start != std::string::npos) {
                    value = value.substr(val_start);
                }

                // Remove quotes if present
                if (value.size() >= 2) {
                    if ((value.front() == '"' && value.back() == '"') ||
                        (value.front() == '\'' && value.back() == '\'')) {
                        value = value.substr(1, value.size() - 2);
                    }
                }

                sections_[current_section_][String(key.c_str())] = String(value.c_str());
            }
        };

        // =============================================================================
        // Config File Loader
        // =============================================================================

        // Load config from file
        [[nodiscard]] inline auto load_config_file(const String &path) -> Res<Config> {
            std::ifstream file(path.c_str());
            if (!file.is_open()) {
                return result::err(err::io("Failed to open config file"));
            }

            std::stringstream buffer;
            buffer << file.rdbuf();
            String content = String(buffer.str().c_str());

            ConfigParser parser;
            auto parse_res = parser.parse(content);
            if (parse_res.is_err()) {
                return result::err(parse_res.error());
            }

            Config config = default_config();

            // [node] section
            if (parser.has_section("node")) {
                config.node.name = parser.get_or("node", "name", "botlink_node");

                auto role_str = parser.get_or("node", "role", "member");
                if (role_str == "relay") {
                    config.node.role = Role::Relay;
                } else {
                    config.node.role = Role::Member;
                }

                config.node.interface = InterfaceName(parser.get_or("node", "interface", "botlink0").c_str());

                auto mtu_str = parser.get_or("node", "mtu", "1420");
                config.node.mtu = static_cast<u16>(std::atoi(mtu_str.c_str()));
            }

            // [overlay] section
            if (parser.has_section("overlay")) {
                auto addr_str = parser.get("overlay", "addr");
                if (addr_str.has_value()) {
                    auto slash_pos = addr_str->find('/');
                    if (slash_pos != String::npos) {
                        config.node.overlay.addr.addr = String(addr_str->c_str(), slash_pos);
                        config.node.overlay.addr.prefix_len =
                            static_cast<u8>(std::atoi(addr_str->c_str() + slash_pos + 1));
                    } else {
                        config.node.overlay.addr.addr = addr_str.value();
                        config.node.overlay.addr.prefix_len = 24;
                    }
                }

                auto listen_str = parser.get("overlay", "listen");
                if (listen_str.has_value()) {
                    auto ep_res = net::parse_endpoint(listen_str.value());
                    if (ep_res.is_ok()) {
                        config.node.overlay.listen.push_back(ep_res.value());
                    }
                }
            }

            // [identity] section
            if (parser.has_section("identity")) {
                auto ed_priv = parser.get("identity", "ed25519_private");
                if (ed_priv.has_value()) {
                    auto key_res = crypto::private_key_from_hex(ed_priv.value());
                    if (key_res.is_ok()) {
                        config.identity.ed25519_private = key_res.value();
                        config.identity.ed25519_public =
                            crypto::ed25519_public_from_private(config.identity.ed25519_private);
                        config.identity.ed25519_id =
                            crypto::to_hex(config.identity.ed25519_public.data.begin(), 32).substr(0, 16);
                    }
                }

                auto x_priv = parser.get("identity", "x25519_private");
                if (x_priv.has_value()) {
                    auto key_res = crypto::private_key_from_hex(x_priv.value());
                    if (key_res.is_ok()) {
                        config.identity.x25519_private = key_res.value();
                        config.identity.x25519_public =
                            crypto::x25519_public_from_private(config.identity.x25519_private);
                    }
                }
            }

            // [trust] section
            if (parser.has_section("trust")) {
                auto chain_path = parser.get("trust", "chain_path");
                if (chain_path.has_value()) {
                    config.trust.chain.path = chain_path.value();
                }

                auto chain_name = parser.get("trust", "chain_name");
                if (chain_name.has_value()) {
                    config.trust.chain.chain_name = chain_name.value();
                }

                auto min_votes = parser.get("trust", "min_yes_votes");
                if (min_votes.has_value()) {
                    config.trust.policy.min_yes_votes = static_cast<u32>(std::atoi(min_votes->c_str()));
                }

                auto vote_timeout = parser.get("trust", "vote_timeout_ms");
                if (vote_timeout.has_value()) {
                    config.trust.policy.vote_timeout_ms = static_cast<u32>(std::atoi(vote_timeout->c_str()));
                }
            }

            // [bootstrap.X] sections
            for (usize i = 0; i < 10; ++i) {
                String section = String("bootstrap.") + to_str(static_cast<u64>(i));
                if (!parser.has_section(section)) {
                    break;
                }

                BootstrapEntry entry;
                auto type_str = parser.get_or(section, "type", "member");
                entry.type = (type_str == "relay") ? BootstrapType::Relay : BootstrapType::Member;

                auto id = parser.get(section, "id");
                if (id.has_value()) {
                    entry.id = id.value();
                }

                // Parse and validate endpoint (required for all bootstrap entries)
                boolean has_valid_endpoint = false;
                auto endpoint_str = parser.get(section, "endpoint");
                if (endpoint_str.has_value()) {
                    auto ep_res = net::parse_endpoint(endpoint_str.value());
                    if (ep_res.is_ok()) {
                        entry.endpoint = ep_res.value();
                        has_valid_endpoint = true;
                    } else {
                        echo::warn("Bootstrap entry ", section.c_str(), ": invalid endpoint format");
                    }
                }

                // Parse and validate pubkey (required for member types)
                boolean has_valid_pubkey = false;
                auto pubkey_str = parser.get(section, "pubkey");
                if (pubkey_str.has_value()) {
                    auto key_res = crypto::public_key_from_hex(pubkey_str.value());
                    if (key_res.is_ok()) {
                        entry.pubkey = key_res.value();
                        has_valid_pubkey = true;
                    } else {
                        echo::warn("Bootstrap entry ", section.c_str(), ": invalid pubkey format");
                    }
                }

                // Validate required fields before adding entry
                if (!has_valid_endpoint) {
                    echo::warn("Bootstrap entry ", section.c_str(), " skipped: missing or invalid endpoint");
                    continue;
                }

                // Members require a valid pubkey
                if (entry.is_member() && !has_valid_pubkey) {
                    echo::warn("Bootstrap entry ", section.c_str(), " skipped: member type requires valid pubkey");
                    continue;
                }

                config.trust.bootstraps.push_back(entry);
            }

            // [timing] section
            if (parser.has_section("timing")) {
                auto envelope_max_age = parser.get("timing", "envelope_max_age_ms");
                if (envelope_max_age.has_value()) {
                    config.timing.envelope_max_age_ms = static_cast<u64>(std::atoll(envelope_max_age->c_str()));
                }

                auto envelope_max_future = parser.get("timing", "envelope_max_future_ms");
                if (envelope_max_future.has_value()) {
                    config.timing.envelope_max_future_ms = static_cast<u64>(std::atoll(envelope_max_future->c_str()));
                }

                auto handshake_timeout = parser.get("timing", "handshake_timeout_ms");
                if (handshake_timeout.has_value()) {
                    config.timing.handshake_timeout_ms = static_cast<u64>(std::atoll(handshake_timeout->c_str()));
                }

                auto keepalive_interval = parser.get("timing", "keepalive_interval_ms");
                if (keepalive_interval.has_value()) {
                    config.timing.keepalive_interval_ms = static_cast<u64>(std::atoll(keepalive_interval->c_str()));
                }

                auto session_lifetime = parser.get("timing", "session_lifetime_ms");
                if (session_lifetime.has_value()) {
                    config.timing.session_lifetime_ms = static_cast<u64>(std::atoll(session_lifetime->c_str()));
                }

                auto peer_timeout = parser.get("timing", "peer_timeout_ms");
                if (peer_timeout.has_value()) {
                    config.timing.peer_timeout_ms = static_cast<u64>(std::atoll(peer_timeout->c_str()));
                }

                auto sponsor_request_timeout = parser.get("timing", "sponsor_request_timeout_ms");
                if (sponsor_request_timeout.has_value()) {
                    config.timing.sponsor_request_timeout_ms =
                        static_cast<u64>(std::atoll(sponsor_request_timeout->c_str()));
                }

                auto sponsor_max_request_age = parser.get("timing", "sponsor_max_request_age_ms");
                if (sponsor_max_request_age.has_value()) {
                    config.timing.sponsor_max_request_age_ms =
                        static_cast<u64>(std::atoll(sponsor_max_request_age->c_str()));
                }
            }

            // [logging] section
            if (parser.has_section("logging")) {
                config.logging.level = parser.get_or("logging", "level", "info");
            }

            return result::ok(config);
        }

        // =============================================================================
        // Config Template Generator
        // =============================================================================

        // Generate a default config file template
        [[nodiscard]] inline auto generate_config_template(boolean with_comments = true) -> String {
            std::ostringstream ss;

            if (with_comments) {
                ss << "# Botlink Configuration File\n";
                ss << "# Generated template - customize values as needed\n\n";
            }

            ss << "[node]\n";
            if (with_comments)
                ss << "# Node name (used for identification)\n";
            ss << "name = \"my_botlink_node\"\n";
            if (with_comments)
                ss << "# Role: member or relay\n";
            ss << "role = \"member\"\n";
            if (with_comments)
                ss << "# TUN interface name\n";
            ss << "interface = \"botlink0\"\n";
            if (with_comments)
                ss << "# MTU size (default: 1420 for WireGuard compatibility)\n";
            ss << "mtu = 1420\n\n";

            ss << "[overlay]\n";
            if (with_comments)
                ss << "# Overlay network address (CIDR notation)\n";
            ss << "addr = \"10.42.0.1/24\"\n";
            if (with_comments)
                ss << "# Listen endpoint for incoming connections\n";
            ss << "listen = \"0.0.0.0:51820\"\n\n";

            ss << "[identity]\n";
            if (with_comments) {
                ss << "# Ed25519 signing key (hex encoded, 64 chars)\n";
                ss << "# Generate with: botlink keygen\n";
            }
            ss << "ed25519_private = \"\"\n";
            if (with_comments)
                ss << "# X25519 key exchange key (hex encoded, 64 chars)\n";
            ss << "x25519_private = \"\"\n\n";

            ss << "[trust]\n";
            if (with_comments)
                ss << "# Path to trust chain storage\n";
            ss << "chain_path = \"./data/chain\"\n";
            if (with_comments)
                ss << "# Trust chain name\n";
            ss << "chain_name = \"botlink_mesh\"\n";
            if (with_comments)
                ss << "# Minimum yes votes for approval\n";
            ss << "min_yes_votes = 2\n";
            if (with_comments)
                ss << "# Vote timeout in milliseconds\n";
            ss << "vote_timeout_ms = 15000\n\n";

            ss << "[bootstrap.0]\n";
            if (with_comments)
                ss << "# Bootstrap peer configuration\n";
            ss << "type = \"member\"\n";
            ss << "id = \"genesis\"\n";
            ss << "endpoint = \"192.168.1.1:51820\"\n";
            ss << "pubkey = \"\"\n\n";

            ss << "[timing]\n";
            if (with_comments) {
                ss << "# Timing configuration (all values in milliseconds)\n";
                ss << "# Envelope validation - max age before considered stale\n";
            }
            ss << "envelope_max_age_ms = 60000\n";
            if (with_comments)
                ss << "# Max clock drift allowed for future timestamps\n";
            ss << "envelope_max_future_ms = 5000\n";
            if (with_comments)
                ss << "# Handshake timeout\n";
            ss << "handshake_timeout_ms = 5000\n";
            if (with_comments)
                ss << "# Keepalive interval\n";
            ss << "keepalive_interval_ms = 25000\n";
            if (with_comments)
                ss << "# Session lifetime before rekey\n";
            ss << "session_lifetime_ms = 180000\n";
            if (with_comments)
                ss << "# Peer timeout\n";
            ss << "peer_timeout_ms = 120000\n\n";

            ss << "[logging]\n";
            if (with_comments)
                ss << "# Log level: trace, debug, info, warn, error, critical\n";
            ss << "level = \"info\"\n";

            return String(ss.str().c_str());
        }

        // Save config template to file
        [[nodiscard]] inline auto save_config_template(const String &path, boolean with_comments = true) -> VoidRes {
            std::ofstream file(path.c_str());
            if (!file.is_open()) {
                return result::err(err::io("Failed to create config file"));
            }

            String content = generate_config_template(with_comments);
            file << content.c_str();
            file.close();

            return result::ok();
        }

        // Generate config with fresh keys
        [[nodiscard]] inline auto generate_config_with_keys(const String &node_name, const String &overlay_addr,
                                                            const String &listen_endpoint) -> Res<Config> {
            Config config = default_config();
            config.node.name = node_name;

            // Parse overlay address
            auto slash_pos = overlay_addr.find('/');
            if (slash_pos != String::npos) {
                config.node.overlay.addr.addr = String(overlay_addr.c_str(), slash_pos);
                config.node.overlay.addr.prefix_len = static_cast<u8>(std::atoi(overlay_addr.c_str() + slash_pos + 1));
            } else {
                config.node.overlay.addr.addr = overlay_addr;
                config.node.overlay.addr.prefix_len = 24;
            }

            // Parse listen endpoint
            auto ep_res = net::parse_endpoint(listen_endpoint);
            if (ep_res.is_err()) {
                return result::err(ep_res.error());
            }
            config.node.overlay.listen.push_back(ep_res.value());

            // Generate fresh keys
            auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
            auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

            config.identity.ed25519_private = ed_priv;
            config.identity.ed25519_public = ed_pub;
            config.identity.ed25519_id = crypto::to_hex(ed_pub.data.begin(), 32).substr(0, 16);
            config.identity.x25519_private = x_priv;
            config.identity.x25519_public = x_pub;

            return result::ok(config);
        }

        // Serialize config to file format
        [[nodiscard]] inline auto serialize_config(const Config &config) -> String {
            std::ostringstream ss;

            ss << "[node]\n";
            ss << "name = \"" << config.node.name.c_str() << "\"\n";
            ss << "role = \"" << (config.node.is_relay() ? "relay" : "member") << "\"\n";
            ss << "interface = \"" << config.node.interface.c_str() << "\"\n";
            ss << "mtu = " << config.node.mtu << "\n\n";

            ss << "[overlay]\n";
            ss << "addr = \"" << config.node.overlay.addr.addr.c_str() << "/"
               << (int)config.node.overlay.addr.prefix_len << "\"\n";
            if (!config.node.overlay.listen.empty()) {
                ss << "listen = \"" << net::format_endpoint(config.node.overlay.listen[0]).c_str() << "\"\n";
            }
            ss << "\n";

            ss << "[identity]\n";
            ss << "ed25519_private = \"" << crypto::to_hex(config.identity.ed25519_private.data.begin(), 32).c_str()
               << "\"\n";
            ss << "x25519_private = \"" << crypto::to_hex(config.identity.x25519_private.data.begin(), 32).c_str()
               << "\"\n\n";

            ss << "[trust]\n";
            ss << "chain_path = \"" << config.trust.chain.path.c_str() << "\"\n";
            ss << "chain_name = \"" << config.trust.chain.chain_name.c_str() << "\"\n";
            ss << "min_yes_votes = " << config.trust.policy.min_yes_votes << "\n";
            ss << "vote_timeout_ms = " << config.trust.policy.vote_timeout_ms << "\n\n";

            for (usize i = 0; i < config.trust.bootstraps.size(); ++i) {
                const auto &boot = config.trust.bootstraps[i];
                ss << "[bootstrap." << i << "]\n";
                ss << "type = \"" << (boot.is_relay() ? "relay" : "member") << "\"\n";
                ss << "id = \"" << boot.id.c_str() << "\"\n";
                ss << "endpoint = \"" << net::format_endpoint(boot.endpoint).c_str() << "\"\n";
                ss << "pubkey = \"" << crypto::to_hex(boot.pubkey.data.begin(), 32).c_str() << "\"\n\n";
            }

            ss << "[logging]\n";
            ss << "level = \"" << config.logging.level.c_str() << "\"\n";

            return String(ss.str().c_str());
        }

        // Save config to file
        [[nodiscard]] inline auto save_config(const Config &config, const String &path) -> VoidRes {
            std::ofstream file(path.c_str());
            if (!file.is_open()) {
                return result::err(err::io("Failed to create config file"));
            }

            String content = serialize_config(config);
            file << content.c_str();
            file.close();

            return result::ok();
        }

    } // namespace cfg

} // namespace botlink
