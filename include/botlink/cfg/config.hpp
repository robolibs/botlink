/* SPDX-License-Identifier: MIT */
/*
 * Botlink Configuration
 * Configuration structures using datapod types
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/types.hpp>
#include <datapod/datapod.hpp>
#include <echo/echo.hpp>

namespace botlink {

    using namespace dp;

    // =============================================================================
    // Bootstrap Peer Type
    // =============================================================================

    enum class BootstrapType : u8 {
        Member = 0,
        Relay = 1,
    };

    // =============================================================================
    // Bootstrap Entry - A known peer to connect to at startup
    // =============================================================================

    struct BootstrapEntry {
        BootstrapType type = BootstrapType::Member;
        String id;
        Endpoint endpoint;
        PublicKey pubkey;

        BootstrapEntry() = default;

        BootstrapEntry(BootstrapType t, String i, Endpoint e, PublicKey p)
            : type(t), id(std::move(i)), endpoint(e), pubkey(p) {}

        [[nodiscard]] auto is_member() const -> boolean { return type == BootstrapType::Member; }
        [[nodiscard]] auto is_relay() const -> boolean { return type == BootstrapType::Relay; }

        auto members() noexcept { return std::tie(type, id, endpoint, pubkey); }
        auto members() const noexcept { return std::tie(type, id, endpoint, pubkey); }
    };

    // =============================================================================
    // Identity Config - Ed25519 + X25519 key pairs
    // =============================================================================

    struct IdentityConfig {
        // Ed25519 signing key pair
        PrivateKey ed25519_private;
        PublicKey ed25519_public;
        String ed25519_id; // hex or DID string

        // X25519 key exchange pair
        PrivateKey x25519_private;
        PublicKey x25519_public;

        [[nodiscard]] auto has_ed25519() const -> boolean { return !ed25519_private.is_zero(); }
        [[nodiscard]] auto has_x25519() const -> boolean { return !x25519_private.is_zero(); }
        [[nodiscard]] auto is_valid() const -> boolean { return has_ed25519() && has_x25519(); }

        auto members() noexcept {
            return std::tie(ed25519_private, ed25519_public, ed25519_id, x25519_private, x25519_public);
        }
        auto members() const noexcept {
            return std::tie(ed25519_private, ed25519_public, ed25519_id, x25519_private, x25519_public);
        }
    };

    // =============================================================================
    // Trust Policy Config
    // =============================================================================

    struct TrustPolicyConfig {
        u32 min_yes_votes = 2;
        u32 vote_timeout_ms = 15000;
        boolean require_sponsor = true;

        auto members() noexcept { return std::tie(min_yes_votes, vote_timeout_ms, require_sponsor); }
        auto members() const noexcept { return std::tie(min_yes_votes, vote_timeout_ms, require_sponsor); }
    };

    // =============================================================================
    // Trust Chain Config
    // =============================================================================

    struct TrustChainConfig {
        String path;       // Path to trust chain storage
        String chain_name; // Name of the trust chain
        String genesis;    // Genesis block ID or hash

        auto members() noexcept { return std::tie(path, chain_name, genesis); }
        auto members() const noexcept { return std::tie(path, chain_name, genesis); }
    };

    // =============================================================================
    // Trust Config
    // =============================================================================

    struct TrustConfig {
        TrustChainConfig chain;
        TrustPolicyConfig policy;
        Vector<BootstrapEntry> bootstraps;

        auto members() noexcept { return std::tie(chain, policy, bootstraps); }
        auto members() const noexcept { return std::tie(chain, policy, bootstraps); }
    };

    // =============================================================================
    // Relay Config
    // =============================================================================

    struct RelayConfig {
        Vector<String> allow;  // Allowed relay IDs
        Vector<String> prefer; // Preferred relay IDs (in order)

        auto members() noexcept { return std::tie(allow, prefer); }
        auto members() const noexcept { return std::tie(allow, prefer); }
    };

    // =============================================================================
    // Overlay Network Config
    // =============================================================================

    struct OverlayConfig {
        OverlayAddr addr;
        Vector<Endpoint> listen;

        [[nodiscard]] auto is_valid() const -> boolean { return addr.is_valid() && !listen.empty(); }

        auto members() noexcept { return std::tie(addr, listen); }
        auto members() const noexcept { return std::tie(addr, listen); }
    };

    // =============================================================================
    // Node Config - Main node configuration
    // =============================================================================

    struct NodeConfig {
        String name;
        Role role = Role::Member;
        InterfaceName interface{"botlink0"};
        u16 mtu = DEFAULT_MTU;
        OverlayConfig overlay;

        [[nodiscard]] auto is_member() const -> boolean { return role == Role::Member; }
        [[nodiscard]] auto is_relay() const -> boolean { return role == Role::Relay; }

        auto members() noexcept { return std::tie(name, role, interface, mtu, overlay); }
        auto members() const noexcept { return std::tie(name, role, interface, mtu, overlay); }
    };

    // =============================================================================
    // Timing Config - Configurable timeouts and intervals
    // =============================================================================

    struct TimingConfig {
        // Envelope validation
        u64 envelope_max_age_ms = 60000;   // Max age for envelope timestamps (default 60s)
        u64 envelope_max_future_ms = 5000; // Max future drift for envelope timestamps (default 5s)

        // Session management
        u64 handshake_timeout_ms = 5000;   // Handshake timeout (default 5s)
        u64 keepalive_interval_ms = 25000; // Keepalive interval (default 25s)
        u64 session_lifetime_ms = 180000;  // Session lifetime before rekey (default 3min)
        u64 peer_timeout_ms = 120000;      // Peer timeout (default 2min)

        // Sponsor/voting
        u64 sponsor_request_timeout_ms = 60000;  // Sponsor request timeout (default 60s)
        u64 sponsor_max_request_age_ms = 300000; // Max sponsor request age (default 5min)

        auto members() noexcept {
            return std::tie(envelope_max_age_ms, envelope_max_future_ms, handshake_timeout_ms, keepalive_interval_ms,
                            session_lifetime_ms, peer_timeout_ms, sponsor_request_timeout_ms,
                            sponsor_max_request_age_ms);
        }
        auto members() const noexcept {
            return std::tie(envelope_max_age_ms, envelope_max_future_ms, handshake_timeout_ms, keepalive_interval_ms,
                            session_lifetime_ms, peer_timeout_ms, sponsor_request_timeout_ms,
                            sponsor_max_request_age_ms);
        }
    };

    // =============================================================================
    // Logging Config
    // =============================================================================

    struct LoggingConfig {
        String level{"info"};

        [[nodiscard]] auto get_log_level() const -> echo::Level {
            if (level == "trace")
                return echo::Level::Trace;
            if (level == "debug")
                return echo::Level::Debug;
            if (level == "info")
                return echo::Level::Info;
            if (level == "warn")
                return echo::Level::Warn;
            if (level == "error")
                return echo::Level::Error;
            if (level == "critical")
                return echo::Level::Critical;
            return echo::Level::Info;
        }

        auto members() noexcept { return std::tie(level); }
        auto members() const noexcept { return std::tie(level); }
    };

    // =============================================================================
    // Main Config - Complete botlink configuration
    // =============================================================================

    struct Config {
        u32 version = 1;
        NodeConfig node;
        IdentityConfig identity;
        TrustConfig trust;
        RelayConfig relays;
        TimingConfig timing;
        LoggingConfig logging;

        [[nodiscard]] auto is_valid() const -> boolean {
            if (node.name.empty())
                return false;
            if (node.interface.is_empty())
                return false;
            if (!node.overlay.is_valid())
                return false;
            if (!identity.is_valid())
                return false;
            if (trust.bootstraps.empty())
                return false;
            return true;
        }

        auto members() noexcept { return std::tie(version, node, identity, trust, relays, timing, logging); }
        auto members() const noexcept { return std::tie(version, node, identity, trust, relays, timing, logging); }
    };

    // =============================================================================
    // Config Validation
    // =============================================================================

    namespace cfg {

        // Strict validation mode - all fields required
        enum class ValidationMode : u8 {
            Strict = 0,  // All fields required (for runtime)
            Lenient = 1, // Allow incomplete config (for initial setup/testing)
        };

        [[nodiscard]] inline auto validate(const Config &config, ValidationMode mode = ValidationMode::Strict)
            -> VoidRes {
            // Core validation - always required
            if (config.version != 1) {
                return result::err(err::config("Unsupported config version"));
            }

            if (config.node.name.empty()) {
                return result::err(err::config("Node name is required"));
            }

            if (config.node.interface.is_empty()) {
                return result::err(err::config("Interface name is required"));
            }

            // Strict mode additional checks
            if (mode == ValidationMode::Strict) {
                if (!config.node.overlay.is_valid()) {
                    return result::err(err::config("Invalid overlay configuration"));
                }

                if (!config.identity.is_valid()) {
                    return result::err(err::config("Invalid identity configuration"));
                }

                // Bootstrap peers not required for genesis nodes (they create the first network)
                // But still required in strict mode by default
                if (config.trust.bootstraps.empty() && config.node.role != Role::Genesis) {
                    return result::err(err::config("At least one bootstrap peer is required for non-genesis nodes"));
                }
            }

            // Policy validation - always check if set
            if (config.trust.policy.min_yes_votes == 0) {
                return result::err(err::config("min_yes_votes must be at least 1"));
            }

            return result::ok();
        }

        // Convenience function for strict validation
        [[nodiscard]] inline auto validate_strict(const Config &config) -> VoidRes {
            return validate(config, ValidationMode::Strict);
        }

        // Convenience function for lenient validation (for default config, testing)
        [[nodiscard]] inline auto validate_lenient(const Config &config) -> VoidRes {
            return validate(config, ValidationMode::Lenient);
        }

        // Create a minimal default config
        // Note: This config passes lenient validation but may need additional
        // configuration (overlay, identity, bootstraps) for strict validation
        [[nodiscard]] inline auto default_config() -> Config {
            Config config;
            config.version = 1;
            config.node.name = "botlink_node";
            config.node.role = Role::Member;
            config.node.interface = InterfaceName("botlink0");
            config.node.mtu = DEFAULT_MTU;
            config.trust.policy.min_yes_votes = 2; // Reasonable default for voting
            config.trust.policy.vote_timeout_ms = 15000;
            config.logging.level = "info";
            return config;
        }

    } // namespace cfg

} // namespace botlink
