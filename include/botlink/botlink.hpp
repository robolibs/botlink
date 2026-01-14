/* SPDX-License-Identifier: MIT */
/*
 * Botlink - Decentralized Mesh VPN Library
 *
 * Main umbrella header - includes all botlink modules
 *
 * Features:
 * - Cryptographic identity (Ed25519/X25519)
 * - Blockchain-backed trust management
 * - Encrypted P2P communication
 * - NAT traversal with relay support
 * - TUN interface management via wirebit
 *
 * Dependencies:
 * - datapod: POD-compatible data structures
 * - keylock: Cryptographic primitives (libsodium)
 * - blockit: Blockchain ledger
 * - wirebit: TUN/TAP interface management
 * - echo: Logging
 */

#pragma once

// Core modules
#include <botlink/core/metrics.hpp>
#include <botlink/core/result.hpp>
#include <botlink/core/time.hpp>
#include <botlink/core/types.hpp>

// Configuration
#include <botlink/cfg/config.hpp>
#include <botlink/cfg/config_file.hpp>
#include <botlink/cfg/wizard.hpp>

// Cryptography
#include <botlink/crypto/aead.hpp>
#include <botlink/crypto/identity.hpp>
#include <botlink/crypto/kdf.hpp>
#include <botlink/crypto/sign.hpp>

// Trust management
#include <botlink/trust/sponsor.hpp>
#include <botlink/trust/trust_chain.hpp>
#include <botlink/trust/trust_event.hpp>
#include <botlink/trust/trust_view.hpp>
#include <botlink/trust/voting.hpp>

// Networking
#include <botlink/net/control_plane.hpp>
#include <botlink/net/data_plane.hpp>
#include <botlink/net/endpoint.hpp>
#include <botlink/net/relay.hpp>
#include <botlink/net/transport.hpp>

// Network device management
#include <botlink/netdev/netdev.hpp>
#include <botlink/netdev/route_table.hpp>
#ifndef NO_HARDWARE
#include <botlink/netdev/wirebit_backend.hpp>
#endif

// Runtime
#include <botlink/runtime/node.hpp>
#include <botlink/runtime/peer_table.hpp>
#include <botlink/runtime/scheduler.hpp>

namespace botlink {

    // Library version
    inline constexpr u32 VERSION_MAJOR = 0;
    inline constexpr u32 VERSION_MINOR = 1;
    inline constexpr u32 VERSION_PATCH = 0;
    inline constexpr const char *VERSION_STRING = "0.1.0";

    // Initialize libsodium (call once at startup)
    inline auto init() -> VoidRes {
        if (sodium_init() < 0) {
            return result::err(err::crypto("Failed to initialize libsodium"));
        }
        return result::ok();
    }

} // namespace botlink
