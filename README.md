# Botlink

A decentralized mesh VPN library for robots and embedded systems. Botlink provides encrypted peer-to-peer communication with blockchain-backed trust management and NAT traversal support.

## Features

- **Cryptographic Identity**: Ed25519 for signing, X25519 for key exchange
- **Encrypted Tunnels**: ChaCha20-Poly1305 AEAD encryption with replay protection
- **Trust Management**: Blockchain-backed membership with sponsor/voting system
- **NAT Traversal**: Relay support for peers behind NAT
- **TUN Interface**: Virtual network interface via wirebit

## Dependencies

- [datapod](https://github.com/bresilla/datapod) - POD-compatible data structures
- [keylock](https://github.com/bresilla/keylock) - Cryptographic primitives (libsodium)
- [blockit](https://github.com/bresilla/blockit) - Blockchain ledger
- [wirebit](https://github.com/bresilla/wirebit) - TUN/TAP interface management
- [echo](https://github.com/bresilla/echo) - Logging

## Building

### Prerequisites

```bash
# Install libsodium
# Ubuntu/Debian
sudo apt install libsodium-dev

# Arch
sudo pacman -S libsodium

# macOS
brew install libsodium
```

### Build with xmake

```bash
# Configure and build
make build

# Run tests
make test

# Clean
make clean
```

### Build Options

```bash
# Build without hardware (TUN) support (for testing)
xmake f -DNO_HARDWARE=1
xmake build
```

## Usage

### Basic Example

```cpp
#include <botlink/botlink.hpp>

using namespace botlink;

int main() {
    // Initialize libsodium
    if (botlink::init().is_err()) {
        return 1;
    }

    // Generate identity
    auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
    NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

    // Create configuration
    Config config = cfg::default_config();
    config.node.name = "my_robot";
    config.identity.ed25519_private = ed_priv;
    config.identity.ed25519_public = ed_pub;
    config.identity.x25519_private = x_priv;
    config.identity.x25519_public = x_pub;
    config.identity.ed25519_id = crypto::node_id_to_hex(node_id);

    // Create and configure node
    runtime::BotlinkNode node;
    node.configure(config);
    node.start();

    return 0;
}
```

### Configuration File

Botlink uses a TOML-like configuration format:

```toml
[node]
name = "my_robot"
role = "member"
interface = "botlink0"
mtu = 1420

[overlay]
addr = "10.42.0.1/24"
listen = "0.0.0.0:51820"

[identity]
ed25519_private = "hex_encoded_private_key"
ed25519_public = "hex_encoded_public_key"
x25519_private = "hex_encoded_private_key"
x25519_public = "hex_encoded_public_key"

[trust]
chain_name = "swarm_trust"
chain_path = "./trust_data"
min_yes_votes = 2
vote_timeout_ms = 15000

[logging]
level = "info"
```

### Generate Configuration

```cpp
// Generate config with new keys
auto result = cfg::generate_config_with_keys(
    "my_node",           // node name
    "10.42.0.1/24",      // overlay address
    "0.0.0.0:51820"      // listen endpoint
);

if (result.is_ok()) {
    Config config = result.value();
    String config_str = cfg::serialize_config(config);
    // Save to file...
}
```

### Interactive Configuration Wizard

```cpp
cfg::WizardOptions options;
options.generate_keys = true;
options.interactive = true;

cfg::ConfigWizard wizard(options);
Config config = wizard.run();
```

## Trust System

Botlink uses a blockchain-backed trust system where new members must be sponsored and approved by existing members.

### Sponsoring a New Member

```cpp
// Sponsor creates a join proposal
Sponsor sponsor(local_node_id, ed_priv);
auto request = sponsor.create_join_request(candidate_id, candidate_ed_pub, candidate_x_pub);
auto proposal = sponsor.create_proposal(request.value());

// Proposal is broadcast to other members who vote
VotingManager voting(policy, local_node_id);
voting.add_proposal(proposal.value());

// Members cast votes
auto vote_evt = voting.cast_vote(candidate_id, Vote::Yes, "Trusted peer");

// When enough votes are received, member is approved
auto result = voting.record_vote(vote_evt.value());
if (result.value() == VoteResult::Approved) {
    // Add to trust chain
    trust_chain.add_event(approve_event);
}
```

## Metrics

Botlink provides runtime metrics via atomic counters:

```cpp
// Access global metrics
auto& m = metrics::global();

// Handshake stats
uint64_t initiated = m.handshakes_initiated.load();
uint64_t completed = m.handshakes_completed.load();
uint64_t failed = m.handshakes_failed.load();

// Packet stats
uint64_t sent = m.packets_sent.load();
uint64_t dropped_replay = m.packets_dropped_replay.load();

// Reset all metrics
m.reset();
```

## Architecture

```
+-------------------------------------------------------------+
|                      BotlinkNode                            |
|  +-------------+  +-------------+  +---------------------+  |
|  | DataPlane   |  |ControlPlane |  |     Scheduler       |  |
|  | (encrypted  |  | (join/vote  |  |  (timers/keepalive) |  |
|  |  tunnels)   |  |  gossip)    |  |                     |  |
|  +------+------+  +------+------+  +----------+----------+  |
|         |                |                    |             |
|  +------+----------------+--------------------+----------+  |
|  |                     PeerTable                         |  |
|  |              (sessions, endpoints)                    |  |
|  +---------------------------+---------------------------+  |
|                              |                              |
|  +---------------------------+---------------------------+  |
|  |                    TrustView                          |  |
|  |           (in-memory membership table)                |  |
|  +---------------------------+---------------------------+  |
|                              |                              |
|  +---------------------------+---------------------------+  |
|  |                    TrustChain                         |  |
|  |              (blockchain-backed)                      |  |
|  +-------------------------------------------------------+  |
+-------------------------------------------------------------+
```

## Wire Protocol

### Message Types

| Type | Value | Description |
|------|-------|-------------|
| HandshakeInit | 0x20 | Initiator hello |
| HandshakeResp | 0x21 | Responder response |
| Data | 0x22 | Encrypted payload |
| Keepalive | 0x23 | Connection keepalive |
| Rekey | 0x24 | Session rekey request |
| JoinRequest | 0x10 | Membership request |
| JoinProposal | 0x11 | Sponsor proposal |
| VoteCast | 0x12 | Vote message |
| MembershipUpdate | 0x13 | Membership change |

### Data Packet Format

```
+--------+--------+--------+--------------+-------------+
|Version |  Type  | Key ID | Nonce Counter| Ciphertext  |
| 1 byte | 1 byte | 4 bytes|   8 bytes    |  variable   |
+--------+--------+--------+--------------+-------------+
```

### Handshake Flow

```
    Alice                              Bob
      |                                 |
      |------- HandshakeInit ---------> |
      |  (ephemeral X25519 pubkey)      |
      |                                 |
      | <------ HandshakeResp --------- |
      |  (ephemeral X25519 pubkey +     |
      |   encrypted ACK)                |
      |                                 |
      |         [Session Established]   |
      |                                 |
      | <-------- Data ---------------> |
      |  (ChaCha20-Poly1305 encrypted)  |
```

## Security

- **Key Derivation**: HKDF-SHA256 with role-based key separation
- **Encryption**: ChaCha20-Poly1305 AEAD
- **Replay Protection**: Sliding window with 64-bit nonce counters
- **Timestamp Validation**: Configurable max age for messages
- **Identity Proof**: Ed25519 signatures for join requests

## License

MIT License - see LICENSE file for details.
