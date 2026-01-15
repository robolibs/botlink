# Botlink

A decentralized mesh VPN library for robots and embedded systems. Botlink provides encrypted peer-to-peer communication with blockchain-backed trust management and NAT traversal support.

```
    ____        __  ___       __
   / __ )____  / /_/ (_)___  / /__
  / __  / __ \/ __/ / / __ \/ //_/
 / /_/ / /_/ / /_/ / / / / / ,<
/_____/\____/\__/_/_/_/ /_/_/|_|

    Decentralized Mesh VPN for Robots
```

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Module Structure](#module-structure)
- [Core Concepts](#core-concepts)
- [Trust System](#trust-system)
- [Networking](#networking)
- [Wire Protocol](#wire-protocol)
- [State Machines](#state-machines)
- [Building](#building)
- [Usage](#usage)
- [Examples](#examples)
- [Security](#security)
- [API Reference](#api-reference)

---

## Overview

Botlink creates a **WireGuard-like encrypted overlay network** where:

- **Membership is gated by blockchain voting** - New nodes must be sponsored and approved
- **Relays exist but cannot vote** - They only forward encrypted traffic
- **End-to-end encryption** - Relays never see plaintext
- **Decentralized trust** - No single point of authority

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ROBOT SWARM                                  │
│                                                                      │
│    ┌──────────┐         ┌──────────┐         ┌──────────┐           │
│    │ Robot A  │◄───────►│ Robot B  │◄───────►│ Robot C  │           │
│    │ (Member) │         │ (Member) │         │ (Member) │           │
│    └────┬─────┘         └────┬─────┘         └────┬─────┘           │
│         │                    │                    │                  │
│         │    ┌───────────────┴───────────────┐    │                  │
│         │    │                               │    │                  │
│         └────┤      RELAY (non-member)       ├────┘                  │
│              │   - Forwards encrypted pkts   │                       │
│              │   - Cannot vote               │                       │
│              │   - Cannot introduce          │                       │
│              └───────────────────────────────┘                       │
│                                                                      │
│    ════════════════════════════════════════════════════════════     │
│                      TRUST CHAIN (Blockit)                           │
│         Genesis → Join → Vote → Approve → ... → Revoke               │
│    ════════════════════════════════════════════════════════════     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Architecture

### Layered Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        YOUR APPLICATION                              │
│           ROS2 / Controller / Swarm Logic / Mission Planner          │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           BOTLINK LIBRARY                            │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                      runtime/node.hpp                          │  │
│  │                        BotlinkNode                             │  │
│  │   - Event loop          - Config management                    │  │
│  │   - Component orchestration                                    │  │
│  └─────────────────────────────┬─────────────────────────────────┘  │
│                                │                                     │
│    ┌───────────────────────────┼───────────────────────────┐        │
│    │                           │                           │        │
│    ▼                           ▼                           ▼        │
│  ┌─────────────┐    ┌─────────────────────┐    ┌─────────────────┐  │
│  │ TRUST (L1)  │    │     DATA PLANE (L2)  │    │    NETDEV       │  │
│  │             │    │                      │    │                 │  │
│  │ trust_chain │    │ Encrypted tunnels    │    │ TUN interface   │  │
│  │ trust_view  │    │ Handshake + AEAD     │    │ Route table     │  │
│  │ sponsor     │    │ Keepalive + Rekey    │    │ IP assignment   │  │
│  │ voting      │    │ Relay fallback       │    │                 │  │
│  └──────┬──────┘    └──────────┬───────────┘    └────────┬────────┘  │
│         │                      │                         │           │
│    ┌────┴──────────────────────┴─────────────────────────┴────┐     │
│    │                    CRYPTO LAYER                           │     │
│    │  Ed25519 (signing) │ X25519 (ECDH) │ ChaCha20-Poly1305   │     │
│    │  HKDF-SHA256       │ Replay Window │ Secure Key Clear     │     │
│    └────┬──────────────────────────────────────────────────────┘     │
│         │                                                            │
│    ┌────┴──────────────────────────────────────────────────────┐     │
│    │                    CORE TYPES                              │     │
│    │  NodeId │ Endpoint │ PublicKey │ SessionKey │ Result<T>   │     │
│    └────────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────┘
                                │
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
          ┌──────────┐   ┌──────────┐   ┌──────────┐
          │ Datapod  │   │ Keylock  │   │ Blockit  │
          │ (types)  │   │ (crypto) │   │ (chain)  │
          └──────────┘   └──────────┘   └──────────┘
```

### Component Interaction

```
                    ┌──────────────────────────────────────────┐
                    │              BotlinkNode                  │
                    │                                          │
                    │  ┌────────────┐     ┌────────────────┐   │
  UDP Socket ◄──────┼──┤ DataPlane  │     │  ControlPlane  │   │
      │             │  │            │     │                │   │
      │             │  │ • Handshake│     │ • JoinRequest  │   │
      │             │  │ • Encrypt  │     │ • VoteCast     │   │
      │             │  │ • Decrypt  │     │ • Membership   │   │
      │             │  │ • Keepalive│     │ • Gossip       │   │
      │             │  └─────┬──────┘     └───────┬────────┘   │
      │             │        │                    │            │
      │             │        └──────┬─────────────┘            │
      │             │               │                          │
      │             │        ┌──────▼──────┐                   │
      │             │        │  PeerTable  │                   │
      │             │        │             │                   │
      │             │        │ • Sessions  │                   │
      │             │        │ • Endpoints │                   │
      │             │        │ • Keys      │                   │
      │             │        └──────┬──────┘                   │
      │             │               │                          │
      │             │        ┌──────▼──────┐                   │
      │             │        │  TrustView  │◄──── sync ────┐   │
      │             │        │             │               │   │
      │             │        │ • Members   │               │   │
      │             │        │ • Proposals │               │   │
      │             │        └──────┬──────┘               │   │
      │             │               │                      │   │
      │             │        ┌──────▼──────┐        ┌──────┴───┴──┐
      │             │        │ TrustChain  │◄──────►│   Blockit   │
      │             │        │ (ledger)    │        │  (storage)  │
      │             │        └─────────────┘        └─────────────┘
      │             │                                          │
      │             │        ┌─────────────┐                   │
      │             │        │  Scheduler  │                   │
      │             │        │             │                   │
      │             │        │ • Keepalive │                   │
      │             │        │ • Rekey     │                   │
      │             │        │ • Cleanup   │                   │
      │             │        │ • TrustSync │                   │
      │             │        └─────────────┘                   │
      │             └──────────────────────────────────────────┘
      │
      ▼
┌──────────────┐
│  TUN Device  │
│  (botlink0)  │
└──────────────┘
```

---

## Module Structure

```
include/botlink/
├── botlink.hpp              # Umbrella header
│
├── core/                    # Foundation
│   ├── types.hpp            # NodeId, PublicKey, Endpoint, enums
│   ├── result.hpp           # Res<T>, VoidRes, Error handling
│   ├── time.hpp             # Timeout, IntervalTimer, now_ms()
│   └── metrics.hpp          # Atomic counters for stats
│
├── crypto/                  # Cryptographic Operations
│   ├── identity.hpp         # Key generation, NodeId derivation
│   ├── sign.hpp             # Envelope signing/verification
│   ├── kdf.hpp              # HKDF, session keys, rekey
│   └── aead.hpp             # ChaCha20-Poly1305, replay window
│
├── trust/                   # Membership Management
│   ├── trust_event.hpp      # TrustEvent, JoinProposal, Vote
│   ├── trust_chain.hpp      # Blockchain wrapper (Blockit)
│   ├── trust_view.hpp       # In-memory membership state
│   ├── sponsor.hpp          # Join request handling
│   └── voting.hpp           # Vote aggregation, quorum
│
├── net/                     # Network Protocol
│   ├── endpoint.hpp         # IP:port parsing/formatting
│   ├── transport.hpp        # UDP socket wrapper
│   ├── control_plane.hpp    # Join/vote/membership gossip
│   ├── data_plane.hpp       # Encrypted tunnels, handshake
│   └── relay.hpp            # NAT traversal, relay routing
│
├── netdev/                  # Network Device
│   ├── netdev.hpp           # Abstract TUN interface
│   ├── wirebit_backend.hpp  # Wirebit implementation
│   └── route_table.hpp      # Overlay IP → peer routing
│
├── runtime/                 # Node Orchestration
│   ├── node.hpp             # BotlinkNode main class
│   ├── peer_table.hpp       # Peer state management
│   └── scheduler.hpp        # Timer-based tasks
│
└── cfg/                     # Configuration
    ├── config.hpp           # Config structs, validation
    ├── config_file.hpp      # File parsing
    └── wizard.hpp           # Interactive config builder
```

### Module Dependency Graph

```
                         ┌─────────────────┐
                         │    runtime/     │
                         │    node.hpp     │
                         └────────┬────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
       ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
       │    net/     │    │   trust/    │    │   netdev/   │
       │ data_plane  │    │ trust_view  │    │   netdev    │
       │ctrl_plane   │    │ trust_chain │    │ route_table │
       │   relay     │    │  sponsor    │    └──────┬──────┘
       └──────┬──────┘    │  voting     │           │
              │           └──────┬──────┘           │
              │                  │                  │
              └────────┬─────────┴──────────────────┘
                       │
                       ▼
               ┌─────────────┐
               │   crypto/   │
               │  identity   │
               │    sign     │
               │    kdf      │
               │    aead     │
               └──────┬──────┘
                      │
                      ▼
               ┌─────────────┐
               │    core/    │
               │    types    │
               │   result    │
               │    time     │
               │   metrics   │
               └─────────────┘
```

---

## Core Concepts

### Identity

Every node has a cryptographic identity:

```
┌─────────────────────────────────────────────────────────────────┐
│                        NODE IDENTITY                             │
│                                                                  │
│   Ed25519 Key Pair (Signing)        X25519 Key Pair (ECDH)      │
│   ┌─────────────────────────┐       ┌─────────────────────────┐ │
│   │  Private Key (32 bytes) │       │  Private Key (32 bytes) │ │
│   │  Public Key  (32 bytes) │       │  Public Key  (32 bytes) │ │
│   └────────────┬────────────┘       └─────────────────────────┘ │
│                │                                                 │
│                ▼                                                 │
│   ┌────────────────────────┐                                    │
│   │  NodeId = SHA256(      │                                    │
│   │    Ed25519_PubKey)     │                                    │
│   │  (32 bytes / 64 hex)   │                                    │
│   └────────────────────────┘                                    │
│                                                                  │
│   Example: 7c464d211758b1e3a9f2d4c5b6e7f8091234567890abcdef...  │
└─────────────────────────────────────────────────────────────────┘
```

### Roles

```
┌──────────────────────────────────────────────────────────────────┐
│                           ROLES                                   │
│                                                                   │
│   ┌─────────────────────┐         ┌─────────────────────┐        │
│   │       MEMBER        │         │        RELAY        │        │
│   │                     │         │                     │        │
│   │  ✓ Can vote         │         │  ✗ Cannot vote      │        │
│   │  ✓ Can sponsor      │         │  ✗ Cannot sponsor   │        │
│   │  ✓ Can introduce    │         │  ✗ Cannot introduce │        │
│   │  ✓ Send/recv data   │         │  ✓ Forward packets  │        │
│   │  ✓ Trust decisions  │         │  ✗ No trust access  │        │
│   │                     │         │                     │        │
│   │  [Full participant] │         │  [Dumb forwarder]   │        │
│   └─────────────────────┘         └─────────────────────┘        │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### Session Keys

```
┌──────────────────────────────────────────────────────────────────┐
│                     SESSION KEY DERIVATION                        │
│                                                                   │
│   Node A (Initiator)              Node B (Responder)              │
│                                                                   │
│   ephemeral_priv_A ─┐         ┌─ ephemeral_priv_B                │
│   ephemeral_pub_A  ─┼────────►│                                  │
│                     │         │◄─ ephemeral_pub_B                │
│                     │         │                                   │
│                     ▼         ▼                                   │
│              ┌─────────────────────┐                              │
│              │  X25519 ECDH        │                              │
│              │  shared_secret =    │                              │
│              │    DH(priv, pub)    │                              │
│              └──────────┬──────────┘                              │
│                         │                                         │
│                         ▼                                         │
│              ┌─────────────────────┐                              │
│              │  HKDF-SHA256        │                              │
│              │  salt = sorted IDs  │                              │
│              │  info = "botlink"   │                              │
│              └──────────┬──────────┘                              │
│                         │                                         │
│           ┌─────────────┴─────────────┐                          │
│           ▼                           ▼                          │
│   ┌───────────────┐           ┌───────────────┐                  │
│   │ Key Material  │           │ Key Material  │                  │
│   │ (64 bytes)    │           │ (64 bytes)    │                  │
│   │               │           │               │                  │
│   │ [0:32] send_A │           │ [0:32] recv_B │                  │
│   │ [32:64] recv_A│           │ [32:64] send_B│                  │
│   └───────────────┘           └───────────────┘                  │
│                                                                   │
│   Result: A.send = B.recv,  A.recv = B.send                      │
└──────────────────────────────────────────────────────────────────┘
```

---

## Trust System

### Membership Lifecycle

```
                         CANDIDATE LIFECYCLE

    ┌───────────────┐
    │  UNCONFIGURED │   No identity/config
    └───────┬───────┘
            │ configure()
            ▼
    ┌───────────────┐
    │   CONFIGURED  │   Has keys, ready to join
    └───────┬───────┘
            │ send JoinRequest to sponsor
            ▼
    ┌───────────────┐    VoteCast from members
    │    PENDING    │◄──────────────────────────
    │  (candidate)  │
    └───────┬───────┘
            │
     ┌──────┴──────┐
     │             │
     ▼             ▼
┌─────────┐  ┌──────────┐
│APPROVED │  │ REJECTED │
│(member) │  │          │
└────┬────┘  └──────────┘
     │
     │ revoke()
     ▼
┌─────────┐
│ REVOKED │
└─────────┘
```

### Join Flow Sequence

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌────────────┐
│Candidate │     │ Sponsor  │     │ Members  │     │ TrustChain │
│   (C)    │     │   (S)    │     │ (M1..Mn) │     │            │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └─────┬──────┘
     │                │                │                 │
     │ JoinRequest    │                │                 │
     │ (signed proof) │                │                 │
     │───────────────►│                │                 │
     │                │                │                 │
     │                │ verify signature                 │
     │                │ check rate limit                 │
     │                │                │                 │
     │                │ JoinProposal   │                 │
     │                │────────────────┼────────────────►│
     │                │                │                 │
     │                │                │ notify proposal │
     │                │                │◄────────────────│
     │                │                │                 │
     │                │        VoteCast│                 │
     │                │◄───────────────│                 │
     │                │                │                 │
     │                │   (collect votes)               │
     │                │                │                 │
     │                │                │ quorum reached  │
     │                │ JoinApproved   │                 │
     │                │────────────────┼────────────────►│
     │                │                │                 │
     │ MembershipUpdate                │ broadcast       │
     │◄────────────────────────────────┼─────────────────│
     │                │                │                 │
     │  (C is now APPROVED member)     │                 │
     │                │                │                 │
```

### Voting System

```
┌─────────────────────────────────────────────────────────────────┐
│                      VOTING MANAGER                              │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   VotingPolicy                           │    │
│  │  • min_yes_votes: 2     (quorum for approval)           │    │
│  │  • min_no_votes: 3      (quorum for rejection)          │    │
│  │  • vote_timeout_ms: 15000 (15 seconds)                  │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │               ProposalState                              │    │
│  │                                                          │    │
│  │  candidate_id: 0x7c464d21...                            │    │
│  │  votes: {                                                │    │
│  │    0xabc123... : Yes,                                   │    │
│  │    0xdef456... : Yes,                                   │    │
│  │    0x789abc... : No                                     │    │
│  │  }                                                       │    │
│  │  yes_count: 2  ✓ (>= min_yes_votes)                     │    │
│  │  no_count:  1                                            │    │
│  │  expires_at: 1234567890                                 │    │
│  │                                                          │    │
│  │  Result: APPROVED                                        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Networking

### Peer Connection Lifecycle

```
                         PEER CONNECTION STATE

    ┌───────────────┐
    │    UNKNOWN    │   No info about peer
    └───────┬───────┘
            │ receive EndpointAdvert
            ▼
    ┌───────────────┐
    │  CONNECTING   │   Attempting handshake
    └───────┬───────┘
            │
     ┌──────┴──────┬────────────────┐
     │             │                │
     ▼             ▼                ▼
┌─────────┐  ┌───────────┐  ┌─────────────┐
│ DIRECT  │  │ RELAY_TRY │  │ UNREACHABLE │
│         │  │           │  │             │
│handshake│  │via relay  │  │all attempts │
│ success │  │           │  │  failed     │
└────┬────┘  └─────┬─────┘  └─────────────┘
     │             │
     │             │ relay success
     │             ▼
     │       ┌───────────┐
     └──────►│  RELAYED  │
             │           │
             │encrypted  │
             │via relay  │
             └───────────┘
```

### Relay Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                       RELAY FORWARDING                            │
│                                                                   │
│   Peer A (NAT)              Relay R (Public)           Peer B    │
│                                                                   │
│      │    direct attempt       │                          │      │
│      │─────────────────────────┼──────────────────────────┤      │
│      │         (blocked by NAT)│                          │      │
│      │                         │                          │      │
│      │ RelayConnectRequest     │                          │      │
│      │────────────────────────►│                          │      │
│      │                         │                          │      │
│      │                         │  RelayConnectRequest     │      │
│      │                         │─────────────────────────►│      │
│      │                         │                          │      │
│      │        RelayAck         │         RelayAck         │      │
│      │◄────────────────────────│◄─────────────────────────│      │
│      │                         │                          │      │
│      │═══════════════════════════════════════════════════│      │
│      │           RELAY PATH ESTABLISHED                  │      │
│      │═══════════════════════════════════════════════════│      │
│      │                         │                          │      │
│      │  DataPacket (encrypted) │                          │      │
│      │────────────────────────►│  DataPacket (encrypted)  │      │
│      │    src=A, dst=B         │─────────────────────────►│      │
│      │                         │    (opaque to relay)     │      │
│      │                         │                          │      │
│      │  DataPacket (encrypted) │  DataPacket (encrypted)  │      │
│      │◄────────────────────────│◄─────────────────────────│      │
│      │    src=B, dst=A         │                          │      │
│                                                                   │
│   NOTE: Relay R never decrypts - end-to-end between A and B      │
└──────────────────────────────────────────────────────────────────┘
```

---

## Wire Protocol

### Message Types

| Range | Type | Value | Description |
|-------|------|-------|-------------|
| Control | JoinRequest | 0x01 | Candidate → Sponsor |
| Control | JoinProposal | 0x02 | Sponsor → Chain |
| Control | VoteCast | 0x03 | Member → Chain |
| Control | MembershipUpdate | 0x04 | Broadcast |
| Control | EndpointAdvert | 0x05 | Peer discovery |
| Relay | RelayConnect | 0x10 | Request relay path |
| Relay | RelayDisconnect | 0x11 | Close relay path |
| Relay | RelayForward | 0x12 | Forwarded packet |
| Relay | RelayAck | 0x13 | Acknowledgment |
| Data | HandshakeInit | 0x20 | Initiator hello |
| Data | HandshakeResp | 0x21 | Responder hello |
| Data | Data | 0x22 | Encrypted payload |
| Data | Keepalive | 0x23 | Connection keepalive |
| Data | Rekey | 0x24 | Session rekey |

### Envelope Format (Control Plane)

```
┌─────────────────────────────────────────────────────────────────┐
│                     ENVELOPE STRUCTURE                           │
│                                                                  │
│  ┌──────────┬──────────┬──────────┬──────────────────────────┐  │
│  │ Version  │ MsgType  │  Flags   │       Timestamp          │  │
│  │ (1 byte) │ (1 byte) │ (4 bytes)│        (8 bytes)         │  │
│  └──────────┴──────────┴──────────┴──────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                     Sender ID (32 bytes)                   │  │
│  │              NodeId = SHA256(Ed25519_PubKey)               │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Signature (64 bytes)                    │  │
│  │                Ed25519 over header + payload               │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                   Payload (variable)                       │  │
│  │              Message-specific serialized data              │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Total: 110 + payload_len bytes                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Data Packet Format (Data Plane)

```
┌─────────────────────────────────────────────────────────────────┐
│                    DATA PACKET STRUCTURE                         │
│                                                                  │
│  ┌──────────┬──────────┬──────────┬──────────────────────────┐  │
│  │ Version  │ PktType  │  Key ID  │     Nonce Counter        │  │
│  │ (1 byte) │ (1 byte) │ (4 bytes)│        (8 bytes)         │  │
│  └──────────┴──────────┴──────────┴──────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                   Ciphertext (variable)                    │  │
│  │            ChaCha20-Poly1305 encrypted payload             │  │
│  │            (includes 16-byte auth tag)                     │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Nonce construction: counter (8 bytes) + zeros (16 bytes)       │
│  Total: 14 + ciphertext_len bytes                               │
└─────────────────────────────────────────────────────────────────┘
```

### Handshake Protocol

```
┌─────────────────────────────────────────────────────────────────┐
│                     HANDSHAKE PROTOCOL                           │
│                                                                  │
│   Alice (Initiator)                      Bob (Responder)        │
│                                                                  │
│   1. Generate ephemeral X25519                                   │
│      ephemeral_priv, ephemeral_pub                              │
│                                                                  │
│   2. Send HandshakeInit                                          │
│      ┌────────────────────────────┐                             │
│      │ type: HandshakeInit (0x20) │                             │
│      │ ephemeral_pub: [32 bytes]  │                             │
│      │ initiator_id: [32 bytes]   │                             │
│      │ timestamp: [8 bytes]       │                             │
│      └───────────────┬────────────┘                             │
│                      │                                          │
│                      └─────────────────────────────►            │
│                                                                  │
│                              3. Generate ephemeral X25519       │
│                                 ephemeral_priv, ephemeral_pub   │
│                                                                  │
│                              4. Compute shared secret           │
│                                 shared = DH(priv, alice_pub)    │
│                                                                  │
│                              5. Derive session keys             │
│                                 (send_key, recv_key) = HKDF     │
│                                                                  │
│                              6. Send HandshakeResp              │
│      ┌────────────────────────────┐                             │
│      │ type: HandshakeResp (0x21) │                             │
│      │ ephemeral_pub: [32 bytes]  │◄────────────────────────────│
│      │ responder_id: [32 bytes]   │                             │
│      │ encrypted_ack: [encrypted] │                             │
│      └────────────────────────────┘                             │
│                                                                  │
│   7. Compute shared secret                                       │
│      shared = DH(priv, bob_pub)                                 │
│                                                                  │
│   8. Derive session keys                                         │
│      (send_key, recv_key) = HKDF                                │
│                                                                  │
│   9. Verify encrypted_ack                                        │
│                                                                  │
│   ═══════════════════════════════════════════════════════════   │
│                     SESSION ESTABLISHED                          │
│   ═══════════════════════════════════════════════════════════   │
│                                                                  │
│   Alice.send_key == Bob.recv_key                                │
│   Alice.recv_key == Bob.send_key                                │
└─────────────────────────────────────────────────────────────────┘
```

---

## State Machines

### Node State Machine

```
┌─────────────────────────────────────────────────────────────────┐
│                      NODE STATE MACHINE                          │
│                                                                  │
│                    ┌──────────────┐                              │
│                    │ UNCONFIGURED │                              │
│                    └──────┬───────┘                              │
│                           │ configure(config)                    │
│                           ▼                                      │
│                    ┌──────────────┐                              │
│         ┌─────────│  CONFIGURED  │                               │
│         │         └──────┬───────┘                               │
│         │                │ start()                               │
│         │                ▼                                       │
│         │         ┌──────────────┐                               │
│         │         │   STARTING   │──────────┐                    │
│         │         └──────┬───────┘          │                    │
│         │                │ init complete    │ init failed        │
│         │                ▼                  │                    │
│         │         ┌──────────────┐          │                    │
│         │ stop()  │   RUNNING    │          │                    │
│         │    ┌───►│              │          │                    │
│         │    │    │  • poll()    │          │                    │
│         │    │    │  • run()     │          │                    │
│         │    │    └──────┬───────┘          │                    │
│         │    │           │ stop()           │                    │
│         │    │           ▼                  │                    │
│         │    │    ┌──────────────┐          │                    │
│         │    └────│   STOPPING   │          │                    │
│         │         └──────┬───────┘          │                    │
│         │                │ cleanup done     │                    │
│         │                ▼                  ▼                    │
│         │         ┌──────────────┐   ┌──────────────┐            │
│         └────────►│   STOPPED    │   │    ERROR     │            │
│                   └──────────────┘   └──────────────┘            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Event Loop

```
┌─────────────────────────────────────────────────────────────────┐
│                        EVENT LOOP                                │
│                                                                  │
│   ┌───────────────────────────────────────────────────────┐     │
│   │                    poll() cycle                        │     │
│   │                                                        │     │
│   │   ┌─────────────────┐                                  │     │
│   │   │ 1. Scheduler    │  Process timers:                 │     │
│   │   │    tick()       │  • Keepalive (25s)               │     │
│   │   │                 │  • Rekey (120s)                  │     │
│   │   │                 │  • Peer cleanup (60s)            │     │
│   │   │                 │  • Trust sync (30s)              │     │
│   │   └────────┬────────┘  • Vote timeout (5s)             │     │
│   │            │                                           │     │
│   │            ▼                                           │     │
│   │   ┌─────────────────┐                                  │     │
│   │   │ 2. Receive      │  UDP socket recv()               │     │
│   │   │    packets      │                                  │     │
│   │   └────────┬────────┘                                  │     │
│   │            │                                           │     │
│   │            ▼                                           │     │
│   │   ┌─────────────────┐                                  │     │
│   │   │ 3. Dispatch     │  Based on msg_type byte:         │     │
│   │   │    by type      │  • 0x01-0x0F → ControlPlane      │     │
│   │   │                 │  • 0x10-0x1F → RelayManager      │     │
│   │   │                 │  • 0x20-0x2F → DataPlane         │     │
│   │   └────────┬────────┘                                  │     │
│   │            │                                           │     │
│   │            ▼                                           │     │
│   │   ┌─────────────────┐                                  │     │
│   │   │ 4. Process      │  TUN device read/write           │     │
│   │   │    netdev       │  Route overlay packets           │     │
│   │   └────────┬────────┘                                  │     │
│   │            │                                           │     │
│   │            ▼                                           │     │
│   │   ┌─────────────────┐                                  │     │
│   │   │ 5. Sleep        │  Until next timer or 100ms       │     │
│   │   └─────────────────┘                                  │     │
│   │                                                        │     │
│   └───────────────────────────────────────────────────────┘     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Building

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install libsodium-dev

# Arch Linux
sudo pacman -S libsodium

# macOS
brew install libsodium

# Fedora
sudo dnf install libsodium-devel
```

### Build Commands

```bash
# Configure and build
make build

# Run all tests
make test

# Build and run specific example
xmake run mesh_demo
xmake run join_candidate
xmake run sponsor_daemon
xmake run relay_server

# Clean build
make clean

# Build without hardware (TUN) support
xmake f -DNO_HARDWARE=1
xmake build
```

---

## Usage

### Basic Example

```cpp
#include <botlink/botlink.hpp>

using namespace botlink;

int main() {
    // Initialize cryptographic library
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
    config.node.interface = InterfaceName("botlink0");
    config.node.overlay.addr = OverlayAddr("10.42.0.1", 24);

    // Set identity
    config.identity.ed25519_private = ed_priv;
    config.identity.ed25519_public = ed_pub;
    config.identity.x25519_private = x_priv;
    config.identity.x25519_public = x_pub;

    // Create and run node
    runtime::BotlinkNode node;
    node.configure(config);
    node.start();
    node.run();  // Blocking event loop

    return 0;
}
```

### Configuration File Format

```toml
[node]
name = "robot_007"
role = "member"
interface = "botlink0"
mtu = 1420

[overlay]
addr = "10.42.0.7/24"
listen = "0.0.0.0:51820"

[identity]
ed25519_private = "BASE64_ENCODED_KEY"
ed25519_public = "BASE64_ENCODED_KEY"
x25519_private = "BASE64_ENCODED_KEY"
x25519_public = "BASE64_ENCODED_KEY"
ed25519_id = "HEX_NODE_ID"

[trust]
chain_name = "swarm_trust"
chain_path = "./trust_data"
min_yes_votes = 2
vote_timeout_ms = 15000

[relays]
allow = ["RELAY_A", "RELAY_B"]
prefer = ["RELAY_A"]

[logging]
level = "info"
```

---

## Examples

### Available Examples

| Example | Description |
|---------|-------------|
| `minimal_node` | Basic node setup and configuration |
| `join_candidate` | Candidate sending join request |
| `sponsor_daemon` | Sponsor handling join requests |
| `relay_server` | Non-member relay for NAT traversal |
| `mesh_demo` | Full demo with handshake and encryption |

### Running Examples

```bash
# Mesh demo - two nodes with encrypted messaging
xmake run mesh_demo

# Join flow - candidate requesting membership
xmake run join_candidate

# Sponsor - receiving and validating join requests
xmake run sponsor_daemon

# Relay - NAT traversal server
xmake run relay_server
```

---

## Security

### Cryptographic Primitives

| Function | Algorithm | Size |
|----------|-----------|------|
| Signing | Ed25519 | 64-byte signature |
| Key Exchange | X25519 | 32-byte shared secret |
| Encryption | XChaCha20-Poly1305 | 16-byte auth tag |
| Key Derivation | HKDF-SHA256 | Variable output |
| Node ID | SHA-256 | 32 bytes |

### Security Properties

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY GUARANTEES                           │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ CONFIDENTIALITY                                           │   │
│  │ • All data encrypted with ChaCha20-Poly1305              │   │
│  │ • Per-session keys via X25519 ECDH                       │   │
│  │ • Relays see only ciphertext                             │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ INTEGRITY                                                 │   │
│  │ • All control messages Ed25519 signed                    │   │
│  │ • AEAD provides authentication                           │   │
│  │ • Poly1305 MAC on all data packets                       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ REPLAY PROTECTION                                         │   │
│  │ • Sliding window (64 packets) for data plane             │   │
│  │ • Timestamp validation (±30s) for control plane          │   │
│  │ • Counter-mode nonces                                    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ FORWARD SECRECY                                           │   │
│  │ • Ephemeral keys per handshake                           │   │
│  │ • Session rekey every 120 seconds                        │   │
│  │ • Secure key clearing on destruction                     │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ MEMBERSHIP SECURITY                                       │   │
│  │ • Multi-party voting for new members                     │   │
│  │ • Blockchain-backed audit trail                          │   │
│  │ • Cryptographic identity proof                           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Identity Spoofing | Ed25519 signatures on all control messages |
| Replay Attacks | Timestamps + nonce counters + sliding window |
| Man-in-the-Middle | ECDH handshake with identity binding |
| Denial of Service | Rate limiting (1 msg/sec/node) |
| Membership Takeover | Multi-step voting with configurable quorum |
| Key Compromise | Forward secrecy via periodic rekeying |

---

## API Reference

### Core Types

```cpp
using NodeId = Array<u8, 32>;           // SHA256(pubkey)
using PublicKey = Array<u8, 32>;        // Ed25519/X25519 public key
using PrivateKey = Array<u8, 32>;       // Ed25519/X25519 private key
using Signature = Array<u8, 64>;        // Ed25519 signature
using SessionKey = Array<u8, 32>;       // AEAD encryption key
```

### Key Functions

```cpp
// Identity
auto generate_ed25519_keypair() -> Pair<PrivateKey, PublicKey>;
auto generate_x25519_keypair() -> Pair<PrivateKey, PublicKey>;
auto node_id_from_pubkey(const PublicKey&) -> NodeId;

// Signing
auto ed25519_sign(const PrivateKey&, const Vector<u8>&) -> Signature;
auto ed25519_verify(const PublicKey&, const Vector<u8>&, const Signature&) -> bool;

// Key Exchange
auto x25519_shared_secret(const PrivateKey&, const PublicKey&) -> SharedSecret;
auto derive_session_keys(const SharedSecret&, ...) -> Pair<SessionKey, SessionKey>;

// Encryption
auto aead_encrypt(const SessionKey&, const Nonce&, const Vector<u8>&) -> Vector<u8>;
auto aead_decrypt(const SessionKey&, const Nonce&, const Vector<u8>&) -> Res<Vector<u8>>;
```

### Runtime Metrics

```cpp
auto& m = metrics::global();

// Handshakes
m.handshakes_initiated.load();
m.handshakes_completed.load();
m.handshakes_failed.load();

// Packets
m.packets_sent.load();
m.packets_received.load();
m.packets_dropped_replay.load();
m.packets_dropped_decrypt_fail.load();

// Voting
m.proposals_received.load();
m.votes_cast.load();
m.proposals_approved.load();
m.proposals_rejected.load();
```

---

## Dependencies

| Library | Purpose | Link |
|---------|---------|------|
| datapod | POD-compatible data structures | [GitHub](https://github.com/robolibs/datapod) |
| keylock | Cryptographic primitives (libsodium) | [GitHub](https://github.com/robolibs/keylock) |
| blockit | Blockchain ledger | [GitHub](https://github.com/robolibs/blockit) |
| wirebit | TUN/TAP interface management | [GitHub](https://github.com/robolibs/wirebit) |
| netpipe | UDP/TCP transport | [GitHub](https://github.com/robolibs/netpipe) |
| echo | Logging | [GitHub](https://github.com/bresilla/echo) |
| scan | Interactive terminal UI | [GitHub](https://github.com/bresilla/scan) |

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Contributing

Contributions are welcome! Please read the contribution guidelines before submitting pull requests.

```
         ╔══════════════════════════════════════╗
         ║  Built with love for robot swarms    ║
         ║     Secure. Decentralized. Fast.     ║
         ╚══════════════════════════════════════╝
```
