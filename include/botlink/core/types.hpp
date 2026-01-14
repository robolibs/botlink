/* SPDX-License-Identifier: MIT */
/*
 * Botlink Core Types
 * POD-compatible types using datapod primitives
 */

#pragma once

#include <datapod/datapod.hpp>

namespace botlink {

    using namespace dp;

    // =============================================================================
    // Number to String Helpers (avoid std::to_string)
    // =============================================================================

    namespace detail {
        template <typename T> inline auto num_to_string(T value) -> String {
            if (value == 0) {
                return String("0");
            }

            boolean negative = false;
            if constexpr (std::is_signed_v<T>) {
                if (value < 0) {
                    negative = true;
                    value = -value;
                }
            }

            char buf[32];
            usize idx = 31;
            buf[idx] = '\0';

            while (value > 0 && idx > 0) {
                --idx;
                buf[idx] = '0' + static_cast<char>(value % 10);
                value /= 10;
            }

            if (negative && idx > 0) {
                --idx;
                buf[idx] = '-';
            }

            return String(&buf[idx]);
        }
    } // namespace detail

    inline auto to_str(u8 v) -> String { return detail::num_to_string(v); }
    inline auto to_str(u16 v) -> String { return detail::num_to_string(v); }
    inline auto to_str(u32 v) -> String { return detail::num_to_string(v); }
    inline auto to_str(u64 v) -> String { return detail::num_to_string(v); }
    inline auto to_str(i8 v) -> String { return detail::num_to_string(v); }
    inline auto to_str(i16 v) -> String { return detail::num_to_string(v); }
    inline auto to_str(i32 v) -> String { return detail::num_to_string(v); }
    inline auto to_str(i64 v) -> String { return detail::num_to_string(v); }

    // Parse string to number (returns 0 on invalid input)
    inline auto parse_u16(const String &s) -> u16 {
        u16 result = 0;
        for (usize i = 0; i < s.size(); ++i) {
            char c = s[i];
            if (c < '0' || c > '9') {
                break;
            }
            result = result * 10 + static_cast<u16>(c - '0');
        }
        return result;
    }

    inline auto parse_u32(const String &s) -> u32 {
        u32 result = 0;
        for (usize i = 0; i < s.size(); ++i) {
            char c = s[i];
            if (c < '0' || c > '9') {
                break;
            }
            result = result * 10 + static_cast<u32>(c - '0');
        }
        return result;
    }

    // =============================================================================
    // Constants
    // =============================================================================

    inline constexpr usize KEY_SIZE = 32;
    inline constexpr usize KEY_B64_SIZE = ((KEY_SIZE + 2) / 3) * 4 + 1;
    inline constexpr usize NODE_ID_SIZE = 32;
    inline constexpr usize SIGNATURE_SIZE = 64;
    inline constexpr u16 DEFAULT_PORT = 51820;
    inline constexpr u16 DEFAULT_MTU = 1420;

    // =============================================================================
    // Role Enum
    // =============================================================================

    enum class Role : u8 {
        Member = 0, // Full participant: can vote, introduce, tunnel
        Relay = 1,  // Forwarder only: cannot vote, cannot introduce
    };

    [[nodiscard]] inline auto role_to_string(Role role) -> const char * {
        switch (role) {
        case Role::Member:
            return "member";
        case Role::Relay:
            return "relay";
        default:
            return "unknown";
        }
    }

    // =============================================================================
    // Membership Status
    // =============================================================================

    enum class MemberStatus : u8 {
        Unconfigured = 0, // Initial state, no identity
        Configured = 1,   // Has identity, not yet joined
        Pending = 2,      // Join request submitted, awaiting votes
        Approved = 3,     // Membership approved, can participate
        Rejected = 4,     // Join request rejected
        Revoked = 5,      // Membership revoked
    };

    [[nodiscard]] inline auto status_to_string(MemberStatus status) -> const char * {
        switch (status) {
        case MemberStatus::Unconfigured:
            return "unconfigured";
        case MemberStatus::Configured:
            return "configured";
        case MemberStatus::Pending:
            return "pending";
        case MemberStatus::Approved:
            return "approved";
        case MemberStatus::Rejected:
            return "rejected";
        case MemberStatus::Revoked:
            return "revoked";
        default:
            return "unknown";
        }
    }

    // =============================================================================
    // Peer Connectivity Status
    // =============================================================================

    enum class PeerStatus : u8 {
        Unknown = 0,     // No contact attempted
        Connecting = 1,  // Attempting handshake
        Direct = 2,      // Direct P2P connection established
        RelayTry = 3,    // Trying to connect via relay
        Relayed = 4,     // Connected via relay
        Unreachable = 5, // Cannot establish connection
    };

    [[nodiscard]] inline auto peer_status_to_string(PeerStatus status) -> const char * {
        switch (status) {
        case PeerStatus::Unknown:
            return "unknown";
        case PeerStatus::Connecting:
            return "connecting";
        case PeerStatus::Direct:
            return "direct";
        case PeerStatus::RelayTry:
            return "relay_try";
        case PeerStatus::Relayed:
            return "relayed";
        case PeerStatus::Unreachable:
            return "unreachable";
        default:
            return "unknown";
        }
    }

    // =============================================================================
    // Message Types
    // =============================================================================

    enum class MsgType : u8 {
        // Control plane messages
        JoinRequest = 0x01,
        JoinProposal = 0x02,
        VoteCast = 0x03,
        MembershipUpdate = 0x04,
        EndpointAdvert = 0x05,

        // Relay control
        RelayConnect = 0x10,
        RelayDisconnect = 0x11,

        // Data plane messages
        HandshakeInit = 0x20,
        HandshakeResp = 0x21,
        Data = 0x22,
        Keepalive = 0x23,
        Rekey = 0x24,
    };

    // =============================================================================
    // Vote Type
    // =============================================================================

    enum class Vote : u8 {
        Yes = 0,
        No = 1,
        Abstain = 2,
    };

    // =============================================================================
    // Trust Event Kind
    // =============================================================================

    enum class TrustEventKind : u8 {
        JoinProposed = 0,
        VoteCast = 1,
        JoinApproved = 2,
        JoinRejected = 3,
        MemberRevoked = 4,
    };

    // =============================================================================
    // NodeId - Cryptographic identity (hash of public key)
    // =============================================================================

    struct NodeId {
        Array<u8, NODE_ID_SIZE> data{};

        NodeId() = default;

        explicit NodeId(const u8 *src) {
            if (src) {
                for (usize i = 0; i < NODE_ID_SIZE; ++i) {
                    data[i] = src[i];
                }
            }
        }

        [[nodiscard]] auto is_zero() const -> boolean {
            for (usize i = 0; i < NODE_ID_SIZE; ++i) {
                if (data[i] != 0)
                    return false;
            }
            return true;
        }

        [[nodiscard]] auto operator==(const NodeId &other) const -> boolean {
            for (usize i = 0; i < NODE_ID_SIZE; ++i) {
                if (data[i] != other.data[i])
                    return false;
            }
            return true;
        }

        [[nodiscard]] auto operator!=(const NodeId &other) const -> boolean { return !(*this == other); }

        [[nodiscard]] auto raw() -> u8 * { return data.data(); }
        [[nodiscard]] auto raw() const -> const u8 * { return data.data(); }

        auto members() noexcept { return std::tie(data); }
        auto members() const noexcept { return std::tie(data); }
    };

    // =============================================================================
    // PublicKey - Ed25519 or X25519 public key
    // =============================================================================

    struct PublicKey {
        Array<u8, KEY_SIZE> data{};

        PublicKey() = default;

        explicit PublicKey(const u8 *src) {
            if (src) {
                for (usize i = 0; i < KEY_SIZE; ++i) {
                    data[i] = src[i];
                }
            }
        }

        [[nodiscard]] auto is_zero() const -> boolean {
            for (usize i = 0; i < KEY_SIZE; ++i) {
                if (data[i] != 0)
                    return false;
            }
            return true;
        }

        [[nodiscard]] auto operator==(const PublicKey &other) const -> boolean {
            for (usize i = 0; i < KEY_SIZE; ++i) {
                if (data[i] != other.data[i])
                    return false;
            }
            return true;
        }

        [[nodiscard]] auto operator!=(const PublicKey &other) const -> boolean { return !(*this == other); }

        [[nodiscard]] auto raw() -> u8 * { return data.data(); }
        [[nodiscard]] auto raw() const -> const u8 * { return data.data(); }

        auto members() noexcept { return std::tie(data); }
        auto members() const noexcept { return std::tie(data); }
    };

    // =============================================================================
    // PrivateKey - Ed25519 or X25519 private key
    // =============================================================================

    struct PrivateKey {
        Array<u8, KEY_SIZE> data{};

        PrivateKey() = default;

        explicit PrivateKey(const u8 *src) {
            if (src) {
                for (usize i = 0; i < KEY_SIZE; ++i) {
                    data[i] = src[i];
                }
            }
        }

        // Copy constructor
        PrivateKey(const PrivateKey &other) {
            for (usize i = 0; i < KEY_SIZE; ++i) {
                data[i] = other.data[i];
            }
        }

        // Copy assignment
        auto operator=(const PrivateKey &other) -> PrivateKey & {
            if (this != &other) {
                for (usize i = 0; i < KEY_SIZE; ++i) {
                    data[i] = other.data[i];
                }
            }
            return *this;
        }

        // Move constructor - zeros the source after move
        PrivateKey(PrivateKey &&other) noexcept {
            for (usize i = 0; i < KEY_SIZE; ++i) {
                data[i] = other.data[i];
            }
            other.secure_clear();
        }

        // Move assignment - zeros the source after move
        auto operator=(PrivateKey &&other) noexcept -> PrivateKey & {
            if (this != &other) {
                secure_clear(); // Clear current data first
                for (usize i = 0; i < KEY_SIZE; ++i) {
                    data[i] = other.data[i];
                }
                other.secure_clear();
            }
            return *this;
        }

        // RAII: Securely clear key material on destruction
        ~PrivateKey() { secure_clear(); }

        // Secure clear using volatile to prevent optimization
        auto secure_clear() -> void {
            volatile u8 *p = data.data();
            for (usize i = 0; i < KEY_SIZE; ++i) {
                p[i] = 0;
            }
        }

        // Legacy clear method for compatibility
        auto clear() -> void { secure_clear(); }

        [[nodiscard]] auto is_zero() const -> boolean {
            for (usize i = 0; i < KEY_SIZE; ++i) {
                if (data[i] != 0)
                    return false;
            }
            return true;
        }

        [[nodiscard]] auto raw() -> u8 * { return data.data(); }
        [[nodiscard]] auto raw() const -> const u8 * { return data.data(); }

        auto members() noexcept { return std::tie(data); }
        auto members() const noexcept { return std::tie(data); }
    };

    // =============================================================================
    // Signature - Ed25519 signature
    // =============================================================================

    struct Signature {
        Array<u8, SIGNATURE_SIZE> data{};

        Signature() = default;

        explicit Signature(const u8 *src) {
            if (src) {
                for (usize i = 0; i < SIGNATURE_SIZE; ++i) {
                    data[i] = src[i];
                }
            }
        }

        [[nodiscard]] auto is_zero() const -> boolean {
            for (usize i = 0; i < SIGNATURE_SIZE; ++i) {
                if (data[i] != 0)
                    return false;
            }
            return true;
        }

        [[nodiscard]] auto raw() -> u8 * { return data.data(); }
        [[nodiscard]] auto raw() const -> const u8 * { return data.data(); }

        auto members() noexcept { return std::tie(data); }
        auto members() const noexcept { return std::tie(data); }
    };

    // =============================================================================
    // KeyB64 - Base64 encoded key string
    // =============================================================================

    struct KeyB64 {
        Array<char, KEY_B64_SIZE> data{};

        KeyB64() = default;

        explicit KeyB64(const char *src) {
            if (src) {
                usize i = 0;
                while (i < KEY_B64_SIZE - 1 && src[i] != '\0') {
                    data[i] = src[i];
                    ++i;
                }
                data[i] = '\0';
            }
        }

        [[nodiscard]] auto c_str() const -> const char * { return data.data(); }
        [[nodiscard]] auto raw() -> char * { return data.data(); }

        auto members() noexcept { return std::tie(data); }
        auto members() const noexcept { return std::tie(data); }
    };

    // =============================================================================
    // Endpoint - Network endpoint (IP + port)
    // =============================================================================

    enum class AddrFamily : u8 {
        None = 0,
        IPv4 = 2,  // AF_INET
        IPv6 = 10, // AF_INET6
    };

    struct IPv4Addr {
        Array<u8, 4> octets{};

        IPv4Addr() = default;

        IPv4Addr(u8 a, u8 b, u8 c, u8 d) : octets{a, b, c, d} {}

        [[nodiscard]] auto is_zero() const -> boolean {
            return octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] == 0;
        }

        [[nodiscard]] auto operator==(const IPv4Addr &other) const -> boolean { return octets == other.octets; }

        auto members() noexcept { return std::tie(octets); }
        auto members() const noexcept { return std::tie(octets); }
    };

    struct IPv6Addr {
        Array<u8, 16> octets{};

        IPv6Addr() = default;

        [[nodiscard]] auto is_zero() const -> boolean {
            for (usize i = 0; i < 16; ++i) {
                if (octets[i] != 0)
                    return false;
            }
            return true;
        }

        [[nodiscard]] auto operator==(const IPv6Addr &other) const -> boolean { return octets == other.octets; }

        auto members() noexcept { return std::tie(octets); }
        auto members() const noexcept { return std::tie(octets); }
    };

    struct Endpoint {
        AddrFamily family = AddrFamily::None;
        IPv4Addr ipv4{};
        IPv6Addr ipv6{};
        u16 port = 0;

        Endpoint() = default;

        Endpoint(IPv4Addr addr, u16 p) : family(AddrFamily::IPv4), ipv4(addr), port(p) {}

        Endpoint(IPv6Addr addr, u16 p) : family(AddrFamily::IPv6), ipv6(addr), port(p) {}

        [[nodiscard]] auto is_ipv4() const -> boolean { return family == AddrFamily::IPv4; }
        [[nodiscard]] auto is_ipv6() const -> boolean { return family == AddrFamily::IPv6; }
        [[nodiscard]] auto is_valid() const -> boolean { return family != AddrFamily::None && port > 0; }

        [[nodiscard]] auto operator==(const Endpoint &other) const -> boolean {
            if (family != other.family || port != other.port)
                return false;
            if (family == AddrFamily::IPv4)
                return ipv4 == other.ipv4;
            if (family == AddrFamily::IPv6)
                return ipv6 == other.ipv6;
            return true;
        }

        [[nodiscard]] auto operator!=(const Endpoint &other) const -> boolean { return !(*this == other); }

        auto members() noexcept { return std::tie(family, ipv4, ipv6, port); }
        auto members() const noexcept { return std::tie(family, ipv4, ipv6, port); }
    };

    // =============================================================================
    // OverlayAddr - Overlay network address with CIDR
    // =============================================================================

    struct OverlayAddr {
        String addr;        // IP address as string (e.g., "10.42.0.1")
        u8 prefix_len = 24; // CIDR prefix length

        OverlayAddr() = default;

        OverlayAddr(const String &a, u8 p) : addr(a), prefix_len(p) {}

        OverlayAddr(const char *a, u8 p) : addr(a), prefix_len(p) {}

        [[nodiscard]] auto is_valid() const -> boolean {
            if (addr.empty()) {
                return false;
            }
            // Basic validation: check for IPv4 pattern
            u32 a = 0, b = 0, c = 0, d = 0;
            if (sscanf(addr.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                return prefix_len <= 32 && a <= 255 && b <= 255 && c <= 255 && d <= 255;
            }
            // Could be IPv6 - simplified check
            return prefix_len <= 128;
        }

        [[nodiscard]] auto as_cidr() const -> String { return addr + "/" + to_str(prefix_len); }

        auto members() noexcept { return std::tie(addr, prefix_len); }
        auto members() const noexcept { return std::tie(addr, prefix_len); }
    };

    // =============================================================================
    // Timestamp - Milliseconds since epoch
    // =============================================================================

    struct Timestamp {
        u64 ms = 0;

        Timestamp() = default;
        explicit Timestamp(u64 milliseconds) : ms(milliseconds) {}

        [[nodiscard]] auto operator<(const Timestamp &other) const -> boolean { return ms < other.ms; }
        [[nodiscard]] auto operator>(const Timestamp &other) const -> boolean { return ms > other.ms; }
        [[nodiscard]] auto operator<=(const Timestamp &other) const -> boolean { return ms <= other.ms; }
        [[nodiscard]] auto operator>=(const Timestamp &other) const -> boolean { return ms >= other.ms; }
        [[nodiscard]] auto operator==(const Timestamp &other) const -> boolean { return ms == other.ms; }

        auto members() noexcept { return std::tie(ms); }
        auto members() const noexcept { return std::tie(ms); }
    };

    // =============================================================================
    // Duration - Time duration in milliseconds
    // =============================================================================

    struct Duration {
        u64 ms = 0;

        Duration() = default;
        explicit Duration(u64 milliseconds) : ms(milliseconds) {}

        static auto from_secs(u64 secs) -> Duration { return Duration(secs * 1000); }
        static auto from_mins(u64 mins) -> Duration { return Duration(mins * 60 * 1000); }

        [[nodiscard]] auto as_secs() const -> u64 { return ms / 1000; }
        [[nodiscard]] auto as_ms() const -> u64 { return ms; }

        auto members() noexcept { return std::tie(ms); }
        auto members() const noexcept { return std::tie(ms); }
    };

    // =============================================================================
    // InterfaceName - Network interface name
    // =============================================================================

    inline constexpr usize IFNAME_SIZE = 16; // IFNAMSIZ

    struct InterfaceName {
        Array<char, IFNAME_SIZE> data{};

        InterfaceName() = default;

        explicit InterfaceName(const char *src) {
            if (src) {
                usize i = 0;
                while (i < IFNAME_SIZE - 1 && src[i] != '\0') {
                    data[i] = src[i];
                    ++i;
                }
                data[i] = '\0';
            }
        }

        [[nodiscard]] auto c_str() const -> const char * { return data.data(); }
        [[nodiscard]] auto raw() -> char * { return data.data(); }

        [[nodiscard]] auto is_empty() const -> boolean { return data[0] == '\0'; }

        auto members() noexcept { return std::tie(data); }
        auto members() const noexcept { return std::tie(data); }
    };

} // namespace botlink

// =============================================================================
// Hash Specialization for NodeId (needed for dp::Map<NodeId, ...>)
// =============================================================================

namespace datapod {

    template <> struct Hasher<botlink::NodeId> {
        auto operator()(const botlink::NodeId &id) const -> hash_t {
            // FNV-1a hash of the 32-byte NodeId
            hash_t hash = 14695981039346656037ULL;
            for (usize i = 0; i < botlink::NODE_ID_SIZE; ++i) {
                hash ^= static_cast<hash_t>(id.data[i]);
                hash *= 1099511628211ULL;
            }
            return hash;
        }
    };

} // namespace datapod
