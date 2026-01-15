/* SPDX-License-Identifier: LGPL-2.1+ */
/*
 * Modern C++ WireGuard Management Library
 *
 * Original C implementation:
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2008-2012 Pablo Neira Ayuso <pablo@netfilter.org>.
 *
 * C++ conversion using datapod library.
 */

#ifndef WIREGUARD_HPP
#define WIREGUARD_HPP

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <datapod/datapod.hpp>
#include <keylock/keylock.hpp>

#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <linux/genetlink.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace wg {

    using namespace dp;

    // =============================================================================
    // Constants
    // =============================================================================

    inline constexpr usize KEY_SIZE = 32;
    inline constexpr usize KEY_B64_SIZE = ((KEY_SIZE + 2) / 3) * 4 + 1;
    inline constexpr const char *GENL_NAME = "wireguard";
    inline constexpr u8 GENL_VERSION = 1;

    // =============================================================================
    // Forward Declarations
    // =============================================================================

    class AllowedIp;
    class Peer;
    class Device;
    class NetlinkSocket;
    class GenetlinkSocket;

    // =============================================================================
    // Key Types
    // =============================================================================

    struct Key {
        Array<u8, KEY_SIZE> data{};

        Key() = default;

        explicit Key(const u8 *src) {
            if (src) {
                std::memcpy(data.data(), src, KEY_SIZE);
            }
        }

        [[nodiscard]] auto is_zero() const -> bool {
            volatile u8 acc = 0;
            for (usize i = 0; i < KEY_SIZE; ++i) {
                acc |= data[i];
                __asm__("" : "=r"(acc) : "0"(acc));
            }
            return static_cast<bool>(1 & ((acc - 1) >> 8));
        }

        [[nodiscard]] auto operator==(const Key &other) const -> bool {
            return std::memcmp(data.data(), other.data.data(), KEY_SIZE) == 0;
        }

        [[nodiscard]] auto operator!=(const Key &other) const -> bool { return !(*this == other); }

        [[nodiscard]] auto raw() -> u8 * { return data.data(); }
        [[nodiscard]] auto raw() const -> const u8 * { return data.data(); }
    };

    struct KeyB64 {
        Array<char, KEY_B64_SIZE> data{};

        KeyB64() = default;

        explicit KeyB64(const char *src) {
            if (src) {
                std::strncpy(data.data(), src, KEY_B64_SIZE - 1);
                data[KEY_B64_SIZE - 1] = '\0';
            }
        }

        [[nodiscard]] auto c_str() const -> const char * { return data.data(); }
        [[nodiscard]] auto raw() -> char * { return data.data(); }
    };

    // =============================================================================
    // Time Types
    // =============================================================================

    struct Timespec64 {
        i64 tv_sec = 0;
        i64 tv_nsec = 0;
    };

    // =============================================================================
    // Endpoint Type
    // =============================================================================

    struct Endpoint {
        union {
            sockaddr addr;
            sockaddr_in addr4;
            sockaddr_in6 addr6;
        };

        Endpoint() : addr6{} {}

        [[nodiscard]] auto family() const -> u16 { return addr.sa_family; }
        [[nodiscard]] auto is_ipv4() const -> bool { return family() == AF_INET; }
        [[nodiscard]] auto is_ipv6() const -> bool { return family() == AF_INET6; }
    };

    // =============================================================================
    // Allowed IP
    // =============================================================================

    class AllowedIp {
      public:
        u16 family = 0;
        union {
            in_addr ip4;
            in6_addr ip6;
        };
        u8 cidr = 0;

        AllowedIp() { std::memset(&ip6, 0, sizeof(ip6)); }

        [[nodiscard]] auto is_ipv4() const -> bool { return family == AF_INET; }
        [[nodiscard]] auto is_ipv6() const -> bool { return family == AF_INET6; }

        [[nodiscard]] auto is_valid() const -> bool {
            if (family == AF_INET && cidr <= 32)
                return true;
            if (family == AF_INET6 && cidr <= 128)
                return true;
            return false;
        }
    };

    // =============================================================================
    // Peer Flags
    // =============================================================================

    enum class PeerFlags : u32 {
        None = 0,
        RemoveMe = 1U << 0,
        ReplaceAllowedIps = 1U << 1,
        HasPublicKey = 1U << 2,
        HasPresharedKey = 1U << 3,
        HasPersistentKeepaliveInterval = 1U << 4
    };

    inline auto operator|(PeerFlags a, PeerFlags b) -> PeerFlags {
        return static_cast<PeerFlags>(static_cast<u32>(a) | static_cast<u32>(b));
    }

    inline auto operator&(PeerFlags a, PeerFlags b) -> PeerFlags {
        return static_cast<PeerFlags>(static_cast<u32>(a) & static_cast<u32>(b));
    }

    inline auto operator|=(PeerFlags &a, PeerFlags b) -> PeerFlags & {
        a = a | b;
        return a;
    }

    inline auto has_flag(PeerFlags flags, PeerFlags flag) -> bool {
        return (static_cast<u32>(flags) & static_cast<u32>(flag)) != 0;
    }

    // =============================================================================
    // Device Flags
    // =============================================================================

    enum class DeviceFlags : u32 {
        None = 0,
        ReplacePeers = 1U << 0,
        HasPrivateKey = 1U << 1,
        HasPublicKey = 1U << 2,
        HasListenPort = 1U << 3,
        HasFwmark = 1U << 4
    };

    inline auto operator|(DeviceFlags a, DeviceFlags b) -> DeviceFlags {
        return static_cast<DeviceFlags>(static_cast<u32>(a) | static_cast<u32>(b));
    }

    inline auto operator&(DeviceFlags a, DeviceFlags b) -> DeviceFlags {
        return static_cast<DeviceFlags>(static_cast<u32>(a) & static_cast<u32>(b));
    }

    inline auto operator|=(DeviceFlags &a, DeviceFlags b) -> DeviceFlags & {
        a = a | b;
        return a;
    }

    inline auto has_flag(DeviceFlags flags, DeviceFlags flag) -> bool {
        return (static_cast<u32>(flags) & static_cast<u32>(flag)) != 0;
    }

    // =============================================================================
    // Peer Class
    // =============================================================================

    class Peer {
      public:
        PeerFlags flags = PeerFlags::None;
        Key public_key;
        Key preshared_key;
        Endpoint endpoint;
        Timespec64 last_handshake_time;
        u64 rx_bytes = 0;
        u64 tx_bytes = 0;
        u16 persistent_keepalive_interval = 0;
        Vector<AllowedIp> allowed_ips;

        Peer() = default;

        [[nodiscard]] auto has_public_key() const -> bool { return has_flag(flags, PeerFlags::HasPublicKey); }

        [[nodiscard]] auto has_preshared_key() const -> bool { return has_flag(flags, PeerFlags::HasPresharedKey); }

        [[nodiscard]] auto should_remove() const -> bool { return has_flag(flags, PeerFlags::RemoveMe); }

        [[nodiscard]] auto should_replace_allowed_ips() const -> bool {
            return has_flag(flags, PeerFlags::ReplaceAllowedIps);
        }

        auto add_allowed_ip(AllowedIp ip) -> void { allowed_ips.push_back(ip); }
    };

    // =============================================================================
    // Device Class
    // =============================================================================

    class Device {
      public:
        Array<char, IFNAMSIZ> name{};
        u32 ifindex = 0;
        DeviceFlags flags = DeviceFlags::None;
        Key public_key;
        Key private_key;
        u32 fwmark = 0;
        u16 listen_port = 0;
        Vector<Peer> peers;

        Device() = default;

        explicit Device(const char *device_name) {
            if (device_name) {
                std::strncpy(name.data(), device_name, IFNAMSIZ - 1);
                name[IFNAMSIZ - 1] = '\0';
            }
        }

        [[nodiscard]] auto get_name() const -> const char * { return name.data(); }

        [[nodiscard]] auto has_private_key() const -> bool { return has_flag(flags, DeviceFlags::HasPrivateKey); }

        [[nodiscard]] auto has_public_key() const -> bool { return has_flag(flags, DeviceFlags::HasPublicKey); }

        [[nodiscard]] auto has_listen_port() const -> bool { return has_flag(flags, DeviceFlags::HasListenPort); }

        [[nodiscard]] auto has_fwmark() const -> bool { return has_flag(flags, DeviceFlags::HasFwmark); }

        [[nodiscard]] auto should_replace_peers() const -> bool { return has_flag(flags, DeviceFlags::ReplacePeers); }

        auto add_peer(Peer peer) -> void { peers.push_back(std::move(peer)); }

        auto find_peer(const Key &pub_key) -> Optional<Peer *> {
            for (auto &peer : peers) {
                if (peer.public_key == pub_key) {
                    return &peer;
                }
            }
            return {};
        }
    };

    // =============================================================================
    // Netlink Attribute Commands
    // =============================================================================

    enum class WgCmd : u8 { GetDevice = 0, SetDevice = 1 };

    enum class WgDeviceAttr : u16 {
        Unspec = 0,
        Ifindex = 1,
        Ifname = 2,
        PrivateKey = 3,
        PublicKey = 4,
        Flags = 5,
        ListenPort = 6,
        Fwmark = 7,
        Peers = 8
    };

    enum class WgPeerAttr : u16 {
        Unspec = 0,
        PublicKey = 1,
        PresharedKey = 2,
        Flags = 3,
        Endpoint = 4,
        PersistentKeepaliveInterval = 5,
        LastHandshakeTime = 6,
        RxBytes = 7,
        TxBytes = 8,
        AllowedIps = 9,
        ProtocolVersion = 10
    };

    enum class WgAllowedIpAttr : u16 { Unspec = 0, Family = 1, IpAddr = 2, CidrMask = 3 };

    // =============================================================================
    // Netlink Constants
    // =============================================================================

    namespace nl {

        inline constexpr usize ALIGNTO = 4;
        inline constexpr auto ALIGN(usize len) -> usize { return (len + ALIGNTO - 1) & ~(ALIGNTO - 1); }
        inline constexpr auto HDRLEN() -> usize { return ALIGN(sizeof(nlmsghdr)); }
        inline constexpr auto ATTR_HDRLEN() -> usize { return ALIGN(sizeof(nlattr)); }

        inline auto ideal_socket_buffer_size() -> usize {
            static usize size = 0;
            if (size == 0) {
                size = static_cast<usize>(sysconf(_SC_PAGESIZE));
                if (size > 8192)
                    size = 8192;
            }
            return size;
        }

    } // namespace nl

    // =============================================================================
    // Netlink Message Builder
    // =============================================================================

    class NetlinkMessage {
      private:
        Vector<u8> buffer_;
        nlmsghdr *header_ = nullptr;

      public:
        explicit NetlinkMessage(usize initial_size = 0) {
            usize size = initial_size > 0 ? initial_size : nl::ideal_socket_buffer_size();
            buffer_.resize(size);
            std::memset(buffer_.data(), 0, size);
            header_ = reinterpret_cast<nlmsghdr *>(buffer_.data());
            header_->nlmsg_len = nl::HDRLEN();
        }

        [[nodiscard]] auto header() -> nlmsghdr * { return header_; }
        [[nodiscard]] auto header() const -> const nlmsghdr * { return header_; }
        [[nodiscard]] auto data() -> u8 * { return buffer_.data(); }
        [[nodiscard]] auto data() const -> const u8 * { return buffer_.data(); }
        [[nodiscard]] auto capacity() const -> usize { return buffer_.size(); }
        [[nodiscard]] auto length() const -> u32 { return header_->nlmsg_len; }

        [[nodiscard]] auto payload() -> void * { return reinterpret_cast<char *>(header_) + nl::HDRLEN(); }

        [[nodiscard]] auto payload_tail() -> void * {
            return reinterpret_cast<char *>(header_) + nl::ALIGN(header_->nlmsg_len);
        }

        template <typename T> auto put_extra_header() -> T * {
            auto *ptr = reinterpret_cast<T *>(payload_tail());
            usize len = nl::ALIGN(sizeof(T));
            header_->nlmsg_len += len;
            std::memset(ptr, 0, len);
            return ptr;
        }

        auto put_attr(u16 type, const void *data, usize len) -> bool {
            if (header_->nlmsg_len + nl::ATTR_HDRLEN() + nl::ALIGN(len) > capacity()) {
                return false;
            }

            auto *attr = reinterpret_cast<nlattr *>(payload_tail());
            u16 payload_len = nl::ALIGN(sizeof(nlattr)) + len;
            attr->nla_type = type;
            attr->nla_len = payload_len;

            std::memcpy(reinterpret_cast<char *>(attr) + nl::ATTR_HDRLEN(), data, len);
            header_->nlmsg_len += nl::ALIGN(payload_len);

            // Zero padding
            usize pad = nl::ALIGN(len) - len;
            if (pad > 0) {
                std::memset(reinterpret_cast<char *>(attr) + nl::ATTR_HDRLEN() + len, 0, pad);
            }
            return true;
        }

        auto put_attr_u8(u16 type, u8 value) -> bool { return put_attr(type, &value, sizeof(u8)); }

        auto put_attr_u16(u16 type, u16 value) -> bool { return put_attr(type, &value, sizeof(u16)); }

        auto put_attr_u32(u16 type, u32 value) -> bool { return put_attr(type, &value, sizeof(u32)); }

        auto put_attr_strz(u16 type, const char *str) -> bool { return put_attr(type, str, std::strlen(str) + 1); }

        auto nest_start(u16 type) -> nlattr * {
            if (header_->nlmsg_len + nl::ATTR_HDRLEN() > capacity()) {
                return nullptr;
            }

            auto *start = reinterpret_cast<nlattr *>(payload_tail());
            start->nla_type = NLA_F_NESTED | type;
            header_->nlmsg_len += nl::ALIGN(sizeof(nlattr));
            return start;
        }

        auto nest_end(nlattr *start) -> void {
            start->nla_len = reinterpret_cast<char *>(payload_tail()) - reinterpret_cast<char *>(start);
        }

        auto nest_cancel(nlattr *start) -> void {
            header_->nlmsg_len -= reinterpret_cast<char *>(payload_tail()) - reinterpret_cast<char *>(start);
        }
    };

    // =============================================================================
    // Netlink Socket
    // =============================================================================

    class NetlinkSocket {
      private:
        int fd_ = -1;
        sockaddr_nl addr_{};

      public:
        NetlinkSocket() = default;

        ~NetlinkSocket() { close(); }

        // Non-copyable
        NetlinkSocket(const NetlinkSocket &) = delete;
        auto operator=(const NetlinkSocket &) -> NetlinkSocket & = delete;

        // Movable
        NetlinkSocket(NetlinkSocket &&other) noexcept : fd_(other.fd_), addr_(other.addr_) { other.fd_ = -1; }

        auto operator=(NetlinkSocket &&other) noexcept -> NetlinkSocket & {
            if (this != &other) {
                close();
                fd_ = other.fd_;
                addr_ = other.addr_;
                other.fd_ = -1;
            }
            return *this;
        }

        [[nodiscard]] auto is_open() const -> bool { return fd_ >= 0; }
        [[nodiscard]] auto fd() const -> int { return fd_; }
        [[nodiscard]] auto portid() const -> u32 { return addr_.nl_pid; }

        [[nodiscard]] static auto open(int protocol) -> Res<NetlinkSocket> {
            NetlinkSocket sock;
            sock.fd_ = socket(AF_NETLINK, SOCK_RAW, protocol);
            if (sock.fd_ < 0) {
                return result::err(Error::io_error("Failed to open netlink socket"));
            }
            return result::ok(std::move(sock));
        }

        [[nodiscard]] auto bind(u32 groups = 0, pid_t pid = 0) -> VoidRes {
            addr_.nl_family = AF_NETLINK;
            addr_.nl_groups = groups;
            addr_.nl_pid = pid;

            if (::bind(fd_, reinterpret_cast<sockaddr *>(&addr_), sizeof(addr_)) < 0) {
                return result::err(Error::io_error("Failed to bind netlink socket"));
            }

            socklen_t addr_len = sizeof(addr_);
            if (getsockname(fd_, reinterpret_cast<sockaddr *>(&addr_), &addr_len) < 0) {
                return result::err(Error::io_error("Failed to get socket name"));
            }

            if (addr_len != sizeof(addr_) || addr_.nl_family != AF_NETLINK) {
                return result::err(Error::invalid_argument("Invalid socket address"));
            }

            return result::ok();
        }

        [[nodiscard]] auto send(const void *buf, usize len) -> Res<isize> {
            sockaddr_nl snl{};
            snl.nl_family = AF_NETLINK;

            isize ret = sendto(fd_, buf, len, 0, reinterpret_cast<const sockaddr *>(&snl), sizeof(snl));
            if (ret < 0) {
                return result::err(Error::io_error("Failed to send netlink message"));
            }
            return result::ok(ret);
        }

        [[nodiscard]] auto recv(void *buf, usize bufsiz) -> Res<isize> {
            sockaddr_nl addr{};
            iovec iov{buf, bufsiz};
            msghdr msg{};
            msg.msg_name = &addr;
            msg.msg_namelen = sizeof(sockaddr_nl);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            isize ret = recvmsg(fd_, &msg, 0);
            if (ret < 0) {
                return result::err(Error::io_error("Failed to receive netlink message"));
            }

            if (msg.msg_flags & MSG_TRUNC) {
                return result::err(Error::out_of_range("Message truncated"));
            }

            if (msg.msg_namelen != sizeof(sockaddr_nl)) {
                return result::err(Error::invalid_argument("Invalid message address"));
            }

            return result::ok(ret);
        }

        auto close() -> void {
            if (fd_ >= 0) {
                ::close(fd_);
                fd_ = -1;
            }
        }
    };

    // =============================================================================
    // Genetlink Socket (for WireGuard communication)
    // =============================================================================

    class GenetlinkSocket {
      private:
        NetlinkSocket nl_;
        Vector<u8> buffer_;
        u16 family_id_ = 0;
        u8 version_ = 0;
        u32 seq_ = 0;
        u32 portid_ = 0;

      public:
        GenetlinkSocket() = default;

        [[nodiscard]] auto is_open() const -> bool { return nl_.is_open(); }
        [[nodiscard]] auto family_id() const -> u16 { return family_id_; }
        [[nodiscard]] auto seq() const -> u32 { return seq_; }
        [[nodiscard]] auto portid() const -> u32 { return portid_; }

        [[nodiscard]] static auto open(const char *family_name, u8 version) -> Res<GenetlinkSocket> {
            GenetlinkSocket sock;

            sock.buffer_.resize(nl::ideal_socket_buffer_size());

            auto nl_result = NetlinkSocket::open(NETLINK_GENERIC);
            if (nl_result.is_err()) {
                return result::err(nl_result.error());
            }
            sock.nl_ = std::move(nl_result.value());

            auto bind_result = sock.nl_.bind();
            if (bind_result.is_err()) {
                return result::err(bind_result.error());
            }

            sock.portid_ = sock.nl_.portid();

            // Request family ID
            NetlinkMessage msg;
            auto *nlh = msg.header();
            nlh->nlmsg_type = GENL_ID_CTRL;
            nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
            sock.seq_ = static_cast<u32>(time(nullptr));
            nlh->nlmsg_seq = sock.seq_;

            auto *genl = msg.put_extra_header<genlmsghdr>();
            genl->cmd = CTRL_CMD_GETFAMILY;
            genl->version = 1;

            msg.put_attr_strz(CTRL_ATTR_FAMILY_NAME, family_name);

            auto send_result = sock.nl_.send(msg.data(), msg.length());
            if (send_result.is_err()) {
                return result::err(send_result.error());
            }

            // Receive response
            auto recv_result = sock.nl_.recv(sock.buffer_.data(), sock.buffer_.size());
            if (recv_result.is_err()) {
                return result::err(recv_result.error());
            }

            // Parse family ID from response
            auto *resp = reinterpret_cast<nlmsghdr *>(sock.buffer_.data());
            if (resp->nlmsg_type == NLMSG_ERROR) {
                auto *err = reinterpret_cast<nlmsgerr *>(reinterpret_cast<char *>(resp) + nl::HDRLEN());
                if (err->error != 0) {
                    return result::err(Error::io_error("Failed to get family ID"));
                }
            }

            // Find CTRL_ATTR_FAMILY_ID in attributes
            auto *attr_start = reinterpret_cast<nlattr *>(reinterpret_cast<char *>(resp) + nl::HDRLEN() +
                                                          nl::ALIGN(sizeof(genlmsghdr)));
            usize remaining = resp->nlmsg_len - nl::HDRLEN() - nl::ALIGN(sizeof(genlmsghdr));

            while (remaining >= sizeof(nlattr)) {
                auto *attr = reinterpret_cast<nlattr *>(reinterpret_cast<char *>(attr_start));

                if (attr->nla_len < sizeof(nlattr) || attr->nla_len > remaining) {
                    break;
                }

                if ((attr->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_FAMILY_ID) {
                    sock.family_id_ = *reinterpret_cast<u16 *>(reinterpret_cast<char *>(attr) + nl::ATTR_HDRLEN());
                    break;
                }

                usize advance = nl::ALIGN(attr->nla_len);
                attr_start = reinterpret_cast<nlattr *>(reinterpret_cast<char *>(attr_start) + advance);
                remaining -= advance;
            }

            if (sock.family_id_ == 0) {
                return result::err(Error::not_found("WireGuard kernel module not loaded"));
            }

            sock.version_ = version;
            return result::ok(std::move(sock));
        }

        [[nodiscard]] auto prepare_message(u8 cmd, u16 flags) -> NetlinkMessage {
            NetlinkMessage msg;
            auto *nlh = msg.header();
            nlh->nlmsg_type = family_id_;
            nlh->nlmsg_flags = flags;
            seq_ = static_cast<u32>(time(nullptr));
            nlh->nlmsg_seq = seq_;

            auto *genl = msg.put_extra_header<genlmsghdr>();
            genl->cmd = cmd;
            genl->version = version_;

            return msg;
        }

        [[nodiscard]] auto send(const NetlinkMessage &msg) -> VoidRes {
            auto result = nl_.send(msg.data(), msg.length());
            if (result.is_err()) {
                return result::err(result.error());
            }
            return result::ok();
        }

        template <typename Callback> [[nodiscard]] auto recv_run(Callback &&cb) -> VoidRes {
            while (true) {
                auto recv_result = nl_.recv(buffer_.data(), buffer_.size());
                if (recv_result.is_err()) {
                    return result::err(recv_result.error());
                }

                isize len = recv_result.value();
                if (len <= 0) {
                    break;
                }

                auto *nlh = reinterpret_cast<nlmsghdr *>(buffer_.data());
                while (len >= static_cast<isize>(sizeof(nlmsghdr)) && nlh->nlmsg_len >= sizeof(nlmsghdr) &&
                       static_cast<isize>(nlh->nlmsg_len) <= len) {

                    if (nlh->nlmsg_type == NLMSG_ERROR) {
                        auto *err = reinterpret_cast<nlmsgerr *>(reinterpret_cast<char *>(nlh) + nl::HDRLEN());
                        if (err->error < 0) {
                            errno = -err->error;
                            return result::err(Error::io_error("Netlink error"));
                        }
                        return result::ok();
                    }

                    if (nlh->nlmsg_type == NLMSG_DONE) {
                        return result::ok();
                    }

                    // Process message with callback
                    int cb_result = cb(nlh);
                    if (cb_result <= 0) {
                        if (cb_result < 0) {
                            return result::err(Error::io_error("Callback error"));
                        }
                        return result::ok();
                    }

                    // Move to next message
                    usize advance = nl::ALIGN(nlh->nlmsg_len);
                    nlh = reinterpret_cast<nlmsghdr *>(reinterpret_cast<char *>(nlh) + advance);
                    len -= advance;
                }
            }

            return result::ok();
        }
    };

    // =============================================================================
    // Key Operations (using keylock/libsodium)
    // =============================================================================

    namespace key {

        namespace detail {

            // WireGuard-specific base64 encoding (constant-time)
            inline auto encode_base64(char dest[4], const u8 src[3]) -> void {
                const u8 input[] = {
                    static_cast<u8>((src[0] >> 2) & 63), static_cast<u8>(((src[0] << 4) | (src[1] >> 4)) & 63),
                    static_cast<u8>(((src[1] << 2) | (src[2] >> 6)) & 63), static_cast<u8>(src[2] & 63)};

                for (u32 i = 0; i < 4; ++i) {
                    dest[i] = static_cast<char>(input[i] + 'A' + (((25 - input[i]) >> 8) & 6) -
                                                (((51 - input[i]) >> 8) & 75) - (((61 - input[i]) >> 8) & 15) +
                                                (((62 - input[i]) >> 8) & 3));
                }
            }

            // WireGuard-specific base64 decoding (constant-time)
            inline auto decode_base64(const char src[4]) -> int {
                int val = 0;
                for (u32 i = 0; i < 4; ++i) {
                    val |= (-1 + ((((('A' - 1) - src[i]) & (src[i] - ('Z' + 1))) >> 8) & (src[i] - 64)) +
                            ((((('a' - 1) - src[i]) & (src[i] - ('z' + 1))) >> 8) & (src[i] - 70)) +
                            ((((('0' - 1) - src[i]) & (src[i] - ('9' + 1))) >> 8) & (src[i] + 5)) +
                            ((((('+' - 1) - src[i]) & (src[i] - ('+' + 1))) >> 8) & 63) +
                            ((((('/' - 1) - src[i]) & (src[i] - ('/' + 1))) >> 8) & 64))
                           << (18 - 6 * i);
                }
                return val;
            }

        } // namespace detail

        // Convert key to WireGuard base64 format
        inline auto to_base64(KeyB64 &base64, const Key &key) -> void {
            for (u32 i = 0; i < 32 / 3; ++i) {
                detail::encode_base64(&base64.data[i * 4], &key.data[i * 3]);
            }
            const u8 temp[3] = {key.data[10 * 3 + 0], key.data[10 * 3 + 1], 0};
            detail::encode_base64(&base64.data[10 * 4], temp);
            base64.data[KEY_B64_SIZE - 2] = '=';
            base64.data[KEY_B64_SIZE - 1] = '\0';
        }

        // Parse key from WireGuard base64 format
        inline auto from_base64(Key &key, const KeyB64 &base64) -> Res<void> {
            if (std::strlen(base64.c_str()) != KEY_B64_SIZE - 1 || base64.data[KEY_B64_SIZE - 2] != '=') {
                return result::err(Error::invalid_argument("Invalid base64 key"));
            }

            volatile u8 ret = 0;
            for (u32 i = 0; i < 32 / 3; ++i) {
                int val = detail::decode_base64(&base64.data[i * 4]);
                ret |= static_cast<u32>(val) >> 31;
                key.data[i * 3 + 0] = (val >> 16) & 0xff;
                key.data[i * 3 + 1] = (val >> 8) & 0xff;
                key.data[i * 3 + 2] = val & 0xff;
            }

            const char temp[4] = {base64.data[10 * 4 + 0], base64.data[10 * 4 + 1], base64.data[10 * 4 + 2], 'A'};
            int val = detail::decode_base64(temp);
            ret |= (static_cast<u32>(val) >> 31) | (val & 0xff);
            key.data[10 * 3 + 0] = (val >> 16) & 0xff;
            key.data[10 * 3 + 1] = (val >> 8) & 0xff;

            if (ret != 0) {
                return result::err(Error::invalid_argument("Invalid base64 encoding"));
            }

            return result::ok();
        }

        // Generate random preshared key using keylock (libsodium)
        inline auto generate_preshared(Key &key) -> void {
            auto random_bytes = keylock::utils::Common::generate_random_bytes(KEY_SIZE);
            std::memcpy(key.raw(), random_bytes.data(), KEY_SIZE);
            keylock::utils::Common::secure_clear(random_bytes.data(), random_bytes.size());
        }

        // Generate Curve25519 private key using keylock (libsodium)
        inline auto generate_private(Key &private_key) -> void {
            // Use libsodium's secure random generation via keylock
            auto random_bytes = keylock::utils::Common::generate_random_bytes(KEY_SIZE);
            std::memcpy(private_key.raw(), random_bytes.data(), KEY_SIZE);
            keylock::utils::Common::secure_clear(random_bytes.data(), random_bytes.size());

            // Clamp for Curve25519 (WireGuard format)
            private_key.data[0] &= 248;
            private_key.data[31] = (private_key.data[31] & 127) | 64;
        }

        // Derive Curve25519 public key from private key using libsodium
        inline auto generate_public(Key &public_key, const Key &private_key) -> void {
            // Use libsodium's crypto_scalarmult_base for Curve25519 point multiplication
            // This computes public_key = private_key * G where G is the base point
            crypto_scalarmult_base(public_key.raw(), private_key.raw());
        }

        // Generate a complete WireGuard keypair using keylock
        inline auto generate_keypair() -> Pair<Key, Key> {
            Key private_key, public_key;
            generate_private(private_key);
            generate_public(public_key, private_key);
            return {private_key, public_key};
        }

        // Generate keypair using keylock's X25519 context
        inline auto generate_keypair_x25519() -> Pair<Key, Key> {
            keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::X25519_Box);
            auto keypair = ctx.generate_keypair();

            Key private_key, public_key;

            // Copy public key (32 bytes)
            std::memcpy(public_key.raw(), keypair.public_key.data(),
                        std::min(keypair.public_key.size(), static_cast<usize>(KEY_SIZE)));

            // For X25519, private key in keylock is 64 bytes (pub + secret)
            // WireGuard uses just the 32-byte secret portion
            if (keypair.private_key.size() >= KEY_SIZE) {
                // The secret key is the first 32 bytes in libsodium's format
                std::memcpy(private_key.raw(), keypair.private_key.data(), KEY_SIZE);
            }

            // Secure clear the original keypair
            keylock::utils::Common::secure_clear(keypair.private_key.data(), keypair.private_key.size());
            keylock::utils::Common::secure_clear(keypair.public_key.data(), keypair.public_key.size());

            return {private_key, public_key};
        }

        // Convert Key to keylock vector format
        inline auto to_vector(const Key &key) -> std::vector<u8> {
            return std::vector<u8>(key.data.begin(), key.data.end());
        }

        // Convert keylock vector to Key
        inline auto from_vector(Key &key, const std::vector<u8> &vec) -> bool {
            if (vec.size() < KEY_SIZE)
                return false;
            std::memcpy(key.raw(), vec.data(), KEY_SIZE);
            return true;
        }

        // Get keylock crypto context for advanced operations
        inline auto get_context() -> keylock::crypto::Context {
            return keylock::crypto::Context(keylock::crypto::Context::Algorithm::X25519_Box);
        }

    } // namespace key

    // =============================================================================
    // Device Management API
    // =============================================================================

    namespace api {

        namespace detail {

            inline auto add_del_iface(const char *ifname, bool add) -> VoidRes {
                auto nl_result = NetlinkSocket::open(NETLINK_ROUTE);
                if (nl_result.is_err()) {
                    return result::err(nl_result.error());
                }
                auto nl = std::move(nl_result.value());

                auto bind_result = nl.bind();
                if (bind_result.is_err()) {
                    return result::err(bind_result.error());
                }

                NetlinkMessage msg;
                auto *nlh = msg.header();
                nlh->nlmsg_type = add ? RTM_NEWLINK : RTM_DELLINK;
                nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (add ? NLM_F_CREATE | NLM_F_EXCL : 0);
                nlh->nlmsg_seq = static_cast<u32>(time(nullptr));

                auto *ifm = msg.put_extra_header<ifinfomsg>();
                ifm->ifi_family = AF_UNSPEC;

                msg.put_attr_strz(IFLA_IFNAME, ifname);

                auto *nest = msg.nest_start(IFLA_LINKINFO);
                msg.put_attr_strz(IFLA_INFO_KIND, GENL_NAME);
                msg.nest_end(nest);

                auto send_result = nl.send(msg.data(), msg.length());
                if (send_result.is_err()) {
                    return result::err(send_result.error());
                }

                Vector<u8> buffer(nl::ideal_socket_buffer_size());
                auto recv_result = nl.recv(buffer.data(), buffer.size());
                if (recv_result.is_err()) {
                    return result::err(recv_result.error());
                }

                auto *resp = reinterpret_cast<nlmsghdr *>(buffer.data());
                if (resp->nlmsg_type == NLMSG_ERROR) {
                    auto *err = reinterpret_cast<nlmsgerr *>(reinterpret_cast<char *>(resp) + nl::HDRLEN());
                    if (err->error != 0) {
                        errno = -err->error;
                        return result::err(Error::io_error("Failed to create/delete interface"));
                    }
                }

                return result::ok();
            }

        } // namespace detail

        [[nodiscard]] inline auto add_device(const char *device_name) -> VoidRes {
            return detail::add_del_iface(device_name, true);
        }

        [[nodiscard]] inline auto del_device(const char *device_name) -> VoidRes {
            return detail::add_del_iface(device_name, false);
        }

        [[nodiscard]] inline auto list_device_names() -> Res<Vector<String>> {
            auto nl_result = NetlinkSocket::open(NETLINK_ROUTE);
            if (nl_result.is_err()) {
                return result::err(nl_result.error());
            }
            auto nl = std::move(nl_result.value());

            auto bind_result = nl.bind();
            if (bind_result.is_err()) {
                return result::err(bind_result.error());
            }

            NetlinkMessage msg;
            auto *nlh = msg.header();
            nlh->nlmsg_type = RTM_GETLINK;
            nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
            nlh->nlmsg_seq = static_cast<u32>(time(nullptr));

            auto *ifm = msg.put_extra_header<ifinfomsg>();
            ifm->ifi_family = AF_UNSPEC;

            auto send_result = nl.send(msg.data(), msg.length());
            if (send_result.is_err()) {
                return result::err(send_result.error());
            }

            Vector<String> devices;
            Vector<u8> buffer(nl::ideal_socket_buffer_size());
            u32 seq = nlh->nlmsg_seq;
            u32 portid = nl.portid();

            while (true) {
                auto recv_result = nl.recv(buffer.data(), buffer.size());
                if (recv_result.is_err()) {
                    return result::err(recv_result.error());
                }

                isize len = recv_result.value();
                if (len <= 0)
                    break;

                auto *resp = reinterpret_cast<nlmsghdr *>(buffer.data());
                bool done = false;

                while (len >= static_cast<isize>(sizeof(nlmsghdr)) && resp->nlmsg_len >= sizeof(nlmsghdr) &&
                       static_cast<isize>(resp->nlmsg_len) <= len) {

                    if (resp->nlmsg_type == NLMSG_DONE) {
                        done = true;
                        break;
                    }

                    if (resp->nlmsg_type == NLMSG_ERROR) {
                        auto *err = reinterpret_cast<nlmsgerr *>(reinterpret_cast<char *>(resp) + nl::HDRLEN());
                        if (err->error != 0) {
                            return result::err(Error::io_error("Netlink error"));
                        }
                        done = true;
                        break;
                    }

                    // Parse interface info
                    const char *if_name = nullptr;
                    bool is_wireguard = false;

                    auto *attr_start = reinterpret_cast<nlattr *>(reinterpret_cast<char *>(resp) + nl::HDRLEN() +
                                                                  nl::ALIGN(sizeof(ifinfomsg)));
                    usize remaining = resp->nlmsg_len - nl::HDRLEN() - nl::ALIGN(sizeof(ifinfomsg));

                    while (remaining >= sizeof(nlattr)) {
                        auto *attr = attr_start;
                        if (attr->nla_len < sizeof(nlattr) || attr->nla_len > remaining)
                            break;

                        u16 type = attr->nla_type & NLA_TYPE_MASK;

                        if (type == IFLA_IFNAME) {
                            if_name = reinterpret_cast<const char *>(attr) + nl::ATTR_HDRLEN();
                        } else if (type == IFLA_LINKINFO) {
                            // Parse nested LINKINFO
                            auto *nested =
                                reinterpret_cast<nlattr *>(reinterpret_cast<char *>(attr) + nl::ATTR_HDRLEN());
                            usize nested_remaining = attr->nla_len - nl::ATTR_HDRLEN();

                            while (nested_remaining >= sizeof(nlattr)) {
                                if (nested->nla_len < sizeof(nlattr) || nested->nla_len > nested_remaining)
                                    break;

                                u16 nested_type = nested->nla_type & NLA_TYPE_MASK;
                                if (nested_type == IFLA_INFO_KIND) {
                                    const char *kind = reinterpret_cast<const char *>(nested) + nl::ATTR_HDRLEN();
                                    if (std::strcmp(kind, GENL_NAME) == 0) {
                                        is_wireguard = true;
                                    }
                                }

                                usize advance = nl::ALIGN(nested->nla_len);
                                nested = reinterpret_cast<nlattr *>(reinterpret_cast<char *>(nested) + advance);
                                nested_remaining -= advance;
                            }
                        }

                        usize advance = nl::ALIGN(attr->nla_len);
                        attr_start = reinterpret_cast<nlattr *>(reinterpret_cast<char *>(attr_start) + advance);
                        remaining -= advance;
                    }

                    if (if_name && is_wireguard) {
                        devices.push_back(String(if_name));
                    }

                    usize advance = nl::ALIGN(resp->nlmsg_len);
                    resp = reinterpret_cast<nlmsghdr *>(reinterpret_cast<char *>(resp) + advance);
                    len -= advance;
                }

                if (done)
                    break;
            }

            return result::ok(std::move(devices));
        }

        [[nodiscard]] inline auto get_device(const char *device_name) -> Res<Device> {
            auto nlg_result = GenetlinkSocket::open(GENL_NAME, GENL_VERSION);
            if (nlg_result.is_err()) {
                return result::err(nlg_result.error());
            }
            auto nlg = std::move(nlg_result.value());

            auto msg = nlg.prepare_message(static_cast<u8>(WgCmd::GetDevice), NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP);
            msg.put_attr_strz(static_cast<u16>(WgDeviceAttr::Ifname), device_name);

            auto send_result = nlg.send(msg);
            if (send_result.is_err()) {
                return result::err(send_result.error());
            }

            Device device(device_name);
            Peer *current_peer = nullptr;

            auto recv_result = nlg.recv_run([&](const nlmsghdr *nlh) -> int {
                // Parse device attributes
                auto *attr_start = reinterpret_cast<const nlattr *>(reinterpret_cast<const char *>(nlh) + nl::HDRLEN() +
                                                                    nl::ALIGN(sizeof(genlmsghdr)));
                usize remaining = nlh->nlmsg_len - nl::HDRLEN() - nl::ALIGN(sizeof(genlmsghdr));

                while (remaining >= sizeof(nlattr)) {
                    auto *attr = attr_start;
                    if (attr->nla_len < sizeof(nlattr) || attr->nla_len > remaining)
                        break;

                    u16 type = attr->nla_type & NLA_TYPE_MASK;
                    const void *payload = reinterpret_cast<const char *>(attr) + nl::ATTR_HDRLEN();
                    usize payload_len = attr->nla_len - nl::ATTR_HDRLEN();

                    switch (static_cast<WgDeviceAttr>(type)) {
                    case WgDeviceAttr::Ifindex:
                        if (payload_len >= sizeof(u32)) {
                            device.ifindex = *reinterpret_cast<const u32 *>(payload);
                        }
                        break;
                    case WgDeviceAttr::Ifname:
                        std::strncpy(device.name.data(), reinterpret_cast<const char *>(payload), IFNAMSIZ - 1);
                        break;
                    case WgDeviceAttr::PrivateKey:
                        if (payload_len == KEY_SIZE) {
                            std::memcpy(device.private_key.raw(), payload, KEY_SIZE);
                            device.flags |= DeviceFlags::HasPrivateKey;
                        }
                        break;
                    case WgDeviceAttr::PublicKey:
                        if (payload_len == KEY_SIZE) {
                            std::memcpy(device.public_key.raw(), payload, KEY_SIZE);
                            device.flags |= DeviceFlags::HasPublicKey;
                        }
                        break;
                    case WgDeviceAttr::ListenPort:
                        if (payload_len >= sizeof(u16)) {
                            device.listen_port = *reinterpret_cast<const u16 *>(payload);
                            device.flags |= DeviceFlags::HasListenPort;
                        }
                        break;
                    case WgDeviceAttr::Fwmark:
                        if (payload_len >= sizeof(u32)) {
                            device.fwmark = *reinterpret_cast<const u32 *>(payload);
                            device.flags |= DeviceFlags::HasFwmark;
                        }
                        break;
                    case WgDeviceAttr::Peers: {
                        // Parse nested peers
                        auto *peer_attr = reinterpret_cast<const nlattr *>(payload);
                        usize peer_remaining = payload_len;

                        while (peer_remaining >= sizeof(nlattr)) {
                            if (peer_attr->nla_len < sizeof(nlattr) || peer_attr->nla_len > peer_remaining)
                                break;

                            Peer peer;

                            // Parse single peer
                            auto *inner = reinterpret_cast<const nlattr *>(reinterpret_cast<const char *>(peer_attr) +
                                                                           nl::ATTR_HDRLEN());
                            usize inner_remaining = peer_attr->nla_len - nl::ATTR_HDRLEN();

                            while (inner_remaining >= sizeof(nlattr)) {
                                if (inner->nla_len < sizeof(nlattr) || inner->nla_len > inner_remaining)
                                    break;

                                u16 inner_type = inner->nla_type & NLA_TYPE_MASK;
                                const void *inner_payload = reinterpret_cast<const char *>(inner) + nl::ATTR_HDRLEN();
                                usize inner_payload_len = inner->nla_len - nl::ATTR_HDRLEN();

                                switch (static_cast<WgPeerAttr>(inner_type)) {
                                case WgPeerAttr::PublicKey:
                                    if (inner_payload_len == KEY_SIZE) {
                                        std::memcpy(peer.public_key.raw(), inner_payload, KEY_SIZE);
                                        peer.flags |= PeerFlags::HasPublicKey;
                                    }
                                    break;
                                case WgPeerAttr::PresharedKey:
                                    if (inner_payload_len == KEY_SIZE) {
                                        std::memcpy(peer.preshared_key.raw(), inner_payload, KEY_SIZE);
                                        if (!peer.preshared_key.is_zero()) {
                                            peer.flags |= PeerFlags::HasPresharedKey;
                                        }
                                    }
                                    break;
                                case WgPeerAttr::Endpoint:
                                    if (inner_payload_len >= sizeof(sockaddr)) {
                                        auto *sa = reinterpret_cast<const sockaddr *>(inner_payload);
                                        if (sa->sa_family == AF_INET && inner_payload_len >= sizeof(sockaddr_in)) {
                                            std::memcpy(&peer.endpoint.addr4, inner_payload, sizeof(sockaddr_in));
                                        } else if (sa->sa_family == AF_INET6 &&
                                                   inner_payload_len >= sizeof(sockaddr_in6)) {
                                            std::memcpy(&peer.endpoint.addr6, inner_payload, sizeof(sockaddr_in6));
                                        }
                                    }
                                    break;
                                case WgPeerAttr::PersistentKeepaliveInterval:
                                    if (inner_payload_len >= sizeof(u16)) {
                                        peer.persistent_keepalive_interval =
                                            *reinterpret_cast<const u16 *>(inner_payload);
                                        peer.flags |= PeerFlags::HasPersistentKeepaliveInterval;
                                    }
                                    break;
                                case WgPeerAttr::LastHandshakeTime:
                                    if (inner_payload_len >= sizeof(Timespec64)) {
                                        std::memcpy(&peer.last_handshake_time, inner_payload, sizeof(Timespec64));
                                    }
                                    break;
                                case WgPeerAttr::RxBytes:
                                    if (inner_payload_len >= sizeof(u64)) {
                                        peer.rx_bytes = *reinterpret_cast<const u64 *>(inner_payload);
                                    }
                                    break;
                                case WgPeerAttr::TxBytes:
                                    if (inner_payload_len >= sizeof(u64)) {
                                        peer.tx_bytes = *reinterpret_cast<const u64 *>(inner_payload);
                                    }
                                    break;
                                case WgPeerAttr::AllowedIps: {
                                    // Parse allowed IPs
                                    auto *ip_attr = reinterpret_cast<const nlattr *>(inner_payload);
                                    usize ip_remaining = inner_payload_len;

                                    while (ip_remaining >= sizeof(nlattr)) {
                                        if (ip_attr->nla_len < sizeof(nlattr) || ip_attr->nla_len > ip_remaining)
                                            break;

                                        AllowedIp allowed_ip;

                                        auto *ip_inner = reinterpret_cast<const nlattr *>(
                                            reinterpret_cast<const char *>(ip_attr) + nl::ATTR_HDRLEN());
                                        usize ip_inner_remaining = ip_attr->nla_len - nl::ATTR_HDRLEN();

                                        while (ip_inner_remaining >= sizeof(nlattr)) {
                                            if (ip_inner->nla_len < sizeof(nlattr) ||
                                                ip_inner->nla_len > ip_inner_remaining)
                                                break;

                                            u16 ip_type = ip_inner->nla_type & NLA_TYPE_MASK;
                                            const void *ip_payload =
                                                reinterpret_cast<const char *>(ip_inner) + nl::ATTR_HDRLEN();
                                            usize ip_payload_len = ip_inner->nla_len - nl::ATTR_HDRLEN();

                                            switch (static_cast<WgAllowedIpAttr>(ip_type)) {
                                            case WgAllowedIpAttr::Family:
                                                if (ip_payload_len >= sizeof(u16)) {
                                                    allowed_ip.family = *reinterpret_cast<const u16 *>(ip_payload);
                                                }
                                                break;
                                            case WgAllowedIpAttr::IpAddr:
                                                if (ip_payload_len == sizeof(in_addr)) {
                                                    std::memcpy(&allowed_ip.ip4, ip_payload, sizeof(in_addr));
                                                } else if (ip_payload_len == sizeof(in6_addr)) {
                                                    std::memcpy(&allowed_ip.ip6, ip_payload, sizeof(in6_addr));
                                                }
                                                break;
                                            case WgAllowedIpAttr::CidrMask:
                                                if (ip_payload_len >= sizeof(u8)) {
                                                    allowed_ip.cidr = *reinterpret_cast<const u8 *>(ip_payload);
                                                }
                                                break;
                                            default:
                                                break;
                                            }

                                            usize ip_advance = nl::ALIGN(ip_inner->nla_len);
                                            ip_inner = reinterpret_cast<const nlattr *>(
                                                reinterpret_cast<const char *>(ip_inner) + ip_advance);
                                            ip_inner_remaining -= ip_advance;
                                        }

                                        if (allowed_ip.is_valid()) {
                                            peer.allowed_ips.push_back(allowed_ip);
                                        }

                                        usize ip_advance = nl::ALIGN(ip_attr->nla_len);
                                        ip_attr = reinterpret_cast<const nlattr *>(
                                            reinterpret_cast<const char *>(ip_attr) + ip_advance);
                                        ip_remaining -= ip_advance;
                                    }
                                    break;
                                }
                                default:
                                    break;
                                }

                                usize inner_advance = nl::ALIGN(inner->nla_len);
                                inner = reinterpret_cast<const nlattr *>(reinterpret_cast<const char *>(inner) +
                                                                         inner_advance);
                                inner_remaining -= inner_advance;
                            }

                            if (has_flag(peer.flags, PeerFlags::HasPublicKey)) {
                                device.peers.push_back(std::move(peer));
                            }

                            usize peer_advance = nl::ALIGN(peer_attr->nla_len);
                            peer_attr = reinterpret_cast<const nlattr *>(reinterpret_cast<const char *>(peer_attr) +
                                                                         peer_advance);
                            peer_remaining -= peer_advance;
                        }
                        break;
                    }
                    default:
                        break;
                    }

                    usize advance = nl::ALIGN(attr->nla_len);
                    attr_start = reinterpret_cast<const nlattr *>(reinterpret_cast<const char *>(attr_start) + advance);
                    remaining -= advance;
                }

                return 1; // Continue processing
            });

            if (recv_result.is_err()) {
                return result::err(recv_result.error());
            }

            return result::ok(std::move(device));
        }

        [[nodiscard]] inline auto set_device(const Device &device) -> VoidRes {
            auto nlg_result = GenetlinkSocket::open(GENL_NAME, GENL_VERSION);
            if (nlg_result.is_err()) {
                return result::err(nlg_result.error());
            }
            auto nlg = std::move(nlg_result.value());

            auto msg = nlg.prepare_message(static_cast<u8>(WgCmd::SetDevice), NLM_F_REQUEST | NLM_F_ACK);

            msg.put_attr_strz(static_cast<u16>(WgDeviceAttr::Ifname), device.get_name());

            // Device attributes
            if (device.has_private_key()) {
                msg.put_attr(static_cast<u16>(WgDeviceAttr::PrivateKey), device.private_key.raw(), KEY_SIZE);
            }

            if (device.has_listen_port()) {
                msg.put_attr_u16(static_cast<u16>(WgDeviceAttr::ListenPort), device.listen_port);
            }

            if (device.has_fwmark()) {
                msg.put_attr_u32(static_cast<u16>(WgDeviceAttr::Fwmark), device.fwmark);
            }

            u32 dev_flags = 0;
            if (device.should_replace_peers()) {
                dev_flags |= 1U << 0; // WGDEVICE_F_REPLACE_PEERS
            }
            if (dev_flags != 0) {
                msg.put_attr_u32(static_cast<u16>(WgDeviceAttr::Flags), dev_flags);
            }

            // Add peers
            if (!device.peers.empty()) {
                auto *peers_nest = msg.nest_start(static_cast<u16>(WgDeviceAttr::Peers));
                if (!peers_nest) {
                    return result::err(Error::out_of_range("Message buffer too small"));
                }

                for (const auto &peer : device.peers) {
                    auto *peer_nest = msg.nest_start(0);
                    if (!peer_nest) {
                        msg.nest_end(peers_nest);
                        break;
                    }

                    // Public key (required)
                    if (!msg.put_attr(static_cast<u16>(WgPeerAttr::PublicKey), peer.public_key.raw(), KEY_SIZE)) {
                        msg.nest_cancel(peer_nest);
                        msg.nest_end(peers_nest);
                        break;
                    }

                    // Peer flags
                    u32 peer_flags = 0;
                    if (peer.should_remove()) {
                        peer_flags |= 1U << 0; // WGPEER_F_REMOVE_ME
                    }
                    if (peer.should_replace_allowed_ips()) {
                        peer_flags |= 1U << 1; // WGPEER_F_REPLACE_ALLOWEDIPS
                    }
                    if (peer_flags != 0) {
                        msg.put_attr_u32(static_cast<u16>(WgPeerAttr::Flags), peer_flags);
                    }

                    // Preshared key
                    if (peer.has_preshared_key()) {
                        msg.put_attr(static_cast<u16>(WgPeerAttr::PresharedKey), peer.preshared_key.raw(), KEY_SIZE);
                    }

                    // Endpoint
                    if (peer.endpoint.is_ipv4()) {
                        msg.put_attr(static_cast<u16>(WgPeerAttr::Endpoint), &peer.endpoint.addr4, sizeof(sockaddr_in));
                    } else if (peer.endpoint.is_ipv6()) {
                        msg.put_attr(static_cast<u16>(WgPeerAttr::Endpoint), &peer.endpoint.addr6,
                                     sizeof(sockaddr_in6));
                    }

                    // Persistent keepalive
                    if (has_flag(peer.flags, PeerFlags::HasPersistentKeepaliveInterval)) {
                        msg.put_attr_u16(static_cast<u16>(WgPeerAttr::PersistentKeepaliveInterval),
                                         peer.persistent_keepalive_interval);
                    }

                    // Allowed IPs
                    if (!peer.allowed_ips.empty()) {
                        auto *ips_nest = msg.nest_start(static_cast<u16>(WgPeerAttr::AllowedIps));
                        if (ips_nest) {
                            for (const auto &ip : peer.allowed_ips) {
                                auto *ip_nest = msg.nest_start(0);
                                if (!ip_nest)
                                    break;

                                msg.put_attr_u16(static_cast<u16>(WgAllowedIpAttr::Family), ip.family);

                                if (ip.is_ipv4()) {
                                    msg.put_attr(static_cast<u16>(WgAllowedIpAttr::IpAddr), &ip.ip4, sizeof(in_addr));
                                } else if (ip.is_ipv6()) {
                                    msg.put_attr(static_cast<u16>(WgAllowedIpAttr::IpAddr), &ip.ip6, sizeof(in6_addr));
                                }

                                msg.put_attr_u8(static_cast<u16>(WgAllowedIpAttr::CidrMask), ip.cidr);

                                msg.nest_end(ip_nest);
                            }
                            msg.nest_end(ips_nest);
                        }
                    }

                    msg.nest_end(peer_nest);
                }

                msg.nest_end(peers_nest);
            }

            auto send_result = nlg.send(msg);
            if (send_result.is_err()) {
                return result::err(send_result.error());
            }

            auto recv_result = nlg.recv_run([](const nlmsghdr *) { return 1; });
            if (recv_result.is_err()) {
                return result::err(recv_result.error());
            }

            return result::ok();
        }

    } // namespace api

    // =============================================================================
    // Convenience Type Aliases
    // =============================================================================

    using WgKey = Key;
    using WgKeyB64 = KeyB64;
    using WgAllowedIp = AllowedIp;
    using WgEndpoint = Endpoint;
    using WgPeer = Peer;
    using WgDevice = Device;

} // namespace wg

#endif // WIREGUARD_HPP
