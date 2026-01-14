/* SPDX-License-Identifier: MIT */
/*
 * Botlink Wirebit Backend
 * TUN interface implementation using wirebit
 *
 * Uses ioctl() for interface configuration instead of shelling out to `ip` commands.
 * This is more secure and doesn't require sudo for most operations if the process
 * has CAP_NET_ADMIN capability.
 */

#pragma once

#ifndef NO_HARDWARE

#include <arpa/inet.h>
#include <botlink/core/result.hpp>
#include <botlink/core/types.hpp>
#include <botlink/netdev/netdev.hpp>
#include <cstring>
#include <datapod/datapod.hpp>
#include <echo/echo.hpp>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wirebit/eth/tun_link.hpp>
#include <wirebit/wirebit.hpp>

namespace botlink {

    using namespace dp;

    namespace netdev {

        // =============================================================================
        // Interface Configuration via ioctl (no sudo/system() calls)
        // =============================================================================

        namespace ifconfig {

            // Get a socket for ioctl operations
            inline auto get_ioctl_socket() -> i32 {
                i32 sock = socket(AF_INET, SOCK_DGRAM, 0);
                if (sock < 0) {
                    echo::warn("ifconfig: Failed to create ioctl socket");
                }
                return sock;
            }

            // Set interface flags (up/down)
            inline auto set_interface_flags(const String &name, i16 flags, boolean set) -> VoidRes {
                i32 sock = get_ioctl_socket();
                if (sock < 0) {
                    return result::err(err::io("Failed to create socket for ioctl"));
                }

                struct ifreq ifr;
                std::memset(&ifr, 0, sizeof(ifr));
                std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);

                // Get current flags
                if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
                    close(sock);
                    return result::err(err::io("Failed to get interface flags"));
                }

                // Modify flags
                if (set) {
                    ifr.ifr_flags |= flags;
                } else {
                    ifr.ifr_flags &= ~flags;
                }

                // Set new flags
                if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
                    close(sock);
                    return result::err(err::io("Failed to set interface flags"));
                }

                close(sock);
                return result::ok();
            }

            // Bring interface up
            inline auto interface_up(const String &name) -> VoidRes {
                return set_interface_flags(name, IFF_UP | IFF_RUNNING, true);
            }

            // Bring interface down
            inline auto interface_down(const String &name) -> VoidRes {
                return set_interface_flags(name, IFF_UP, false);
            }

            // Set MTU
            inline auto set_mtu(const String &name, u16 mtu) -> VoidRes {
                i32 sock = get_ioctl_socket();
                if (sock < 0) {
                    return result::err(err::io("Failed to create socket for ioctl"));
                }

                struct ifreq ifr;
                std::memset(&ifr, 0, sizeof(ifr));
                std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
                ifr.ifr_mtu = mtu;

                if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
                    close(sock);
                    return result::err(err::io("Failed to set MTU"));
                }

                close(sock);
                return result::ok();
            }

            // Parse CIDR address (e.g., "10.0.0.1/24") into address and prefix length
            struct CidrParts {
                String addr;
                u8 prefix;
            };

            inline auto parse_cidr(const String &cidr) -> CidrParts {
                auto slash_pos = cidr.find('/');
                if (slash_pos == String::npos) {
                    return {String(cidr), 24}; // Default to /24
                }
                String addr = String(cidr.c_str(), slash_pos);
                u8 prefix = static_cast<u8>(std::atoi(cidr.c_str() + slash_pos + 1));
                return {std::move(addr), prefix};
            }

            // Convert prefix length to netmask
            inline auto prefix_to_netmask(u8 prefix) -> u32 {
                if (prefix >= 32) {
                    return 0xFFFFFFFF;
                }
                if (prefix == 0) {
                    return 0;
                }
                return htonl(~((1u << (32 - prefix)) - 1));
            }

            // Assign IPv4 address to interface
            inline auto assign_ipv4_address(const String &name, const String &addr_cidr) -> VoidRes {
                i32 sock = get_ioctl_socket();
                if (sock < 0) {
                    return result::err(err::io("Failed to create socket for ioctl"));
                }

                auto parts = parse_cidr(addr_cidr);
                const String &addr_str = parts.addr;
                u8 prefix = parts.prefix;

                struct ifreq ifr;
                std::memset(&ifr, 0, sizeof(ifr));
                std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);

                // Set IP address
                struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
                sin->sin_family = AF_INET;
                if (inet_pton(AF_INET, addr_str.c_str(), &sin->sin_addr) != 1) {
                    close(sock);
                    return result::err(err::invalid("Invalid IPv4 address"));
                }

                if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
                    close(sock);
                    return result::err(err::io("Failed to set interface address"));
                }

                // Set netmask
                sin->sin_addr.s_addr = prefix_to_netmask(prefix);
                if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
                    close(sock);
                    // Not fatal - address was set
                    echo::warn("ifconfig: Failed to set netmask");
                }

                close(sock);
                return result::ok();
            }

            // Check if interface exists
            inline auto interface_exists(const String &name) -> boolean {
                i32 sock = get_ioctl_socket();
                if (sock < 0) {
                    return false;
                }

                struct ifreq ifr;
                std::memset(&ifr, 0, sizeof(ifr));
                std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);

                boolean exists = (ioctl(sock, SIOCGIFINDEX, &ifr) >= 0);
                close(sock);
                return exists;
            }

        } // namespace ifconfig

        // =============================================================================
        // Wirebit TUN Backend
        // =============================================================================

        class WirebitBackend : public NetdevBackend {
          private:
            InterfaceInfo info_;
            Optional<wirebit::TunLink> tun_;
            boolean destroy_on_close_ = true;

          public:
            WirebitBackend() = default;

            ~WirebitBackend() override {
                if (tun_.has_value() && destroy_on_close_) {
                    down(info_.name);
                }
            }

            // Disable copy
            WirebitBackend(const WirebitBackend &) = delete;
            WirebitBackend &operator=(const WirebitBackend &) = delete;

            // Move constructor
            WirebitBackend(WirebitBackend &&other) noexcept
                : info_(other.info_), destroy_on_close_(other.destroy_on_close_) {
                if (other.tun_.has_value()) {
                    tun_ = std::move(other.tun_);
                    other.tun_.reset();
                }
                other.info_.fd = -1;
                other.destroy_on_close_ = false;
            }

            // Move assignment
            WirebitBackend &operator=(WirebitBackend &&other) noexcept {
                if (this != &other) {
                    info_ = other.info_;
                    destroy_on_close_ = other.destroy_on_close_;
                    if (other.tun_.has_value()) {
                        tun_ = std::move(other.tun_);
                        other.tun_.reset();
                    }
                    other.info_.fd = -1;
                    other.destroy_on_close_ = false;
                }
                return *this;
            }

            auto create_interface(const InterfaceName &name) -> VoidRes override {
                wirebit::TunConfig config;
                config.interface_name = wirebit::String(name.c_str());
                config.create_if_missing = true;
                config.destroy_on_close = false; // We'll manage this ourselves
                config.set_up_on_create = false; // We'll call up() explicitly
                config.ip_address = "";          // We'll call assign_addr() explicitly

                auto result = wirebit::TunLink::create(config);
                if (!result.is_ok()) {
                    return result::err(err::io(result.error().message.c_str()));
                }

                tun_ = std::move(result.value());
                info_.name = name;
                info_.state = InterfaceState::Down;
                info_.fd = tun_->tun_fd();

                echo::info("WirebitBackend: Created TUN interface ", name.c_str());
                return result::ok();
            }

            auto set_mtu(const InterfaceName &name, u16 mtu) -> VoidRes override {
                auto res = ifconfig::set_mtu(name.c_str(), mtu);
                if (res.is_err()) {
                    echo::warn("WirebitBackend: Failed to set MTU: ", res.error().message.c_str());
                    // Not fatal, continue
                }

                info_.mtu = mtu;
                return result::ok();
            }

            auto assign_addr(const InterfaceName &name, const OverlayAddr &addr) -> VoidRes override {
                // Format: "10.42.0.7/24"
                String addr_str = addr.addr + "/" + to_str(addr.prefix_len);

                auto res = ifconfig::assign_ipv4_address(name.c_str(), addr_str);
                if (res.is_err()) {
                    // May already be assigned
                    echo::warn("WirebitBackend: Failed to assign address: ", res.error().message.c_str());
                }

                info_.addr = addr;
                return result::ok();
            }

            auto up(const InterfaceName &name) -> VoidRes override {
                auto res = ifconfig::interface_up(name.c_str());
                if (res.is_err()) {
                    return result::err(err::io("Failed to bring interface up"));
                }

                info_.state = InterfaceState::Up;
                echo::info("WirebitBackend: Interface ", name.c_str(), " is up");
                return result::ok();
            }

            auto down(const InterfaceName &name) -> VoidRes override {
                auto res = ifconfig::interface_down(name.c_str());
                if (res.is_err()) {
                    echo::warn("WirebitBackend: Failed to bring interface down: ", res.error().message.c_str());
                }

                info_.state = InterfaceState::Down;
                return result::ok();
            }

            auto destroy(const InterfaceName &name) -> VoidRes override {
                // First bring down
                down(name);

                // Release the TUN - wirebit will handle destruction if destroy_on_close was set
                // For TUN interfaces created via /dev/net/tun, they are typically destroyed
                // when the last file descriptor is closed
                tun_.reset();

                // Note: Deleting persistent interfaces requires netlink or ip commands.
                // If the interface was created by wirebit with destroy_on_close=true,
                // it will be deleted when tun_.reset() is called above.
                // If it still exists, check if it's gone
                if (ifconfig::interface_exists(name.c_str())) {
                    echo::warn("WirebitBackend: Interface ", name.c_str(),
                               " still exists after release (may need manual cleanup)");
                }

                info_.fd = -1;
                echo::info("WirebitBackend: Interface ", name.c_str(), " destroyed");
                return result::ok();
            }

            auto read_packet() -> Res<IpPacket> override {
                if (!tun_.has_value()) {
                    return result::err(err::io("Interface not created"));
                }

                auto result = tun_->recv();
                if (!result.is_ok()) {
                    return result::err(err::timeout("No packets available"));
                }

                const auto &frame = result.value();
                IpPacket pkt;
                pkt.data.reserve(frame.payload.size());
                for (const auto &byte : frame.payload) {
                    pkt.data.push_back(byte);
                }
                pkt.timestamp_ms = time::now_ms();

                return result::ok(pkt);
            }

            auto write_packet(const IpPacket &pkt) -> VoidRes override {
                if (!tun_.has_value()) {
                    return result::err(err::io("Interface not created"));
                }

                if (pkt.data.empty()) {
                    return result::err(err::invalid("Empty packet"));
                }

                // Create wirebit frame
                wirebit::Bytes payload;
                payload.reserve(pkt.data.size());
                for (const auto &byte : pkt.data) {
                    payload.push_back(byte);
                }

                wirebit::Frame frame = wirebit::make_frame(wirebit::FrameType::IP, std::move(payload), 0, 0);

                auto result = tun_->send(frame);
                if (!result.is_ok()) {
                    return result::err(err::io(result.error().message.c_str()));
                }

                return result::ok();
            }

            auto can_read() const -> boolean override { return tun_.has_value() && tun_->can_recv(); }

            auto can_write() const -> boolean override { return tun_.has_value() && tun_->can_send() && info_.is_up(); }

            auto fd() const -> i32 override { return info_.fd; }

            auto info() const -> const InterfaceInfo & override { return info_; }

            // Set whether to destroy interface on close
            auto set_destroy_on_close(boolean destroy) -> void { destroy_on_close_ = destroy; }
        };

        // =============================================================================
        // Factory function
        // =============================================================================

        [[nodiscard]] inline auto create_wirebit_backend() -> Res<WirebitBackend> {
            return result::ok(WirebitBackend());
        }

    } // namespace netdev

} // namespace botlink

#endif // NO_HARDWARE
