/* SPDX-License-Identifier: MIT */
/*
 * Botlink Netdev
 * Abstract network interface for TUN/TAP operations
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/types.hpp>
#include <datapod/datapod.hpp>
#include <echo/echo.hpp>

namespace botlink {

    using namespace dp;

    namespace netdev {

        // =============================================================================
        // Interface State
        // =============================================================================

        enum class InterfaceState : u8 {
            Down = 0,
            Up = 1,
            Error = 2,
        };

        // =============================================================================
        // Interface Info
        // =============================================================================

        struct InterfaceInfo {
            InterfaceName name;
            OverlayAddr addr;
            u16 mtu = DEFAULT_MTU;
            InterfaceState state = InterfaceState::Down;
            i32 fd = -1;

            InterfaceInfo() = default;

            [[nodiscard]] auto is_up() const -> boolean { return state == InterfaceState::Up; }
            [[nodiscard]] auto is_valid() const -> boolean { return fd >= 0; }

            auto members() noexcept { return std::tie(name, addr, mtu, state, fd); }
            auto members() const noexcept { return std::tie(name, addr, mtu, state, fd); }
        };

        // =============================================================================
        // IP Packet (raw)
        // =============================================================================

        struct IpPacket {
            Vector<u8> data;
            u64 timestamp_ms = 0;

            IpPacket() = default;
            explicit IpPacket(Vector<u8> d) : data(std::move(d)), timestamp_ms(time::now_ms()) {}

            [[nodiscard]] auto size() const -> usize { return data.size(); }
            [[nodiscard]] auto empty() const -> boolean { return data.empty(); }

            // Get IP version (4 or 6)
            [[nodiscard]] auto ip_version() const -> u8 {
                if (data.empty()) {
                    return 0;
                }
                return (data[0] >> 4) & 0x0F;
            }

            // Check if IPv4
            [[nodiscard]] auto is_ipv4() const -> boolean { return ip_version() == 4; }

            // Check if IPv6
            [[nodiscard]] auto is_ipv6() const -> boolean { return ip_version() == 6; }

            auto members() noexcept { return std::tie(data, timestamp_ms); }
            auto members() const noexcept { return std::tie(data, timestamp_ms); }
        };

        // =============================================================================
        // Netdev Backend Interface (Abstract)
        // =============================================================================

        class NetdevBackend {
          public:
            virtual ~NetdevBackend() = default;

            // Create and configure interface
            virtual auto create_interface(const InterfaceName &name) -> VoidRes = 0;

            // Set MTU
            virtual auto set_mtu(const InterfaceName &name, u16 mtu) -> VoidRes = 0;

            // Assign IP address with CIDR
            virtual auto assign_addr(const InterfaceName &name, const OverlayAddr &addr) -> VoidRes = 0;

            // Bring interface up
            virtual auto up(const InterfaceName &name) -> VoidRes = 0;

            // Bring interface down
            virtual auto down(const InterfaceName &name) -> VoidRes = 0;

            // Destroy interface
            virtual auto destroy(const InterfaceName &name) -> VoidRes = 0;

            // Read a packet (non-blocking)
            virtual auto read_packet() -> Res<IpPacket> = 0;

            // Write a packet
            virtual auto write_packet(const IpPacket &pkt) -> VoidRes = 0;

            // Check if packets are available
            virtual auto can_read() const -> boolean = 0;

            // Check if can write
            virtual auto can_write() const -> boolean = 0;

            // Get file descriptor (for polling)
            virtual auto fd() const -> i32 = 0;

            // Get interface info
            virtual auto info() const -> const InterfaceInfo & = 0;
        };

        // =============================================================================
        // Null Backend (for testing without privileges)
        // =============================================================================

        class NullBackend : public NetdevBackend {
          private:
            InterfaceInfo info_;
            Vector<IpPacket> rx_queue_;
            Vector<IpPacket> tx_queue_;

          public:
            NullBackend() = default;

            auto create_interface(const InterfaceName &name) -> VoidRes override {
                info_.name = name;
                info_.state = InterfaceState::Down;
                info_.fd = 0; // Fake fd
                echo::debug("NullBackend: Created interface ", name.c_str());
                return result::ok();
            }

            auto set_mtu(const InterfaceName & /*name*/, u16 mtu) -> VoidRes override {
                info_.mtu = mtu;
                return result::ok();
            }

            auto assign_addr(const InterfaceName & /*name*/, const OverlayAddr &addr) -> VoidRes override {
                info_.addr = addr;
                return result::ok();
            }

            auto up(const InterfaceName & /*name*/) -> VoidRes override {
                info_.state = InterfaceState::Up;
                echo::debug("NullBackend: Interface up");
                return result::ok();
            }

            auto down(const InterfaceName & /*name*/) -> VoidRes override {
                info_.state = InterfaceState::Down;
                echo::debug("NullBackend: Interface down");
                return result::ok();
            }

            auto destroy(const InterfaceName & /*name*/) -> VoidRes override {
                info_.state = InterfaceState::Down;
                info_.fd = -1;
                echo::debug("NullBackend: Interface destroyed");
                return result::ok();
            }

            auto read_packet() -> Res<IpPacket> override {
                if (rx_queue_.empty()) {
                    return result::err(err::timeout("No packets available"));
                }
                auto pkt = rx_queue_.back();
                rx_queue_.pop_back();
                return result::ok(pkt);
            }

            auto write_packet(const IpPacket &pkt) -> VoidRes override {
                tx_queue_.push_back(pkt);
                return result::ok();
            }

            auto can_read() const -> boolean override { return !rx_queue_.empty(); }

            auto can_write() const -> boolean override { return info_.is_up(); }

            auto fd() const -> i32 override { return info_.fd; }

            auto info() const -> const InterfaceInfo & override { return info_; }

            // Test helpers
            auto inject_packet(const IpPacket &pkt) -> void { rx_queue_.push_back(pkt); }

            auto get_tx_queue() -> Vector<IpPacket> & { return tx_queue_; }
        };

    } // namespace netdev

} // namespace botlink
