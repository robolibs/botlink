/* SPDX-License-Identifier: MIT */
/*
 * Botlink Route Table
 * Overlay routes mapping destination addresses to peers
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/time.hpp>
#include <botlink/core/types.hpp>
#include <datapod/datapod.hpp>
#include <echo/echo.hpp>

namespace botlink {

    using namespace dp;

    namespace netdev {

        // =============================================================================
        // Route Entry
        // =============================================================================

        struct RouteEntry {
            OverlayAddr dest;         // Destination address/subnet
            NodeId next_hop;          // Peer to send traffic to
            u64 added_at_ms = 0;      // When route was added
            u64 last_used_ms = 0;     // Last time traffic was sent
            u32 metric = 0;           // Route metric (lower = preferred)
            boolean is_direct = true; // Direct route vs via relay
            String relay_id;          // Relay ID if not direct

            RouteEntry() = default;

            [[nodiscard]] auto age_ms() const -> u64 { return time::now_ms() - added_at_ms; }

            [[nodiscard]] auto idle_ms() const -> u64 { return time::now_ms() - last_used_ms; }

            auto members() noexcept {
                return std::tie(dest, next_hop, added_at_ms, last_used_ms, metric, is_direct, relay_id);
            }
            auto members() const noexcept {
                return std::tie(dest, next_hop, added_at_ms, last_used_ms, metric, is_direct, relay_id);
            }
        };

        // =============================================================================
        // Route Table
        // =============================================================================

        class RouteTable {
          private:
            Vector<RouteEntry> routes_;
            OverlayAddr local_addr_;

          public:
            RouteTable() = default;

            explicit RouteTable(const OverlayAddr &local_addr) : local_addr_(local_addr) {}

            // =============================================================================
            // Route Management
            // =============================================================================

            // Add or update a route
            auto add_route(const RouteEntry &route) -> VoidRes {
                // Check for existing route to same destination
                for (auto &existing : routes_) {
                    if (existing.dest.addr == route.dest.addr && existing.dest.prefix_len == route.dest.prefix_len) {
                        // Update existing route if new one has better metric
                        if (route.metric < existing.metric) {
                            existing = route;
                            echo::debug("RouteTable: Updated route to ", route.dest.addr.c_str());
                        }
                        return result::ok();
                    }
                }

                // Add new route
                routes_.push_back(route);
                echo::debug("RouteTable: Added route to ", route.dest.addr.c_str());
                return result::ok();
            }

            // Add a direct route to a peer
            auto add_direct_route(const OverlayAddr &dest, const NodeId &peer_id, u32 metric = 0) -> VoidRes {
                RouteEntry entry;
                entry.dest = dest;
                entry.next_hop = peer_id;
                entry.added_at_ms = time::now_ms();
                entry.last_used_ms = time::now_ms();
                entry.metric = metric;
                entry.is_direct = true;

                return add_route(entry);
            }

            // Add a relayed route
            auto add_relay_route(const OverlayAddr &dest, const NodeId &peer_id, const String &relay_id,
                                 u32 metric = 100) -> VoidRes {
                RouteEntry entry;
                entry.dest = dest;
                entry.next_hop = peer_id;
                entry.added_at_ms = time::now_ms();
                entry.last_used_ms = time::now_ms();
                entry.metric = metric;
                entry.is_direct = false;
                entry.relay_id = relay_id;

                return add_route(entry);
            }

            // Remove routes to a peer
            auto remove_routes_to_peer(const NodeId &peer_id) -> usize {
                usize removed = 0;
                Vector<RouteEntry> remaining;

                for (const auto &route : routes_) {
                    if (route.next_hop != peer_id) {
                        remaining.push_back(route);
                    } else {
                        ++removed;
                    }
                }

                routes_ = remaining;
                return removed;
            }

            // Remove route to destination
            auto remove_route(const OverlayAddr &dest) -> boolean {
                Vector<RouteEntry> remaining;

                for (const auto &route : routes_) {
                    if (route.dest.addr != dest.addr || route.dest.prefix_len != dest.prefix_len) {
                        remaining.push_back(route);
                    }
                }

                boolean removed = (remaining.size() < routes_.size());
                routes_ = remaining;
                return removed;
            }

            // =============================================================================
            // Route Lookup
            // =============================================================================

            // Simple IP address matching (IPv4 only for now)
            [[nodiscard]] auto parse_ipv4(const String &addr) const -> Optional<u32> {
                u32 a = 0, b = 0, c = 0, d = 0;
                if (sscanf(addr.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
                    return Optional<u32>();
                }
                return static_cast<u32>((a << 24) | (b << 16) | (c << 8) | d);
            }

            [[nodiscard]] auto matches_subnet(const String &ip, const OverlayAddr &subnet) const -> boolean {
                auto ip_val = parse_ipv4(ip);
                auto subnet_val = parse_ipv4(subnet.addr);

                if (!ip_val.has_value() || !subnet_val.has_value()) {
                    return false;
                }

                if (subnet.prefix_len == 0) {
                    return true; // Default route
                }

                u32 mask = 0xFFFFFFFF << (32 - subnet.prefix_len);
                return (ip_val.value() & mask) == (subnet_val.value() & mask);
            }

            // Lookup route for destination IP
            [[nodiscard]] auto lookup(const String &dest_ip) const -> Optional<RouteEntry> {
                Optional<RouteEntry> best;
                u8 best_prefix_len = 0;

                for (const auto &route : routes_) {
                    if (matches_subnet(dest_ip, route.dest)) {
                        // Prefer longer prefix match
                        if (!best.has_value() || route.dest.prefix_len > best_prefix_len ||
                            (route.dest.prefix_len == best_prefix_len && route.metric < best->metric)) {
                            best = route;
                            best_prefix_len = route.dest.prefix_len;
                        }
                    }
                }

                return best;
            }

            // Lookup route for raw IP packet (extract destination from header)
            [[nodiscard]] auto lookup_packet(const Vector<u8> &pkt) const -> Optional<RouteEntry> {
                if (pkt.size() < 20) {
                    return Optional<RouteEntry>(); // Too short for IPv4
                }

                // Check IP version
                u8 version = (pkt[0] >> 4) & 0x0F;
                if (version != 4) {
                    return Optional<RouteEntry>(); // Only IPv4 for now
                }

                // Extract destination address (bytes 16-19)
                u8 a = pkt[16];
                u8 b = pkt[17];
                u8 c = pkt[18];
                u8 d = pkt[19];

                String dest_ip = to_str(a) + "." + to_str(b) + "." + to_str(c) + "." + to_str(d);

                return lookup(dest_ip);
            }

            // =============================================================================
            // Query
            // =============================================================================

            [[nodiscard]] auto get_all_routes() const -> const Vector<RouteEntry> & { return routes_; }

            [[nodiscard]] auto get_routes_to_peer(const NodeId &peer_id) const -> Vector<RouteEntry> {
                Vector<RouteEntry> result;
                for (const auto &route : routes_) {
                    if (route.next_hop == peer_id) {
                        result.push_back(route);
                    }
                }
                return result;
            }

            [[nodiscard]] auto route_count() const -> usize { return routes_.size(); }

            // =============================================================================
            // Maintenance
            // =============================================================================

            // Mark route as used
            auto mark_used(const OverlayAddr &dest) -> void {
                for (auto &route : routes_) {
                    if (route.dest.addr == dest.addr && route.dest.prefix_len == dest.prefix_len) {
                        route.last_used_ms = time::now_ms();
                        break;
                    }
                }
            }

            // Remove stale routes (not used for a while)
            auto cleanup_stale(u64 max_idle_ms) -> usize {
                Vector<RouteEntry> remaining;
                usize removed = 0;

                for (const auto &route : routes_) {
                    if (route.idle_ms() <= max_idle_ms) {
                        remaining.push_back(route);
                    } else {
                        ++removed;
                    }
                }

                routes_ = remaining;
                return removed;
            }

            // Clear all routes
            auto clear() -> void { routes_.clear(); }
        };

    } // namespace netdev

} // namespace botlink
