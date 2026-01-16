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

            // =============================================================================
            // IPv4 Address Handling
            // =============================================================================

            [[nodiscard]] auto parse_ipv4(const String &addr) const -> Optional<u32> {
                u32 a = 0, b = 0, c = 0, d = 0;
                if (sscanf(addr.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
                    return Optional<u32>();
                }
                return static_cast<u32>((a << 24) | (b << 16) | (c << 8) | d);
            }

            [[nodiscard]] auto matches_subnet_ipv4(const String &ip, const OverlayAddr &subnet) const -> boolean {
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

            // =============================================================================
            // IPv6 Address Handling
            // =============================================================================

            // IPv6 address stored as 16 bytes (128 bits)
            struct IPv6Addr {
                u8 bytes[16] = {0};

                [[nodiscard]] auto is_zero() const -> boolean {
                    for (usize i = 0; i < 16; ++i) {
                        if (bytes[i] != 0)
                            return false;
                    }
                    return true;
                }
            };

            // Parse IPv6 address string (supports :: shorthand)
            [[nodiscard]] auto parse_ipv6(const String &addr) const -> Optional<IPv6Addr> {
                IPv6Addr result;
                String ip = addr;

                // Find position of :: if present
                auto double_colon = ip.find("::");
                boolean has_double_colon = (double_colon != String::npos);

                // Split into groups
                Vector<u16> left_groups;
                Vector<u16> right_groups;

                usize pos = 0;
                usize colon_pos;
                String group_str;

                if (has_double_colon) {
                    // Parse left side of ::
                    String left_part = ip.substr(0, double_colon);
                    String right_part = (double_colon + 2 < ip.size()) ? ip.substr(double_colon + 2) : "";

                    // Parse left groups
                    pos = 0;
                    while (pos < left_part.size()) {
                        colon_pos = left_part.find(':', pos);
                        if (colon_pos == String::npos) {
                            group_str = left_part.substr(pos);
                            pos = left_part.size();
                        } else {
                            group_str = left_part.substr(pos, colon_pos - pos);
                            pos = colon_pos + 1;
                        }
                        if (!group_str.empty()) {
                            u32 value = 0;
                            if (sscanf(group_str.c_str(), "%x", &value) != 1 || value > 0xFFFF) {
                                return Optional<IPv6Addr>();
                            }
                            left_groups.push_back(static_cast<u16>(value));
                        }
                    }

                    // Parse right groups
                    pos = 0;
                    while (pos < right_part.size()) {
                        colon_pos = right_part.find(':', pos);
                        if (colon_pos == String::npos) {
                            group_str = right_part.substr(pos);
                            pos = right_part.size();
                        } else {
                            group_str = right_part.substr(pos, colon_pos - pos);
                            pos = colon_pos + 1;
                        }
                        if (!group_str.empty()) {
                            u32 value = 0;
                            if (sscanf(group_str.c_str(), "%x", &value) != 1 || value > 0xFFFF) {
                                return Optional<IPv6Addr>();
                            }
                            right_groups.push_back(static_cast<u16>(value));
                        }
                    }

                    // Fill in the address
                    usize left_count = left_groups.size();
                    usize right_count = right_groups.size();
                    usize zero_count = 8 - left_count - right_count;

                    usize idx = 0;
                    for (usize i = 0; i < left_count; ++i) {
                        result.bytes[idx++] = static_cast<u8>(left_groups[i] >> 8);
                        result.bytes[idx++] = static_cast<u8>(left_groups[i] & 0xFF);
                    }
                    for (usize i = 0; i < zero_count; ++i) {
                        result.bytes[idx++] = 0;
                        result.bytes[idx++] = 0;
                    }
                    for (usize i = 0; i < right_count; ++i) {
                        result.bytes[idx++] = static_cast<u8>(right_groups[i] >> 8);
                        result.bytes[idx++] = static_cast<u8>(right_groups[i] & 0xFF);
                    }
                } else {
                    // Parse all 8 groups
                    Vector<u16> groups;
                    pos = 0;
                    while (pos < ip.size()) {
                        colon_pos = ip.find(':', pos);
                        if (colon_pos == String::npos) {
                            group_str = ip.substr(pos);
                            pos = ip.size();
                        } else {
                            group_str = ip.substr(pos, colon_pos - pos);
                            pos = colon_pos + 1;
                        }
                        if (!group_str.empty()) {
                            u32 value = 0;
                            if (sscanf(group_str.c_str(), "%x", &value) != 1 || value > 0xFFFF) {
                                return Optional<IPv6Addr>();
                            }
                            groups.push_back(static_cast<u16>(value));
                        }
                    }

                    if (groups.size() != 8) {
                        return Optional<IPv6Addr>();
                    }

                    for (usize i = 0; i < 8; ++i) {
                        result.bytes[i * 2] = static_cast<u8>(groups[i] >> 8);
                        result.bytes[i * 2 + 1] = static_cast<u8>(groups[i] & 0xFF);
                    }
                }

                return result;
            }

            [[nodiscard]] auto matches_subnet_ipv6(const String &ip, const OverlayAddr &subnet) const -> boolean {
                auto ip_addr = parse_ipv6(ip);
                auto subnet_addr = parse_ipv6(subnet.addr);

                if (!ip_addr.has_value() || !subnet_addr.has_value()) {
                    return false;
                }

                if (subnet.prefix_len == 0) {
                    return true; // Default route
                }

                // Compare prefix_len bits
                u8 prefix = subnet.prefix_len;
                for (usize i = 0; i < 16 && prefix > 0; ++i) {
                    u8 bits_to_compare = (prefix >= 8) ? 8 : prefix;
                    u8 mask = static_cast<u8>(0xFF << (8 - bits_to_compare));

                    if ((ip_addr->bytes[i] & mask) != (subnet_addr->bytes[i] & mask)) {
                        return false;
                    }

                    prefix -= bits_to_compare;
                }

                return true;
            }

            // =============================================================================
            // Unified subnet matching
            // =============================================================================

            [[nodiscard]] auto matches_subnet(const String &ip, const OverlayAddr &subnet) const -> boolean {
                // Detect IP version based on presence of ':' (IPv6) or '.' (IPv4)
                boolean is_ipv6 = (ip.find(':') != String::npos);
                boolean subnet_is_ipv6 = (subnet.addr.find(':') != String::npos);

                // Both must be same version
                if (is_ipv6 != subnet_is_ipv6) {
                    return false;
                }

                if (is_ipv6) {
                    return matches_subnet_ipv6(ip, subnet);
                } else {
                    return matches_subnet_ipv4(ip, subnet);
                }
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
            // Supports both IPv4 and IPv6 packets
            [[nodiscard]] auto lookup_packet(const Vector<u8> &pkt) const -> Optional<RouteEntry> {
                if (pkt.empty()) {
                    return Optional<RouteEntry>();
                }

                // Check IP version
                u8 version = (pkt[0] >> 4) & 0x0F;

                if (version == 4) {
                    // IPv4 packet - need at least 20 bytes for header
                    if (pkt.size() < 20) {
                        return Optional<RouteEntry>();
                    }

                    // Extract destination address (bytes 16-19)
                    u8 a = pkt[16];
                    u8 b = pkt[17];
                    u8 c = pkt[18];
                    u8 d = pkt[19];

                    String dest_ip = to_str(a) + "." + to_str(b) + "." + to_str(c) + "." + to_str(d);
                    return lookup(dest_ip);
                } else if (version == 6) {
                    // IPv6 packet - need at least 40 bytes for header
                    if (pkt.size() < 40) {
                        return Optional<RouteEntry>();
                    }

                    // Extract destination address (bytes 24-39)
                    // Format: 8 groups of 4 hex digits separated by colons
                    String dest_ip;
                    for (usize i = 0; i < 8; ++i) {
                        u16 group = (static_cast<u16>(pkt[24 + i * 2]) << 8) | pkt[24 + i * 2 + 1];
                        char buf[8];
                        snprintf(buf, sizeof(buf), "%x", group);
                        if (i > 0) {
                            dest_ip += ":";
                        }
                        dest_ip += buf;
                    }

                    return lookup(dest_ip);
                }

                return Optional<RouteEntry>(); // Unknown IP version
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
