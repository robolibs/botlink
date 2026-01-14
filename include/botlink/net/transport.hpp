/* SPDX-License-Identifier: MIT */
/*
 * Botlink Transport
 * Thin wrapper around netpipe for UDP transport
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/types.hpp>
#include <botlink/net/endpoint.hpp>
#include <datapod/datapod.hpp>
#include <netpipe/netpipe.hpp>

namespace botlink {

    using namespace dp;

    namespace net {

        // =============================================================================
        // Type Aliases - Use netpipe types directly
        // =============================================================================

        // Message type (same as netpipe)
        using Message = netpipe::Message; // dp::Vector<dp::u8>

        // UDP socket wrapper using netpipe
        using UdpSocket = netpipe::UdpDatagram;

        // UDP endpoint using netpipe
        using UdpEndpoint = netpipe::UdpEndpoint;

        // =============================================================================
        // Constants
        // =============================================================================

        inline constexpr usize MAX_UDP_SIZE = 1400; // Safe MTU

        // =============================================================================
        // Endpoint Conversion Utilities
        // =============================================================================

        // Convert botlink::Endpoint to netpipe::UdpEndpoint
        [[nodiscard]] inline auto to_udp_endpoint(const Endpoint &ep) -> UdpEndpoint {
            char buf[64];
            if (ep.is_ipv4()) {
                snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ep.ipv4.octets[0], ep.ipv4.octets[1], ep.ipv4.octets[2],
                         ep.ipv4.octets[3]);
                return UdpEndpoint{String(buf), ep.port};
            } else {
                // Format IPv6 address (without brackets for the host string)
                return UdpEndpoint{format_ipv6_addr(ep.ipv6), ep.port};
            }
        }

        // Convert netpipe::UdpEndpoint to botlink::Endpoint
        [[nodiscard]] inline auto from_udp_endpoint(const UdpEndpoint &ep) -> Endpoint {
            Endpoint result;
            result.port = ep.port;

            // Try to parse as IPv4 first
            u32 a = 0, b = 0, c = 0, d = 0;
            if (sscanf(ep.host.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                result.family = AddrFamily::IPv4;
                result.ipv4.octets[0] = static_cast<u8>(a);
                result.ipv4.octets[1] = static_cast<u8>(b);
                result.ipv4.octets[2] = static_cast<u8>(c);
                result.ipv4.octets[3] = static_cast<u8>(d);
            } else {
                // Try IPv6 (handle both with and without brackets)
                String host = ep.host;
                if (!host.empty() && host[0] == '[') {
                    // Strip brackets
                    usize end = host.find(']');
                    if (end != String::npos) {
                        host = host.substr(1, end - 1);
                    }
                }
                auto ipv6_res = parse_ipv6_addr(host);
                if (ipv6_res.is_ok()) {
                    result.family = AddrFamily::IPv6;
                    result.ipv6 = ipv6_res.value();
                } else {
                    // Default to IPv6 with zero address on parse failure
                    result.family = AddrFamily::IPv6;
                }
            }

            return result;
        }

        // =============================================================================
        // Helper Functions
        // =============================================================================

        // Parse endpoint from string "ip:port" or "[ipv6]:port"
        [[nodiscard]] inline auto parse_endpoint_str(const char *str) -> Res<Endpoint> {
            String s(str);

            // Check for IPv6 bracket format [addr]:port
            if (!s.empty() && s[0] == '[') {
                usize bracket_end = s.find(']');
                if (bracket_end == String::npos) {
                    return result::err(err::invalid("Invalid IPv6 endpoint: missing ]"));
                }

                String addr_str = s.substr(1, bracket_end - 1);
                u16 port = DEFAULT_PORT;

                if (bracket_end + 1 < s.size() && s[bracket_end + 1] == ':') {
                    String port_str = s.substr(bracket_end + 2);
                    auto port_res = parse_port(port_str);
                    if (port_res.is_err()) {
                        return result::err(port_res.error());
                    }
                    port = port_res.value();
                }

                auto ipv6_res = parse_ipv6_addr(addr_str);
                if (ipv6_res.is_err()) {
                    return result::err(ipv6_res.error());
                }

                return result::ok(Endpoint(ipv6_res.value(), port));
            }

            // IPv4 format: ip:port
            // Find the colon separating IP and port (for IPv4, only one colon expected)
            usize colon_pos = s.rfind(':');
            if (colon_pos == String::npos) {
                return result::err(err::invalid("Invalid endpoint format (missing port)"));
            }

            // Extract IP and port parts
            String ip_part = s.substr(0, colon_pos);
            String port_part = s.substr(colon_pos + 1);

            // Parse and validate port
            auto port_res = parse_port(port_part);
            if (port_res.is_err()) {
                return result::err(port_res.error());
            }

            Endpoint ep;
            ep.port = port_res.value();

            // Parse IPv4
            u32 a = 0, b = 0, c = 0, d = 0;
            if (sscanf(ip_part.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                ep.family = AddrFamily::IPv4;
                ep.ipv4.octets[0] = static_cast<u8>(a);
                ep.ipv4.octets[1] = static_cast<u8>(b);
                ep.ipv4.octets[2] = static_cast<u8>(c);
                ep.ipv4.octets[3] = static_cast<u8>(d);
                return result::ok(ep);
            }

            // Maybe it's an IPv6 without brackets (less common but possible)
            auto ipv6_res = parse_ipv6_addr(ip_part);
            if (ipv6_res.is_ok()) {
                return result::ok(Endpoint(ipv6_res.value(), port_res.value()));
            }

            return result::err(err::invalid("Invalid IP address"));
        }

        // Format endpoint to string
        [[nodiscard]] inline auto format_endpoint(const Endpoint &ep) -> String {
            char buf[80];

            if (ep.is_ipv4()) {
                snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u", ep.ipv4.octets[0], ep.ipv4.octets[1], ep.ipv4.octets[2],
                         ep.ipv4.octets[3], ep.port);
                return String(buf);
            } else {
                // Format IPv6 with brackets: [addr]:port
                String ipv6_str = format_ipv6_addr(ep.ipv6);
                snprintf(buf, sizeof(buf), "[%s]:%u", ipv6_str.c_str(), ep.port);
                return String(buf);
            }
        }

        // Format as URI (udp://ip:port)
        [[nodiscard]] inline auto format_uri(const char *scheme, const Endpoint &ep) -> String {
            String result = String(scheme) + "://";
            result += format_endpoint(ep);
            return result;
        }

    } // namespace net

} // namespace botlink
