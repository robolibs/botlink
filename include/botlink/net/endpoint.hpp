/* SPDX-License-Identifier: MIT */
/*
 * Botlink Endpoint
 * UDP endpoint parsing and formatting (udp://ip:port)
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/types.hpp>
#include <datapod/datapod.hpp>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

namespace botlink {

    using namespace dp;

    namespace net {

        // =============================================================================
        // Port Validation
        // =============================================================================

        // Validate port string and return port number
        // Returns error on invalid input, empty string, or zero port
        [[nodiscard]] inline auto parse_port(const String &port_str) -> Res<u16> {
            if (port_str.empty()) {
                return result::err(err::invalid("Empty port string"));
            }

            u32 port = 0;
            for (usize i = 0; i < port_str.size(); ++i) {
                char c = port_str[i];
                if (c < '0' || c > '9') {
                    return result::err(err::invalid("Invalid character in port number"));
                }
                port = port * 10 + static_cast<u32>(c - '0');
                if (port > 65535) {
                    return result::err(err::invalid("Port number out of range"));
                }
            }

            if (port == 0) {
                return result::err(err::invalid("Port 0 is not allowed"));
            }

            return result::ok(static_cast<u16>(port));
        }

        // =============================================================================
        // IPv6 Parsing and Formatting
        // =============================================================================

        // Parse a single IPv6 hex group (0-FFFF)
        [[nodiscard]] inline auto parse_ipv6_group(const String &str, usize start, usize end) -> Res<u16> {
            if (end <= start || end - start > 4) {
                return result::err(err::invalid("Invalid IPv6 group length"));
            }

            u16 value = 0;
            for (usize i = start; i < end; ++i) {
                char c = str[i];
                u16 digit = 0;
                if (c >= '0' && c <= '9') {
                    digit = static_cast<u16>(c - '0');
                } else if (c >= 'a' && c <= 'f') {
                    digit = static_cast<u16>(c - 'a' + 10);
                } else if (c >= 'A' && c <= 'F') {
                    digit = static_cast<u16>(c - 'A' + 10);
                } else {
                    return result::err(err::invalid("Invalid hex character in IPv6 address"));
                }
                value = static_cast<u16>((value << 4) | digit);
            }
            return result::ok(value);
        }

        // Parse IPv6 address string like "2001:db8::1" or "::1" or "::"
        [[nodiscard]] inline auto parse_ipv6_addr(const String &addr_str) -> Res<IPv6Addr> {
            IPv6Addr addr{};

            if (addr_str.empty()) {
                return result::err(err::invalid("Empty IPv6 address"));
            }

            // Find :: position (if any)
            isize double_colon_pos = -1;
            for (usize i = 0; i + 1 < addr_str.size(); ++i) {
                if (addr_str[i] == ':' && addr_str[i + 1] == ':') {
                    if (double_colon_pos >= 0) {
                        return result::err(err::invalid("Multiple :: in IPv6 address"));
                    }
                    double_colon_pos = static_cast<isize>(i);
                }
            }

            // Split into groups
            Vector<u16> left_groups;
            Vector<u16> right_groups;

            if (double_colon_pos < 0) {
                // No ::, must have exactly 8 groups
                usize start = 0;
                for (usize i = 0; i <= addr_str.size(); ++i) {
                    if (i == addr_str.size() || addr_str[i] == ':') {
                        if (i > start) {
                            auto group_res = parse_ipv6_group(addr_str, start, i);
                            if (group_res.is_err()) {
                                return result::err(group_res.error());
                            }
                            left_groups.push_back(group_res.value());
                        } else if (i > 0 && i < addr_str.size()) {
                            // Empty group without :: is invalid
                            return result::err(err::invalid("Empty group in IPv6 address"));
                        }
                        start = i + 1;
                    }
                }

                if (left_groups.size() != 8) {
                    return result::err(err::invalid("IPv6 address must have 8 groups without ::"));
                }
            } else {
                // Has :: - parse left and right parts
                String left_part = addr_str.substr(0, static_cast<usize>(double_colon_pos));
                String right_part = addr_str.substr(static_cast<usize>(double_colon_pos) + 2);

                // Parse left part
                if (!left_part.empty()) {
                    usize start = 0;
                    for (usize i = 0; i <= left_part.size(); ++i) {
                        if (i == left_part.size() || left_part[i] == ':') {
                            if (i > start) {
                                auto group_res = parse_ipv6_group(left_part, start, i);
                                if (group_res.is_err()) {
                                    return result::err(group_res.error());
                                }
                                left_groups.push_back(group_res.value());
                            }
                            start = i + 1;
                        }
                    }
                }

                // Parse right part
                if (!right_part.empty()) {
                    usize start = 0;
                    for (usize i = 0; i <= right_part.size(); ++i) {
                        if (i == right_part.size() || right_part[i] == ':') {
                            if (i > start) {
                                auto group_res = parse_ipv6_group(right_part, start, i);
                                if (group_res.is_err()) {
                                    return result::err(group_res.error());
                                }
                                right_groups.push_back(group_res.value());
                            }
                            start = i + 1;
                        }
                    }
                }

                if (left_groups.size() + right_groups.size() > 7) {
                    return result::err(err::invalid("Too many groups in IPv6 address with ::"));
                }
            }

            // Fill in the address
            usize pos = 0;

            // Left groups
            for (const auto &group : left_groups) {
                if (pos >= 16) {
                    return result::err(err::invalid("IPv6 address overflow"));
                }
                addr.octets[pos++] = static_cast<u8>((group >> 8) & 0xFF);
                addr.octets[pos++] = static_cast<u8>(group & 0xFF);
            }

            // Zero fill for ::
            if (double_colon_pos >= 0) {
                usize zeros_needed = 8 - left_groups.size() - right_groups.size();
                for (usize i = 0; i < zeros_needed; ++i) {
                    addr.octets[pos++] = 0;
                    addr.octets[pos++] = 0;
                }
            }

            // Right groups
            for (const auto &group : right_groups) {
                if (pos >= 16) {
                    return result::err(err::invalid("IPv6 address overflow"));
                }
                addr.octets[pos++] = static_cast<u8>((group >> 8) & 0xFF);
                addr.octets[pos++] = static_cast<u8>(group & 0xFF);
            }

            return result::ok(addr);
        }

        // Format IPv6 address with :: compression
        [[nodiscard]] inline auto format_ipv6_addr(const IPv6Addr &addr) -> String {
            // Find longest run of zero groups for :: compression
            i32 best_start = -1;
            i32 best_len = 0;
            i32 curr_start = -1;
            i32 curr_len = 0;

            for (i32 i = 0; i < 8; ++i) {
                u16 group = static_cast<u16>((static_cast<u16>(addr.octets[i * 2]) << 8) | addr.octets[i * 2 + 1]);
                if (group == 0) {
                    if (curr_start < 0) {
                        curr_start = i;
                        curr_len = 1;
                    } else {
                        ++curr_len;
                    }
                } else {
                    if (curr_len > best_len && curr_len > 1) {
                        best_start = curr_start;
                        best_len = curr_len;
                    }
                    curr_start = -1;
                    curr_len = 0;
                }
            }
            if (curr_len > best_len && curr_len > 1) {
                best_start = curr_start;
                best_len = curr_len;
            }

            // Build string
            String result;
            char buf[8];

            for (i32 i = 0; i < 8; ++i) {
                if (best_start >= 0 && i == best_start) {
                    result += "::";
                    i += best_len - 1;
                    continue;
                }

                if (i > 0 && !(best_start >= 0 && i == best_start + best_len)) {
                    result += ":";
                }

                u16 group = static_cast<u16>((static_cast<u16>(addr.octets[i * 2]) << 8) | addr.octets[i * 2 + 1]);
                snprintf(buf, sizeof(buf), "%x", group);
                result += buf;
            }

            // Handle all-zeros case
            if (result.empty() || result == "::0") {
                result = "::";
            }

            return result;
        }

        // =============================================================================
        // URI Scheme
        // =============================================================================

        enum class Scheme : u8 {
            UDP = 0,
            TCP = 1, // Future
        };

        [[nodiscard]] inline auto scheme_to_string(Scheme s) -> const char * {
            switch (s) {
            case Scheme::UDP:
                return "udp";
            case Scheme::TCP:
                return "tcp";
            default:
                return "unknown";
            }
        }

        // =============================================================================
        // Parsed URI - udp://host:port or tcp://host:port
        // =============================================================================

        struct ParsedUri {
            Scheme scheme = Scheme::UDP;
            String host;
            u16 port = 0;
            boolean is_ipv6 = false;

            ParsedUri() = default;

            auto members() noexcept { return std::tie(scheme, host, port, is_ipv6); }
            auto members() const noexcept { return std::tie(scheme, host, port, is_ipv6); }
        };

        // =============================================================================
        // Parsing Functions
        // =============================================================================

        // Parse URI string like "udp://192.168.1.1:51820" or "udp://[::1]:51820"
        [[nodiscard]] inline auto parse_uri(const String &uri) -> Res<ParsedUri> {
            ParsedUri result;

            // Find scheme separator
            usize scheme_end = 0;
            for (usize i = 0; i < uri.size(); ++i) {
                if (uri[i] == ':' && i + 2 < uri.size() && uri[i + 1] == '/' && uri[i + 2] == '/') {
                    scheme_end = i;
                    break;
                }
            }

            if (scheme_end == 0) {
                return result::err(err::invalid("Invalid URI: missing scheme"));
            }

            // Parse scheme
            String scheme_str = uri.substr(0, scheme_end);
            if (scheme_str == "udp" || scheme_str == "UDP") {
                result.scheme = Scheme::UDP;
            } else if (scheme_str == "tcp" || scheme_str == "TCP") {
                result.scheme = Scheme::TCP;
            } else {
                return result::err(err::invalid("Invalid URI: unknown scheme"));
            }

            // Skip "://"
            usize host_start = scheme_end + 3;
            if (host_start >= uri.size()) {
                return result::err(err::invalid("Invalid URI: missing host"));
            }

            // Check for IPv6 (starts with [)
            if (uri[host_start] == '[') {
                result.is_ipv6 = true;
                // Find closing bracket
                usize bracket_end = host_start + 1;
                while (bracket_end < uri.size() && uri[bracket_end] != ']') {
                    ++bracket_end;
                }
                if (bracket_end >= uri.size()) {
                    return result::err(err::invalid("Invalid URI: missing ] for IPv6"));
                }

                result.host = uri.substr(host_start + 1, bracket_end - host_start - 1);

                // Find port after ]
                if (bracket_end + 1 < uri.size() && uri[bracket_end + 1] == ':') {
                    String port_str = uri.substr(bracket_end + 2);
                    auto port_res = parse_port(port_str);
                    if (port_res.is_err()) {
                        return result::err(port_res.error());
                    }
                    result.port = port_res.value();
                } else {
                    result.port = DEFAULT_PORT;
                }
            } else {
                // IPv4 or hostname
                result.is_ipv6 = false;
                usize port_sep = uri.size();
                for (usize i = host_start; i < uri.size(); ++i) {
                    if (uri[i] == ':') {
                        port_sep = i;
                        break;
                    }
                }

                result.host = uri.substr(host_start, port_sep - host_start);

                if (port_sep < uri.size() - 1) {
                    String port_str = uri.substr(port_sep + 1);
                    auto port_res = parse_port(port_str);
                    if (port_res.is_err()) {
                        return result::err(port_res.error());
                    }
                    result.port = port_res.value();
                } else {
                    result.port = DEFAULT_PORT;
                }
            }

            return result::ok(result);
        }

        // =============================================================================
        // DNS Resolution (supports both IPv4 and IPv6)
        // =============================================================================

        // Resolve hostname to endpoint using getaddrinfo (supports IPv4 and IPv6)
        [[nodiscard]] inline auto resolve_hostname(const String &hostname, u16 port) -> Res<Endpoint> {
            struct addrinfo hints {};
            hints.ai_family = AF_UNSPEC;     // Allow both IPv4 and IPv6
            hints.ai_socktype = SOCK_DGRAM;  // UDP
            hints.ai_flags = AI_ADDRCONFIG;  // Only return addresses we can use

            char port_str[16];
            snprintf(port_str, sizeof(port_str), "%u", port);

            struct addrinfo *result = nullptr;
            int ret = getaddrinfo(hostname.c_str(), port_str, &hints, &result);
            if (ret != 0) {
                return result::err(err::network(gai_strerror(ret)));
            }

            if (result == nullptr) {
                return result::err(err::network("DNS resolution returned no results"));
            }

            Endpoint ep;

            // Use first result (prefer IPv6 if available)
            struct addrinfo *addr = result;
            while (addr != nullptr) {
                if (addr->ai_family == AF_INET6) {
                    // IPv6 address
                    auto *sin6 = reinterpret_cast<struct sockaddr_in6 *>(addr->ai_addr);
                    ep.family = AddrFamily::IPv6;
                    ep.port = port;
                    for (usize i = 0; i < 16; ++i) {
                        ep.ipv6.octets[i] = sin6->sin6_addr.s6_addr[i];
                    }
                    freeaddrinfo(result);
                    return result::ok(ep);
                }
                addr = addr->ai_next;
            }

            // Fall back to IPv4
            addr = result;
            if (addr->ai_family == AF_INET) {
                auto *sin = reinterpret_cast<struct sockaddr_in *>(addr->ai_addr);
                ep.family = AddrFamily::IPv4;
                ep.port = port;
                u32 ip_addr = ntohl(sin->sin_addr.s_addr);
                ep.ipv4.octets[0] = static_cast<u8>((ip_addr >> 24) & 0xFF);
                ep.ipv4.octets[1] = static_cast<u8>((ip_addr >> 16) & 0xFF);
                ep.ipv4.octets[2] = static_cast<u8>((ip_addr >> 8) & 0xFF);
                ep.ipv4.octets[3] = static_cast<u8>(ip_addr & 0xFF);
                freeaddrinfo(result);
                return result::ok(ep);
            }

            freeaddrinfo(result);
            return result::err(err::network("DNS resolution returned unsupported address family"));
        }

        // Check if a string looks like an IP address (not a hostname)
        [[nodiscard]] inline auto looks_like_ip_address(const String &str) -> boolean {
            if (str.empty()) {
                return false;
            }

            // IPv6 check: contains colons
            for (usize i = 0; i < str.size(); ++i) {
                if (str[i] == ':') {
                    return true; // Has colons, likely IPv6
                }
            }

            // IPv4 check: all digits and dots
            boolean has_dot = false;
            for (usize i = 0; i < str.size(); ++i) {
                char c = str[i];
                if (c == '.') {
                    has_dot = true;
                } else if (c < '0' || c > '9') {
                    return false; // Has non-digit/non-dot, it's a hostname
                }
            }

            return has_dot; // If all digits/dots and has at least one dot, it's IPv4
        }

        // =============================================================================
        // Endpoint Parsing
        // =============================================================================

        // Parse endpoint string "192.168.1.1:51820" or "[::1]:8080" or "hostname:port"
        [[nodiscard]] inline auto parse_endpoint(const String &str) -> Res<Endpoint> {
            // Check if it looks like a URI
            boolean has_scheme = false;
            for (usize i = 0; i < str.size() && i < 10; ++i) {
                if (str[i] == ':' && i + 2 < str.size() && str[i + 1] == '/' && str[i + 2] == '/') {
                    has_scheme = true;
                    break;
                }
            }

            if (has_scheme) {
                auto uri_res = parse_uri(str);
                if (uri_res.is_err()) {
                    return result::err(uri_res.error());
                }

                // Convert to endpoint - handle IPv6, IPv4, and hostnames
                if (uri_res.value().is_ipv6) {
                    // Parse IPv6 literal
                    auto ipv6_res = parse_ipv6_addr(uri_res.value().host);
                    if (ipv6_res.is_err()) {
                        return result::err(ipv6_res.error());
                    }
                    return result::ok(Endpoint(ipv6_res.value(), uri_res.value().port));
                } else if (looks_like_ip_address(uri_res.value().host)) {
                    // Parse IPv4 literal
                    std::string host_str(uri_res.value().host.c_str());
                    u32 a = 0, b = 0, c = 0, d = 0;
                    if (sscanf(host_str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
                        return result::err(err::invalid("Invalid IPv4 address"));
                    }
                    return result::ok(Endpoint(
                        IPv4Addr(static_cast<u8>(a), static_cast<u8>(b), static_cast<u8>(c), static_cast<u8>(d)),
                        uri_res.value().port));
                } else {
                    // DNS resolution for hostname (supports IPv4 and IPv6)
                    return resolve_hostname(uri_res.value().host, uri_res.value().port);
                }
            }

            // Direct endpoint format: "192.168.1.1:51820" or "[::1]:8080"
            if (!str.empty() && str[0] == '[') {
                // IPv6
                usize bracket_end = 1;
                while (bracket_end < str.size() && str[bracket_end] != ']') {
                    ++bracket_end;
                }
                if (bracket_end >= str.size()) {
                    return result::err(err::invalid("Invalid IPv6 endpoint: missing ]"));
                }

                String addr_str = str.substr(1, bracket_end - 1);

                // Require explicit port for direct endpoint format
                if (bracket_end + 1 >= str.size() || str[bracket_end + 1] != ':') {
                    return result::err(err::invalid("Invalid IPv6 endpoint: missing port"));
                }

                String port_str = str.substr(bracket_end + 2);
                auto port_res = parse_port(port_str);
                if (port_res.is_err()) {
                    return result::err(port_res.error());
                }

                // Parse IPv6 address
                auto ipv6_res = parse_ipv6_addr(addr_str);
                if (ipv6_res.is_err()) {
                    return result::err(ipv6_res.error());
                }
                return result::ok(Endpoint(ipv6_res.value(), port_res.value()));
            } else {
                // IPv4 or hostname - require explicit port for direct endpoint format
                usize port_sep = str.size();
                for (usize i = 0; i < str.size(); ++i) {
                    if (str[i] == ':') {
                        port_sep = i;
                        break;
                    }
                }

                // Require port separator for direct endpoint format
                if (port_sep == str.size()) {
                    return result::err(err::invalid("Invalid endpoint format (missing port)"));
                }

                String addr_str = str.substr(0, port_sep);
                String port_str = str.substr(port_sep + 1);

                auto port_res = parse_port(port_str);
                if (port_res.is_err()) {
                    return result::err(port_res.error());
                }

                // Check if it's an IP address or hostname
                if (looks_like_ip_address(addr_str)) {
                    // Parse IPv4 literal
                    u32 a = 0, b = 0, c = 0, d = 0;
                    if (sscanf(addr_str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
                        return result::err(err::invalid("Invalid IPv4 address"));
                    }
                    return result::ok(
                        Endpoint(IPv4Addr(static_cast<u8>(a), static_cast<u8>(b), static_cast<u8>(c), static_cast<u8>(d)),
                                 port_res.value()));
                } else {
                    // DNS resolution for hostname (supports IPv4 and IPv6)
                    return resolve_hostname(addr_str, port_res.value());
                }
            }
        }

        // =============================================================================
        // Formatting Functions
        // =============================================================================

        // Note: format_endpoint and format_uri are defined in transport.hpp

        // =============================================================================
        // Endpoint List Parsing
        // =============================================================================

        // Parse comma-separated list of endpoints
        [[nodiscard]] inline auto parse_endpoint_list(const String &list) -> Res<Vector<Endpoint>> {
            Vector<Endpoint> result;

            usize start = 0;
            for (usize i = 0; i <= list.size(); ++i) {
                if (i == list.size() || list[i] == ',') {
                    if (i > start) {
                        String ep_str = list.substr(start, i - start);
                        // Trim whitespace
                        usize trim_start = 0;
                        usize trim_end = ep_str.size();
                        while (trim_start < trim_end && (ep_str[trim_start] == ' ' || ep_str[trim_start] == '\t')) {
                            ++trim_start;
                        }
                        while (trim_end > trim_start && (ep_str[trim_end - 1] == ' ' || ep_str[trim_end - 1] == '\t')) {
                            --trim_end;
                        }
                        if (trim_end > trim_start) {
                            String trimmed = ep_str.substr(trim_start, trim_end - trim_start);
                            auto ep_res = parse_endpoint(trimmed);
                            if (ep_res.is_ok()) {
                                result.push_back(ep_res.value());
                            }
                        }
                    }
                    start = i + 1;
                }
            }

            return result::ok(result);
        }

    } // namespace net

} // namespace botlink
