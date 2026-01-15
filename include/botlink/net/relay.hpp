/* SPDX-License-Identifier: MIT */
/*
 * Botlink Relay
 * Relay routing and selection logic for NAT traversal
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/time.hpp>
#include <botlink/core/types.hpp>
#include <botlink/net/endpoint.hpp>
#include <botlink/net/transport.hpp>
#include <datapod/datapod.hpp>
#include <echo/echo.hpp>

namespace botlink {

    using namespace dp;

    namespace net {

        // =============================================================================
        // Relay Message Types
        // =============================================================================

        enum class RelayMsgType : u8 {
            RelayConnect = 0x10,
            RelayDisconnect = 0x11,
            RelayForward = 0x12,
            RelayAck = 0x13,
            RelayError = 0x14,
        };

        // =============================================================================
        // Relay Info - Information about a relay server
        // =============================================================================

        struct RelayInfo {
            String id;
            Endpoint endpoint;
            PublicKey pubkey;
            u64 last_seen_ms = 0;
            u64 latency_ms = 0;
            boolean is_connected = false;
            u32 current_load = 0; // Optional: number of active connections

            RelayInfo() = default;

            [[nodiscard]] auto is_stale(u64 max_age_ms) const -> boolean {
                return (time::now_ms() - last_seen_ms) > max_age_ms;
            }

            auto members() noexcept {
                return std::tie(id, endpoint, pubkey, last_seen_ms, latency_ms, is_connected, current_load);
            }
            auto members() const noexcept {
                return std::tie(id, endpoint, pubkey, last_seen_ms, latency_ms, is_connected, current_load);
            }
        };

        // =============================================================================
        // Relay Connect Request - Ask relay to forward traffic to/from peer
        // =============================================================================

        struct RelayConnectRequest {
            NodeId requester_id;
            NodeId target_peer_id;
            u64 timestamp_ms = 0;

            RelayConnectRequest() = default;

            auto members() noexcept { return std::tie(requester_id, target_peer_id, timestamp_ms); }
            auto members() const noexcept { return std::tie(requester_id, target_peer_id, timestamp_ms); }
        };

        // =============================================================================
        // Relay Forward Packet - Wrapper for relayed data
        // =============================================================================

        struct RelayForwardPacket {
            NodeId source_id;
            NodeId target_id;
            Vector<u8> payload; // Encrypted data (opaque to relay)
            u64 timestamp_ms = 0;

            RelayForwardPacket() = default;

            auto members() noexcept { return std::tie(source_id, target_id, payload, timestamp_ms); }
            auto members() const noexcept { return std::tie(source_id, target_id, payload, timestamp_ms); }
        };

        // =============================================================================
        // Relay Route - A path through a relay to reach a peer
        // =============================================================================

        struct RelayRoute {
            NodeId peer_id;
            String relay_id;
            Endpoint relay_endpoint;
            u64 established_at_ms = 0;
            u64 last_used_ms = 0;
            boolean is_active = false;

            RelayRoute() = default;

            [[nodiscard]] auto age_ms() const -> u64 { return time::now_ms() - established_at_ms; }

            auto members() noexcept {
                return std::tie(peer_id, relay_id, relay_endpoint, established_at_ms, last_used_ms, is_active);
            }
            auto members() const noexcept {
                return std::tie(peer_id, relay_id, relay_endpoint, established_at_ms, last_used_ms, is_active);
            }
        };

        // =============================================================================
        // Relay Manager - Manages relay connections and routing
        // =============================================================================

        class RelayManager {
          private:
            NodeId local_node_id_;
            Vector<RelayInfo> relays_;
            Vector<String> preferred_relays_;
            Vector<String> allowed_relays_;
            Map<NodeId, RelayRoute> relay_routes_; // Peer -> relay route
            UdpSocket *socket_;
            u64 relay_timeout_ms_ = 30000;

          public:
            explicit RelayManager(const NodeId &local_id, UdpSocket *socket)
                : local_node_id_(local_id), socket_(socket) {}

            // =============================================================================
            // Configuration
            // =============================================================================

            auto add_relay(const RelayInfo &relay) -> void { relays_.push_back(relay); }

            auto set_preferred_relays(const Vector<String> &relays) -> void { preferred_relays_ = relays; }

            auto set_allowed_relays(const Vector<String> &relays) -> void { allowed_relays_ = relays; }

            // =============================================================================
            // Relay Selection
            // =============================================================================

            // Select best relay for a peer
            [[nodiscard]] auto select_relay() -> Optional<RelayInfo> {
                // First try preferred relays
                for (const auto &pref_id : preferred_relays_) {
                    for (const auto &relay : relays_) {
                        if (relay.id == pref_id && !relay.is_stale(relay_timeout_ms_)) {
                            return relay;
                        }
                    }
                }

                // Fall back to any allowed relay with lowest latency
                Optional<RelayInfo> best;
                for (const auto &relay : relays_) {
                    if (relay.is_stale(relay_timeout_ms_)) {
                        continue;
                    }

                    // Check if allowed
                    if (!allowed_relays_.empty()) {
                        boolean allowed = false;
                        for (const auto &allowed_id : allowed_relays_) {
                            if (relay.id == allowed_id) {
                                allowed = true;
                                break;
                            }
                        }
                        if (!allowed) {
                            continue;
                        }
                    }

                    if (!best.has_value() || relay.latency_ms < best->latency_ms) {
                        best = relay;
                    }
                }

                return best;
            }

            // =============================================================================
            // Relay Connection
            // =============================================================================

            // Request relay connection to a peer
            auto request_relay_route(const NodeId &peer_id) -> VoidRes {
                auto relay = select_relay();
                if (!relay.has_value()) {
                    return result::err(err::not_found("No available relay"));
                }

                // Create connect request
                RelayConnectRequest req;
                req.requester_id = local_node_id_;
                req.target_peer_id = peer_id;
                req.timestamp_ms = time::now_ms();

                auto buf = dp::serialize<dp::Mode::WITH_VERSION>(req);
                Vector<u8> payload;
                payload.push_back(static_cast<u8>(RelayMsgType::RelayConnect));
                for (const auto &b : buf) {
                    payload.push_back(b);
                }

                auto res = socket_->send_to(payload, to_udp_endpoint(relay->endpoint));
                if (res.is_err()) {
                    return result::err(err::io("Failed to send relay connect request"));
                }

                // Create pending relay route
                RelayRoute route;
                route.peer_id = peer_id;
                route.relay_id = relay->id;
                route.relay_endpoint = relay->endpoint;
                route.established_at_ms = time::now_ms();
                route.is_active = false; // Not active until ACK received

                relay_routes_[peer_id] = route;

                echo::info("RelayManager: Requested relay route to peer");
                return result::ok();
            }

            // Handle relay ACK
            auto handle_relay_ack(const NodeId &peer_id) -> VoidRes {
                auto it = relay_routes_.find(peer_id);
                if (it == relay_routes_.end()) {
                    return result::err(err::not_found("No pending relay route"));
                }

                it->second.is_active = true;
                it->second.last_used_ms = time::now_ms();

                echo::info("RelayManager: Relay route established");
                return result::ok();
            }

            // =============================================================================
            // Data Forwarding
            // =============================================================================

            // Send data through relay
            auto send_via_relay(const NodeId &peer_id, const Vector<u8> &data) -> VoidRes {
                auto it = relay_routes_.find(peer_id);
                if (it == relay_routes_.end() || !it->second.is_active) {
                    return result::err(err::invalid("No active relay route to peer"));
                }

                // Create forward packet
                RelayForwardPacket fwd;
                fwd.source_id = local_node_id_;
                fwd.target_id = peer_id;
                fwd.payload = data;
                fwd.timestamp_ms = time::now_ms();

                auto buf = dp::serialize<dp::Mode::WITH_VERSION>(fwd);
                Vector<u8> payload;
                payload.push_back(static_cast<u8>(RelayMsgType::RelayForward));
                for (const auto &b : buf) {
                    payload.push_back(b);
                }

                it->second.last_used_ms = time::now_ms();

                auto send_res = socket_->send_to(payload, to_udp_endpoint(it->second.relay_endpoint));
                if (send_res.is_err()) {
                    return result::err(err::io("Failed to send via relay"));
                }
                return result::ok();
            }

            // Handle incoming relayed packet
            auto handle_relay_forward(const Vector<u8> &data) -> Res<RelayForwardPacket> {
                if (data.size() < 2) {
                    return result::err(err::invalid("Data too short"));
                }

                auto fwd_res = serial::deserialize<RelayForwardPacket>(data, 1);
                if (fwd_res.is_err()) {
                    return result::err(fwd_res.error());
                }

                const auto &fwd = fwd_res.value();

                // Verify we are the target
                if (fwd.target_id != local_node_id_) {
                    return result::err(err::invalid("Not the target of this forwarded packet"));
                }

                return result::ok(fwd);
            }

            // =============================================================================
            // Message Handling
            // =============================================================================

            // Handle incoming relay messages (client side)
            auto handle_message(const Vector<u8> &data, const Endpoint & /*sender_ep*/) -> VoidRes {
                if (data.empty()) {
                    return result::err(err::invalid("Empty message"));
                }

                auto msg_type = static_cast<RelayMsgType>(data[0]);

                switch (msg_type) {
                case RelayMsgType::RelayAck: {
                    // Find which route this ACK is for
                    for (auto &[peer_id, route] : relay_routes_) {
                        if (!route.is_active) {
                            route.is_active = true;
                            route.last_used_ms = time::now_ms();
                            echo::info("RelayManager: Relay route activated");
                            return result::ok();
                        }
                    }
                    return result::ok();
                }
                case RelayMsgType::RelayForward: {
                    auto fwd_res = handle_relay_forward(data);
                    if (fwd_res.is_err()) {
                        return result::err(fwd_res.error());
                    }
                    // The actual payload needs to be processed by the caller
                    return result::ok();
                }
                default:
                    return result::err(err::invalid("Unknown relay message type"));
                }
            }

            // =============================================================================
            // Query
            // =============================================================================

            [[nodiscard]] auto has_relay_route(const NodeId &peer_id) const -> boolean {
                auto it = relay_routes_.find(peer_id);
                return it != relay_routes_.end() && it->second.is_active;
            }

            [[nodiscard]] auto get_relay_route(const NodeId &peer_id) const -> Optional<RelayRoute> {
                auto it = relay_routes_.find(peer_id);
                if (it == relay_routes_.end()) {
                    return Optional<RelayRoute>();
                }
                return it->second;
            }

            [[nodiscard]] auto get_relays() const -> const Vector<RelayInfo> & { return relays_; }

            // =============================================================================
            // Maintenance
            // =============================================================================

            // Cleanup stale relay routes
            auto cleanup_stale_routes(u64 max_idle_ms) -> Vector<NodeId> {
                Vector<NodeId> removed;
                u64 now = time::now_ms();

                for (const auto &[peer_id, route] : relay_routes_) {
                    if ((now - route.last_used_ms) > max_idle_ms) {
                        removed.push_back(peer_id);
                    }
                }

                for (const auto &id : removed) {
                    relay_routes_.erase(id);
                }

                return removed;
            }

            // Remove relay route
            auto remove_relay_route(const NodeId &peer_id) -> void { relay_routes_.erase(peer_id); }

            // Update relay latency/status
            auto update_relay(const String &relay_id, u64 latency_ms, boolean connected) -> void {
                for (auto &relay : relays_) {
                    if (relay.id == relay_id) {
                        relay.latency_ms = latency_ms;
                        relay.is_connected = connected;
                        relay.last_seen_ms = time::now_ms();
                        break;
                    }
                }
            }
        };

        // =============================================================================
        // Relay Server - For running a relay node (non-member)
        // =============================================================================

        class RelayServer {
          private:
            String relay_id_;
            UdpSocket *socket_;
            Map<NodeId, Endpoint> client_endpoints_;  // Node -> their endpoint
            Map<NodeId, Vector<NodeId>> connections_; // Node -> nodes they want to reach

          public:
            explicit RelayServer(const String &relay_id, UdpSocket *socket) : relay_id_(relay_id), socket_(socket) {}

            // Handle incoming relay messages
            auto handle_message(const Vector<u8> &data, const Endpoint &sender_ep) -> VoidRes {
                if (data.empty()) {
                    return result::err(err::invalid("Empty message"));
                }

                auto msg_type = static_cast<RelayMsgType>(data[0]);

                switch (msg_type) {
                case RelayMsgType::RelayConnect:
                    return handle_connect(data, sender_ep);
                case RelayMsgType::RelayDisconnect:
                    return handle_disconnect(data, sender_ep);
                case RelayMsgType::RelayForward:
                    return handle_forward(data, sender_ep);
                default:
                    return result::err(err::invalid("Unknown relay message type"));
                }
            }

          private:
            auto handle_connect(const Vector<u8> &data, const Endpoint &sender_ep) -> VoidRes {
                if (data.size() < 2) {
                    return result::err(err::invalid("Data too short"));
                }

                auto req_res = serial::deserialize<RelayConnectRequest>(data, 1);
                if (req_res.is_err()) {
                    return result::err(req_res.error());
                }
                const auto &req = req_res.value();

                // Register client
                client_endpoints_[req.requester_id] = sender_ep;

                // Add connection mapping
                connections_[req.requester_id].push_back(req.target_peer_id);

                // Send ACK
                Vector<u8> ack;
                ack.push_back(static_cast<u8>(RelayMsgType::RelayAck));
                socket_->send_to(ack, to_udp_endpoint(sender_ep));

                echo::info("RelayServer: Client connected");
                return result::ok();
            }

            auto handle_disconnect(const Vector<u8> & /*data*/, const Endpoint & /*sender_ep*/) -> VoidRes {
                // TODO: Remove client registration
                echo::info("RelayServer: Client disconnected");
                return result::ok();
            }

            auto handle_forward(const Vector<u8> &data, const Endpoint & /*sender_ep*/) -> VoidRes {
                if (data.size() < 2) {
                    return result::err(err::invalid("Data too short"));
                }

                auto fwd_res = serial::deserialize<RelayForwardPacket>(data, 1);
                if (fwd_res.is_err()) {
                    return result::err(fwd_res.error());
                }
                const auto &fwd = fwd_res.value();

                // Find target's endpoint
                auto it = client_endpoints_.find(fwd.target_id);
                if (it == client_endpoints_.end()) {
                    echo::warn("RelayServer: Target not registered");
                    return result::err(err::not_found("Target not registered"));
                }

                // Forward the packet
                socket_->send_to(data, to_udp_endpoint(it->second));

                echo::debug("RelayServer: Forwarded packet");
                return result::ok();
            }
        };

    } // namespace net

} // namespace botlink
