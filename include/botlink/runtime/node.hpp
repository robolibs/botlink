/* SPDX-License-Identifier: MIT */
/*
 * Botlink Node
 * Main orchestrator that brings together all components
 */

#pragma once

#include <botlink/cfg/config.hpp>
#include <botlink/core/result.hpp>
#include <botlink/core/time.hpp>
#include <botlink/core/types.hpp>
#include <botlink/crypto/identity.hpp>
#include <botlink/net/control_plane.hpp>
#include <botlink/net/data_plane.hpp>
#include <botlink/net/endpoint.hpp>
#include <botlink/net/relay.hpp>
#include <botlink/net/transport.hpp>
#include <botlink/netdev/netdev.hpp>
#include <botlink/netdev/route_table.hpp>
#include <botlink/runtime/peer_table.hpp>
#include <botlink/runtime/scheduler.hpp>
#include <botlink/trust/sponsor.hpp>
#include <botlink/trust/trust_chain.hpp>
#include <botlink/trust/trust_view.hpp>
#include <botlink/trust/voting.hpp>
#include <datapod/datapod.hpp>
#include <echo/echo.hpp>

namespace botlink {

    using namespace dp;

    namespace runtime {

        // =============================================================================
        // Node State
        // =============================================================================

        enum class NodeState : u8 {
            Unconfigured = 0,
            Configured = 1,
            Starting = 2,
            Running = 3,
            Stopping = 4,
            Stopped = 5,
            Error = 6,
        };

        [[nodiscard]] inline auto node_state_to_string(NodeState state) -> const char * {
            switch (state) {
            case NodeState::Unconfigured:
                return "unconfigured";
            case NodeState::Configured:
                return "configured";
            case NodeState::Starting:
                return "starting";
            case NodeState::Running:
                return "running";
            case NodeState::Stopping:
                return "stopping";
            case NodeState::Stopped:
                return "stopped";
            case NodeState::Error:
                return "error";
            default:
                return "unknown";
            }
        }

        // =============================================================================
        // Node Statistics
        // =============================================================================

        struct NodeStats {
            u64 packets_sent = 0;
            u64 packets_received = 0;
            u64 bytes_sent = 0;
            u64 bytes_received = 0;
            u64 handshakes_completed = 0;
            u64 handshakes_failed = 0;
            u64 started_at_ms = 0;

            [[nodiscard]] auto uptime_ms() const -> u64 {
                if (started_at_ms == 0) {
                    return 0;
                }
                return time::now_ms() - started_at_ms;
            }

            auto members() noexcept {
                return std::tie(packets_sent, packets_received, bytes_sent, bytes_received, handshakes_completed,
                                handshakes_failed, started_at_ms);
            }
            auto members() const noexcept {
                return std::tie(packets_sent, packets_received, bytes_sent, bytes_received, handshakes_completed,
                                handshakes_failed, started_at_ms);
            }
        };

        // =============================================================================
        // Botlink Node
        // =============================================================================

        class BotlinkNode {
          private:
            // Configuration
            Config config_;
            NodeState state_ = NodeState::Unconfigured;
            NodeStats stats_;

            // Identity
            NodeId local_node_id_;

            // Components (owned)
            Optional<net::UdpSocket> socket_;
            Optional<TrustChain> trust_chain_;
            Optional<TrustView> trust_view_;
            Optional<PeerTable> peer_table_;
            Optional<Sponsor> sponsor_;
            Optional<VotingManager> voting_;
            Optional<net::RelayManager> relay_manager_;
            Optional<netdev::RouteTable> route_table_;
            Optional<Scheduler> scheduler_;

            // Components (not owned, for extensibility)
            netdev::NetdevBackend *netdev_ = nullptr;
            net::ControlPlane *control_plane_ = nullptr;
            net::DataPlane *data_plane_ = nullptr;

            // Event loop control
            boolean running_ = false;

          public:
            BotlinkNode() = default;

            // =============================================================================
            // Initialization
            // =============================================================================

            // Configure the node
            auto configure(const Config &config) -> VoidRes {
                // Validate config
                auto validate_res = cfg::validate(config);
                if (validate_res.is_err()) {
                    return validate_res;
                }

                config_ = config;

                // Derive NodeId from Ed25519 public key
                local_node_id_ = crypto::node_id_from_pubkey(config_.identity.ed25519_public);

                state_ = NodeState::Configured;
                echo::info("BotlinkNode: Configured with node ID ",
                           crypto::node_id_to_hex(local_node_id_).substr(0, 16).c_str(), "...");
                return result::ok();
            }

            // Start the node
            auto start() -> VoidRes {
                if (state_ != NodeState::Configured && state_ != NodeState::Stopped) {
                    return result::err(err::invalid("Node not in configurable state"));
                }

                state_ = NodeState::Starting;
                echo::info("BotlinkNode: Starting...");

                // Initialize trust chain
                auto chain_res = init_trust_chain();
                if (chain_res.is_err()) {
                    state_ = NodeState::Error;
                    return chain_res;
                }

                // Initialize trust view
                trust_view_.emplace(config_.trust.policy.min_yes_votes, config_.trust.policy.vote_timeout_ms);

                // Initialize peer table
                peer_table_.emplace(25000, 120000, 180000); // keepalive, handshake timeout, session lifetime

                // Initialize transport
                if (!config_.node.overlay.listen.empty()) {
                    net::UdpSocket sock;
                    auto udp_ep = net::to_udp_endpoint(config_.node.overlay.listen[0]);
                    auto bind_res = sock.bind(udp_ep);
                    if (bind_res.is_ok()) {
                        socket_ = std::move(sock);
                    } else {
                        echo::warn("BotlinkNode: Failed to bind socket");
                    }
                }

                // Initialize sponsor (if member)
                if (config_.node.is_member()) {
                    sponsor_.emplace(local_node_id_, config_.identity.ed25519_private, 60000, 10);
                }

                // Initialize voting
                VotingPolicy policy;
                policy.min_yes_votes = config_.trust.policy.min_yes_votes;
                policy.vote_timeout_ms = config_.trust.policy.vote_timeout_ms;
                voting_.emplace(policy, local_node_id_);

                // Initialize relay manager
                if (socket_.has_value()) {
                    relay_manager_.emplace(local_node_id_, &socket_.value());

                    // Add bootstrap relays
                    for (const auto &bootstrap : config_.trust.bootstraps) {
                        if (bootstrap.is_relay()) {
                            net::RelayInfo info;
                            info.id = bootstrap.id;
                            info.endpoint = bootstrap.endpoint;
                            info.pubkey = bootstrap.pubkey;
                            relay_manager_->add_relay(info);
                        }
                    }
                }

                // Initialize route table
                route_table_.emplace(config_.node.overlay.addr);

                // Initialize scheduler
                scheduler_.emplace();
                setup_timers();

                // Connect to bootstrap peers
                connect_to_bootstraps();

                state_ = NodeState::Running;
                stats_.started_at_ms = time::now_ms();
                running_ = true;

                echo::info("BotlinkNode: Started successfully");
                return result::ok();
            }

            // Stop the node
            auto stop() -> VoidRes {
                if (state_ != NodeState::Running) {
                    return result::err(err::invalid("Node not running"));
                }

                state_ = NodeState::Stopping;
                running_ = false;
                echo::info("BotlinkNode: Stopping...");

                // Clear scheduler
                if (scheduler_.has_value()) {
                    scheduler_->clear();
                }

                // Close socket
                socket_.reset();

                // Save trust chain
                if (trust_chain_.has_value() && !config_.trust.chain.path.empty()) {
                    trust_chain_->save_to_file(config_.trust.chain.path);
                }

                state_ = NodeState::Stopped;
                echo::info("BotlinkNode: Stopped");
                return result::ok();
            }

            // =============================================================================
            // Event Loop
            // =============================================================================

            // Run one iteration of the event loop
            auto poll() -> VoidRes {
                if (state_ != NodeState::Running) {
                    return result::err(err::invalid("Node not running"));
                }

                // Process timers
                if (scheduler_.has_value()) {
                    scheduler_->process();
                }

                // Process incoming packets
                if (socket_.has_value()) {
                    process_incoming_packets();
                }

                // Process netdev packets (if available)
                if (netdev_ != nullptr && netdev_->can_read()) {
                    process_netdev_packets();
                }

                return result::ok();
            }

            // Run event loop (blocking)
            auto run() -> VoidRes {
                while (running_) {
                    auto res = poll();
                    if (res.is_err()) {
                        echo::error("BotlinkNode: Poll error: ", res.error().message.c_str());
                    }

                    // Sleep until next timer or use poll timeout
                    i64 timeout = 100; // Default 100ms
                    if (scheduler_.has_value()) {
                        i64 next = scheduler_->time_until_next_ms();
                        if (next >= 0 && next < timeout) {
                            timeout = next;
                        }
                    }

                    time::sleep_ms(static_cast<u64>(timeout));
                }

                return result::ok();
            }

            // =============================================================================
            // Peer Operations
            // =============================================================================

            // Connect to a peer
            auto connect_peer(const NodeId &peer_id, const Endpoint &ep) -> VoidRes {
                if (!trust_view_.has_value()) {
                    return result::err(err::invalid("Trust view not initialized"));
                }

                // Check if peer is approved
                if (!trust_view_->is_member(peer_id)) {
                    return result::err(err::permission("Peer is not an approved member"));
                }

                // Add to peer table
                if (peer_table_.has_value()) {
                    auto member = trust_view_->get_member(peer_id);
                    if (member.has_value()) {
                        peer_table_->add_peer(peer_id, member->ed25519_pubkey, member->x25519_pubkey);
                        Vector<Endpoint> eps;
                        eps.push_back(ep);
                        peer_table_->update_endpoints(peer_id, std::move(eps));
                    }
                }

                // Initiate handshake via data plane
                if (data_plane_ != nullptr) {
                    return data_plane_->initiate_handshake(peer_id, ep);
                }

                echo::info("BotlinkNode: Initiated connection to peer");
                return result::ok();
            }

            // =============================================================================
            // Setters (for external components)
            // =============================================================================

            auto set_netdev(netdev::NetdevBackend *netdev) -> void { netdev_ = netdev; }
            auto set_control_plane(net::ControlPlane *cp) -> void { control_plane_ = cp; }
            auto set_data_plane(net::DataPlane *dp) -> void { data_plane_ = dp; }

            // =============================================================================
            // Getters
            // =============================================================================

            [[nodiscard]] auto state() const -> NodeState { return state_; }
            [[nodiscard]] auto config() const -> const Config & { return config_; }
            [[nodiscard]] auto stats() const -> const NodeStats & { return stats_; }
            [[nodiscard]] auto local_node_id() const -> const NodeId & { return local_node_id_; }
            [[nodiscard]] auto is_running() const -> boolean { return state_ == NodeState::Running; }

            [[nodiscard]] auto trust_view() -> TrustView * {
                return trust_view_.has_value() ? &trust_view_.value() : nullptr;
            }
            [[nodiscard]] auto peer_table() -> PeerTable * {
                return peer_table_.has_value() ? &peer_table_.value() : nullptr;
            }
            [[nodiscard]] auto scheduler() -> Scheduler * {
                return scheduler_.has_value() ? &scheduler_.value() : nullptr;
            }

          private:
            auto init_trust_chain() -> VoidRes {
                // Try to load existing chain
                if (!config_.trust.chain.path.empty()) {
                    TrustChain chain;
                    auto load_res = chain.load_from_file(config_.trust.chain.path);
                    if (load_res.is_ok()) {
                        trust_chain_ = std::move(chain);
                        echo::info("BotlinkNode: Loaded trust chain from file");
                        return result::ok();
                    }
                }

                // Create new chain with genesis
                trust_chain_.emplace(config_.trust.chain.chain_name, local_node_id_, config_.identity.ed25519_public,
                                     config_.identity.x25519_public);

                echo::info("BotlinkNode: Created new trust chain");
                return result::ok();
            }

            auto setup_timers() -> void {
                if (!scheduler_.has_value()) {
                    return;
                }

                // Keepalive timer
                scheduler_->create_repeating(timer_names::KEEPALIVE, 25000, [this]() { send_keepalives(); });

                // Peer cleanup timer
                scheduler_->create_repeating(timer_names::PEER_CLEANUP, 60000, [this]() { cleanup_peers(); });

                // Trust sync timer
                scheduler_->create_repeating(timer_names::TRUST_SYNC, 30000, [this]() { sync_trust(); });

                // Vote timeout processing
                scheduler_->create_repeating(timer_names::VOTE_TIMEOUT, 5000, [this]() { process_vote_timeouts(); });
            }

            auto connect_to_bootstraps() -> void {
                for (const auto &bootstrap : config_.trust.bootstraps) {
                    if (bootstrap.is_member()) {
                        // Derive NodeId from bootstrap pubkey
                        NodeId peer_id = crypto::node_id_from_pubkey(bootstrap.pubkey);

                        // Add to peer table
                        if (peer_table_.has_value()) {
                            peer_table_->add_peer(peer_id, bootstrap.pubkey, bootstrap.pubkey); // X25519 unknown
                            Vector<Endpoint> eps;
                            eps.push_back(bootstrap.endpoint);
                            peer_table_->update_endpoints(peer_id, std::move(eps));
                        }

                        echo::info("BotlinkNode: Added bootstrap peer ", bootstrap.id.c_str());
                    }
                }
            }

            auto process_incoming_packets() -> void {
                if (!socket_.has_value()) {
                    return;
                }

                // Non-blocking receive
                auto recv_res = socket_->recv_from();
                if (recv_res.is_err()) {
                    return; // No packets or error
                }

                auto &[data, sender_udp_ep] = recv_res.value();
                Endpoint sender_ep = net::from_udp_endpoint(sender_udp_ep);
                stats_.packets_received++;
                stats_.bytes_received += data.size();

                if (data.empty()) {
                    echo::warn("BotlinkNode: Received empty packet");
                    return;
                }

                // Dispatch based on first byte (message type marker)
                u8 msg_type = data[0];

                // Control plane messages: 0x01-0x0F
                if (msg_type >= 0x01 && msg_type <= 0x0F) {
                    dispatch_control_packet(data, sender_ep);
                    return;
                }

                // Relay messages: 0x10-0x1F
                if (msg_type >= 0x10 && msg_type <= 0x1F) {
                    dispatch_relay_packet(data, sender_ep);
                    return;
                }

                // Data plane messages: 0x20-0x2F
                if (msg_type >= 0x20 && msg_type <= 0x2F) {
                    dispatch_data_packet(data, sender_ep);
                    return;
                }

                echo::warn("BotlinkNode: Unknown message type 0x", std::hex, static_cast<int>(msg_type));
            }

            auto dispatch_control_packet(const Vector<u8> &data, const Endpoint &sender_ep) -> void {
                // Try to deserialize as envelope first
                auto env_res = crypto::deserialize_envelope(data);
                if (env_res.is_err()) {
                    echo::warn("BotlinkNode: Failed to deserialize control envelope");
                    return;
                }

                const auto &env = env_res.value();

                // Look up sender's public key from trust view
                if (!trust_view_.has_value()) {
                    echo::warn("BotlinkNode: Trust view not initialized");
                    return;
                }

                auto member = trust_view_->get_member(env.sender_id);
                if (!member.has_value()) {
                    echo::warn("BotlinkNode: Unknown sender for control message");
                    return;
                }

                // Delegate to control plane handler
                if (control_plane_ != nullptr) {
                    auto res = control_plane_->handle_envelope(env, member->ed25519_pubkey, sender_ep);
                    if (res.is_err()) {
                        echo::warn("BotlinkNode: Control plane error: ", res.error().message.c_str());
                    }
                } else {
                    echo::debug("BotlinkNode: Control plane not configured, dropping message");
                }
            }

            auto dispatch_relay_packet(const Vector<u8> &data, const Endpoint &sender_ep) -> void {
                if (!relay_manager_.has_value()) {
                    echo::debug("BotlinkNode: Relay manager not initialized");
                    return;
                }

                auto res = relay_manager_->handle_message(data, sender_ep);
                if (res.is_err()) {
                    echo::warn("BotlinkNode: Relay error: ", res.error().message.c_str());
                }
            }

            auto dispatch_data_packet(const Vector<u8> &data, const Endpoint &sender_ep) -> void {
                if (data_plane_ != nullptr) {
                    auto res = data_plane_->handle_packet(data, sender_ep);
                    if (res.is_err()) {
                        echo::warn("BotlinkNode: Data plane error: ", res.error().message.c_str());
                    }
                } else {
                    echo::debug("BotlinkNode: Data plane not configured, dropping message");
                }
            }

            auto process_netdev_packets() -> void {
                if (netdev_ == nullptr) {
                    return;
                }

                auto pkt_res = netdev_->read_packet();
                if (pkt_res.is_err()) {
                    return;
                }

                const auto &pkt = pkt_res.value();

                // Lookup route
                if (route_table_.has_value()) {
                    auto route = route_table_->lookup_packet(pkt.data);
                    if (route.has_value()) {
                        // Get peer for next hop
                        if (peer_table_.has_value()) {
                            auto peer = peer_table_->get_peer(route->next_hop);
                            if (peer.has_value() && (*peer)->has_session()) {
                                // Send encrypted data via data plane
                                if (data_plane_ != nullptr) {
                                    auto res = data_plane_->send_data(route->next_hop, pkt.data);
                                    if (res.is_ok()) {
                                        stats_.packets_sent++;
                                        stats_.bytes_sent += pkt.data.size();
                                    } else {
                                        echo::warn("BotlinkNode: Failed to forward packet: ",
                                                   res.error().message.c_str());
                                    }
                                }
                            } else {
                                echo::debug("BotlinkNode: No session for next hop, dropping packet");
                            }
                        }
                    }
                }
            }

            auto send_keepalives() -> void {
                if (!peer_table_.has_value() || data_plane_ == nullptr) {
                    return;
                }

                for (auto *peer : peer_table_->get_connected_peers()) {
                    data_plane_->send_keepalive(peer->node_id);
                }
            }

            auto cleanup_peers() -> void {
                if (!peer_table_.has_value()) {
                    return;
                }

                // Cleanup is handled by peer_table's get_timed_out() method
                auto timed_out = peer_table_->get_timed_out();
                for (const auto &id : timed_out) {
                    peer_table_->set_status(id, PeerStatus::Unknown);
                }
            }

            auto sync_trust() -> void {
                // Request chain sync from connected peers
                if (!peer_table_.has_value() || control_plane_ == nullptr) {
                    return;
                }

                // Get connected peers and request sync from first available
                auto connected = peer_table_->get_connected_peers();
                for (auto *peer : connected) {
                    auto ep = peer->preferred_endpoint();
                    if (ep.has_value()) {
                        auto res = control_plane_->send_chain_sync_request(ep.value());
                        if (res.is_ok()) {
                            echo::debug("BotlinkNode: Requested chain sync from peer");
                            break; // Only need to sync from one peer
                        }
                    }
                }
            }

            auto process_vote_timeouts() -> void {
                if (!voting_.has_value()) {
                    return;
                }

                auto expired = voting_->process_timeouts();
                if (!expired.empty()) {
                    echo::info("BotlinkNode: ", expired.size(), " proposals expired");
                }
            }
        };

    } // namespace runtime

} // namespace botlink
