/* SPDX-License-Identifier: MIT */
/*
 * Botlink Data Plane
 * Encrypted tunnel packets, handshake, and keepalive
 */

#pragma once

#include <botlink/core/metrics.hpp>
#include <botlink/core/result.hpp>
#include <botlink/core/time.hpp>
#include <botlink/core/types.hpp>
#include <botlink/crypto/aead.hpp>
#include <botlink/crypto/identity.hpp>
#include <botlink/crypto/kdf.hpp>
#include <botlink/net/endpoint.hpp>
#include <botlink/net/transport.hpp>
#include <botlink/runtime/peer_table.hpp>
#include <botlink/trust/trust_view.hpp>
#include <datapod/datapod.hpp>
#include <echo/echo.hpp>

namespace botlink {

    using namespace dp;

    namespace net {

        // =============================================================================
        // Data Plane Message Types
        // =============================================================================

        enum class DataMsgType : u8 {
            HandshakeInit = 0x20,
            HandshakeResp = 0x21,
            Data = 0x22,
            Keepalive = 0x23,
            Rekey = 0x24,
        };

        // =============================================================================
        // Handshake Init - Initiator sends to responder
        // =============================================================================

        struct HandshakeInit {
            NodeId initiator_id;
            PublicKey initiator_x25519; // Ephemeral X25519 public key
            u64 timestamp_ms = 0;
            crypto::Nonce nonce;

            HandshakeInit() = default;

            auto members() noexcept { return std::tie(initiator_id, initiator_x25519, timestamp_ms, nonce); }
            auto members() const noexcept { return std::tie(initiator_id, initiator_x25519, timestamp_ms, nonce); }
        };

        // =============================================================================
        // Handshake Response - Responder sends to initiator
        // =============================================================================

        struct HandshakeResp {
            NodeId responder_id;
            PublicKey responder_x25519; // Ephemeral X25519 public key
            u64 timestamp_ms = 0;
            crypto::Nonce nonce;
            Vector<u8> encrypted_ack; // AEAD encrypted acknowledgment

            HandshakeResp() = default;

            auto members() noexcept {
                return std::tie(responder_id, responder_x25519, timestamp_ms, nonce, encrypted_ack);
            }
            auto members() const noexcept {
                return std::tie(responder_id, responder_x25519, timestamp_ms, nonce, encrypted_ack);
            }
        };

        // =============================================================================
        // Keepalive Packet
        // =============================================================================

        struct KeepalivePacket {
            u32 key_id = 0;
            u64 timestamp_ms = 0;

            KeepalivePacket() = default;

            auto members() noexcept { return std::tie(key_id, timestamp_ms); }
            auto members() const noexcept { return std::tie(key_id, timestamp_ms); }
        };

        // =============================================================================
        // Rekey Request
        // =============================================================================

        struct RekeyRequest {
            NodeId sender_id;
            PublicKey new_x25519; // New ephemeral key
            u32 new_key_id = 0;
            u64 timestamp_ms = 0;

            RekeyRequest() = default;

            auto members() noexcept { return std::tie(sender_id, new_x25519, new_key_id, timestamp_ms); }
            auto members() const noexcept { return std::tie(sender_id, new_x25519, new_key_id, timestamp_ms); }
        };

        // =============================================================================
        // Handshake State
        // =============================================================================

        enum class HandshakeState : u8 {
            None = 0,
            InitSent = 1,
            InitReceived = 2,
            Complete = 3,
            Failed = 4,
        };

        struct HandshakeSession {
            NodeId peer_id;
            HandshakeState state = HandshakeState::None;
            PrivateKey local_ephemeral_priv;
            PublicKey local_ephemeral_pub;
            PublicKey peer_ephemeral_pub;
            u64 started_at_ms = 0;
            u64 timeout_ms = 5000;
            u8 retries = 0;
            u8 max_retries = 3;

            HandshakeSession() = default;

            [[nodiscard]] auto is_timed_out() const -> boolean { return (time::now_ms() - started_at_ms) > timeout_ms; }

            [[nodiscard]] auto can_retry() const -> boolean { return retries < max_retries; }
        };

        // =============================================================================
        // Data Plane Handler
        // =============================================================================

        class DataPlane {
          private:
            NodeId local_node_id_;
            PrivateKey local_x25519_;
            PublicKey local_x25519_pub_;
            TrustView *trust_view_;
            PeerTable *peer_table_;
            UdpSocket *socket_;

            Map<NodeId, HandshakeSession> handshakes_;
            u64 handshake_timeout_ms_ = 5000;
            u64 keepalive_interval_ms_ = 25000;
            u64 rekey_interval_ms_ = 120000;

          public:
            DataPlane(const NodeId &local_id, const PrivateKey &x25519_priv, const PublicKey &x25519_pub,
                      TrustView *trust_view, PeerTable *peer_table, UdpSocket *socket)
                : local_node_id_(local_id), local_x25519_(x25519_priv), local_x25519_pub_(x25519_pub),
                  trust_view_(trust_view), peer_table_(peer_table), socket_(socket) {}

            // =============================================================================
            // Handshake Initiation
            // =============================================================================

            // Initiate handshake with a peer
            auto initiate_handshake(const NodeId &peer_id, const Endpoint &peer_ep) -> VoidRes {
                // Check if peer is approved
                if (trust_view_ != nullptr && !trust_view_->is_member(peer_id)) {
                    return result::err(err::permission("Peer is not an approved member"));
                }

                // Check if we already have a session
                auto peer = peer_table_->get_peer(peer_id);
                if (peer.has_value() && (*peer)->is_connected()) {
                    return result::err(err::invalid("Already connected to peer"));
                }

                // Check for existing handshake
                auto hs_it = handshakes_.find(peer_id);
                if (hs_it != handshakes_.end() && hs_it->second.state == HandshakeState::InitSent) {
                    if (!hs_it->second.is_timed_out()) {
                        return result::err(err::invalid("Handshake already in progress"));
                    }
                }

                // Generate ephemeral key pair
                auto [eph_priv, eph_pub] = crypto::generate_x25519_keypair();

                // Create handshake session
                HandshakeSession session;
                session.peer_id = peer_id;
                session.state = HandshakeState::InitSent;
                session.local_ephemeral_priv = eph_priv;
                session.local_ephemeral_pub = eph_pub;
                session.started_at_ms = time::now_ms();

                // Create init message
                HandshakeInit init;
                init.initiator_id = local_node_id_;
                init.initiator_x25519 = eph_pub;
                init.timestamp_ms = time::now_ms();
                init.nonce = crypto::generate_nonce();

                // Serialize and send
                auto buf = dp::serialize<dp::Mode::WITH_VERSION>(init);
                Vector<u8> payload;
                payload.push_back(static_cast<u8>(DataMsgType::HandshakeInit));
                for (const auto &b : buf) {
                    payload.push_back(b);
                }

                auto res = socket_->send_to(payload, to_udp_endpoint(peer_ep));
                if (res.is_err()) {
                    return result::err(err::io("Failed to send handshake init"));
                }

                handshakes_[peer_id] = session;
                metrics::inc_handshakes_initiated();
                echo::info("DataPlane: Sent handshake init to peer");
                return result::ok();
            }

            // =============================================================================
            // Handshake Response
            // =============================================================================

            auto handle_handshake_init(const Vector<u8> &data, const Endpoint &sender_ep) -> VoidRes {
                if (data.size() < 2) {
                    return result::err(err::invalid("Data too short"));
                }

                auto init_res = serial::deserialize<HandshakeInit>(data, 1);
                if (init_res.is_err()) {
                    return result::err(init_res.error());
                }
                const auto &init = init_res.value();

                // Check if initiator is approved
                if (trust_view_ != nullptr && !trust_view_->is_member(init.initiator_id)) {
                    return result::err(err::permission("Initiator is not an approved member"));
                }

                // Generate our ephemeral key
                auto [eph_priv, eph_pub] = crypto::generate_x25519_keypair();

                // Compute shared secret
                auto shared_res = crypto::x25519_shared_secret(eph_priv, init.initiator_x25519);
                if (shared_res.is_err()) {
                    return result::err(shared_res.error());
                }

                // Derive session keys (we are responder, so initiator passed first)
                auto [send_key, recv_key] =
                    crypto::derive_responder_keys(shared_res.value(), init.initiator_id, local_node_id_, 1);

                // Create session in peer table
                if (peer_table_ != nullptr) {
                    // Add peer if not exists
                    auto peer = peer_table_->get_peer(init.initiator_id);
                    if (!peer.has_value()) {
                        // Get peer's keys from trust view
                        if (trust_view_ != nullptr) {
                            auto member = trust_view_->get_member(init.initiator_id);
                            if (member.has_value()) {
                                peer_table_->add_peer(init.initiator_id, member->ed25519_pubkey, member->x25519_pubkey);
                            }
                        }
                    }
                    peer_table_->create_session(init.initiator_id, send_key, recv_key);
                    Vector<Endpoint> eps;
                    eps.push_back(sender_ep);
                    peer_table_->update_endpoints(init.initiator_id, std::move(eps));
                }

                // Create response
                HandshakeResp resp;
                resp.responder_id = local_node_id_;
                resp.responder_x25519 = eph_pub;
                resp.timestamp_ms = time::now_ms();
                resp.nonce = crypto::generate_nonce();

                // Encrypt acknowledgment
                Vector<u8> ack;
                ack.push_back(0x01); // Simple ACK
                auto enc_res = crypto::aead_encrypt(send_key, resp.nonce, ack);
                if (enc_res.is_ok()) {
                    resp.encrypted_ack = enc_res.value();
                }

                // Serialize and send response
                auto resp_buf = serial::serialize(resp);
                Vector<u8> payload;
                payload.push_back(static_cast<u8>(DataMsgType::HandshakeResp));
                for (const auto &b : resp_buf) {
                    payload.push_back(b);
                }

                socket_->send_to(payload, to_udp_endpoint(sender_ep));

                metrics::inc_handshakes_completed();
                metrics::inc_sessions_created();
                echo::info("DataPlane: Completed handshake as responder");
                return result::ok();
            }

            auto handle_handshake_resp(const Vector<u8> &data, const Endpoint &sender_ep) -> VoidRes {
                if (data.size() < 2) {
                    return result::err(err::invalid("Data too short"));
                }

                auto resp_res = serial::deserialize<HandshakeResp>(data, 1);
                if (resp_res.is_err()) {
                    return result::err(resp_res.error());
                }
                const auto &resp = resp_res.value();

                // Find pending handshake
                auto hs_it = handshakes_.find(resp.responder_id);
                if (hs_it == handshakes_.end()) {
                    return result::err(err::not_found("No pending handshake for this peer"));
                }

                if (hs_it->second.state != HandshakeState::InitSent) {
                    return result::err(err::invalid("Unexpected handshake state"));
                }

                // Compute shared secret
                auto shared_res =
                    crypto::x25519_shared_secret(hs_it->second.local_ephemeral_priv, resp.responder_x25519);
                if (shared_res.is_err()) {
                    hs_it->second.state = HandshakeState::Failed;
                    metrics::inc_handshakes_failed();
                    return result::err(shared_res.error());
                }

                // Derive session keys (we are initiator)
                auto [send_key, recv_key] =
                    crypto::derive_initiator_keys(shared_res.value(), local_node_id_, resp.responder_id, 1);

                // Create session in peer table
                if (peer_table_ != nullptr) {
                    peer_table_->create_session(resp.responder_id, send_key, recv_key);
                    Vector<Endpoint> eps;
                    eps.push_back(sender_ep);
                    peer_table_->update_endpoints(resp.responder_id, std::move(eps));
                }

                hs_it->second.state = HandshakeState::Complete;
                hs_it->second.peer_ephemeral_pub = resp.responder_x25519;

                metrics::inc_handshakes_completed();
                metrics::inc_sessions_created();
                echo::info("DataPlane: Completed handshake as initiator");
                return result::ok();
            }

            // =============================================================================
            // Data Transmission
            // =============================================================================

            // Send encrypted data packet to peer
            auto send_data(const NodeId &peer_id, const Vector<u8> &data) -> VoidRes {
                auto peer = peer_table_->get_peer(peer_id);
                if (!peer.has_value()) {
                    return result::err(err::not_found("Peer not found"));
                }

                if (!(*peer)->is_connected()) {
                    return result::err(err::invalid("Not connected to peer"));
                }

                if (!(*peer)->has_session()) {
                    return result::err(err::invalid("No session with peer"));
                }

                auto &session = (*peer)->session.value();

                // Get current endpoint
                auto ep = (*peer)->preferred_endpoint();
                if (!ep.has_value()) {
                    return result::err(err::invalid("No endpoint for peer"));
                }

                // Encrypt data with incrementing nonce counter
                u64 nonce_counter = session.next_send_nonce(); // Atomically increment
                auto nonce = crypto::nonce_from_counter(nonce_counter);
                auto enc_res = crypto::aead_encrypt(session.send_key, nonce, data);
                if (enc_res.is_err()) {
                    return result::err(enc_res.error());
                }

                // Create data packet
                crypto::DataPacket pkt;
                pkt.version = 1;
                pkt.packet_type = static_cast<u8>(DataMsgType::Data);
                pkt.key_id = session.send_key.key_id;
                pkt.nonce_counter = nonce_counter;
                pkt.ciphertext = enc_res.value();

                auto serialized = crypto::serialize_data_packet(pkt);
                auto send_res = socket_->send_to(serialized, to_udp_endpoint(ep.value()));
                if (send_res.is_err()) {
                    return result::err(err::io("Failed to send data packet"));
                }

                // Update send time
                session.last_send_ms = time::now_ms();
                peer_table_->record_send(peer_id, serialized.size());

                return result::ok();
            }

            // Handle incoming data packet
            auto handle_data_packet(const Vector<u8> &data, const Endpoint &sender_ep) -> Res<Vector<u8>> {
                auto pkt_res = crypto::deserialize_data_packet(data);
                if (pkt_res.is_err()) {
                    return result::err(pkt_res.error());
                }

                const auto &pkt = pkt_res.value();

                // Find peer by key_id
                for (auto *peer : peer_table_->get_connected_peers()) {
                    if (!peer->has_session()) {
                        continue;
                    }

                    auto &session = peer->session.value();
                    if (session.recv_key.key_id != pkt.key_id) {
                        continue;
                    }

                    // Check replay protection BEFORE attempting decryption
                    if (!session.recv_window.check_and_update(pkt.nonce_counter)) {
                        metrics::inc_packets_dropped_replay();
                        return result::err(err::crypto("Replay detected - packet rejected"));
                    }

                    auto nonce = crypto::nonce_from_counter(pkt.nonce_counter);
                    auto dec_res = crypto::aead_decrypt(session.recv_key, nonce, pkt.ciphertext);
                    if (dec_res.is_ok()) {
                        // Update session and peer state
                        session.last_recv_ms = time::now_ms();
                        peer_table_->record_recv(peer->node_id, data.size());

                        // Update peer endpoints
                        Vector<Endpoint> eps;
                        eps.push_back(sender_ep);
                        peer_table_->update_endpoints(peer->node_id, std::move(eps));
                        return result::ok(dec_res.value());
                    } else {
                        // Decryption failed - this shouldn't happen if key_id matched
                        metrics::inc_packets_dropped_decrypt_fail();
                        echo::warn("DataPlane: Decryption failed for matching key_id");
                    }
                }

                metrics::inc_packets_dropped_no_session();
                return result::err(err::crypto("Failed to decrypt packet"));
            }

            // =============================================================================
            // Keepalive
            // =============================================================================

            auto send_keepalive(const NodeId &peer_id) -> VoidRes {
                auto peer = peer_table_->get_peer(peer_id);
                if (!peer.has_value()) {
                    return result::err(err::not_found("Peer not found"));
                }

                if (!(*peer)->has_session()) {
                    return result::err(err::invalid("No session with peer"));
                }

                const auto &session = (*peer)->session.value();

                auto ep = (*peer)->preferred_endpoint();
                if (!ep.has_value()) {
                    return result::err(err::invalid("No endpoint for peer"));
                }

                KeepalivePacket keepalive;
                keepalive.key_id = session.send_key.key_id;
                keepalive.timestamp_ms = time::now_ms();

                auto buf = dp::serialize<dp::Mode::WITH_VERSION>(keepalive);
                Vector<u8> payload;
                payload.push_back(static_cast<u8>(DataMsgType::Keepalive));
                for (const auto &b : buf) {
                    payload.push_back(b);
                }

                auto send_res = socket_->send_to(payload, to_udp_endpoint(ep.value()));
                if (send_res.is_err()) {
                    return result::err(err::io("Failed to send keepalive"));
                }
                return result::ok();
            }

            // =============================================================================
            // Rekey
            // =============================================================================

            // Initiate rekey with a peer
            auto send_rekey(const NodeId &peer_id) -> VoidRes {
                auto peer = peer_table_->get_peer(peer_id);
                if (!peer.has_value()) {
                    return result::err(err::not_found("Peer not found"));
                }

                if (!(*peer)->has_session()) {
                    return result::err(err::invalid("No session with peer"));
                }

                auto ep = (*peer)->preferred_endpoint();
                if (!ep.has_value()) {
                    return result::err(err::invalid("No endpoint for peer"));
                }

                // Generate new ephemeral key for rekey
                auto [new_priv, new_pub] = crypto::generate_x25519_keypair();

                // Create rekey request
                RekeyRequest rekey;
                rekey.sender_id = local_node_id_;
                rekey.new_x25519 = new_pub;
                rekey.new_key_id = (*peer)->session->send_key.key_id + 1;
                rekey.timestamp_ms = time::now_ms();

                // Serialize and send
                auto buf = dp::serialize<dp::Mode::WITH_VERSION>(rekey);
                Vector<u8> payload;
                payload.push_back(static_cast<u8>(DataMsgType::Rekey));
                for (const auto &b : buf) {
                    payload.push_back(b);
                }

                auto res = socket_->send_to(payload, to_udp_endpoint(ep.value()));
                if (res.is_err()) {
                    return result::err(err::io("Failed to send rekey request"));
                }

                // Store pending rekey session
                HandshakeSession hs;
                hs.peer_id = peer_id;
                hs.state = HandshakeState::InitSent;
                hs.local_ephemeral_priv = new_priv;
                hs.local_ephemeral_pub = new_pub;
                hs.started_at_ms = time::now_ms();
                handshakes_[peer_id] = hs;

                echo::info("DataPlane: Sent rekey request to peer");
                return result::ok();
            }

            // =============================================================================
            // Main Handler
            // =============================================================================

            auto handle_packet(const Vector<u8> &data, const Endpoint &sender_ep) -> VoidRes {
                if (data.empty()) {
                    return result::err(err::invalid("Empty packet"));
                }

                auto msg_type = static_cast<DataMsgType>(data[0]);

                switch (msg_type) {
                case DataMsgType::HandshakeInit:
                    return handle_handshake_init(data, sender_ep);
                case DataMsgType::HandshakeResp:
                    return handle_handshake_resp(data, sender_ep);
                case DataMsgType::Data: {
                    auto res = handle_data_packet(data, sender_ep);
                    if (res.is_err()) {
                        return result::err(res.error());
                    }
                    // Data was decrypted - caller should process it
                    return result::ok();
                }
                case DataMsgType::Keepalive:
                    echo::debug("Received keepalive");
                    return result::ok();
                case DataMsgType::Rekey:
                    return handle_rekey(data, sender_ep);
                default:
                    return result::err(err::invalid("Unknown data message type"));
                }
            }

          private:
            // Handle incoming rekey request
            auto handle_rekey(const Vector<u8> &data, const Endpoint &sender_ep) -> VoidRes {
                if (data.size() < 2) {
                    return result::err(err::invalid("Rekey data too short"));
                }

                auto rekey_res = serial::deserialize<RekeyRequest>(data, 1);
                if (rekey_res.is_err()) {
                    return result::err(rekey_res.error());
                }

                const auto &rekey = rekey_res.value();

                // Verify sender is an approved member
                if (trust_view_ != nullptr && !trust_view_->is_member(rekey.sender_id)) {
                    return result::err(err::permission("Non-member cannot send rekey"));
                }

                // Get peer
                auto peer = peer_table_->get_peer(rekey.sender_id);
                if (!peer.has_value()) {
                    return result::err(err::not_found("Unknown peer"));
                }

                if (!(*peer)->has_session()) {
                    return result::err(err::invalid("No existing session with peer"));
                }

                // Generate our new ephemeral key
                auto [new_priv, new_pub] = crypto::generate_x25519_keypair();

                // Compute new shared secret
                auto shared_res = crypto::x25519_shared_secret(new_priv, rekey.new_x25519);
                if (shared_res.is_err()) {
                    return result::err(shared_res.error());
                }

                // Derive new session keys (we are responding, so we're "responder" role)
                auto [new_send_key, new_recv_key] = crypto::derive_responder_keys(shared_res.value(), rekey.sender_id,
                                                                                  local_node_id_, rekey.new_key_id);

                // Update session with new keys
                peer_table_->create_session(rekey.sender_id, new_send_key, new_recv_key);

                // Send rekey response with our new public key
                RekeyRequest response;
                response.sender_id = local_node_id_;
                response.new_x25519 = new_pub;
                response.new_key_id = rekey.new_key_id;
                response.timestamp_ms = time::now_ms();

                auto buf = dp::serialize<dp::Mode::WITH_VERSION>(response);
                Vector<u8> payload;
                payload.push_back(static_cast<u8>(DataMsgType::Rekey));
                for (const auto &b : buf) {
                    payload.push_back(b);
                }

                socket_->send_to(payload, to_udp_endpoint(sender_ep));

                metrics::inc_handshakes_completed();
                echo::info("DataPlane: Completed rekey as responder");
                return result::ok();
            }

            // =============================================================================
            // Getters
            // =============================================================================

            [[nodiscard]] auto keepalive_interval_ms() const -> u64 { return keepalive_interval_ms_; }
            [[nodiscard]] auto rekey_interval_ms() const -> u64 { return rekey_interval_ms_; }
        };

    } // namespace net

} // namespace botlink
