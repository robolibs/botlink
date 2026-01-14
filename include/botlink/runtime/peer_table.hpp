/* SPDX-License-Identifier: MIT */
/*
 * Botlink Peer Table
 * Runtime peer connection tracking
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/time.hpp>
#include <botlink/core/types.hpp>
#include <botlink/crypto/aead.hpp>
#include <botlink/crypto/kdf.hpp>
#include <datapod/datapod.hpp>

namespace botlink {

    using namespace dp;

    // =============================================================================
    // Peer Session - Cryptographic state for a peer connection
    // =============================================================================

    struct PeerSession {
        crypto::SessionKey send_key;
        crypto::SessionKey recv_key;
        u64 send_nonce = 0;
        crypto::ReplayWindow recv_window;
        u64 established_at_ms = 0;
        u64 last_send_ms = 0;
        u64 last_recv_ms = 0;
        u32 rekey_count = 0;

        PeerSession() = default;

        [[nodiscard]] auto next_send_nonce() -> u64 { return send_nonce++; }

        [[nodiscard]] auto age_ms() const -> u64 { return time::now_ms() - established_at_ms; }

        [[nodiscard]] auto idle_send_ms() const -> u64 { return time::now_ms() - last_send_ms; }

        [[nodiscard]] auto idle_recv_ms() const -> u64 { return time::now_ms() - last_recv_ms; }

        auto members() noexcept {
            return std::tie(send_key, recv_key, send_nonce, recv_window, established_at_ms, last_send_ms, last_recv_ms,
                            rekey_count);
        }
        auto members() const noexcept {
            return std::tie(send_key, recv_key, send_nonce, recv_window, established_at_ms, last_send_ms, last_recv_ms,
                            rekey_count);
        }
    };

    // =============================================================================
    // Peer Entry - Full peer state
    // =============================================================================

    struct PeerEntry {
        NodeId node_id;
        PublicKey ed25519_pubkey;
        PublicKey x25519_pubkey;
        PeerStatus status = PeerStatus::Unknown;
        Vector<Endpoint> endpoints;
        usize preferred_endpoint_idx = 0;
        Optional<PeerSession> session;
        u64 rx_bytes = 0;
        u64 tx_bytes = 0;
        u64 last_handshake_ms = 0;

        PeerEntry() = default;

        [[nodiscard]] auto is_connected() const -> boolean {
            return status == PeerStatus::Direct || status == PeerStatus::Relayed;
        }

        [[nodiscard]] auto has_session() const -> boolean { return session.has_value(); }

        [[nodiscard]] auto preferred_endpoint() const -> Optional<Endpoint> {
            if (endpoints.empty()) {
                return nullopt;
            }
            if (preferred_endpoint_idx >= endpoints.size()) {
                return endpoints[0];
            }
            return endpoints[preferred_endpoint_idx];
        }

        auto members() noexcept {
            return std::tie(node_id, ed25519_pubkey, x25519_pubkey, status, endpoints, preferred_endpoint_idx, session,
                            rx_bytes, tx_bytes, last_handshake_ms);
        }
        auto members() const noexcept {
            return std::tie(node_id, ed25519_pubkey, x25519_pubkey, status, endpoints, preferred_endpoint_idx, session,
                            rx_bytes, tx_bytes, last_handshake_ms);
        }
    };

    // =============================================================================
    // Peer Table - Manages all peer connections
    // =============================================================================

    class PeerTable {
      private:
        Map<NodeId, PeerEntry> peers_;
        u64 keepalive_interval_ms_ = 25000;
        u64 rekey_after_ms_ = 120000;
        u64 session_timeout_ms_ = 180000;

      public:
        PeerTable() = default;

        explicit PeerTable(u64 keepalive_ms, u64 rekey_ms, u64 timeout_ms)
            : keepalive_interval_ms_(keepalive_ms), rekey_after_ms_(rekey_ms), session_timeout_ms_(timeout_ms) {}

        // =============================================================================
        // Peer Queries
        // =============================================================================

        [[nodiscard]] auto get_peer(const NodeId &id) -> Optional<PeerEntry *> {
            auto it = peers_.find(id);
            if (it != peers_.end()) {
                return &it->second;
            }
            return nullopt;
        }

        [[nodiscard]] auto get_peer(const NodeId &id) const -> Optional<const PeerEntry *> {
            auto it = peers_.find(id);
            if (it != peers_.end()) {
                return &it->second;
            }
            return nullopt;
        }

        [[nodiscard]] auto has_peer(const NodeId &id) const -> boolean { return peers_.find(id) != peers_.end(); }

        [[nodiscard]] auto peer_count() const -> usize { return peers_.size(); }

        [[nodiscard]] auto connected_count() const -> usize {
            usize count = 0;
            for (const auto &[_, peer] : peers_) {
                if (peer.is_connected())
                    ++count;
            }
            return count;
        }

        [[nodiscard]] auto get_all_peers() -> Vector<PeerEntry *> {
            Vector<PeerEntry *> result;
            for (auto &[_, peer] : peers_) {
                result.push_back(&peer);
            }
            return result;
        }

        [[nodiscard]] auto get_connected_peers() -> Vector<PeerEntry *> {
            Vector<PeerEntry *> result;
            for (auto &[_, peer] : peers_) {
                if (peer.is_connected()) {
                    result.push_back(&peer);
                }
            }
            return result;
        }

        // =============================================================================
        // Peer Management
        // =============================================================================

        // Add or update a peer
        auto add_peer(const NodeId &id, const PublicKey &ed25519, const PublicKey &x25519) -> PeerEntry * {
            auto it = peers_.find(id);
            if (it != peers_.end()) {
                // Update existing
                it->second.ed25519_pubkey = ed25519;
                it->second.x25519_pubkey = x25519;
                return &it->second;
            }

            // Create new
            PeerEntry entry;
            entry.node_id = id;
            entry.ed25519_pubkey = ed25519;
            entry.x25519_pubkey = x25519;
            entry.status = PeerStatus::Unknown;

            auto [new_it, inserted] = peers_.emplace(id, entry);
            return &new_it->second;
        }

        // Remove a peer
        auto remove_peer(const NodeId &id) -> boolean {
            auto it = peers_.find(id);
            if (it != peers_.end()) {
                peers_.erase(it);
                return true;
            }
            return false;
        }

        // Update peer endpoints
        auto update_endpoints(const NodeId &id, Vector<Endpoint> endpoints) -> void {
            auto it = peers_.find(id);
            if (it != peers_.end()) {
                it->second.endpoints = std::move(endpoints);
            }
        }

        // Update peer status
        auto set_status(const NodeId &id, PeerStatus status) -> void {
            auto it = peers_.find(id);
            if (it != peers_.end()) {
                it->second.status = status;
            }
        }

        // =============================================================================
        // Session Management
        // =============================================================================

        // Create a new session for a peer
        auto create_session(const NodeId &id, const crypto::SessionKey &send_key, const crypto::SessionKey &recv_key)
            -> boolean {
            auto it = peers_.find(id);
            if (it == peers_.end()) {
                return false;
            }

            PeerSession session;
            session.send_key = send_key;
            session.recv_key = recv_key;
            session.send_nonce = 0;
            session.established_at_ms = time::now_ms();
            session.last_send_ms = session.established_at_ms;
            session.last_recv_ms = session.established_at_ms;

            it->second.session = session;
            it->second.status = PeerStatus::Direct;
            it->second.last_handshake_ms = session.established_at_ms;

            return true;
        }

        // Clear session for a peer
        auto clear_session(const NodeId &id) -> void {
            auto it = peers_.find(id);
            if (it != peers_.end()) {
                if (it->second.session.has_value()) {
                    // Secure clear keys
                    it->second.session->send_key.clear();
                    it->second.session->recv_key.clear();
                }
                it->second.session = nullopt;
                it->second.status = PeerStatus::Unknown;
            }
        }

        // Rekey a session
        auto rekey_session(const NodeId &id) -> boolean {
            auto it = peers_.find(id);
            if (it == peers_.end() || !it->second.session.has_value()) {
                return false;
            }

            auto &session = it->second.session.value();
            session.send_key = crypto::rekey(session.send_key);
            session.recv_key = crypto::rekey(session.recv_key);
            session.rekey_count++;
            session.recv_window = crypto::ReplayWindow{}; // Reset replay window

            return true;
        }

        // Record data sent to peer
        auto record_send(const NodeId &id, usize bytes) -> void {
            auto it = peers_.find(id);
            if (it != peers_.end()) {
                it->second.tx_bytes += bytes;
                if (it->second.session.has_value()) {
                    it->second.session->last_send_ms = time::now_ms();
                }
            }
        }

        // Record data received from peer
        auto record_recv(const NodeId &id, usize bytes) -> void {
            auto it = peers_.find(id);
            if (it != peers_.end()) {
                it->second.rx_bytes += bytes;
                if (it->second.session.has_value()) {
                    it->second.session->last_recv_ms = time::now_ms();
                }
            }
        }

        // =============================================================================
        // Maintenance
        // =============================================================================

        // Get peers that need keepalive
        [[nodiscard]] auto get_keepalive_needed() -> Vector<NodeId> {
            Vector<NodeId> result;
            u64 now = time::now_ms();

            for (const auto &[id, peer] : peers_) {
                if (peer.session.has_value() && peer.session->idle_send_ms() >= keepalive_interval_ms_) {
                    result.push_back(id);
                }
            }

            return result;
        }

        // Get peers that need rekey
        [[nodiscard]] auto get_rekey_needed() -> Vector<NodeId> {
            Vector<NodeId> result;

            for (const auto &[id, peer] : peers_) {
                if (peer.session.has_value() && peer.session->age_ms() >= rekey_after_ms_) {
                    result.push_back(id);
                }
            }

            return result;
        }

        // Get peers with timed-out sessions
        [[nodiscard]] auto get_timed_out() -> Vector<NodeId> {
            Vector<NodeId> result;

            for (const auto &[id, peer] : peers_) {
                if (peer.session.has_value() && peer.session->idle_recv_ms() >= session_timeout_ms_) {
                    result.push_back(id);
                }
            }

            return result;
        }

        // Cleanup timed-out sessions
        auto cleanup_timed_out() -> Vector<NodeId> {
            auto timed_out = get_timed_out();
            for (const auto &id : timed_out) {
                clear_session(id);
            }
            return timed_out;
        }
    };

} // namespace botlink
