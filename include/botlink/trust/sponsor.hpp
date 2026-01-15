/* SPDX-License-Identifier: MIT */
/*
 * Botlink Sponsor
 * Sponsor flow helpers for introducing new members
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/time.hpp>
#include <botlink/core/types.hpp>
#include <botlink/crypto/identity.hpp>
#include <botlink/crypto/sign.hpp>
#include <botlink/trust/trust_chain.hpp>
#include <botlink/trust/trust_event.hpp>
#include <datapod/datapod.hpp>
#include <echo/echo.hpp>

namespace botlink {

    using namespace dp;

    // =============================================================================
    // Join Request - Candidate sends to sponsor
    // =============================================================================

    struct JoinRequest {
        NodeId candidate_id;
        PublicKey candidate_ed25519;
        PublicKey candidate_x25519;
        OverlayAddr requested_addr;
        u64 timestamp_ms = 0;
        String metadata;          // Optional: reason, capabilities, etc.
        Signature identity_proof; // Signature proving ownership of ed25519 key

        JoinRequest() = default;

        auto members() noexcept {
            return std::tie(candidate_id, candidate_ed25519, candidate_x25519, requested_addr, timestamp_ms, metadata,
                            identity_proof);
        }
        auto members() const noexcept {
            return std::tie(candidate_id, candidate_ed25519, candidate_x25519, requested_addr, timestamp_ms, metadata,
                            identity_proof);
        }

        // Create the data that must be signed for identity proof
        [[nodiscard]] auto get_identity_proof_data() const -> Vector<u8> {
            Vector<u8> data;
            data.reserve(32 + 32 + 8 + 16); // pubkeys + timestamp + prefix

            // Magic prefix for domain separation
            const char *prefix = "BOTLINK_JOIN_V1:";
            for (const char *p = prefix; *p; ++p) {
                data.push_back(static_cast<u8>(*p));
            }

            // Ed25519 public key
            for (usize i = 0; i < 32; ++i) {
                data.push_back(candidate_ed25519.data[i]);
            }

            // X25519 public key
            for (usize i = 0; i < 32; ++i) {
                data.push_back(candidate_x25519.data[i]);
            }

            // Timestamp (little endian)
            for (usize i = 0; i < 8; ++i) {
                data.push_back(static_cast<u8>((timestamp_ms >> (i * 8)) & 0xFF));
            }

            return data;
        }
    };

    // =============================================================================
    // Sponsor Session - Tracks pending join request from candidate
    // =============================================================================

    struct SponsorSession {
        JoinRequest request;
        NodeId sponsor_id;
        u64 received_at_ms = 0;
        boolean submitted_to_chain = false;
        u64 submitted_at_ms = 0;

        SponsorSession() = default;

        [[nodiscard]] auto age_ms() const -> u64 { return time::now_ms() - received_at_ms; }

        [[nodiscard]] auto is_stale(u64 timeout_ms) const -> boolean { return age_ms() > timeout_ms; }

        auto members() noexcept {
            return std::tie(request, sponsor_id, received_at_ms, submitted_to_chain, submitted_at_ms);
        }
        auto members() const noexcept {
            return std::tie(request, sponsor_id, received_at_ms, submitted_to_chain, submitted_at_ms);
        }
    };

    // =============================================================================
    // Sponsor - Manages incoming join requests and submits proposals
    // =============================================================================

    class Sponsor {
      private:
        NodeId local_node_id_;
        PrivateKey local_ed25519_;
        Map<NodeId, SponsorSession> pending_requests_;
        u64 request_timeout_ms_;
        u32 max_pending_;

      public:
        explicit Sponsor(const NodeId &local_id, const PrivateKey &ed25519_key, u64 request_timeout_ms = 60000,
                         u32 max_pending = 10)
            : local_node_id_(local_id), local_ed25519_(ed25519_key), request_timeout_ms_(request_timeout_ms),
              max_pending_(max_pending) {}

        // =============================================================================
        // Request Handling
        // =============================================================================

        // Receive a join request from a candidate
        auto receive_request(const JoinRequest &request) -> VoidRes {
            // Validate request
            if (request.candidate_id.is_zero()) {
                return result::err(err::invalid("Candidate ID is zero"));
            }

            if (request.candidate_ed25519.is_zero()) {
                return result::err(err::invalid("Candidate Ed25519 key is zero"));
            }

            if (request.candidate_x25519.is_zero()) {
                return result::err(err::invalid("Candidate X25519 key is zero"));
            }

            // Verify that candidate_id matches the ed25519 public key
            NodeId expected_id = crypto::node_id_from_pubkey(request.candidate_ed25519);
            if (expected_id != request.candidate_id) {
                return result::err(err::invalid("Candidate ID does not match Ed25519 public key"));
            }

            // Verify identity proof signature
            auto proof_data = request.get_identity_proof_data();
            if (!crypto::ed25519_verify(request.candidate_ed25519, proof_data, request.identity_proof)) {
                return result::err(err::crypto("Identity proof signature verification failed"));
            }

            // Check timestamp freshness (prevent replay attacks)
            u64 now = time::now_ms();
            constexpr u64 MAX_REQUEST_AGE_MS = 300000; // 5 minutes
            if (request.timestamp_ms + MAX_REQUEST_AGE_MS < now) {
                return result::err(err::invalid("Join request timestamp too old"));
            }
            if (request.timestamp_ms > now + 60000) { // 1 minute future tolerance
                return result::err(err::invalid("Join request timestamp in the future"));
            }

            // Check if we already have a pending request from this candidate
            if (pending_requests_.find(request.candidate_id) != pending_requests_.end()) {
                return result::err(err::invalid("Already have pending request from this candidate"));
            }

            // Check max pending limit
            if (pending_requests_.size() >= max_pending_) {
                // Try to cleanup stale requests first
                cleanup_stale();
                if (pending_requests_.size() >= max_pending_) {
                    return result::err(err::invalid("Too many pending requests"));
                }
            }

            // Create session
            SponsorSession session;
            session.request = request;
            session.sponsor_id = local_node_id_;
            session.received_at_ms = time::now_ms();
            session.submitted_to_chain = false;

            pending_requests_[request.candidate_id] = session;

            echo::info("Sponsor: Received and validated join request from candidate");
            return result::ok();
        }

        // Submit a pending request to the trust chain as a proposal
        auto submit_proposal(const NodeId &candidate_id, TrustChain &chain) -> VoidRes {
            auto it = pending_requests_.find(candidate_id);
            if (it == pending_requests_.end()) {
                return result::err(err::not_found("No pending request from this candidate"));
            }

            if (it->second.submitted_to_chain) {
                return result::err(err::invalid("Request already submitted to chain"));
            }

            // Create join proposal
            JoinProposal proposal;
            proposal.candidate_id = it->second.request.candidate_id;
            proposal.candidate_ed25519 = it->second.request.candidate_ed25519;
            proposal.candidate_x25519 = it->second.request.candidate_x25519;
            proposal.sponsor_id = local_node_id_;
            proposal.timestamp_ms = time::now_ms();
            proposal.justification = it->second.request.metadata;

            // Submit to chain
            auto res = chain.propose_join(proposal);
            if (res.is_err()) {
                return res;
            }

            // Mark as submitted
            it->second.submitted_to_chain = true;
            it->second.submitted_at_ms = time::now_ms();

            echo::info("Sponsor: Submitted join proposal to trust chain");
            return result::ok();
        }

        // =============================================================================
        // Query
        // =============================================================================

        [[nodiscard]] auto has_pending(const NodeId &candidate_id) const -> boolean {
            return pending_requests_.find(candidate_id) != pending_requests_.end();
        }

        [[nodiscard]] auto get_pending(const NodeId &candidate_id) const -> Optional<SponsorSession> {
            auto it = pending_requests_.find(candidate_id);
            if (it == pending_requests_.end()) {
                return Optional<SponsorSession>();
            }
            return it->second;
        }

        [[nodiscard]] auto pending_count() const -> usize { return pending_requests_.size(); }

        [[nodiscard]] auto get_all_pending() const -> Vector<SponsorSession> {
            Vector<SponsorSession> result;
            for (const auto &[_, session] : pending_requests_) {
                result.push_back(session);
            }
            return result;
        }

        // =============================================================================
        // Cleanup
        // =============================================================================

        // Remove request for a candidate (e.g., after approval/rejection)
        auto remove_request(const NodeId &candidate_id) -> void { pending_requests_.erase(candidate_id); }

        // Cleanup stale requests
        auto cleanup_stale() -> Vector<NodeId> {
            Vector<NodeId> removed;
            for (const auto &[node_id, session] : pending_requests_) {
                if (session.is_stale(request_timeout_ms_)) {
                    removed.push_back(node_id);
                }
            }
            for (const auto &id : removed) {
                pending_requests_.erase(id);
            }
            return removed;
        }
    };

    // =============================================================================
    // Serialization helpers
    // =============================================================================

    namespace sponsor {

        inline auto serialize_join_request(const JoinRequest &req) -> Vector<u8> {
            auto buf = dp::serialize<dp::Mode::WITH_VERSION>(const_cast<JoinRequest &>(req));
            Vector<u8> result;
            result.reserve(buf.size());
            for (const auto &byte : buf) {
                result.push_back(byte);
            }
            return result;
        }

        inline auto deserialize_join_request(const Vector<u8> &data) -> Res<JoinRequest> {
            return serial::deserialize<JoinRequest>(data);
        }

        // Create a signed join request
        inline auto create_join_request(const PrivateKey &ed25519_priv, const PublicKey &ed25519_pub,
                                        const PublicKey &x25519_pub, const OverlayAddr &requested_addr = {},
                                        const String &metadata = "") -> JoinRequest {
            JoinRequest req;
            req.candidate_id = crypto::node_id_from_pubkey(ed25519_pub);
            req.candidate_ed25519 = ed25519_pub;
            req.candidate_x25519 = x25519_pub;
            req.requested_addr = requested_addr;
            req.timestamp_ms = time::now_ms();
            req.metadata = metadata;

            // Sign the identity proof
            auto proof_data = req.get_identity_proof_data();
            req.identity_proof = crypto::ed25519_sign(ed25519_priv, proof_data);

            return req;
        }

    } // namespace sponsor

} // namespace botlink
