/* SPDX-License-Identifier: MIT */
/*
 * Botlink Control Plane
 * Join/vote/membership gossip message handling
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/time.hpp>
#include <botlink/core/types.hpp>
#include <botlink/crypto/identity.hpp>
#include <botlink/crypto/sign.hpp>
#include <botlink/net/endpoint.hpp>
#include <botlink/net/transport.hpp>
#include <botlink/trust/sponsor.hpp>
#include <botlink/trust/trust_view.hpp>
#include <botlink/trust/voting.hpp>
#include <datapod/datapod.hpp>
#include <echo/echo.hpp>

namespace botlink {

    using namespace dp;

    namespace net {

        // =============================================================================
        // Control Message Types
        // =============================================================================

        enum class ControlMsgType : u8 {
            JoinRequest = 0x01,
            JoinProposal = 0x02,
            VoteCast = 0x03,
            MembershipUpdate = 0x04,
            EndpointAdvert = 0x05,
            MembershipSnapshot = 0x06,
            ChainSyncRequest = 0x07,
            ChainSyncResponse = 0x08,
        };

        // =============================================================================
        // Endpoint Advertisement - "I can be reached at..."
        // =============================================================================

        struct EndpointAdvert {
            NodeId node_id;
            Vector<Endpoint> endpoints;
            u64 timestamp_ms = 0;
            Optional<NodeId> relay_id; // If reachable via relay

            EndpointAdvert() = default;

            auto members() noexcept { return std::tie(node_id, endpoints, timestamp_ms, relay_id); }
            auto members() const noexcept { return std::tie(node_id, endpoints, timestamp_ms, relay_id); }
        };

        // =============================================================================
        // Membership Update - "Candidate X approved/rejected"
        // =============================================================================

        struct MembershipUpdate {
            NodeId candidate_id;
            boolean approved = false;
            u64 chain_height = 0;
            u64 timestamp_ms = 0;

            MembershipUpdate() = default;

            auto members() noexcept { return std::tie(candidate_id, approved, chain_height, timestamp_ms); }
            auto members() const noexcept { return std::tie(candidate_id, approved, chain_height, timestamp_ms); }
        };

        // =============================================================================
        // Membership Snapshot Request/Response
        // =============================================================================

        struct MembershipSnapshotRequest {
            NodeId requester_id;
            u64 known_height = 0;
            u64 timestamp_ms = 0;

            MembershipSnapshotRequest() = default;

            auto members() noexcept { return std::tie(requester_id, known_height, timestamp_ms); }
            auto members() const noexcept { return std::tie(requester_id, known_height, timestamp_ms); }
        };

        struct MembershipSnapshotResponse {
            Vector<MemberEntry> member_entries;
            u64 chain_height = 0;
            u64 timestamp_ms = 0;

            MembershipSnapshotResponse() = default;

            auto members() noexcept { return std::tie(member_entries, chain_height, timestamp_ms); }
            auto members() const noexcept { return std::tie(member_entries, chain_height, timestamp_ms); }
        };

        // =============================================================================
        // Chain Sync Request/Response - Synchronize trust chain with peers
        // =============================================================================

        struct ChainSyncRequest {
            NodeId requester_id;
            u64 known_height = 0;  // Height of local chain
            u64 timestamp_ms = 0;

            ChainSyncRequest() = default;

            auto members() noexcept { return std::tie(requester_id, known_height, timestamp_ms); }
            auto members() const noexcept { return std::tie(requester_id, known_height, timestamp_ms); }
        };

        struct ChainSyncResponse {
            u64 chain_height = 0;        // Total chain height
            u64 start_height = 0;        // Height of first event in this response
            Vector<TrustEvent> events;   // Events from start_height onwards
            u64 timestamp_ms = 0;

            ChainSyncResponse() = default;

            auto members() noexcept { return std::tie(chain_height, start_height, events, timestamp_ms); }
            auto members() const noexcept { return std::tie(chain_height, start_height, events, timestamp_ms); }
        };

        // =============================================================================
        // Control Plane Handler
        // =============================================================================

        class ControlPlane {
          private:
            NodeId local_node_id_;
            PrivateKey local_ed25519_;
            PublicKey local_ed25519_pub_;
            TrustView *trust_view_;
            TrustChain *trust_chain_;
            Sponsor *sponsor_;
            VotingManager *voting_;
            UdpSocket *socket_;

            // Rate limiting
            Map<NodeId, u64> last_request_time_;
            u64 rate_limit_ms_ = 1000; // 1 request per second per node

            // Envelope validation
            u64 max_envelope_age_ms_ = 60000; // 60 seconds max age for control messages

          public:
            ControlPlane(const NodeId &local_id, const PrivateKey &ed25519_priv, const PublicKey &ed25519_pub,
                         TrustView *trust_view, TrustChain *trust_chain, Sponsor *sponsor, VotingManager *voting,
                         UdpSocket *socket)
                : local_node_id_(local_id), local_ed25519_(ed25519_priv), local_ed25519_pub_(ed25519_pub),
                  trust_view_(trust_view), trust_chain_(trust_chain), sponsor_(sponsor), voting_(voting),
                  socket_(socket) {}

            // =============================================================================
            // Configuration
            // =============================================================================

            auto set_rate_limit_ms(u64 ms) -> void { rate_limit_ms_ = ms; }
            auto set_max_envelope_age_ms(u64 ms) -> void { max_envelope_age_ms_ = ms; }

            // =============================================================================
            // Sending
            // =============================================================================

            // Send join request to sponsor
            auto send_join_request(const JoinRequest &request, const Endpoint &sponsor_endpoint) -> VoidRes {
                Envelope env = crypto::create_signed_envelope(MsgType::JoinRequest, local_node_id_, local_ed25519_,
                                                              sponsor::serialize_join_request(request));

                auto serialized = crypto::serialize_envelope(env);
                auto res = socket_->send_to(serialized, to_udp_endpoint(sponsor_endpoint));
                if (res.is_err()) {
                    return result::err(err::io("Failed to send join request"));
                }
                return result::ok();
            }

            // Send vote cast to peers
            auto send_vote(const VoteCastEvent &vote, const Vector<Endpoint> &peer_endpoints) -> VoidRes {
                TrustEvent evt = vote.to_event();
                Vector<u8> payload = trust::serialize_event(evt);

                Envelope env =
                    crypto::create_signed_envelope(MsgType::VoteCast, local_node_id_, local_ed25519_, payload);

                auto serialized = crypto::serialize_envelope(env);

                for (const auto &ep : peer_endpoints) {
                    auto res = socket_->send_to(serialized, to_udp_endpoint(ep));
                    if (res.is_err()) {
                        echo::warn("Failed to send vote to peer");
                    }
                }

                return result::ok();
            }

            // Send membership update to peers
            auto send_membership_update(const MembershipUpdate &update, const Vector<Endpoint> &peer_endpoints)
                -> VoidRes {
                auto buf = dp::serialize<dp::Mode::WITH_VERSION>(const_cast<MembershipUpdate &>(update));
                Vector<u8> payload;
                for (const auto &b : buf) {
                    payload.push_back(b);
                }

                Envelope env =
                    crypto::create_signed_envelope(MsgType::MembershipUpdate, local_node_id_, local_ed25519_, payload);

                auto serialized = crypto::serialize_envelope(env);

                for (const auto &ep : peer_endpoints) {
                    auto res = socket_->send_to(serialized, to_udp_endpoint(ep));
                    if (res.is_err()) {
                        echo::warn("Failed to send membership update to peer");
                    }
                }

                return result::ok();
            }

            // Send endpoint advertisement
            auto send_endpoint_advert(const EndpointAdvert &advert, const Vector<Endpoint> &peer_endpoints) -> VoidRes {
                auto buf = dp::serialize<dp::Mode::WITH_VERSION>(const_cast<EndpointAdvert &>(advert));
                Vector<u8> payload;
                for (const auto &b : buf) {
                    payload.push_back(b);
                }

                Envelope env =
                    crypto::create_signed_envelope(MsgType::EndpointAdvert, local_node_id_, local_ed25519_, payload);

                auto serialized = crypto::serialize_envelope(env);

                for (const auto &ep : peer_endpoints) {
                    auto res = socket_->send_to(serialized, to_udp_endpoint(ep));
                    if (res.is_err()) {
                        echo::warn("Failed to send endpoint advert to peer");
                    }
                }

                return result::ok();
            }

            // Send chain sync request to a peer
            auto send_chain_sync_request(const Endpoint &peer_endpoint) -> VoidRes {
                if (trust_chain_ == nullptr) {
                    return result::err(err::invalid("Trust chain not configured"));
                }

                ChainSyncRequest req;
                req.requester_id = local_node_id_;
                req.known_height = trust_chain_->length();
                req.timestamp_ms = time::now_ms();

                auto buf = dp::serialize<dp::Mode::WITH_VERSION>(req);
                Vector<u8> payload;
                for (const auto &b : buf) {
                    payload.push_back(b);
                }

                // Use special control message type for chain sync
                Envelope env = crypto::create_signed_envelope(
                    static_cast<MsgType>(ControlMsgType::ChainSyncRequest), local_node_id_, local_ed25519_, payload);

                auto serialized = crypto::serialize_envelope(env);
                auto res = socket_->send_to(serialized, to_udp_endpoint(peer_endpoint));
                if (res.is_err()) {
                    return result::err(err::io("Failed to send chain sync request"));
                }

                echo::debug("ControlPlane: Sent chain sync request (local height: ", req.known_height, ")");
                return result::ok();
            }

            // Send chain sync response to a peer
            auto send_chain_sync_response(const ChainSyncResponse &response, const Endpoint &peer_endpoint) -> VoidRes {
                auto buf = dp::serialize<dp::Mode::WITH_VERSION>(const_cast<ChainSyncResponse &>(response));
                Vector<u8> payload;
                for (const auto &b : buf) {
                    payload.push_back(b);
                }

                Envelope env = crypto::create_signed_envelope(
                    static_cast<MsgType>(ControlMsgType::ChainSyncResponse), local_node_id_, local_ed25519_, payload);

                auto serialized = crypto::serialize_envelope(env);
                auto res = socket_->send_to(serialized, to_udp_endpoint(peer_endpoint));
                if (res.is_err()) {
                    return result::err(err::io("Failed to send chain sync response"));
                }

                echo::debug("ControlPlane: Sent chain sync response (events: ", response.events.size(), ")");
                return result::ok();
            }

            // =============================================================================
            // Sponsor -> Voting Workflow
            // =============================================================================

            // Submit a pending sponsor request to both chain and voting manager
            auto submit_and_track_proposal(const NodeId &candidate_id) -> VoidRes {
                if (sponsor_ == nullptr || voting_ == nullptr || trust_chain_ == nullptr) {
                    return result::err(err::invalid("Sponsor/voting/chain not configured"));
                }

                auto pending = sponsor_->get_pending(candidate_id);
                if (!pending.has_value()) {
                    return result::err(err::not_found("No pending request from this candidate"));
                }

                // Create join proposal from sponsor request
                JoinProposal proposal;
                proposal.candidate_id = pending->request.candidate_id;
                proposal.candidate_ed25519 = pending->request.candidate_ed25519;
                proposal.candidate_x25519 = pending->request.candidate_x25519;
                proposal.sponsor_id = local_node_id_;
                proposal.timestamp_ms = time::now_ms();
                proposal.justification = pending->request.metadata;

                // Submit to trust chain
                auto chain_res = trust_chain_->propose_join(proposal);
                if (chain_res.is_err()) {
                    return chain_res;
                }

                // Add to voting manager for tracking
                auto voting_res = voting_->add_proposal(proposal);
                if (voting_res.is_err()) {
                    return voting_res;
                }

                echo::info("ControlPlane: Submitted proposal to chain and voting manager");
                return result::ok();
            }

            // Process a voting decision and emit membership update
            auto process_decision(const NodeId &candidate_id, const Vector<Endpoint> &peer_endpoints) -> VoidRes {
                if (voting_ == nullptr || trust_chain_ == nullptr || trust_view_ == nullptr) {
                    return result::err(err::invalid("Voting/chain/view not configured"));
                }

                auto proposal = voting_->get_proposal(candidate_id);
                if (!proposal.has_value()) {
                    return result::err(err::not_found("No proposal found"));
                }

                if (!proposal->decided) {
                    return result::err(err::invalid("Proposal not yet decided"));
                }

                // Record decision to chain
                MembershipDecision decision;
                decision.candidate_id = proposal->candidate_id;
                decision.candidate_ed25519 = proposal->candidate_ed25519;
                decision.candidate_x25519 = proposal->candidate_x25519;
                decision.approved = proposal->approved;
                decision.yes_votes = proposal->count_yes();
                decision.no_votes = proposal->count_no();
                decision.abstain_votes = proposal->count_abstain();
                decision.timestamp_ms = time::now_ms();

                auto chain_res = trust_chain_->record_decision(decision);
                if (chain_res.is_err()) {
                    echo::warn("Failed to record decision to chain: ", chain_res.error().message.c_str());
                }

                // Update trust view
                if (proposal->approved) {
                    MemberEntry entry;
                    entry.node_id = proposal->candidate_id;
                    entry.ed25519_pubkey = proposal->candidate_ed25519;
                    entry.x25519_pubkey = proposal->candidate_x25519;
                    entry.status = MemberStatus::Approved;
                    entry.joined_at_ms = time::now_ms();
                    trust_view_->add_member(entry);
                }

                // Emit membership update to peers
                MembershipUpdate update;
                update.candidate_id = candidate_id;
                update.approved = proposal->approved;
                update.chain_height = trust_chain_->length();
                update.timestamp_ms = time::now_ms();

                auto send_res = send_membership_update(update, peer_endpoints);
                if (send_res.is_err()) {
                    echo::warn("Failed to send membership update to peers");
                }

                // Clean up sponsor request
                if (sponsor_ != nullptr) {
                    sponsor_->remove_request(candidate_id);
                }

                echo::info("ControlPlane: Processed membership decision - ",
                           proposal->approved ? "APPROVED" : "REJECTED");
                return result::ok();
            }

            // Check all pending proposals for decisions and process them
            auto process_pending_decisions(const Vector<Endpoint> &peer_endpoints) -> Vector<NodeId> {
                Vector<NodeId> processed;
                if (voting_ == nullptr) {
                    return processed;
                }

                // First process timeouts
                auto expired = voting_->process_timeouts();
                for (const auto &id : expired) {
                    auto res = process_decision(id, peer_endpoints);
                    if (res.is_ok()) {
                        processed.push_back(id);
                    }
                }

                // Check for any decided proposals
                auto decided = voting_->get_decided_proposals();
                for (const auto &state : decided) {
                    // Skip if already processed (e.g., by timeout)
                    bool already_processed = false;
                    for (const auto &id : processed) {
                        if (id == state.candidate_id) {
                            already_processed = true;
                            break;
                        }
                    }
                    if (already_processed) {
                        continue;
                    }

                    // Process if recently decided (within last few seconds)
                    u64 age = time::now_ms() - state.decided_at_ms;
                    if (age < 5000) {
                        auto res = process_decision(state.candidate_id, peer_endpoints);
                        if (res.is_ok()) {
                            processed.push_back(state.candidate_id);
                        }
                    }
                }

                return processed;
            }

            // =============================================================================
            // Receiving
            // =============================================================================

            // Handle incoming envelope
            auto handle_envelope(const Envelope &env, const PublicKey &sender_pubkey, const Endpoint &sender_ep)
                -> VoidRes {
                // Validate envelope (timestamp + signature)
                auto validation = crypto::validate_envelope(env, sender_pubkey, max_envelope_age_ms_);
                if (validation.is_err()) {
                    echo::warn("ControlPlane: Envelope validation failed: ", validation.error().message.c_str());
                    return validation;
                }

                // Rate limit check
                if (!check_rate_limit(env.sender_id)) {
                    return result::err(err::permission("Rate limited"));
                }

                switch (env.msg_type) {
                case MsgType::JoinRequest:
                    return handle_join_request(env, sender_ep);
                case MsgType::VoteCast:
                    return handle_vote_cast(env);
                case MsgType::MembershipUpdate:
                    return handle_membership_update(env);
                case MsgType::EndpointAdvert:
                    return handle_endpoint_advert(env);
                case static_cast<MsgType>(ControlMsgType::ChainSyncRequest):
                    return handle_chain_sync_request(env, sender_ep);
                case static_cast<MsgType>(ControlMsgType::ChainSyncResponse):
                    return handle_chain_sync_response(env);
                default:
                    return result::err(err::invalid("Unknown control message type"));
                }
            }

          private:
            auto check_rate_limit(const NodeId &sender_id) -> boolean {
                u64 now = time::now_ms();
                auto it = last_request_time_.find(sender_id);
                if (it != last_request_time_.end()) {
                    if (now - it->second < rate_limit_ms_) {
                        return false;
                    }
                }
                last_request_time_[sender_id] = now;
                return true;
            }

            auto handle_join_request(const Envelope &env, const Endpoint & /*sender_ep*/) -> VoidRes {
                if (sponsor_ == nullptr) {
                    return result::err(err::invalid("Not configured as sponsor"));
                }

                auto req_res = sponsor::deserialize_join_request(env.payload);
                if (req_res.is_err()) {
                    return result::err(req_res.error());
                }

                return sponsor_->receive_request(req_res.value());
            }

            auto handle_vote_cast(const Envelope &env) -> VoidRes {
                if (voting_ == nullptr) {
                    return result::err(err::invalid("Voting not configured"));
                }

                auto evt_res = trust::deserialize_event(env.payload);
                if (evt_res.is_err()) {
                    return result::err(evt_res.error());
                }

                const auto &evt = evt_res.value();
                if (evt.kind != TrustEventKind::VoteCast) {
                    return result::err(err::invalid("Not a vote cast event"));
                }

                // Check if sender is an approved member
                if (trust_view_ != nullptr && !trust_view_->is_member(env.sender_id)) {
                    return result::err(err::permission("Non-member cannot vote"));
                }

                VoteCastEvent vote_evt;
                vote_evt.candidate_id = evt.subject_id;
                vote_evt.voter_id = evt.actor_id;
                vote_evt.vote = evt.vote;
                vote_evt.timestamp_ms = evt.timestamp_ms;
                vote_evt.reason = evt.metadata;

                // Record vote to trust chain
                if (trust_chain_ != nullptr) {
                    auto chain_res = trust_chain_->cast_vote(vote_evt);
                    if (chain_res.is_err()) {
                        echo::warn("Failed to record vote to chain: ", chain_res.error().message.c_str());
                    }
                }

                // Record vote in voting manager
                auto vote_res = voting_->record_vote(vote_evt);
                if (vote_res.is_err()) {
                    return result::err(vote_res.error());
                }

                // Check if vote caused a decision
                VoteResult result = vote_res.value();
                if (result == VoteResult::Approved) {
                    echo::info("ControlPlane: Vote caused APPROVAL for candidate - call process_pending_decisions()");
                } else if (result == VoteResult::Rejected) {
                    echo::info("ControlPlane: Vote caused REJECTION for candidate - call process_pending_decisions()");
                }

                return result::ok();
            }

            auto handle_membership_update(const Envelope &env) -> VoidRes {
                // Verify sender is approved member
                if (trust_view_ != nullptr && !trust_view_->is_member(env.sender_id)) {
                    return result::err(err::permission("Non-member cannot send updates"));
                }

                auto update_res = serial::deserialize<MembershipUpdate>(env.payload);
                if (update_res.is_err()) {
                    return result::err(update_res.error());
                }

                const auto &update = update_res.value();

                // Check if we already know about this decision
                if (voting_ != nullptr) {
                    auto proposal = voting_->get_proposal(update.candidate_id);
                    if (proposal.has_value() && proposal->decided) {
                        // We already processed this decision
                        echo::debug("ControlPlane: Received redundant membership update");
                        return result::ok();
                    }
                }

                // Check chain height - if sender's chain is ahead, we may need to sync
                if (trust_chain_ != nullptr && update.chain_height > trust_chain_->length()) {
                    echo::info("ControlPlane: Peer has newer chain (", update.chain_height, " vs ",
                               trust_chain_->length(), ") - chain sync may be needed");
                }

                echo::info("ControlPlane: Received membership update - candidate ",
                           update.approved ? "APPROVED" : "REJECTED");

                // Note: Full handling would require verifying the decision against the chain
                // For gossip protocol, we trust updates from approved members but should
                // verify against our own chain state before applying

                return result::ok();
            }

            auto handle_endpoint_advert(const Envelope &env) -> VoidRes {
                // Verify sender is approved member
                if (trust_view_ != nullptr && !trust_view_->is_member(env.sender_id)) {
                    return result::err(err::permission("Non-member cannot advertise endpoints"));
                }

                auto advert_res = serial::deserialize<EndpointAdvert>(env.payload);
                if (advert_res.is_err()) {
                    return result::err(advert_res.error());
                }

                echo::debug("Received endpoint advertisement");
                // TODO: Update peer endpoint cache

                return result::ok();
            }

            auto handle_chain_sync_request(const Envelope &env, const Endpoint &sender_ep) -> VoidRes {
                // Verify sender is approved member
                if (trust_view_ != nullptr && !trust_view_->is_member(env.sender_id)) {
                    return result::err(err::permission("Non-member cannot request chain sync"));
                }

                if (trust_chain_ == nullptr) {
                    return result::err(err::invalid("Trust chain not configured"));
                }

                auto req_res = serial::deserialize<ChainSyncRequest>(env.payload);
                if (req_res.is_err()) {
                    return result::err(req_res.error());
                }

                const auto &req = req_res.value();
                u64 local_height = trust_chain_->length();

                echo::debug("ControlPlane: Received chain sync request (peer height: ", req.known_height,
                            ", local height: ", local_height, ")");

                // If peer is already up to date or ahead, nothing to send
                if (req.known_height >= local_height) {
                    echo::debug("ControlPlane: Peer already up to date");
                    return result::ok();
                }

                // Build response with events the peer doesn't have
                ChainSyncResponse response;
                response.chain_height = local_height;
                response.start_height = req.known_height;
                response.timestamp_ms = time::now_ms();

                // Get all events from chain and send those after peer's known height
                auto all_events = trust_chain_->get_all_nodes_with_latest_event();
                for (const auto &[node_id, evt] : all_events) {
                    // Include events the peer might not have
                    response.events.push_back(evt);
                }

                // Send response back to requester
                return send_chain_sync_response(response, sender_ep);
            }

            auto handle_chain_sync_response(const Envelope &env) -> VoidRes {
                // Verify sender is approved member
                if (trust_view_ != nullptr && !trust_view_->is_member(env.sender_id)) {
                    return result::err(err::permission("Non-member cannot send chain sync response"));
                }

                if (trust_chain_ == nullptr || trust_view_ == nullptr) {
                    return result::err(err::invalid("Trust chain/view not configured"));
                }

                auto resp_res = serial::deserialize<ChainSyncResponse>(env.payload);
                if (resp_res.is_err()) {
                    return result::err(resp_res.error());
                }

                const auto &resp = resp_res.value();
                echo::info("ControlPlane: Received chain sync response with ", resp.events.size(), " events");

                // Process each event and update local state
                for (const auto &evt : resp.events) {
                    // Validate and add event to local chain
                    auto add_res = trust_chain_->add_event(evt);
                    if (add_res.is_err()) {
                        echo::warn("ControlPlane: Failed to add synced event: ", add_res.error().message.c_str());
                        continue;
                    }

                    // Update trust view based on event type
                    if (evt.kind == TrustEventKind::JoinApproved) {
                        MemberEntry entry;
                        entry.node_id = evt.subject_id;
                        entry.ed25519_pubkey = evt.subject_pubkey;
                        entry.x25519_pubkey = evt.subject_x25519;
                        entry.status = MemberStatus::Approved;
                        entry.joined_at_ms = evt.timestamp_ms;
                        trust_view_->add_member(entry);
                        echo::info("ControlPlane: Synced new member from chain");
                    } else if (evt.kind == TrustEventKind::MemberRevoked) {
                        trust_view_->remove_member(evt.subject_id);
                        echo::info("ControlPlane: Synced member revocation from chain");
                    }
                }

                echo::info("ControlPlane: Chain sync complete (new height: ", trust_chain_->length(), ")");
                return result::ok();
            }
        };

    } // namespace net

} // namespace botlink
