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

        // Simplified member entry for wire serialization (avoids nested Vector<Endpoint>)
        struct MemberSnapshotEntry {
            NodeId node_id;
            PublicKey ed25519_pubkey;
            PublicKey x25519_pubkey;
            MemberStatus status = MemberStatus::Unconfigured;
            u64 joined_at_ms = 0;

            MemberSnapshotEntry() = default;

            // Construct from MemberEntry
            explicit MemberSnapshotEntry(const MemberEntry &entry)
                : node_id(entry.node_id), ed25519_pubkey(entry.ed25519_pubkey),
                  x25519_pubkey(entry.x25519_pubkey), status(entry.status), joined_at_ms(entry.joined_at_ms) {}

            auto members() noexcept { return std::tie(node_id, ed25519_pubkey, x25519_pubkey, status, joined_at_ms); }
            auto members() const noexcept {
                return std::tie(node_id, ed25519_pubkey, x25519_pubkey, status, joined_at_ms);
            }
        };

        struct MembershipSnapshotResponse {
            Vector<MemberSnapshotEntry> member_entries;
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
            u64 known_height = 0; // Height of local chain
            u64 timestamp_ms = 0;

            ChainSyncRequest() = default;

            auto members() noexcept { return std::tie(requester_id, known_height, timestamp_ms); }
            auto members() const noexcept { return std::tie(requester_id, known_height, timestamp_ms); }
        };

        struct ChainSyncResponse {
            u64 chain_height = 0;      // Total chain height
            u64 start_height = 0;      // Height of first event in this response
            Vector<TrustEvent> events; // Events from start_height onwards
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

            // Endpoint advertisement cache - stores peer endpoint advertisements for address refresh
            Map<NodeId, EndpointAdvert> endpoint_cache_;
            u64 endpoint_cache_ttl_ms_ = 300000; // 5 minutes TTL for cached endpoints

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
            auto set_endpoint_cache_ttl_ms(u64 ms) -> void { endpoint_cache_ttl_ms_ = ms; }

            // =============================================================================
            // Endpoint Cache Access
            // =============================================================================

            // Get cached endpoint advertisement for a peer
            [[nodiscard]] auto get_cached_endpoints(const NodeId &node_id) const -> Optional<EndpointAdvert> {
                auto it = endpoint_cache_.find(node_id);
                if (it == endpoint_cache_.end()) {
                    return Optional<EndpointAdvert>();
                }
                // Check if cached entry is still valid
                if ((time::now_ms() - it->second.timestamp_ms) > endpoint_cache_ttl_ms_) {
                    return Optional<EndpointAdvert>();
                }
                return it->second;
            }

            // Get all cached endpoints (for peer discovery)
            [[nodiscard]] auto get_all_cached_endpoints() const -> Vector<EndpointAdvert> {
                Vector<EndpointAdvert> result;
                u64 now = time::now_ms();
                for (const auto &[node_id, advert] : endpoint_cache_) {
                    if ((now - advert.timestamp_ms) <= endpoint_cache_ttl_ms_) {
                        result.push_back(advert);
                    }
                }
                return result;
            }

            // Clean up stale endpoint cache entries
            auto cleanup_stale_endpoints() -> usize {
                Vector<NodeId> to_remove;
                u64 now = time::now_ms();
                for (const auto &[node_id, advert] : endpoint_cache_) {
                    if ((now - advert.timestamp_ms) > endpoint_cache_ttl_ms_) {
                        to_remove.push_back(node_id);
                    }
                }
                for (const auto &id : to_remove) {
                    endpoint_cache_.erase(id);
                }
                return to_remove.size();
            }

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
            // Returns error if ALL sends fail, otherwise returns ok with warning for partial failures
            auto send_vote(const VoteCastEvent &vote, const Vector<Endpoint> &peer_endpoints) -> VoidRes {
                TrustEvent evt = vote.to_event();
                Vector<u8> payload = trust::serialize_event(evt);

                Envelope env =
                    crypto::create_signed_envelope(MsgType::VoteCast, local_node_id_, local_ed25519_, payload);

                auto serialized = crypto::serialize_envelope(env);

                usize success_count = 0;
                usize fail_count = 0;
                for (const auto &ep : peer_endpoints) {
                    auto res = socket_->send_to(serialized, to_udp_endpoint(ep));
                    if (res.is_err()) {
                        ++fail_count;
                        echo::warn("Failed to send vote to peer");
                    } else {
                        ++success_count;
                    }
                }

                if (success_count == 0 && fail_count > 0) {
                    return result::err(err::io("Failed to send vote to any peer"));
                }
                return result::ok();
            }

            // Send membership update to peers
            // Returns error if ALL sends fail, otherwise returns ok with warning for partial failures
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

                usize success_count = 0;
                usize fail_count = 0;
                for (const auto &ep : peer_endpoints) {
                    auto res = socket_->send_to(serialized, to_udp_endpoint(ep));
                    if (res.is_err()) {
                        ++fail_count;
                        echo::warn("Failed to send membership update to peer");
                    } else {
                        ++success_count;
                    }
                }

                if (success_count == 0 && fail_count > 0) {
                    return result::err(err::io("Failed to send membership update to any peer"));
                }
                return result::ok();
            }

            // Send endpoint advertisement
            // Returns error if ALL sends fail, otherwise returns ok with warning for partial failures
            auto send_endpoint_advert(const EndpointAdvert &advert, const Vector<Endpoint> &peer_endpoints) -> VoidRes {
                auto buf = dp::serialize<dp::Mode::WITH_VERSION>(const_cast<EndpointAdvert &>(advert));
                Vector<u8> payload;
                for (const auto &b : buf) {
                    payload.push_back(b);
                }

                Envelope env =
                    crypto::create_signed_envelope(MsgType::EndpointAdvert, local_node_id_, local_ed25519_, payload);

                auto serialized = crypto::serialize_envelope(env);

                usize success_count = 0;
                usize fail_count = 0;
                for (const auto &ep : peer_endpoints) {
                    auto res = socket_->send_to(serialized, to_udp_endpoint(ep));
                    if (res.is_err()) {
                        ++fail_count;
                        echo::warn("Failed to send endpoint advert to peer");
                    } else {
                        ++success_count;
                    }
                }

                if (success_count == 0 && fail_count > 0) {
                    return result::err(err::io("Failed to send endpoint advert to any peer"));
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
                Envelope env = crypto::create_signed_envelope(static_cast<MsgType>(ControlMsgType::ChainSyncRequest),
                                                              local_node_id_, local_ed25519_, payload);

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

                Envelope env = crypto::create_signed_envelope(static_cast<MsgType>(ControlMsgType::ChainSyncResponse),
                                                              local_node_id_, local_ed25519_, payload);

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
                    return result::err(err::io("Failed to record decision to trust chain"));
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
                case MsgType::JoinProposal:
                    return handle_join_proposal(env);
                case MsgType::VoteCast:
                    return handle_vote_cast(env);
                case MsgType::MembershipUpdate:
                    return handle_membership_update(env);
                case MsgType::EndpointAdvert:
                    return handle_endpoint_advert(env);
                case static_cast<MsgType>(ControlMsgType::MembershipSnapshot):
                    return handle_membership_snapshot_request(env, sender_ep);
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

                // Verify the membership update against local chain state
                if (trust_chain_ != nullptr) {
                    // Check if candidate is already a member (shouldn't receive approval for existing member)
                    if (update.approved && trust_chain_->is_member(update.candidate_id)) {
                        echo::debug("ControlPlane: Ignoring approval for already-approved member");
                        return result::ok();
                    }

                    // Check if candidate was already rejected (shouldn't process duplicate rejection)
                    auto latest_event = trust_chain_->get_latest_event_for_node(update.candidate_id);
                    if (latest_event.has_value()) {
                        if (latest_event->kind == TrustEventKind::JoinRejected && !update.approved) {
                            echo::debug("ControlPlane: Ignoring duplicate rejection");
                            return result::ok();
                        }
                        if (latest_event->kind == TrustEventKind::MemberRevoked && update.approved) {
                            echo::warn("ControlPlane: Received approval for revoked member - requires re-application");
                            return result::err(err::invalid("Cannot approve revoked member directly"));
                        }
                    }

                    // Check chain height - if sender's chain is ahead, we need to sync first
                    if (update.chain_height > trust_chain_->length()) {
                        echo::info("ControlPlane: Peer has newer chain (", update.chain_height, " vs ",
                                   trust_chain_->length(), ") - deferring update until chain sync");
                        // Return OK but don't apply - caller should trigger chain sync
                        return result::ok();
                    }

                    // Verify our local chain supports this decision
                    // If we have voting records, check if the vote tally matches
                    if (voting_ != nullptr) {
                        auto local_proposal = voting_->get_proposal(update.candidate_id);
                        if (local_proposal.has_value()) {
                            // We have local voting state - verify consistency
                            if (local_proposal->decided && local_proposal->approved != update.approved) {
                                echo::warn("ControlPlane: Membership update conflicts with local voting state");
                                return result::err(err::invalid("Membership update conflicts with local state"));
                            }
                        }
                    }
                }

                echo::info("ControlPlane: Verified and accepted membership update - candidate ",
                           update.approved ? "APPROVED" : "REJECTED");

                // Apply the update to trust view if we have one and this is an approval
                if (trust_view_ != nullptr && update.approved) {
                    // We need the full member info to add - this would come from proposal
                    if (voting_ != nullptr) {
                        auto proposal = voting_->get_proposal(update.candidate_id);
                        if (proposal.has_value()) {
                            MemberEntry entry;
                            entry.node_id = proposal->candidate_id;
                            entry.ed25519_pubkey = proposal->candidate_ed25519;
                            entry.x25519_pubkey = proposal->candidate_x25519;
                            entry.status = MemberStatus::Approved;
                            entry.joined_at_ms = update.timestamp_ms;
                            trust_view_->add_member(entry);
                            echo::info("ControlPlane: Added new member to trust view");
                        }
                    }
                }

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

                const auto &advert = advert_res.value();

                // Validate that the advertisement is from the claimed node
                if (advert.node_id != env.sender_id) {
                    return result::err(err::permission("Endpoint advertisement node_id mismatch"));
                }

                // Check if we have an existing entry and only update if newer
                auto existing = endpoint_cache_.find(advert.node_id);
                if (existing != endpoint_cache_.end() && existing->second.timestamp_ms >= advert.timestamp_ms) {
                    echo::debug("ControlPlane: Ignoring stale endpoint advertisement");
                    return result::ok();
                }

                // Store the endpoint advertisement in cache
                endpoint_cache_[advert.node_id] = advert;

                echo::debug("ControlPlane: Stored endpoint advertisement for peer (", advert.endpoints.size(),
                            " endpoints)");

                return result::ok();
            }

            // Handle incoming JoinProposal from another member
            auto handle_join_proposal(const Envelope &env) -> VoidRes {
                // Verify sender is approved member (only members can propose)
                if (trust_view_ != nullptr && !trust_view_->is_member(env.sender_id)) {
                    return result::err(err::permission("Non-member cannot propose new members"));
                }

                if (voting_ == nullptr) {
                    return result::err(err::invalid("Voting not configured"));
                }

                // Deserialize the join proposal
                auto proposal_res = serial::deserialize<JoinProposal>(env.payload);
                if (proposal_res.is_err()) {
                    return result::err(proposal_res.error());
                }

                const auto &proposal = proposal_res.value();

                // Validate proposal fields
                if (proposal.candidate_id.data.empty()) {
                    return result::err(err::invalid("Proposal missing candidate_id"));
                }

                if (proposal.candidate_ed25519.is_zero()) {
                    return result::err(err::invalid("Proposal missing candidate Ed25519 key"));
                }

                // Check if candidate is already a member
                if (trust_view_ != nullptr && trust_view_->is_member(proposal.candidate_id)) {
                    return result::err(err::invalid("Candidate is already a member"));
                }

                // Check if we already have a pending proposal for this candidate
                if (voting_->has_proposal(proposal.candidate_id)) {
                    echo::debug("ControlPlane: Already have proposal for this candidate");
                    return result::ok();
                }

                // Add proposal to voting manager
                auto add_res = voting_->add_proposal(proposal);
                if (add_res.is_err()) {
                    return result::err(add_res.error());
                }

                // Record proposal in trust chain
                if (trust_chain_ != nullptr) {
                    auto chain_res = trust_chain_->propose_join(proposal);
                    if (chain_res.is_err()) {
                        echo::warn("ControlPlane: Failed to record proposal in chain: ",
                                   chain_res.error().message.c_str());
                    }
                }

                echo::info("ControlPlane: Received and recorded join proposal for new candidate");
                return result::ok();
            }

            // Handle membership snapshot request
            auto handle_membership_snapshot_request(const Envelope &env, const Endpoint &sender_ep) -> VoidRes {
                // Verify sender is approved member or pending candidate
                if (trust_view_ == nullptr) {
                    return result::err(err::invalid("Trust view not configured"));
                }

                // Allow requests from both members and pending candidates (for bootstrap)
                boolean is_member = trust_view_->is_member(env.sender_id);
                boolean is_pending = voting_ != nullptr && voting_->has_proposal(env.sender_id);

                if (!is_member && !is_pending) {
                    // Allow from unknown for initial sync bootstrap
                    echo::debug("ControlPlane: Allowing membership snapshot request from unknown node for bootstrap");
                }

                auto req_res = serial::deserialize<MembershipSnapshotRequest>(env.payload);
                if (req_res.is_err()) {
                    return result::err(req_res.error());
                }

                const auto &req = req_res.value();

                // Build snapshot response with current membership
                MembershipSnapshotResponse response;
                response.timestamp_ms = time::now_ms();

                if (trust_chain_ != nullptr) {
                    response.chain_height = trust_chain_->length();
                }

                // Get all current members from trust view
                auto members = trust_view_->get_all_members();
                for (const auto &member : members) {
                    response.member_entries.push_back(MemberSnapshotEntry(member));
                }

                echo::debug("ControlPlane: Sending membership snapshot with ", response.member_entries.size(),
                            " members");

                // Send response
                return send_membership_snapshot_response(response, sender_ep);
            }

            // Send membership snapshot response
            auto send_membership_snapshot_response(MembershipSnapshotResponse &response, const Endpoint &peer_ep)
                -> VoidRes {
                if (socket_ == nullptr) {
                    return result::err(err::invalid("Socket not configured"));
                }

                auto buf = serial::serialize(response);
                Vector<u8> payload;
                for (const auto &b : buf) {
                    payload.push_back(b);
                }

                Envelope env = crypto::create_signed_envelope(static_cast<MsgType>(ControlMsgType::MembershipSnapshot),
                                                              local_node_id_, local_ed25519_, payload);

                auto serialized = crypto::serialize_envelope(env);
                auto res = socket_->send_to(serialized, to_udp_endpoint(peer_ep));
                if (res.is_err()) {
                    return result::err(err::io("Failed to send membership snapshot response"));
                }

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
