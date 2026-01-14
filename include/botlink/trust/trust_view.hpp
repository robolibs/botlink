/* SPDX-License-Identifier: MIT */
/*
 * Botlink Trust View
 * In-memory membership table derived from trust chain
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/time.hpp>
#include <botlink/core/types.hpp>
#include <botlink/trust/trust_chain.hpp>
#include <datapod/datapod.hpp>

namespace botlink {

    using namespace dp;

    // =============================================================================
    // Member Entry - In-memory record of a member
    // =============================================================================

    struct MemberEntry {
        NodeId node_id;
        PublicKey ed25519_pubkey;
        PublicKey x25519_pubkey;
        MemberStatus status = MemberStatus::Unconfigured;
        u64 joined_at_ms = 0;
        u64 last_seen_ms = 0;
        Vector<Endpoint> endpoints;

        MemberEntry() = default;

        [[nodiscard]] auto is_active() const -> boolean { return status == MemberStatus::Approved; }

        auto members() noexcept {
            return std::tie(node_id, ed25519_pubkey, x25519_pubkey, status, joined_at_ms, last_seen_ms, endpoints);
        }
        auto members() const noexcept {
            return std::tie(node_id, ed25519_pubkey, x25519_pubkey, status, joined_at_ms, last_seen_ms, endpoints);
        }
    };

    // =============================================================================
    // Pending Proposal - Tracks an in-progress join proposal
    // =============================================================================

    struct PendingProposal {
        NodeId candidate_id;
        PublicKey candidate_ed25519;
        PublicKey candidate_x25519;
        NodeId sponsor_id;
        u64 proposed_at_ms = 0;
        u64 expires_at_ms = 0;
        Map<NodeId, Vote> votes;

        PendingProposal() = default;

        [[nodiscard]] auto count_yes() const -> u32 {
            u32 count = 0;
            for (const auto &[_, vote] : votes) {
                if (vote == Vote::Yes)
                    ++count;
            }
            return count;
        }

        [[nodiscard]] auto count_no() const -> u32 {
            u32 count = 0;
            for (const auto &[_, vote] : votes) {
                if (vote == Vote::No)
                    ++count;
            }
            return count;
        }

        [[nodiscard]] auto is_expired() const -> boolean { return time::now_ms() >= expires_at_ms; }

        auto members() noexcept {
            return std::tie(candidate_id, candidate_ed25519, candidate_x25519, sponsor_id, proposed_at_ms,
                            expires_at_ms, votes);
        }
        auto members() const noexcept {
            return std::tie(candidate_id, candidate_ed25519, candidate_x25519, sponsor_id, proposed_at_ms,
                            expires_at_ms, votes);
        }
    };

    // =============================================================================
    // Trust View - In-memory membership table
    // =============================================================================

    class TrustView {
      private:
        Map<NodeId, MemberEntry> members_;
        Map<NodeId, PendingProposal> pending_;
        u32 min_yes_votes_ = 2;
        u64 vote_timeout_ms_ = 15000;

      public:
        TrustView() = default;

        explicit TrustView(u32 min_yes_votes, u64 vote_timeout_ms)
            : min_yes_votes_(min_yes_votes), vote_timeout_ms_(vote_timeout_ms) {}

        // =============================================================================
        // Member Queries
        // =============================================================================

        [[nodiscard]] auto is_member(const NodeId &id) const -> boolean {
            auto it = members_.find(id);
            return it != members_.end() && it->second.is_active();
        }

        [[nodiscard]] auto get_member(const NodeId &id) const -> Optional<MemberEntry> {
            auto it = members_.find(id);
            if (it != members_.end()) {
                return it->second;
            }
            return nullopt;
        }

        [[nodiscard]] auto get_all_members() const -> Vector<MemberEntry> {
            Vector<MemberEntry> result;
            for (const auto &[_, entry] : members_) {
                if (entry.is_active()) {
                    result.push_back(entry);
                }
            }
            return result;
        }

        [[nodiscard]] auto member_count() const -> usize {
            usize count = 0;
            for (const auto &[_, entry] : members_) {
                if (entry.is_active())
                    ++count;
            }
            return count;
        }

        // Get public key for a member
        [[nodiscard]] auto get_ed25519_pubkey(const NodeId &id) const -> Optional<PublicKey> {
            auto it = members_.find(id);
            if (it != members_.end()) {
                return it->second.ed25519_pubkey;
            }
            return nullopt;
        }

        [[nodiscard]] auto get_x25519_pubkey(const NodeId &id) const -> Optional<PublicKey> {
            auto it = members_.find(id);
            if (it != members_.end()) {
                return it->second.x25519_pubkey;
            }
            return nullopt;
        }

        // =============================================================================
        // Membership Mutations
        // =============================================================================

        // Add a new approved member directly (for genesis or sync)
        auto add_member(const MemberEntry &entry) -> void { members_[entry.node_id] = entry; }

        // Remove a member (revoke)
        auto remove_member(const NodeId &id) -> boolean {
            auto it = members_.find(id);
            if (it != members_.end()) {
                it->second.status = MemberStatus::Revoked;
                return true;
            }
            return false;
        }

        // Update member's last seen time
        auto touch_member(const NodeId &id) -> void {
            auto it = members_.find(id);
            if (it != members_.end()) {
                it->second.last_seen_ms = time::now_ms();
            }
        }

        // Update member's endpoint list
        auto update_endpoints(const NodeId &id, Vector<Endpoint> endpoints) -> void {
            auto it = members_.find(id);
            if (it != members_.end()) {
                it->second.endpoints = std::move(endpoints);
            }
        }

        // =============================================================================
        // Proposal Management
        // =============================================================================

        // Create a new join proposal
        auto create_proposal(const JoinProposal &proposal) -> VoidRes {
            if (is_member(proposal.candidate_id)) {
                return result::err(err::invalid("Node is already a member"));
            }

            if (pending_.find(proposal.candidate_id) != pending_.end()) {
                return result::err(err::invalid("Proposal already pending for this node"));
            }

            PendingProposal pending;
            pending.candidate_id = proposal.candidate_id;
            pending.candidate_ed25519 = proposal.candidate_ed25519;
            pending.candidate_x25519 = proposal.candidate_x25519;
            pending.sponsor_id = proposal.sponsor_id;
            pending.proposed_at_ms = time::now_ms();
            pending.expires_at_ms = pending.proposed_at_ms + vote_timeout_ms_;

            pending_[proposal.candidate_id] = pending;
            return result::ok();
        }

        // Record a vote for a pending proposal
        auto record_vote(const NodeId &candidate_id, const NodeId &voter_id, Vote vote) -> VoidRes {
            auto it = pending_.find(candidate_id);
            if (it == pending_.end()) {
                return result::err(err::not_found("No pending proposal for this node"));
            }

            if (!is_member(voter_id)) {
                return result::err(err::permission("Voter is not a member"));
            }

            it->second.votes[voter_id] = vote;
            return result::ok();
        }

        // Check if a proposal has reached quorum and should be decided
        [[nodiscard]] auto check_proposal_status(const NodeId &candidate_id) const
            -> Tuple<boolean, boolean, u32, u32> {
            // Returns: (has_quorum, is_approved, yes_count, no_count)

            auto it = pending_.find(candidate_id);
            if (it == pending_.end()) {
                return {false, false, 0, 0};
            }

            u32 yes_count = it->second.count_yes();
            u32 no_count = it->second.count_no();

            boolean has_quorum = yes_count >= min_yes_votes_ || no_count >= min_yes_votes_;
            boolean is_approved = yes_count >= min_yes_votes_;

            return Tuple<boolean, boolean, u32, u32>(std::move(has_quorum), std::move(is_approved),
                                                     std::move(yes_count), std::move(no_count));
        }

        // Approve a pending proposal
        auto approve_proposal(const NodeId &candidate_id) -> VoidRes {
            auto it = pending_.find(candidate_id);
            if (it == pending_.end()) {
                return result::err(err::not_found("No pending proposal for this node"));
            }

            MemberEntry entry;
            entry.node_id = it->second.candidate_id;
            entry.ed25519_pubkey = it->second.candidate_ed25519;
            entry.x25519_pubkey = it->second.candidate_x25519;
            entry.status = MemberStatus::Approved;
            entry.joined_at_ms = time::now_ms();

            members_[candidate_id] = entry;
            pending_.erase(it);

            return result::ok();
        }

        // Reject a pending proposal
        auto reject_proposal(const NodeId &candidate_id) -> VoidRes {
            auto it = pending_.find(candidate_id);
            if (it == pending_.end()) {
                return result::err(err::not_found("No pending proposal for this node"));
            }

            pending_.erase(it);
            return result::ok();
        }

        // Get pending proposal
        [[nodiscard]] auto get_pending_proposal(const NodeId &candidate_id) const -> Optional<PendingProposal> {
            auto it = pending_.find(candidate_id);
            if (it != pending_.end()) {
                return it->second;
            }
            return nullopt;
        }

        // Get all pending proposals
        [[nodiscard]] auto get_all_pending() const -> Vector<PendingProposal> {
            Vector<PendingProposal> result;
            for (const auto &[_, proposal] : pending_) {
                result.push_back(proposal);
            }
            return result;
        }

        // Clean up expired proposals
        auto cleanup_expired() -> Vector<NodeId> {
            Vector<NodeId> expired;
            // First pass: collect expired node IDs
            for (const auto &[node_id, proposal] : pending_) {
                if (proposal.is_expired()) {
                    expired.push_back(node_id);
                }
            }
            // Second pass: remove expired proposals
            for (const auto &node_id : expired) {
                pending_.erase(node_id);
            }
            return expired;
        }

        // =============================================================================
        // Sync from Trust Chain
        // =============================================================================

        // Rebuild view from trust chain
        // Processes full event history to compute current status for each member
        // Handles JoinApproved, JoinRejected, and MemberRevoked events properly
        auto sync_from_chain(const TrustChain &chain) -> void {
            members_.clear();
            pending_.clear();

            // Get all nodes with their latest events
            auto nodes_with_events = chain.get_all_nodes_with_latest_event();

            for (const auto &[node_id, latest_evt] : nodes_with_events) {
                MemberEntry entry;
                entry.node_id = node_id;
                entry.ed25519_pubkey = latest_evt.subject_pubkey;
                entry.x25519_pubkey = latest_evt.subject_x25519;

                // Determine status based on the latest event kind
                switch (latest_evt.kind) {
                case TrustEventKind::JoinApproved:
                    entry.status = MemberStatus::Approved;
                    entry.joined_at_ms = latest_evt.timestamp_ms;
                    members_[node_id] = entry;
                    break;

                case TrustEventKind::JoinRejected:
                    // Rejected members are tracked but not active
                    entry.status = MemberStatus::Rejected;
                    members_[node_id] = entry;
                    break;

                case TrustEventKind::MemberRevoked:
                    // Revoked members are tracked but not active
                    // They may have been previously approved
                    entry.status = MemberStatus::Revoked;
                    members_[node_id] = entry;
                    break;

                case TrustEventKind::JoinProposed:
                case TrustEventKind::VoteCast:
                    // These represent pending proposals - add to pending_
                    {
                        PendingProposal proposal;
                        proposal.candidate_id = node_id;
                        proposal.candidate_ed25519 = latest_evt.subject_pubkey;
                        proposal.candidate_x25519 = latest_evt.subject_x25519;
                        proposal.sponsor_id = latest_evt.actor_id;
                        proposal.proposed_at_ms = latest_evt.timestamp_ms;
                        proposal.expires_at_ms = latest_evt.timestamp_ms + vote_timeout_ms_;
                        pending_[node_id] = proposal;
                    }
                    break;
                }
            }
        }
    };

} // namespace botlink
