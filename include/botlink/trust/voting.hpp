/* SPDX-License-Identifier: MIT */
/*
 * Botlink Voting
 * Vote aggregation and timeout management for membership decisions
 */

#pragma once

#include <botlink/core/metrics.hpp>
#include <botlink/core/result.hpp>
#include <botlink/core/time.hpp>
#include <botlink/core/types.hpp>
#include <botlink/trust/trust_chain.hpp>
#include <botlink/trust/trust_event.hpp>
#include <datapod/datapod.hpp>
#include <echo/echo.hpp>

namespace botlink {

    using namespace dp;

    // =============================================================================
    // Vote Record - Tracks a single vote
    // =============================================================================

    struct VoteRecord {
        NodeId voter_id;
        Vote vote = Vote::Abstain;
        u64 timestamp_ms = 0;
        String reason;

        VoteRecord() = default;

        auto members() noexcept { return std::tie(voter_id, vote, timestamp_ms, reason); }
        auto members() const noexcept { return std::tie(voter_id, vote, timestamp_ms, reason); }
    };

    // =============================================================================
    // Proposal State - Tracks voting state for a proposal
    // =============================================================================

    struct ProposalState {
        NodeId candidate_id;
        NodeId sponsor_id;
        PublicKey candidate_ed25519;
        PublicKey candidate_x25519;
        u64 proposed_at_ms = 0;
        Vector<VoteRecord> votes;
        boolean decided = false;
        boolean approved = false;
        u64 decided_at_ms = 0;

        ProposalState() = default;

        [[nodiscard]] auto count_yes() const -> u32 {
            u32 count = 0;
            for (const auto &v : votes) {
                if (v.vote == Vote::Yes)
                    ++count;
            }
            return count;
        }

        [[nodiscard]] auto count_no() const -> u32 {
            u32 count = 0;
            for (const auto &v : votes) {
                if (v.vote == Vote::No)
                    ++count;
            }
            return count;
        }

        [[nodiscard]] auto count_abstain() const -> u32 {
            u32 count = 0;
            for (const auto &v : votes) {
                if (v.vote == Vote::Abstain)
                    ++count;
            }
            return count;
        }

        [[nodiscard]] auto has_voted(const NodeId &voter_id) const -> boolean {
            for (const auto &v : votes) {
                if (v.voter_id == voter_id)
                    return true;
            }
            return false;
        }

        [[nodiscard]] auto age_ms() const -> u64 { return time::now_ms() - proposed_at_ms; }

        [[nodiscard]] auto is_expired(u64 timeout_ms) const -> boolean { return !decided && age_ms() > timeout_ms; }

        auto members() noexcept {
            return std::tie(candidate_id, sponsor_id, candidate_ed25519, candidate_x25519, proposed_at_ms, votes,
                            decided, approved, decided_at_ms);
        }
        auto members() const noexcept {
            return std::tie(candidate_id, sponsor_id, candidate_ed25519, candidate_x25519, proposed_at_ms, votes,
                            decided, approved, decided_at_ms);
        }
    };

    // =============================================================================
    // Voting Policy - Configurable voting rules
    // =============================================================================

    struct VotingPolicy {
        u32 min_yes_votes = 2;       // Minimum yes votes to approve
        u32 min_no_votes = 2;        // Minimum no votes to reject (0 = only yes threshold matters)
        u64 vote_timeout_ms = 15000; // Timeout for voting (ms)
        boolean require_sponsor = true;

        VotingPolicy() = default;

        auto members() noexcept { return std::tie(min_yes_votes, min_no_votes, vote_timeout_ms, require_sponsor); }
        auto members() const noexcept {
            return std::tie(min_yes_votes, min_no_votes, vote_timeout_ms, require_sponsor);
        }
    };

    // =============================================================================
    // Vote Result
    // =============================================================================

    enum class VoteResult : u8 {
        Pending = 0,  // Still waiting for votes
        Approved = 1, // Got enough yes votes
        Rejected = 2, // Got enough no votes
        Expired = 3,  // Timed out without quorum
    };

    // =============================================================================
    // Voting Manager - Manages active proposals and vote collection
    // =============================================================================

    class VotingManager {
      private:
        VotingPolicy policy_;
        Map<NodeId, ProposalState> proposals_;
        NodeId local_node_id_;

      public:
        explicit VotingManager(const VotingPolicy &policy, const NodeId &local_id)
            : policy_(policy), local_node_id_(local_id) {}

        // =============================================================================
        // Proposal Management
        // =============================================================================

        // Start tracking a new proposal
        auto add_proposal(const JoinProposal &proposal) -> VoidRes {
            if (proposals_.find(proposal.candidate_id) != proposals_.end()) {
                return result::err(err::invalid("Proposal already exists for this candidate"));
            }

            ProposalState state;
            state.candidate_id = proposal.candidate_id;
            state.sponsor_id = proposal.sponsor_id;
            state.candidate_ed25519 = proposal.candidate_ed25519;
            state.candidate_x25519 = proposal.candidate_x25519;
            state.proposed_at_ms = proposal.timestamp_ms > 0 ? proposal.timestamp_ms : time::now_ms();
            state.decided = false;

            proposals_[proposal.candidate_id] = state;

            metrics::inc_proposals_received();
            echo::debug("VotingManager: Added proposal for candidate");
            return result::ok();
        }

        // Record a vote
        auto record_vote(const VoteCastEvent &vote_evt) -> Res<VoteResult> {
            auto it = proposals_.find(vote_evt.candidate_id);
            if (it == proposals_.end()) {
                return result::err(err::not_found("No proposal for this candidate"));
            }

            if (it->second.decided) {
                return result::err(err::invalid("Proposal already decided"));
            }

            // Check for duplicate vote
            if (it->second.has_voted(vote_evt.voter_id)) {
                return result::err(err::invalid("Voter has already voted"));
            }

            // Record the vote
            VoteRecord record;
            record.voter_id = vote_evt.voter_id;
            record.vote = vote_evt.vote;
            record.timestamp_ms = vote_evt.timestamp_ms > 0 ? vote_evt.timestamp_ms : time::now_ms();
            record.reason = vote_evt.reason;

            it->second.votes.push_back(record);

            metrics::inc_votes_received();
            echo::debug("VotingManager: Recorded vote");

            // Check if we've reached a decision
            return check_decision(it->second);
        }

        // Cast our own vote
        auto cast_vote(const NodeId &candidate_id, Vote vote, const String &reason = "") -> Res<VoteCastEvent> {
            auto it = proposals_.find(candidate_id);
            if (it == proposals_.end()) {
                return result::err(err::not_found("No proposal for this candidate"));
            }

            if (it->second.decided) {
                return result::err(err::invalid("Proposal already decided"));
            }

            if (it->second.has_voted(local_node_id_)) {
                return result::err(err::invalid("Already voted on this proposal"));
            }

            VoteCastEvent evt;
            evt.candidate_id = candidate_id;
            evt.voter_id = local_node_id_;
            evt.vote = vote;
            evt.timestamp_ms = time::now_ms();
            evt.reason = reason;

            metrics::inc_votes_cast();
            return result::ok(evt);
        }

        // =============================================================================
        // Decision Logic
        // =============================================================================

        [[nodiscard]] auto check_decision(ProposalState &state) -> Res<VoteResult> {
            if (state.decided) {
                return result::ok(state.approved ? VoteResult::Approved : VoteResult::Rejected);
            }

            u32 yes_count = state.count_yes();
            u32 no_count = state.count_no();

            // Check for approval
            if (yes_count >= policy_.min_yes_votes) {
                state.decided = true;
                state.approved = true;
                state.decided_at_ms = time::now_ms();
                metrics::inc_proposals_approved();
                echo::info("VotingManager: Proposal APPROVED");
                return result::ok(VoteResult::Approved);
            }

            // Check for rejection
            if (policy_.min_no_votes > 0 && no_count >= policy_.min_no_votes) {
                state.decided = true;
                state.approved = false;
                state.decided_at_ms = time::now_ms();
                metrics::inc_proposals_rejected();
                echo::info("VotingManager: Proposal REJECTED");
                return result::ok(VoteResult::Rejected);
            }

            // Check for expiration
            if (state.is_expired(policy_.vote_timeout_ms)) {
                state.decided = true;
                state.approved = false;
                state.decided_at_ms = time::now_ms();
                metrics::inc_proposals_expired();
                echo::info("VotingManager: Proposal EXPIRED");
                return result::ok(VoteResult::Expired);
            }

            return result::ok(VoteResult::Pending);
        }

        // =============================================================================
        // Query
        // =============================================================================

        [[nodiscard]] auto get_proposal(const NodeId &candidate_id) const -> Optional<ProposalState> {
            auto it = proposals_.find(candidate_id);
            if (it == proposals_.end()) {
                return Optional<ProposalState>();
            }
            return it->second;
        }

        [[nodiscard]] auto has_proposal(const NodeId &candidate_id) const -> boolean {
            return proposals_.find(candidate_id) != proposals_.end();
        }

        [[nodiscard]] auto get_pending_proposals() const -> Vector<ProposalState> {
            Vector<ProposalState> result;
            for (const auto &[_, state] : proposals_) {
                if (!state.decided) {
                    result.push_back(state);
                }
            }
            return result;
        }

        [[nodiscard]] auto get_decided_proposals() const -> Vector<ProposalState> {
            Vector<ProposalState> result;
            for (const auto &[_, state] : proposals_) {
                if (state.decided) {
                    result.push_back(state);
                }
            }
            return result;
        }

        // =============================================================================
        // Maintenance
        // =============================================================================

        // Process all proposals and check for timeouts
        auto process_timeouts() -> Vector<NodeId> {
            Vector<NodeId> expired;
            for (auto &[node_id, state] : proposals_) {
                if (!state.decided && state.is_expired(policy_.vote_timeout_ms)) {
                    state.decided = true;
                    state.approved = false;
                    state.decided_at_ms = time::now_ms();
                    expired.push_back(node_id);
                }
            }
            return expired;
        }

        // Remove decided proposals older than given age
        auto cleanup_decided(u64 max_age_ms) -> usize {
            Vector<NodeId> to_remove;
            u64 now = time::now_ms();
            for (const auto &[node_id, state] : proposals_) {
                if (state.decided && (now - state.decided_at_ms) > max_age_ms) {
                    to_remove.push_back(node_id);
                }
            }
            for (const auto &id : to_remove) {
                proposals_.erase(id);
            }
            return to_remove.size();
        }

        // Remove a specific proposal
        auto remove_proposal(const NodeId &candidate_id) -> void { proposals_.erase(candidate_id); }

        // Get policy
        [[nodiscard]] auto policy() const -> const VotingPolicy & { return policy_; }
    };

} // namespace botlink
