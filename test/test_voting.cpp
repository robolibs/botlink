/* SPDX-License-Identifier: MIT */
/*
 * Botlink Voting Tests
 * Tests for vote management and voting manager
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

// Helper to create a test NodeId
static NodeId make_node_id(u8 seed) {
    NodeId id;
    for (usize i = 0; i < NODE_ID_SIZE; ++i) {
        id.data[i] = static_cast<u8>(seed + i);
    }
    return id;
}

// Helper to create a test PublicKey
static PublicKey make_pubkey(u8 seed) {
    PublicKey key;
    for (usize i = 0; i < KEY_SIZE; ++i) {
        key.data[i] = static_cast<u8>(seed + i);
    }
    return key;
}

TEST_SUITE("Voting - VoteRecord") {

    TEST_CASE("VoteRecord default values") {
        VoteRecord record;
        CHECK(record.vote == Vote::Abstain);
        CHECK(record.timestamp_ms == 0);
        CHECK(record.reason.empty());
    }

    TEST_CASE("VoteRecord with values") {
        VoteRecord record;
        record.voter_id = make_node_id(1);
        record.vote = Vote::Yes;
        record.timestamp_ms = 12345;
        record.reason = "looks good";

        CHECK(record.vote == Vote::Yes);
        CHECK(record.timestamp_ms == 12345);
        CHECK(record.reason == "looks good");
    }

}

TEST_SUITE("Voting - ProposalState") {

    TEST_CASE("ProposalState default values") {
        ProposalState state;
        CHECK(state.proposed_at_ms == 0);
        CHECK(state.decided == false);
        CHECK(state.approved == false);
        CHECK(state.votes.empty());
    }

    TEST_CASE("ProposalState count_yes") {
        ProposalState state;

        VoteRecord v1;
        v1.vote = Vote::Yes;
        state.votes.push_back(v1);

        VoteRecord v2;
        v2.vote = Vote::Yes;
        state.votes.push_back(v2);

        VoteRecord v3;
        v3.vote = Vote::No;
        state.votes.push_back(v3);

        CHECK(state.count_yes() == 2);
    }

    TEST_CASE("ProposalState count_no") {
        ProposalState state;

        VoteRecord v1;
        v1.vote = Vote::No;
        state.votes.push_back(v1);

        VoteRecord v2;
        v2.vote = Vote::No;
        state.votes.push_back(v2);

        CHECK(state.count_no() == 2);
    }

    TEST_CASE("ProposalState count_abstain") {
        ProposalState state;

        VoteRecord v1;
        v1.vote = Vote::Abstain;
        state.votes.push_back(v1);

        CHECK(state.count_abstain() == 1);
    }

    TEST_CASE("ProposalState has_voted") {
        ProposalState state;
        NodeId voter1 = make_node_id(1);
        NodeId voter2 = make_node_id(2);

        VoteRecord v1;
        v1.voter_id = voter1;
        v1.vote = Vote::Yes;
        state.votes.push_back(v1);

        CHECK(state.has_voted(voter1) == true);
        CHECK(state.has_voted(voter2) == false);
    }

    TEST_CASE("ProposalState is_expired") {
        ProposalState state;
        state.proposed_at_ms = time::now_ms() - 20000;  // 20 seconds ago
        state.decided = false;

        CHECK(state.is_expired(15000) == true);  // 15 second timeout
        CHECK(state.is_expired(30000) == false); // 30 second timeout
    }

    TEST_CASE("ProposalState is_expired returns false when decided") {
        ProposalState state;
        state.proposed_at_ms = time::now_ms() - 20000;
        state.decided = true;

        CHECK(state.is_expired(15000) == false);  // Already decided
    }

}

TEST_SUITE("Voting - VotingPolicy") {

    TEST_CASE("VotingPolicy default values") {
        VotingPolicy policy;
        CHECK(policy.min_yes_votes == 2);
        CHECK(policy.min_no_votes == 2);
        CHECK(policy.vote_timeout_ms == 15000);
        CHECK(policy.require_sponsor == true);
    }

    TEST_CASE("VotingPolicy custom values") {
        VotingPolicy policy;
        policy.min_yes_votes = 3;
        policy.min_no_votes = 1;
        policy.vote_timeout_ms = 30000;
        policy.require_sponsor = false;

        CHECK(policy.min_yes_votes == 3);
        CHECK(policy.min_no_votes == 1);
        CHECK(policy.vote_timeout_ms == 30000);
        CHECK(policy.require_sponsor == false);
    }

}

TEST_SUITE("Voting - VotingManager") {

    TEST_CASE("Add proposal") {
        VotingPolicy policy;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        JoinProposal proposal;
        proposal.candidate_id = make_node_id(10);
        proposal.sponsor_id = make_node_id(1);
        proposal.candidate_ed25519 = make_pubkey(10);
        proposal.candidate_x25519 = make_pubkey(20);
        proposal.timestamp_ms = time::now_ms();

        auto result = manager.add_proposal(proposal);
        CHECK(result.is_ok());
        CHECK(manager.has_proposal(proposal.candidate_id) == true);
    }

    TEST_CASE("Add duplicate proposal fails") {
        VotingPolicy policy;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        JoinProposal proposal;
        proposal.candidate_id = make_node_id(10);

        auto r1 = manager.add_proposal(proposal);
        CHECK(r1.is_ok());

        auto r2 = manager.add_proposal(proposal);
        CHECK(r2.is_err());
    }

    TEST_CASE("Record vote") {
        VotingPolicy policy;
        policy.min_yes_votes = 2;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        NodeId candidate = make_node_id(10);

        JoinProposal proposal;
        proposal.candidate_id = candidate;
        manager.add_proposal(proposal);

        VoteCastEvent vote;
        vote.candidate_id = candidate;
        vote.voter_id = make_node_id(1);
        vote.vote = Vote::Yes;
        vote.timestamp_ms = time::now_ms();

        auto result = manager.record_vote(vote);
        REQUIRE(result.is_ok());
        CHECK(result.value() == VoteResult::Pending);  // Need 2 yes votes
    }

    TEST_CASE("Record vote for unknown candidate fails") {
        VotingPolicy policy;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        VoteCastEvent vote;
        vote.candidate_id = make_node_id(99);  // Unknown
        vote.voter_id = make_node_id(1);
        vote.vote = Vote::Yes;

        auto result = manager.record_vote(vote);
        CHECK(result.is_err());
    }

    TEST_CASE("Duplicate vote fails") {
        VotingPolicy policy;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        NodeId candidate = make_node_id(10);
        NodeId voter = make_node_id(1);

        JoinProposal proposal;
        proposal.candidate_id = candidate;
        manager.add_proposal(proposal);

        VoteCastEvent vote;
        vote.candidate_id = candidate;
        vote.voter_id = voter;
        vote.vote = Vote::Yes;

        auto r1 = manager.record_vote(vote);
        CHECK(r1.is_ok());

        auto r2 = manager.record_vote(vote);  // Same voter again
        CHECK(r2.is_err());
    }

    TEST_CASE("Approval with enough yes votes") {
        VotingPolicy policy;
        policy.min_yes_votes = 2;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        NodeId candidate = make_node_id(10);

        JoinProposal proposal;
        proposal.candidate_id = candidate;
        manager.add_proposal(proposal);

        // First yes vote
        VoteCastEvent vote1;
        vote1.candidate_id = candidate;
        vote1.voter_id = make_node_id(1);
        vote1.vote = Vote::Yes;

        auto r1 = manager.record_vote(vote1);
        REQUIRE(r1.is_ok());
        CHECK(r1.value() == VoteResult::Pending);

        // Second yes vote - should approve
        VoteCastEvent vote2;
        vote2.candidate_id = candidate;
        vote2.voter_id = make_node_id(2);
        vote2.vote = Vote::Yes;

        auto r2 = manager.record_vote(vote2);
        REQUIRE(r2.is_ok());
        CHECK(r2.value() == VoteResult::Approved);
    }

    TEST_CASE("Rejection with enough no votes") {
        VotingPolicy policy;
        policy.min_yes_votes = 2;
        policy.min_no_votes = 2;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        NodeId candidate = make_node_id(10);

        JoinProposal proposal;
        proposal.candidate_id = candidate;
        manager.add_proposal(proposal);

        // Two no votes
        VoteCastEvent vote1;
        vote1.candidate_id = candidate;
        vote1.voter_id = make_node_id(1);
        vote1.vote = Vote::No;
        manager.record_vote(vote1);

        VoteCastEvent vote2;
        vote2.candidate_id = candidate;
        vote2.voter_id = make_node_id(2);
        vote2.vote = Vote::No;

        auto r2 = manager.record_vote(vote2);
        REQUIRE(r2.is_ok());
        CHECK(r2.value() == VoteResult::Rejected);
    }

    TEST_CASE("Cast own vote") {
        VotingPolicy policy;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        NodeId candidate = make_node_id(10);

        JoinProposal proposal;
        proposal.candidate_id = candidate;
        manager.add_proposal(proposal);

        auto result = manager.cast_vote(candidate, Vote::Yes, "approved");
        REQUIRE(result.is_ok());

        VoteCastEvent evt = result.value();
        CHECK(evt.candidate_id == candidate);
        CHECK(evt.voter_id == local_id);
        CHECK(evt.vote == Vote::Yes);
        CHECK(evt.reason == "approved");
    }

    TEST_CASE("Cast vote for unknown candidate fails") {
        VotingPolicy policy;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        auto result = manager.cast_vote(make_node_id(99), Vote::Yes);
        CHECK(result.is_err());
    }

    TEST_CASE("Get pending proposals") {
        VotingPolicy policy;
        policy.min_yes_votes = 10;  // High threshold so nothing gets decided
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        JoinProposal p1;
        p1.candidate_id = make_node_id(10);
        manager.add_proposal(p1);

        JoinProposal p2;
        p2.candidate_id = make_node_id(20);
        manager.add_proposal(p2);

        auto pending = manager.get_pending_proposals();
        CHECK(pending.size() == 2);
    }

    TEST_CASE("Remove proposal") {
        VotingPolicy policy;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        NodeId candidate = make_node_id(10);

        JoinProposal proposal;
        proposal.candidate_id = candidate;
        manager.add_proposal(proposal);

        CHECK(manager.has_proposal(candidate) == true);

        manager.remove_proposal(candidate);

        CHECK(manager.has_proposal(candidate) == false);
    }

    TEST_CASE("Get policy") {
        VotingPolicy policy;
        policy.min_yes_votes = 5;
        NodeId local_id = make_node_id(0);
        VotingManager manager(policy, local_id);

        CHECK(manager.policy().min_yes_votes == 5);
    }

}

TEST_SUITE("Voting - VoteResult enum") {

    TEST_CASE("VoteResult values") {
        CHECK(static_cast<u8>(VoteResult::Pending) == 0);
        CHECK(static_cast<u8>(VoteResult::Approved) == 1);
        CHECK(static_cast<u8>(VoteResult::Rejected) == 2);
        CHECK(static_cast<u8>(VoteResult::Expired) == 3);
    }

}
