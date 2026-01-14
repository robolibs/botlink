/* SPDX-License-Identifier: MIT */
/*
 * Botlink Trust Tests
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Trust - TrustView") {

    TEST_CASE("Empty trust view") {
        TrustView view(2, 15000);

        CHECK(view.member_count() == 0);
    }

    TEST_CASE("Add member") {
        TrustView view(2, 15000);

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        MemberEntry entry;
        entry.node_id = node_id;
        entry.ed25519_pubkey = ed_pub;
        entry.x25519_pubkey = x_pub;
        entry.status = MemberStatus::Approved;
        entry.joined_at_ms = time::now_ms();

        view.add_member(entry);

        CHECK(view.member_count() == 1);
        CHECK(view.is_member(node_id));
    }

    TEST_CASE("Get member") {
        TrustView view(2, 15000);

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        MemberEntry entry;
        entry.node_id = node_id;
        entry.ed25519_pubkey = ed_pub;
        entry.x25519_pubkey = x_pub;
        entry.status = MemberStatus::Approved;

        view.add_member(entry);

        auto member = view.get_member(node_id);
        REQUIRE(member.has_value());
        CHECK(member->node_id == node_id);
        CHECK(member->ed25519_pubkey == ed_pub);
    }

    TEST_CASE("Remove member") {
        TrustView view(2, 15000);

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        MemberEntry entry;
        entry.node_id = node_id;
        entry.ed25519_pubkey = ed_pub;
        entry.x25519_pubkey = x_pub;
        entry.status = MemberStatus::Approved;

        view.add_member(entry);
        CHECK(view.member_count() == 1);

        view.remove_member(node_id);
        CHECK(view.member_count() == 0);
        CHECK_FALSE(view.is_member(node_id));
    }

    TEST_CASE("Get all approved members") {
        TrustView view(2, 15000);

        // Add approved member
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [x_priv1, x_pub1] = crypto::generate_x25519_keypair();
        NodeId node1 = crypto::node_id_from_pubkey(ed_pub1);

        MemberEntry entry1;
        entry1.node_id = node1;
        entry1.ed25519_pubkey = ed_pub1;
        entry1.x25519_pubkey = x_pub1;
        entry1.status = MemberStatus::Approved;
        view.add_member(entry1);

        // Add pending member
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();
        NodeId node2 = crypto::node_id_from_pubkey(ed_pub2);

        MemberEntry entry2;
        entry2.node_id = node2;
        entry2.ed25519_pubkey = ed_pub2;
        entry2.x25519_pubkey = x_pub2;
        entry2.status = MemberStatus::Pending;
        view.add_member(entry2);

        auto approved = view.get_all_members();
        CHECK(approved.size() == 1);
        CHECK(approved[0].node_id == node1);
    }

    TEST_CASE("Create and approve proposal") {
        TrustView view(2, 15000);

        // Add first member (voter)
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [x_priv1, x_pub1] = crypto::generate_x25519_keypair();
        NodeId voter1 = crypto::node_id_from_pubkey(ed_pub1);

        MemberEntry voter_entry;
        voter_entry.node_id = voter1;
        voter_entry.ed25519_pubkey = ed_pub1;
        voter_entry.x25519_pubkey = x_pub1;
        voter_entry.status = MemberStatus::Approved;
        view.add_member(voter_entry);

        // Add second member (voter)
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();
        NodeId voter2 = crypto::node_id_from_pubkey(ed_pub2);

        MemberEntry voter_entry2;
        voter_entry2.node_id = voter2;
        voter_entry2.ed25519_pubkey = ed_pub2;
        voter_entry2.x25519_pubkey = x_pub2;
        voter_entry2.status = MemberStatus::Approved;
        view.add_member(voter_entry2);

        // Create proposal for candidate
        auto [ed_priv3, ed_pub3] = crypto::generate_ed25519_keypair();
        auto [x_priv3, x_pub3] = crypto::generate_x25519_keypair();
        NodeId candidate = crypto::node_id_from_pubkey(ed_pub3);

        JoinProposal proposal;
        proposal.candidate_id = candidate;
        proposal.candidate_ed25519 = ed_pub3;
        proposal.candidate_x25519 = x_pub3;
        proposal.sponsor_id = voter1;

        auto create_res = view.create_proposal(proposal);
        CHECK(create_res.is_ok());

        // Vote yes from both voters
        view.record_vote(candidate, voter1, Vote::Yes);
        view.record_vote(candidate, voter2, Vote::Yes);

        // Check status
        auto [has_quorum, is_approved, yes_count, no_count] = view.check_proposal_status(candidate);
        CHECK(has_quorum);
        CHECK(is_approved);
        CHECK(yes_count == 2);

        // Approve
        auto approve_res = view.approve_proposal(candidate);
        CHECK(approve_res.is_ok());
        CHECK(view.is_member(candidate));
    }

}

TEST_SUITE("Trust - TrustChain") {

    TEST_CASE("Create trust chain with genesis") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        TrustChain chain("test_chain", node_id, ed_pub, x_pub);

        CHECK(chain.is_member(node_id));
        CHECK(chain.length() >= 1);
    }

    TEST_CASE("JoinProposal to_event") {
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [x_priv1, x_pub1] = crypto::generate_x25519_keypair();
        NodeId node1 = crypto::node_id_from_pubkey(ed_pub1);

        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();
        NodeId node2 = crypto::node_id_from_pubkey(ed_pub2);

        JoinProposal proposal;
        proposal.candidate_id = node2;
        proposal.candidate_ed25519 = ed_pub2;
        proposal.candidate_x25519 = x_pub2;
        proposal.sponsor_id = node1;
        proposal.timestamp_ms = time::now_ms();

        TrustEvent evt = proposal.to_event();
        CHECK(evt.kind == TrustEventKind::JoinProposed);
        CHECK(evt.subject_id == node2);
        CHECK(evt.actor_id == node1);
    }

    TEST_CASE("VoteCastEvent to_event") {
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        NodeId voter = crypto::node_id_from_pubkey(ed_pub1);

        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId candidate = crypto::node_id_from_pubkey(ed_pub2);

        VoteCastEvent vote;
        vote.candidate_id = candidate;
        vote.voter_id = voter;
        vote.vote = Vote::Yes;
        vote.timestamp_ms = time::now_ms();

        TrustEvent evt = vote.to_event();
        CHECK(evt.kind == TrustEventKind::VoteCast);
        CHECK(evt.subject_id == candidate);
        CHECK(evt.actor_id == voter);
    }

    TEST_CASE("MembershipDecision to_event") {
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        NodeId candidate = crypto::node_id_from_pubkey(ed_pub1);

        MembershipDecision decision;
        decision.candidate_id = candidate;
        decision.approved = true;
        decision.yes_votes = 2;
        decision.no_votes = 0;
        decision.timestamp_ms = time::now_ms();

        TrustEvent evt = decision.to_event();
        CHECK(evt.kind == TrustEventKind::JoinApproved);
        CHECK(evt.subject_id == candidate);
    }

    TEST_CASE("Get members") {
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [x_priv1, x_pub1] = crypto::generate_x25519_keypair();
        NodeId node1 = crypto::node_id_from_pubkey(ed_pub1);

        TrustChain chain("test_chain", node1, ed_pub1, x_pub1);

        auto members = chain.get_members();
        CHECK(members.size() == 1);
        CHECK(members[0] == node1);
    }

    TEST_CASE("sync_from_chain handles revocation") {
        // Create genesis member
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [x_priv1, x_pub1] = crypto::generate_x25519_keypair();
        NodeId genesis = crypto::node_id_from_pubkey(ed_pub1);

        TrustChain chain("test_sync", genesis, ed_pub1, x_pub1);

        // Genesis should be a member
        CHECK(chain.is_member(genesis));

        // Add a second member by directly adding a JoinApproved event
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();
        NodeId member2 = crypto::node_id_from_pubkey(ed_pub2);

        // Create JoinApproved event directly
        TrustEvent approve_evt;
        approve_evt.kind = TrustEventKind::JoinApproved;
        approve_evt.subject_id = member2;
        approve_evt.actor_id = genesis;
        approve_evt.subject_pubkey = ed_pub2;
        approve_evt.subject_x25519 = x_pub2;
        approve_evt.timestamp_ms = time::now_ms() + 10;
        approve_evt.metadata = "approved";
        auto add_res = chain.add_event(approve_evt);
        if (!add_res.is_ok()) {
            std::string err_msg = std::string("add_event failed: ") + add_res.error().message.c_str();
            FAIL(err_msg);
        }

        // Verify member2 is now a member
        CHECK(chain.is_member(member2));

        // Now revoke member2
        TrustEvent revoke_evt;
        revoke_evt.kind = TrustEventKind::MemberRevoked;
        revoke_evt.subject_id = member2;
        revoke_evt.actor_id = genesis;
        revoke_evt.timestamp_ms = time::now_ms() + 100;
        revoke_evt.metadata = "test revocation";
        chain.add_event(revoke_evt);

        // Verify member2 is no longer a member in the chain
        CHECK_FALSE(chain.is_member(member2));

        // Sync to TrustView and verify
        TrustView view(2, 15000);
        view.sync_from_chain(chain);

        CHECK(view.is_member(genesis));
        CHECK_FALSE(view.is_member(member2));

        // Member2 should still be tracked with Revoked status
        auto member2_entry = view.get_member(member2);
        REQUIRE(member2_entry.has_value());
        CHECK(member2_entry->status == MemberStatus::Revoked);
    }

    TEST_CASE("sync_from_chain handles rejection") {
        // Create genesis member
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [x_priv1, x_pub1] = crypto::generate_x25519_keypair();
        NodeId genesis = crypto::node_id_from_pubkey(ed_pub1);

        TrustChain chain("test_reject", genesis, ed_pub1, x_pub1);

        // Add a rejected candidate
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();
        NodeId rejected = crypto::node_id_from_pubkey(ed_pub2);

        // Create JoinRejected event directly
        TrustEvent reject_evt;
        reject_evt.kind = TrustEventKind::JoinRejected;
        reject_evt.subject_id = rejected;
        reject_evt.actor_id = genesis;
        reject_evt.subject_pubkey = ed_pub2;
        reject_evt.subject_x25519 = x_pub2;
        reject_evt.timestamp_ms = time::now_ms() + 10;
        reject_evt.metadata = "rejected";
        chain.add_event(reject_evt);

        // Sync to TrustView
        TrustView view(2, 15000);
        view.sync_from_chain(chain);

        // Genesis is a member
        CHECK(view.is_member(genesis));

        // Rejected candidate is not a member
        CHECK_FALSE(view.is_member(rejected));

        // But should be tracked with Rejected status
        auto rejected_entry = view.get_member(rejected);
        REQUIRE(rejected_entry.has_value());
        CHECK(rejected_entry->status == MemberStatus::Rejected);
    }

}

TEST_SUITE("Trust - Voting") {

    TEST_CASE("VotingManager add proposal") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);

        VotingPolicy policy;
        policy.min_yes_votes = 2;
        policy.vote_timeout_ms = 15000;

        VotingManager mgr(policy, local_id);

        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();
        NodeId candidate = crypto::node_id_from_pubkey(ed_pub2);

        JoinProposal proposal;
        proposal.candidate_id = candidate;
        proposal.candidate_ed25519 = ed_pub2;
        proposal.candidate_x25519 = x_pub2;
        proposal.sponsor_id = local_id;

        auto result = mgr.add_proposal(proposal);
        CHECK(result.is_ok());
        CHECK(mgr.has_proposal(candidate));
    }

    TEST_CASE("VotingManager record vote") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);

        VotingPolicy policy;
        policy.min_yes_votes = 2;

        VotingManager mgr(policy, local_id);

        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();
        NodeId candidate = crypto::node_id_from_pubkey(ed_pub2);

        JoinProposal proposal;
        proposal.candidate_id = candidate;
        proposal.candidate_ed25519 = ed_pub2;
        proposal.candidate_x25519 = x_pub2;
        proposal.sponsor_id = local_id;
        mgr.add_proposal(proposal);

        // Record first vote
        VoteCastEvent vote1;
        vote1.candidate_id = candidate;
        vote1.voter_id = local_id;
        vote1.vote = Vote::Yes;

        auto res = mgr.record_vote(vote1);
        CHECK(res.is_ok());
        CHECK(res.value() == VoteResult::Pending);
    }

    TEST_CASE("VotingManager approval with enough votes") {
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId voter1 = crypto::node_id_from_pubkey(ed_pub1);
        NodeId voter2 = crypto::node_id_from_pubkey(ed_pub2);

        VotingPolicy policy;
        policy.min_yes_votes = 2;

        VotingManager mgr(policy, voter1);

        auto [ed_priv3, ed_pub3] = crypto::generate_ed25519_keypair();
        auto [x_priv3, x_pub3] = crypto::generate_x25519_keypair();
        NodeId candidate = crypto::node_id_from_pubkey(ed_pub3);

        JoinProposal proposal;
        proposal.candidate_id = candidate;
        proposal.candidate_ed25519 = ed_pub3;
        proposal.candidate_x25519 = x_pub3;
        proposal.sponsor_id = voter1;
        mgr.add_proposal(proposal);

        VoteCastEvent vote1;
        vote1.candidate_id = candidate;
        vote1.voter_id = voter1;
        vote1.vote = Vote::Yes;
        mgr.record_vote(vote1);

        VoteCastEvent vote2;
        vote2.candidate_id = candidate;
        vote2.voter_id = voter2;
        vote2.vote = Vote::Yes;

        auto res = mgr.record_vote(vote2);
        CHECK(res.is_ok());
        CHECK(res.value() == VoteResult::Approved);
    }

    TEST_CASE("ProposalState vote counting") {
        ProposalState state;

        VoteRecord v1;
        v1.vote = Vote::Yes;
        state.votes.push_back(v1);

        VoteRecord v2;
        v2.vote = Vote::No;
        state.votes.push_back(v2);

        VoteRecord v3;
        v3.vote = Vote::Yes;
        state.votes.push_back(v3);

        VoteRecord v4;
        v4.vote = Vote::Abstain;
        state.votes.push_back(v4);

        CHECK(state.count_yes() == 2);
        CHECK(state.count_no() == 1);
        CHECK(state.count_abstain() == 1);
    }

}

TEST_SUITE("Trust - Sponsor") {

    TEST_CASE("Sponsor receive request") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);

        Sponsor sponsor(local_id, ed_priv);

        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();
        NodeId candidate = crypto::node_id_from_pubkey(ed_pub2);

        // Use the helper to create a properly signed join request
        JoinRequest request = sponsor::create_join_request(ed_priv2, ed_pub2, x_pub2);

        auto result = sponsor.receive_request(request);
        CHECK(result.is_ok());
        CHECK(sponsor.has_pending(candidate));
        CHECK(sponsor.pending_count() == 1);
    }

    TEST_CASE("Sponsor reject duplicate request") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);

        Sponsor sponsor(local_id, ed_priv);

        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();

        // Use the helper to create a properly signed join request
        JoinRequest request = sponsor::create_join_request(ed_priv2, ed_pub2, x_pub2);

        sponsor.receive_request(request);

        auto result = sponsor.receive_request(request);
        CHECK(result.is_err());
    }

    TEST_CASE("Sponsor remove request") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);

        Sponsor sponsor(local_id, ed_priv);

        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();
        NodeId candidate = crypto::node_id_from_pubkey(ed_pub2);

        // Use the helper to create a properly signed join request
        JoinRequest request = sponsor::create_join_request(ed_priv2, ed_pub2, x_pub2);

        sponsor.receive_request(request);
        CHECK(sponsor.pending_count() == 1);

        sponsor.remove_request(candidate);
        CHECK(sponsor.pending_count() == 0);
    }

    TEST_CASE("Sponsor reject request with invalid identity proof") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);

        Sponsor sponsor(local_id, ed_priv);

        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();
        NodeId candidate = crypto::node_id_from_pubkey(ed_pub2);

        // Create request manually without proper signature
        JoinRequest request;
        request.candidate_id = candidate;
        request.candidate_ed25519 = ed_pub2;
        request.candidate_x25519 = x_pub2;
        request.timestamp_ms = time::now_ms();
        // identity_proof is left empty/invalid

        auto result = sponsor.receive_request(request);
        CHECK(result.is_err());
        CHECK(sponsor.pending_count() == 0);
    }

}
