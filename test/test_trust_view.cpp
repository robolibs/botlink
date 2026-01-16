/* SPDX-License-Identifier: MIT */
/*
 * Botlink Trust View Tests
 * Tests for in-memory membership table
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("MemberEntry - Basic Structure") {

    TEST_CASE("MemberEntry default values") {
        MemberEntry entry;
        CHECK(entry.status == MemberStatus::Unconfigured);
        CHECK(entry.joined_at_ms == 0);
        CHECK(entry.last_seen_ms == 0);
        CHECK(entry.endpoints.empty());
    }

    TEST_CASE("MemberEntry is_active") {
        MemberEntry entry;
        CHECK_FALSE(entry.is_active());

        entry.status = MemberStatus::Approved;
        CHECK(entry.is_active());

        entry.status = MemberStatus::Revoked;
        CHECK_FALSE(entry.is_active());

        entry.status = MemberStatus::Rejected;
        CHECK_FALSE(entry.is_active());
    }

}

TEST_SUITE("PendingProposal - Basic Structure") {

    TEST_CASE("PendingProposal default values") {
        PendingProposal proposal;
        CHECK(proposal.proposed_at_ms == 0);
        CHECK(proposal.expires_at_ms == 0);
        CHECK(proposal.votes.empty());
    }

    TEST_CASE("PendingProposal vote counting") {
        PendingProposal proposal;

        auto [priv1, pub1] = crypto::generate_ed25519_keypair();
        auto [priv2, pub2] = crypto::generate_ed25519_keypair();
        auto [priv3, pub3] = crypto::generate_ed25519_keypair();

        NodeId voter1 = crypto::node_id_from_pubkey(pub1);
        NodeId voter2 = crypto::node_id_from_pubkey(pub2);
        NodeId voter3 = crypto::node_id_from_pubkey(pub3);

        proposal.votes[voter1] = Vote::Yes;
        proposal.votes[voter2] = Vote::Yes;
        proposal.votes[voter3] = Vote::No;

        CHECK(proposal.count_yes() == 2);
        CHECK(proposal.count_no() == 1);
    }

    TEST_CASE("PendingProposal is_expired") {
        PendingProposal proposal;
        proposal.proposed_at_ms = time::now_ms();
        proposal.expires_at_ms = proposal.proposed_at_ms + 1000; // 1 second from now

        CHECK_FALSE(proposal.is_expired());

        proposal.expires_at_ms = time::now_ms() - 1; // Already expired
        CHECK(proposal.is_expired());
    }

}

TEST_SUITE("TrustView - Member Operations") {

    TEST_CASE("TrustView empty by default") {
        TrustView view;
        CHECK(view.member_count() == 0);
        CHECK(view.get_all_members().empty());
    }

    TEST_CASE("TrustView add member") {
        TrustView view;

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

    TEST_CASE("TrustView get member") {
        TrustView view;

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        MemberEntry entry;
        entry.node_id = node_id;
        entry.ed25519_pubkey = ed_pub;
        entry.x25519_pubkey = x_pub;
        entry.status = MemberStatus::Approved;

        view.add_member(entry);

        auto retrieved = view.get_member(node_id);
        REQUIRE(retrieved.has_value());
        CHECK(retrieved->node_id == node_id);
        CHECK(retrieved->ed25519_pubkey == ed_pub);
    }

    TEST_CASE("TrustView get nonexistent member") {
        TrustView view;

        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(pub);

        auto retrieved = view.get_member(node_id);
        CHECK_FALSE(retrieved.has_value());
    }

    TEST_CASE("TrustView remove member") {
        TrustView view;

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        MemberEntry entry;
        entry.node_id = node_id;
        entry.status = MemberStatus::Approved;

        view.add_member(entry);
        CHECK(view.is_member(node_id));

        bool removed = view.remove_member(node_id);
        CHECK(removed);
        CHECK_FALSE(view.is_member(node_id));

        // Member still exists but with Revoked status
        auto member = view.get_member(node_id);
        REQUIRE(member.has_value());
        CHECK(member->status == MemberStatus::Revoked);
    }

    TEST_CASE("TrustView touch member") {
        TrustView view;

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        MemberEntry entry;
        entry.node_id = node_id;
        entry.status = MemberStatus::Approved;
        entry.last_seen_ms = 0;

        view.add_member(entry);

        view.touch_member(node_id);

        auto member = view.get_member(node_id);
        REQUIRE(member.has_value());
        CHECK(member->last_seen_ms > 0);
    }

    TEST_CASE("TrustView update endpoints") {
        TrustView view;

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        MemberEntry entry;
        entry.node_id = node_id;
        entry.status = MemberStatus::Approved;

        view.add_member(entry);

        Vector<Endpoint> endpoints;
        Endpoint ep;
        ep.port = 51820;
        endpoints.push_back(ep);

        view.update_endpoints(node_id, endpoints);

        auto member = view.get_member(node_id);
        REQUIRE(member.has_value());
        CHECK(member->endpoints.size() == 1);
    }

}

TEST_SUITE("TrustView - Public Key Queries") {

    TEST_CASE("TrustView get ed25519 pubkey") {
        TrustView view;

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        MemberEntry entry;
        entry.node_id = node_id;
        entry.ed25519_pubkey = ed_pub;
        entry.status = MemberStatus::Approved;

        view.add_member(entry);

        auto pubkey = view.get_ed25519_pubkey(node_id);
        REQUIRE(pubkey.has_value());
        CHECK(pubkey.value() == ed_pub);
    }

    TEST_CASE("TrustView get x25519 pubkey") {
        TrustView view;

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        MemberEntry entry;
        entry.node_id = node_id;
        entry.x25519_pubkey = x_pub;
        entry.status = MemberStatus::Approved;

        view.add_member(entry);

        auto pubkey = view.get_x25519_pubkey(node_id);
        REQUIRE(pubkey.has_value());
        CHECK(pubkey.value() == x_pub);
    }

    TEST_CASE("TrustView get pubkey for nonexistent member") {
        TrustView view;

        auto [priv, pub] = crypto::generate_ed25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(pub);

        auto ed_pubkey = view.get_ed25519_pubkey(node_id);
        CHECK_FALSE(ed_pubkey.has_value());

        auto x_pubkey = view.get_x25519_pubkey(node_id);
        CHECK_FALSE(x_pubkey.has_value());
    }

}

TEST_SUITE("TrustView - Proposal Management") {

    TEST_CASE("TrustView create proposal") {
        TrustView view(2, 15000);

        // First add a sponsor member
        auto [sponsor_priv, sponsor_pub] = crypto::generate_ed25519_keypair();
        NodeId sponsor_id = crypto::node_id_from_pubkey(sponsor_pub);

        MemberEntry sponsor_entry;
        sponsor_entry.node_id = sponsor_id;
        sponsor_entry.status = MemberStatus::Approved;
        view.add_member(sponsor_entry);

        // Create proposal for candidate
        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();
        NodeId cand_id = crypto::node_id_from_pubkey(cand_pub);

        JoinProposal proposal;
        proposal.candidate_id = cand_id;
        proposal.candidate_ed25519 = cand_pub;
        proposal.candidate_x25519 = cand_x_pub;
        proposal.sponsor_id = sponsor_id;

        auto result = view.create_proposal(proposal);
        CHECK(result.is_ok());

        auto pending = view.get_pending_proposal(cand_id);
        REQUIRE(pending.has_value());
        CHECK(pending->candidate_id == cand_id);
    }

    TEST_CASE("TrustView reject duplicate proposal") {
        TrustView view(2, 15000);

        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();
        NodeId cand_id = crypto::node_id_from_pubkey(cand_pub);

        auto [sponsor_priv, sponsor_pub] = crypto::generate_ed25519_keypair();
        NodeId sponsor_id = crypto::node_id_from_pubkey(sponsor_pub);

        JoinProposal proposal;
        proposal.candidate_id = cand_id;
        proposal.candidate_ed25519 = cand_pub;
        proposal.candidate_x25519 = cand_x_pub;
        proposal.sponsor_id = sponsor_id;

        auto result1 = view.create_proposal(proposal);
        CHECK(result1.is_ok());

        auto result2 = view.create_proposal(proposal);
        CHECK(result2.is_err());
    }

    TEST_CASE("TrustView reject proposal for existing member") {
        TrustView view(2, 15000);

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        MemberEntry entry;
        entry.node_id = node_id;
        entry.status = MemberStatus::Approved;
        view.add_member(entry);

        auto [sponsor_priv, sponsor_pub] = crypto::generate_ed25519_keypair();
        NodeId sponsor_id = crypto::node_id_from_pubkey(sponsor_pub);

        JoinProposal proposal;
        proposal.candidate_id = node_id;
        proposal.candidate_ed25519 = ed_pub;
        proposal.candidate_x25519 = x_pub;
        proposal.sponsor_id = sponsor_id;

        auto result = view.create_proposal(proposal);
        CHECK(result.is_err());
    }

    TEST_CASE("TrustView record vote") {
        TrustView view(2, 15000);

        // Add voter as member
        auto [voter_priv, voter_pub] = crypto::generate_ed25519_keypair();
        NodeId voter_id = crypto::node_id_from_pubkey(voter_pub);

        MemberEntry voter_entry;
        voter_entry.node_id = voter_id;
        voter_entry.status = MemberStatus::Approved;
        view.add_member(voter_entry);

        // Create proposal
        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();
        NodeId cand_id = crypto::node_id_from_pubkey(cand_pub);

        JoinProposal proposal;
        proposal.candidate_id = cand_id;
        proposal.candidate_ed25519 = cand_pub;
        proposal.candidate_x25519 = cand_x_pub;
        proposal.sponsor_id = voter_id;

        (void)view.create_proposal(proposal);

        // Record vote
        auto result = view.record_vote(cand_id, voter_id, Vote::Yes);
        CHECK(result.is_ok());

        auto pending = view.get_pending_proposal(cand_id);
        REQUIRE(pending.has_value());
        CHECK(pending->count_yes() == 1);
    }

    TEST_CASE("TrustView reject vote from non-member") {
        TrustView view(2, 15000);

        // Create proposal without adding voter as member
        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();
        NodeId cand_id = crypto::node_id_from_pubkey(cand_pub);

        auto [sponsor_priv, sponsor_pub] = crypto::generate_ed25519_keypair();
        NodeId sponsor_id = crypto::node_id_from_pubkey(sponsor_pub);

        JoinProposal proposal;
        proposal.candidate_id = cand_id;
        proposal.candidate_ed25519 = cand_pub;
        proposal.candidate_x25519 = cand_x_pub;
        proposal.sponsor_id = sponsor_id;

        (void)view.create_proposal(proposal);

        auto [voter_priv, voter_pub] = crypto::generate_ed25519_keypair();
        NodeId voter_id = crypto::node_id_from_pubkey(voter_pub);

        auto result = view.record_vote(cand_id, voter_id, Vote::Yes);
        CHECK(result.is_err());
    }

}

TEST_SUITE("TrustView - Proposal Decisions") {

    TEST_CASE("TrustView check proposal status") {
        TrustView view(2, 15000);

        // Add voters as members
        auto [voter1_priv, voter1_pub] = crypto::generate_ed25519_keypair();
        NodeId voter1 = crypto::node_id_from_pubkey(voter1_pub);

        auto [voter2_priv, voter2_pub] = crypto::generate_ed25519_keypair();
        NodeId voter2 = crypto::node_id_from_pubkey(voter2_pub);

        MemberEntry v1_entry;
        v1_entry.node_id = voter1;
        v1_entry.status = MemberStatus::Approved;
        view.add_member(v1_entry);

        MemberEntry v2_entry;
        v2_entry.node_id = voter2;
        v2_entry.status = MemberStatus::Approved;
        view.add_member(v2_entry);

        // Create proposal
        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();
        NodeId cand_id = crypto::node_id_from_pubkey(cand_pub);

        JoinProposal proposal;
        proposal.candidate_id = cand_id;
        proposal.candidate_ed25519 = cand_pub;
        proposal.candidate_x25519 = cand_x_pub;
        proposal.sponsor_id = voter1;

        (void)view.create_proposal(proposal);

        // Before votes - no quorum
        auto [has_quorum1, is_approved1, yes1, no1] = view.check_proposal_status(cand_id);
        CHECK_FALSE(has_quorum1);

        // After one vote - still no quorum
        (void)view.record_vote(cand_id, voter1, Vote::Yes);
        auto [has_quorum2, is_approved2, yes2, no2] = view.check_proposal_status(cand_id);
        CHECK_FALSE(has_quorum2);
        CHECK(yes2 == 1);

        // After two votes - quorum reached
        (void)view.record_vote(cand_id, voter2, Vote::Yes);
        auto [has_quorum3, is_approved3, yes3, no3] = view.check_proposal_status(cand_id);
        CHECK(has_quorum3);
        CHECK(is_approved3);
        CHECK(yes3 == 2);
    }

    TEST_CASE("TrustView approve proposal") {
        TrustView view(1, 15000);

        // Add voter as member
        auto [voter_priv, voter_pub] = crypto::generate_ed25519_keypair();
        NodeId voter_id = crypto::node_id_from_pubkey(voter_pub);

        MemberEntry voter_entry;
        voter_entry.node_id = voter_id;
        voter_entry.status = MemberStatus::Approved;
        view.add_member(voter_entry);

        // Create and approve proposal
        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();
        NodeId cand_id = crypto::node_id_from_pubkey(cand_pub);

        JoinProposal proposal;
        proposal.candidate_id = cand_id;
        proposal.candidate_ed25519 = cand_pub;
        proposal.candidate_x25519 = cand_x_pub;
        proposal.sponsor_id = voter_id;

        (void)view.create_proposal(proposal);

        auto result = view.approve_proposal(cand_id);
        CHECK(result.is_ok());
        CHECK(view.is_member(cand_id));

        // Proposal should be removed
        auto pending = view.get_pending_proposal(cand_id);
        CHECK_FALSE(pending.has_value());
    }

    TEST_CASE("TrustView reject proposal") {
        TrustView view(1, 15000);

        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();
        NodeId cand_id = crypto::node_id_from_pubkey(cand_pub);

        auto [sponsor_priv, sponsor_pub] = crypto::generate_ed25519_keypair();
        NodeId sponsor_id = crypto::node_id_from_pubkey(sponsor_pub);

        JoinProposal proposal;
        proposal.candidate_id = cand_id;
        proposal.candidate_ed25519 = cand_pub;
        proposal.candidate_x25519 = cand_x_pub;
        proposal.sponsor_id = sponsor_id;

        (void)view.create_proposal(proposal);

        auto result = view.reject_proposal(cand_id);
        CHECK(result.is_ok());
        CHECK_FALSE(view.is_member(cand_id));

        // Proposal should be removed
        auto pending = view.get_pending_proposal(cand_id);
        CHECK_FALSE(pending.has_value());
    }

    TEST_CASE("TrustView get all pending proposals") {
        TrustView view(2, 15000);

        auto [cand1_priv, cand1_pub] = crypto::generate_ed25519_keypair();
        auto [cand1_x_priv, cand1_x_pub] = crypto::generate_x25519_keypair();
        NodeId cand1 = crypto::node_id_from_pubkey(cand1_pub);

        auto [cand2_priv, cand2_pub] = crypto::generate_ed25519_keypair();
        auto [cand2_x_priv, cand2_x_pub] = crypto::generate_x25519_keypair();
        NodeId cand2 = crypto::node_id_from_pubkey(cand2_pub);

        auto [sponsor_priv, sponsor_pub] = crypto::generate_ed25519_keypair();
        NodeId sponsor = crypto::node_id_from_pubkey(sponsor_pub);

        JoinProposal p1;
        p1.candidate_id = cand1;
        p1.candidate_ed25519 = cand1_pub;
        p1.candidate_x25519 = cand1_x_pub;
        p1.sponsor_id = sponsor;

        JoinProposal p2;
        p2.candidate_id = cand2;
        p2.candidate_ed25519 = cand2_pub;
        p2.candidate_x25519 = cand2_x_pub;
        p2.sponsor_id = sponsor;

        (void)view.create_proposal(p1);
        (void)view.create_proposal(p2);

        auto pending = view.get_all_pending();
        CHECK(pending.size() == 2);
    }

}

TEST_SUITE("TrustView - Constructor with params") {

    TEST_CASE("TrustView with custom settings") {
        TrustView view(3, 30000);

        // Add voters as members
        auto [v1_priv, v1_pub] = crypto::generate_ed25519_keypair();
        auto [v2_priv, v2_pub] = crypto::generate_ed25519_keypair();
        auto [v3_priv, v3_pub] = crypto::generate_ed25519_keypair();

        NodeId voter1 = crypto::node_id_from_pubkey(v1_pub);
        NodeId voter2 = crypto::node_id_from_pubkey(v2_pub);
        NodeId voter3 = crypto::node_id_from_pubkey(v3_pub);

        MemberEntry e1, e2, e3;
        e1.node_id = voter1;
        e1.status = MemberStatus::Approved;
        e2.node_id = voter2;
        e2.status = MemberStatus::Approved;
        e3.node_id = voter3;
        e3.status = MemberStatus::Approved;

        view.add_member(e1);
        view.add_member(e2);
        view.add_member(e3);

        // Create proposal
        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();
        NodeId cand = crypto::node_id_from_pubkey(cand_pub);

        JoinProposal proposal;
        proposal.candidate_id = cand;
        proposal.candidate_ed25519 = cand_pub;
        proposal.candidate_x25519 = cand_x_pub;
        proposal.sponsor_id = voter1;

        (void)view.create_proposal(proposal);

        // With min_yes_votes=3, need 3 votes for quorum
        (void)view.record_vote(cand, voter1, Vote::Yes);
        (void)view.record_vote(cand, voter2, Vote::Yes);

        auto [has_quorum1, is_approved1, yes1, no1] = view.check_proposal_status(cand);
        CHECK_FALSE(has_quorum1); // Still needs 3rd vote

        (void)view.record_vote(cand, voter3, Vote::Yes);
        auto [has_quorum2, is_approved2, yes2, no2] = view.check_proposal_status(cand);
        CHECK(has_quorum2);
        CHECK(is_approved2);
        CHECK(yes2 == 3);
    }

}
