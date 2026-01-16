/* SPDX-License-Identifier: MIT */
/*
 * Botlink Trust Event Tests
 * Tests for trust chain event structures
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("TrustEvent - Basic Structure") {

    TEST_CASE("TrustEvent default values") {
        TrustEvent evt;
        CHECK(evt.kind == TrustEventKind::JoinProposed);
        CHECK(evt.timestamp_ms == 0);
        CHECK(evt.vote == Vote::Abstain);
        CHECK(evt.metadata.empty());
    }

    TEST_CASE("TrustEvent to_string") {
        TrustEvent evt;
        evt.kind = TrustEventKind::JoinApproved;
        evt.timestamp_ms = 1234567890;

        std::string str = evt.to_string();
        CHECK(str.find("TrustEvent") != std::string::npos);
        CHECK(str.find("1234567890") != std::string::npos);
    }

    TEST_CASE("TrustEvent with node IDs") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId subject = crypto::node_id_from_pubkey(ed_pub);

        auto [actor_priv, actor_pub] = crypto::generate_ed25519_keypair();
        NodeId actor = crypto::node_id_from_pubkey(actor_pub);

        TrustEvent evt;
        evt.kind = TrustEventKind::VoteCast;
        evt.subject_id = subject;
        evt.actor_id = actor;
        evt.subject_pubkey = ed_pub;
        evt.subject_x25519 = x_pub;
        evt.timestamp_ms = time::now_ms();
        evt.vote = Vote::Yes;

        CHECK_FALSE(evt.subject_id.is_zero());
        CHECK_FALSE(evt.actor_id.is_zero());
        CHECK(evt.subject_id != evt.actor_id);
    }

}

TEST_SUITE("JoinProposal - Conversion") {

    TEST_CASE("JoinProposal default values") {
        JoinProposal proposal;
        CHECK(proposal.timestamp_ms == 0);
        CHECK(proposal.justification.empty());
    }

    TEST_CASE("JoinProposal to_event") {
        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();
        NodeId candidate = crypto::node_id_from_pubkey(cand_pub);

        auto [sponsor_priv, sponsor_pub] = crypto::generate_ed25519_keypair();
        NodeId sponsor = crypto::node_id_from_pubkey(sponsor_pub);

        JoinProposal proposal;
        proposal.candidate_id = candidate;
        proposal.candidate_ed25519 = cand_pub;
        proposal.candidate_x25519 = cand_x_pub;
        proposal.sponsor_id = sponsor;
        proposal.timestamp_ms = time::now_ms();
        proposal.justification = "Trusted developer";

        TrustEvent evt = proposal.to_event();

        CHECK(evt.kind == TrustEventKind::JoinProposed);
        CHECK(evt.subject_id == candidate);
        CHECK(evt.actor_id == sponsor);
        CHECK(evt.subject_pubkey == cand_pub);
        CHECK(evt.subject_x25519 == cand_x_pub);
        CHECK(evt.timestamp_ms == proposal.timestamp_ms);
        CHECK(evt.metadata == "Trusted developer");
    }

}

TEST_SUITE("VoteCastEvent - Conversion") {

    TEST_CASE("VoteCastEvent default values") {
        VoteCastEvent vote;
        CHECK(vote.vote == Vote::Abstain);
        CHECK(vote.timestamp_ms == 0);
        CHECK(vote.reason.empty());
    }

    TEST_CASE("VoteCastEvent to_event with Yes vote") {
        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        NodeId candidate = crypto::node_id_from_pubkey(cand_pub);

        auto [voter_priv, voter_pub] = crypto::generate_ed25519_keypair();
        NodeId voter = crypto::node_id_from_pubkey(voter_pub);

        VoteCastEvent vote_evt;
        vote_evt.candidate_id = candidate;
        vote_evt.voter_id = voter;
        vote_evt.vote = Vote::Yes;
        vote_evt.timestamp_ms = time::now_ms();
        vote_evt.reason = "Good candidate";

        TrustEvent evt = vote_evt.to_event();

        CHECK(evt.kind == TrustEventKind::VoteCast);
        CHECK(evt.subject_id == candidate);
        CHECK(evt.actor_id == voter);
        CHECK(evt.vote == Vote::Yes);
        CHECK(evt.metadata == "Good candidate");
    }

    TEST_CASE("VoteCastEvent to_event with No vote") {
        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        NodeId candidate = crypto::node_id_from_pubkey(cand_pub);

        auto [voter_priv, voter_pub] = crypto::generate_ed25519_keypair();
        NodeId voter = crypto::node_id_from_pubkey(voter_pub);

        VoteCastEvent vote_evt;
        vote_evt.candidate_id = candidate;
        vote_evt.voter_id = voter;
        vote_evt.vote = Vote::No;
        vote_evt.timestamp_ms = time::now_ms();
        vote_evt.reason = "Not trusted";

        TrustEvent evt = vote_evt.to_event();

        CHECK(evt.vote == Vote::No);
    }

}

TEST_SUITE("MembershipDecision - Conversion") {

    TEST_CASE("MembershipDecision default values") {
        MembershipDecision decision;
        CHECK(decision.approved == false);
        CHECK(decision.yes_votes == 0);
        CHECK(decision.no_votes == 0);
        CHECK(decision.abstain_votes == 0);
        CHECK(decision.timestamp_ms == 0);
    }

    TEST_CASE("MembershipDecision to_event approved") {
        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();
        NodeId candidate = crypto::node_id_from_pubkey(cand_pub);

        MembershipDecision decision;
        decision.candidate_id = candidate;
        decision.candidate_ed25519 = cand_pub;
        decision.candidate_x25519 = cand_x_pub;
        decision.approved = true;
        decision.yes_votes = 5;
        decision.no_votes = 1;
        decision.abstain_votes = 2;
        decision.timestamp_ms = time::now_ms();

        TrustEvent evt = decision.to_event();

        CHECK(evt.kind == TrustEventKind::JoinApproved);
        CHECK(evt.subject_id == candidate);
        CHECK(evt.subject_pubkey == cand_pub);
        CHECK(evt.subject_x25519 == cand_x_pub);
        // Check metadata contains vote counts
        CHECK(evt.metadata.find("yes:5") != String::npos);
        CHECK(evt.metadata.find("no:1") != String::npos);
        CHECK(evt.metadata.find("abstain:2") != String::npos);
    }

    TEST_CASE("MembershipDecision to_event rejected") {
        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();
        NodeId candidate = crypto::node_id_from_pubkey(cand_pub);

        MembershipDecision decision;
        decision.candidate_id = candidate;
        decision.candidate_ed25519 = cand_pub;
        decision.candidate_x25519 = cand_x_pub;
        decision.approved = false;
        decision.yes_votes = 1;
        decision.no_votes = 5;
        decision.abstain_votes = 2;
        decision.timestamp_ms = time::now_ms();

        TrustEvent evt = decision.to_event();

        CHECK(evt.kind == TrustEventKind::JoinRejected);
    }

}

TEST_SUITE("RevocationEvent - Conversion") {

    TEST_CASE("RevocationEvent to_event") {
        auto [subject_priv, subject_pub] = crypto::generate_ed25519_keypair();
        NodeId subject = crypto::node_id_from_pubkey(subject_pub);

        auto [revoker_priv, revoker_pub] = crypto::generate_ed25519_keypair();
        NodeId revoker = crypto::node_id_from_pubkey(revoker_pub);

        RevocationEvent revoke;
        revoke.subject_id = subject;
        revoke.revoker_id = revoker;
        revoke.timestamp_ms = time::now_ms();
        revoke.reason = "Malicious behavior";

        TrustEvent evt = revoke.to_event();

        CHECK(evt.kind == TrustEventKind::MemberRevoked);
        CHECK(evt.subject_id == subject);
        CHECK(evt.actor_id == revoker);
        CHECK(evt.metadata == "Malicious behavior");
    }

}

TEST_SUITE("TrustEvent - Serialization") {

    TEST_CASE("TrustEvent serialization roundtrip") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId subject = crypto::node_id_from_pubkey(ed_pub);

        TrustEvent original;
        original.kind = TrustEventKind::JoinApproved;
        original.subject_id = subject;
        original.subject_pubkey = ed_pub;
        original.subject_x25519 = x_pub;
        original.timestamp_ms = time::now_ms();
        original.metadata = "test";

        auto bytes = trust::serialize_event(original);
        CHECK_FALSE(bytes.empty());

        auto result = trust::deserialize_event(bytes);
        REQUIRE(result.is_ok());

        auto& parsed = result.value();
        CHECK(parsed.kind == original.kind);
        CHECK(parsed.subject_id == original.subject_id);
        CHECK(parsed.timestamp_ms == original.timestamp_ms);
    }

}

TEST_SUITE("Vote - Values") {

    TEST_CASE("Vote enum values") {
        CHECK(static_cast<u8>(Vote::Yes) == 0);
        CHECK(static_cast<u8>(Vote::No) == 1);
        CHECK(static_cast<u8>(Vote::Abstain) == 2);
    }

}

