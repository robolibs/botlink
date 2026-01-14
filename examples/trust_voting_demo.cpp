/* SPDX-License-Identifier: MIT */
/*
 * Botlink Trust Voting Demo
 * Demonstrates the membership voting system for robot swarms
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

// Helper to create a member identity
struct MemberIdentity {
    PrivateKey ed_priv;
    PublicKey ed_pub;
    PrivateKey x_priv;
    PublicKey x_pub;
    NodeId node_id;
    String name;

    static MemberIdentity generate(const String &name) {
        MemberIdentity id;
        id.name = name;
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        id.ed_priv = ed_priv;
        id.ed_pub = ed_pub;
        id.x_priv = x_priv;
        id.x_pub = x_pub;
        id.node_id = crypto::node_id_from_pubkey(ed_pub);
        return id;
    }

    String short_id() const {
        return crypto::node_id_to_hex(node_id).substr(0, 8);
    }
};

void print_divider(const char *title) {
    std::cout << "\n════════════════════════════════════════════════════════════════\n";
    std::cout << "  " << title << "\n";
    std::cout << "════════════════════════════════════════════════════════════════\n\n";
}

void demo_trust_view() {
    print_divider("TrustView Demo: Managing Robot Swarm Membership");

    // Create TrustView with voting policy
    // Requires 2 yes votes, 15 second timeout
    TrustView view(2, 15000);

    std::cout << "Created TrustView with policy:\n";
    std::cout << "  - Minimum yes votes: 2\n";
    std::cout << "  - Vote timeout: 15 seconds\n\n";

    // Create founding members (genesis)
    MemberIdentity alice = MemberIdentity::generate("Alice");
    MemberIdentity bob = MemberIdentity::generate("Bob");

    std::cout << "Adding founding members...\n";

    // Add Alice as founding member
    MemberEntry alice_entry;
    alice_entry.node_id = alice.node_id;
    alice_entry.ed25519_pubkey = alice.ed_pub;
    alice_entry.x25519_pubkey = alice.x_pub;
    alice_entry.status = MemberStatus::Approved;
    alice_entry.joined_at_ms = time::now_ms();
    view.add_member(alice_entry);
    std::cout << "  + Alice (" << alice.short_id().c_str() << ") - Founding member\n";

    // Add Bob as founding member
    MemberEntry bob_entry;
    bob_entry.node_id = bob.node_id;
    bob_entry.ed25519_pubkey = bob.ed_pub;
    bob_entry.x25519_pubkey = bob.x_pub;
    bob_entry.status = MemberStatus::Approved;
    bob_entry.joined_at_ms = time::now_ms();
    view.add_member(bob_entry);
    std::cout << "  + Bob (" << bob.short_id().c_str() << ") - Founding member\n";

    std::cout << "\nCurrent member count: " << view.member_count() << "\n";

    // New robot wants to join
    print_divider("New Robot Charlie Requests to Join");

    MemberIdentity charlie = MemberIdentity::generate("Charlie");
    std::cout << "Charlie (" << charlie.short_id().c_str() << ") requests to join the swarm\n";
    std::cout << "Alice will sponsor Charlie's membership\n\n";

    // Create join proposal
    JoinProposal proposal;
    proposal.candidate_id = charlie.node_id;
    proposal.candidate_ed25519 = charlie.ed_pub;
    proposal.candidate_x25519 = charlie.x_pub;
    proposal.sponsor_id = alice.node_id;
    proposal.timestamp_ms = time::now_ms();

    auto create_res = view.create_proposal(proposal);
    if (create_res.is_ok()) {
        std::cout << "Proposal created successfully!\n";
    } else {
        std::cout << "Failed to create proposal: " << create_res.error().message.c_str() << "\n";
        return;
    }

    // Voting process
    print_divider("Voting Process");

    std::cout << "Alice votes YES...\n";
    view.record_vote(charlie.node_id, alice.node_id, Vote::Yes);

    auto [has_quorum1, is_approved1, yes1, no1] = view.check_proposal_status(charlie.node_id);
    std::cout << "  Status: yes=" << yes1 << ", no=" << no1 << ", quorum=" << (has_quorum1 ? "yes" : "no") << "\n\n";

    std::cout << "Bob votes YES...\n";
    view.record_vote(charlie.node_id, bob.node_id, Vote::Yes);

    auto [has_quorum2, is_approved2, yes2, no2] = view.check_proposal_status(charlie.node_id);
    std::cout << "  Status: yes=" << yes2 << ", no=" << no2 << ", quorum=" << (has_quorum2 ? "yes" : "no") << "\n";
    std::cout << "  Decision: " << (is_approved2 ? "APPROVED" : "REJECTED") << "\n";

    // Approve the proposal
    if (is_approved2) {
        auto approve_res = view.approve_proposal(charlie.node_id);
        if (approve_res.is_ok()) {
            std::cout << "\nCharlie has been approved and added to the swarm!\n";
        }
    }

    std::cout << "\nFinal member count: " << view.member_count() << "\n";
    std::cout << "Members:\n";
    auto members = view.get_all_members();
    for (const auto &m : members) {
        std::cout << "  - " << crypto::node_id_to_hex(m.node_id).substr(0, 8).c_str() << "\n";
    }
}

void demo_voting_manager() {
    print_divider("VotingManager Demo: Detailed Vote Tracking");

    // Create identities
    MemberIdentity voter1 = MemberIdentity::generate("Voter1");
    MemberIdentity voter2 = MemberIdentity::generate("Voter2");
    MemberIdentity voter3 = MemberIdentity::generate("Voter3");
    MemberIdentity candidate = MemberIdentity::generate("Candidate");

    // Create voting manager
    VotingPolicy policy;
    policy.min_yes_votes = 2;
    policy.min_no_votes = 2;
    policy.vote_timeout_ms = 30000;
    policy.require_sponsor = true;

    VotingManager mgr(policy, voter1.node_id);

    std::cout << "Voting Policy:\n";
    std::cout << "  - Min YES votes to approve: " << policy.min_yes_votes << "\n";
    std::cout << "  - Min NO votes to reject: " << policy.min_no_votes << "\n";
    std::cout << "  - Vote timeout: " << policy.vote_timeout_ms << "ms\n";
    std::cout << "  - Sponsor required: " << (policy.require_sponsor ? "yes" : "no") << "\n\n";

    // Create proposal
    JoinProposal proposal;
    proposal.candidate_id = candidate.node_id;
    proposal.candidate_ed25519 = candidate.ed_pub;
    proposal.candidate_x25519 = candidate.x_pub;
    proposal.sponsor_id = voter1.node_id;
    proposal.timestamp_ms = time::now_ms();

    std::cout << "Creating proposal for candidate " << candidate.short_id().c_str() << "...\n";
    auto add_res = mgr.add_proposal(proposal);
    if (add_res.is_ok()) {
        std::cout << "Proposal added successfully!\n\n";
    }

    // Cast votes
    std::cout << "Casting votes:\n";

    VoteCastEvent vote1;
    vote1.candidate_id = candidate.node_id;
    vote1.voter_id = voter1.node_id;
    vote1.vote = Vote::Yes;
    vote1.reason = "Good credentials";
    vote1.timestamp_ms = time::now_ms();

    auto res1 = mgr.record_vote(vote1);
    std::cout << "  Voter1 votes YES -> Result: ";
    if (res1.is_ok()) {
        switch (res1.value()) {
        case VoteResult::Pending:
            std::cout << "PENDING\n";
            break;
        case VoteResult::Approved:
            std::cout << "APPROVED\n";
            break;
        case VoteResult::Rejected:
            std::cout << "REJECTED\n";
            break;
        case VoteResult::Expired:
            std::cout << "EXPIRED\n";
            break;
        }
    }

    VoteCastEvent vote2;
    vote2.candidate_id = candidate.node_id;
    vote2.voter_id = voter2.node_id;
    vote2.vote = Vote::Yes;
    vote2.timestamp_ms = time::now_ms();

    auto res2 = mgr.record_vote(vote2);
    std::cout << "  Voter2 votes YES -> Result: ";
    if (res2.is_ok()) {
        switch (res2.value()) {
        case VoteResult::Pending:
            std::cout << "PENDING\n";
            break;
        case VoteResult::Approved:
            std::cout << "APPROVED\n";
            break;
        case VoteResult::Rejected:
            std::cout << "REJECTED\n";
            break;
        case VoteResult::Expired:
            std::cout << "EXPIRED\n";
            break;
        }
    }

    std::cout << "\nCandidate " << candidate.short_id().c_str() << " membership approved!\n";
}

void demo_sponsor() {
    print_divider("Sponsor Demo: Handling Join Requests");

    // Create sponsor identity
    MemberIdentity sponsor = MemberIdentity::generate("Sponsor");
    std::cout << "Sponsor: " << sponsor.short_id().c_str() << "\n\n";

    // Create Sponsor instance
    // timeout: 60 seconds, max pending: 10
    Sponsor sponsor_mgr(sponsor.node_id, sponsor.ed_priv, 60000, 10);

    // Simulate incoming join requests from candidates
    MemberIdentity candidate1 = MemberIdentity::generate("Candidate1");
    MemberIdentity candidate2 = MemberIdentity::generate("Candidate2");

    std::cout << "Processing join requests...\n\n";

    // Candidate 1 sends join request (using helper to create signed request)
    JoinRequest req1 = sponsor::create_join_request(candidate1.ed_priv, candidate1.ed_pub, candidate1.x_pub);

    auto res1 = sponsor_mgr.receive_request(req1);
    if (res1.is_ok()) {
        std::cout << "  + Received request from " << candidate1.short_id().c_str() << " - ACCEPTED\n";
    } else {
        std::cout << "  - Request from " << candidate1.short_id().c_str() << " - REJECTED: "
                  << res1.error().message.c_str() << "\n";
    }

    // Candidate 2 sends join request (using helper to create signed request)
    JoinRequest req2 = sponsor::create_join_request(candidate2.ed_priv, candidate2.ed_pub, candidate2.x_pub);

    auto res2 = sponsor_mgr.receive_request(req2);
    if (res2.is_ok()) {
        std::cout << "  + Received request from " << candidate2.short_id().c_str() << " - ACCEPTED\n";
    } else {
        std::cout << "  - Request from " << candidate2.short_id().c_str() << " - REJECTED: "
                  << res2.error().message.c_str() << "\n";
    }

    std::cout << "\nPending requests: " << sponsor_mgr.pending_count() << "\n";

    // Try duplicate request
    std::cout << "\nTrying duplicate request from " << candidate1.short_id().c_str() << "...\n";
    auto dup_res = sponsor_mgr.receive_request(req1);
    if (dup_res.is_err()) {
        std::cout << "  REJECTED (already pending)\n";
    }

    // Remove one request
    std::cout << "\nRemoving request from " << candidate2.short_id().c_str() << "...\n";
    sponsor_mgr.remove_request(candidate2.node_id);
    std::cout << "Pending requests: " << sponsor_mgr.pending_count() << "\n";
}

void demo_trust_chain() {
    print_divider("TrustChain Demo: Blockchain-based Membership");

    // Create genesis member
    MemberIdentity genesis = MemberIdentity::generate("Genesis");
    std::cout << "Creating trust chain with genesis member...\n";
    std::cout << "Genesis: " << genesis.short_id().c_str() << "\n\n";

    // Create TrustChain
    TrustChain chain("robot_swarm_v1", genesis.node_id, genesis.ed_pub, genesis.x_pub);

    std::cout << "Chain ID: " << chain.chain_id().c_str() << "\n";
    std::cout << "Chain length: " << chain.length() << " blocks\n";
    std::cout << "Chain valid: " << (chain.is_valid() ? "yes" : "no") << "\n\n";

    // Check membership
    std::cout << "Genesis is member: " << (chain.is_member(genesis.node_id) ? "yes" : "no") << "\n";

    // Get all members
    auto members = chain.get_members();
    std::cout << "Total members: " << members.size() << "\n";
}

auto main() -> int {
    // Initialize botlink
    auto init_result = botlink::init();
    if (init_result.is_err()) {
        std::cerr << "Failed to initialize: " << init_result.error().message.c_str() << "\n";
        return 1;
    }

    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║            Botlink Trust & Voting System Demo                  ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";

    demo_trust_view();
    demo_voting_manager();
    demo_sponsor();
    demo_trust_chain();

    std::cout << "\n=== Demo Complete ===\n";
    return 0;
}
