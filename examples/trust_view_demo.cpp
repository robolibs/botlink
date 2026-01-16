/* SPDX-License-Identifier: MIT */
/*
 * Trust View Demo
 * Demonstrates in-memory membership table derived from trust chain
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>

using namespace botlink;
using namespace dp;

// Helper to print NodeId
void print_node_id(const char* label, const NodeId& id) {
    String hex = crypto::node_id_to_hex(id);
    std::cout << label << hex.substr(0, 16).c_str() << "...\n";
}

int main() {
    std::cout << "=== Trust View Demo ===\n\n";

    std::cout << "TrustView is an in-memory membership table that tracks\n";
    std::cout << "active members, pending proposals, and vote status.\n";
    std::cout << "It can be synced from a TrustChain for consistency.\n\n";

    // ==========================================================================
    // Step 1: Create TrustView with voting parameters
    // ==========================================================================
    std::cout << "1. Creating TrustView with voting parameters...\n";

    u32 min_yes_votes = 2;
    u64 vote_timeout_ms = 15000;

    TrustView view(min_yes_votes, vote_timeout_ms);

    std::cout << "   Min yes votes for approval: " << min_yes_votes << "\n";
    std::cout << "   Vote timeout: " << vote_timeout_ms << " ms\n";
    std::cout << "   Initial member count: " << view.member_count() << "\n\n";

    // ==========================================================================
    // Step 2: Add founding members directly
    // ==========================================================================
    std::cout << "2. Adding founding members...\n";

    // Create three founding members
    auto [member1_ed_priv, member1_ed_pub] = crypto::generate_ed25519_keypair();
    auto [member1_x_priv, member1_x_pub] = crypto::generate_x25519_keypair();
    NodeId member1_id = crypto::node_id_from_pubkey(member1_ed_pub);

    auto [member2_ed_priv, member2_ed_pub] = crypto::generate_ed25519_keypair();
    auto [member2_x_priv, member2_x_pub] = crypto::generate_x25519_keypair();
    NodeId member2_id = crypto::node_id_from_pubkey(member2_ed_pub);

    auto [member3_ed_priv, member3_ed_pub] = crypto::generate_ed25519_keypair();
    auto [member3_x_priv, member3_x_pub] = crypto::generate_x25519_keypair();
    NodeId member3_id = crypto::node_id_from_pubkey(member3_ed_pub);

    MemberEntry entry1;
    entry1.node_id = member1_id;
    entry1.ed25519_pubkey = member1_ed_pub;
    entry1.x25519_pubkey = member1_x_pub;
    entry1.status = MemberStatus::Approved;
    entry1.joined_at_ms = time::now_ms();
    view.add_member(entry1);

    MemberEntry entry2;
    entry2.node_id = member2_id;
    entry2.ed25519_pubkey = member2_ed_pub;
    entry2.x25519_pubkey = member2_x_pub;
    entry2.status = MemberStatus::Approved;
    entry2.joined_at_ms = time::now_ms();
    view.add_member(entry2);

    MemberEntry entry3;
    entry3.node_id = member3_id;
    entry3.ed25519_pubkey = member3_ed_pub;
    entry3.x25519_pubkey = member3_x_pub;
    entry3.status = MemberStatus::Approved;
    entry3.joined_at_ms = time::now_ms();
    view.add_member(entry3);

    std::cout << "   Member count: " << view.member_count() << "\n";
    print_node_id("   Member 1: ", member1_id);
    print_node_id("   Member 2: ", member2_id);
    print_node_id("   Member 3: ", member3_id);
    std::cout << "\n";

    // ==========================================================================
    // Step 3: Query member status
    // ==========================================================================
    std::cout << "3. Querying member status...\n";

    std::cout << "   Member 1 is member: " << (view.is_member(member1_id) ? "YES" : "NO") << "\n";

    auto member1_info = view.get_member(member1_id);
    if (member1_info.has_value()) {
        std::cout << "   Member 1 status: " << status_to_string(member1_info->status) << "\n";
        std::cout << "   Member 1 is active: " << (member1_info->is_active() ? "YES" : "NO") << "\n";
    }

    // Check non-member
    auto [nonmember_priv, nonmember_pub] = crypto::generate_ed25519_keypair();
    NodeId nonmember_id = crypto::node_id_from_pubkey(nonmember_pub);
    std::cout << "   Random node is member: " << (view.is_member(nonmember_id) ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 4: Get member public keys
    // ==========================================================================
    std::cout << "4. Getting member public keys...\n";

    auto ed_key = view.get_ed25519_pubkey(member1_id);
    if (ed_key.has_value()) {
        std::cout << "   Member 1 Ed25519 key retrieved: YES\n";
        std::cout << "   Key matches: " << (ed_key.value() == member1_ed_pub ? "YES" : "NO") << "\n";
    }

    auto x_key = view.get_x25519_pubkey(member1_id);
    if (x_key.has_value()) {
        std::cout << "   Member 1 X25519 key retrieved: YES\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 5: Create a join proposal
    // ==========================================================================
    std::cout << "5. Creating a join proposal for candidate...\n";

    auto [candidate_ed_priv, candidate_ed_pub] = crypto::generate_ed25519_keypair();
    auto [candidate_x_priv, candidate_x_pub] = crypto::generate_x25519_keypair();
    NodeId candidate_id = crypto::node_id_from_pubkey(candidate_ed_pub);

    JoinProposal proposal;
    proposal.candidate_id = candidate_id;
    proposal.candidate_ed25519 = candidate_ed_pub;
    proposal.candidate_x25519 = candidate_x_pub;
    proposal.sponsor_id = member1_id;
    proposal.timestamp_ms = time::now_ms();
    proposal.justification = "Trusted developer";

    auto proposal_result = view.create_proposal(proposal);
    std::cout << "   Proposal created: " << (proposal_result.is_ok() ? "YES" : "NO") << "\n";
    print_node_id("   Candidate: ", candidate_id);
    print_node_id("   Sponsor: ", member1_id);

    auto pending = view.get_pending_proposal(candidate_id);
    if (pending.has_value()) {
        std::cout << "   Proposal found in pending: YES\n";
        std::cout << "   Proposal expired: " << (pending->is_expired() ? "YES" : "NO") << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 6: Cast votes
    // ==========================================================================
    std::cout << "6. Casting votes...\n";

    // Member 1 votes yes
    auto vote1_result = view.record_vote(candidate_id, member1_id, Vote::Yes);
    std::cout << "   Member 1 votes YES: " << (vote1_result.is_ok() ? "recorded" : "failed") << "\n";

    // Check status after 1 vote
    auto [has_quorum1, is_approved1, yes1, no1] = view.check_proposal_status(candidate_id);
    std::cout << "   After 1 vote - Yes: " << yes1 << ", No: " << no1
              << ", Quorum: " << (has_quorum1 ? "YES" : "NO") << "\n";

    // Member 2 votes yes
    auto vote2_result = view.record_vote(candidate_id, member2_id, Vote::Yes);
    std::cout << "   Member 2 votes YES: " << (vote2_result.is_ok() ? "recorded" : "failed") << "\n";

    // Check status after 2 votes
    auto [has_quorum2, is_approved2, yes2, no2] = view.check_proposal_status(candidate_id);
    std::cout << "   After 2 votes - Yes: " << yes2 << ", No: " << no2
              << ", Quorum: " << (has_quorum2 ? "YES" : "NO")
              << ", Approved: " << (is_approved2 ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 7: Approve the proposal
    // ==========================================================================
    std::cout << "7. Approving the proposal...\n";

    auto approve_result = view.approve_proposal(candidate_id);
    std::cout << "   Approval result: " << (approve_result.is_ok() ? "SUCCESS" : "FAILED") << "\n";
    std::cout << "   Candidate is now member: " << (view.is_member(candidate_id) ? "YES" : "NO") << "\n";
    std::cout << "   Total members: " << view.member_count() << "\n";

    // Pending proposal should be removed
    auto pending_after = view.get_pending_proposal(candidate_id);
    std::cout << "   Pending proposal removed: " << (pending_after.has_value() ? "NO" : "YES") << "\n\n";

    // ==========================================================================
    // Step 8: List all members
    // ==========================================================================
    std::cout << "8. Listing all members...\n";

    auto all_members = view.get_all_members();
    std::cout << "   Total active members: " << all_members.size() << "\n";
    for (const auto& member : all_members) {
        std::cout << "   - ";
        String hex = crypto::node_id_to_hex(member.node_id);
        std::cout << hex.substr(0, 16).c_str() << "... ("
                  << status_to_string(member.status) << ")\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 9: Update member info
    // ==========================================================================
    std::cout << "9. Updating member info...\n";

    // Touch member (update last seen)
    view.touch_member(member1_id);
    auto touched = view.get_member(member1_id);
    if (touched.has_value()) {
        std::cout << "   Member 1 last_seen updated: "
                  << (touched->last_seen_ms > 0 ? "YES" : "NO") << "\n";
    }

    // Update endpoints
    Vector<Endpoint> endpoints;
    Endpoint ep;
    ep.family = AddrFamily::IPv4;
    ep.ipv4.octets[0] = 192;
    ep.ipv4.octets[1] = 168;
    ep.ipv4.octets[2] = 1;
    ep.ipv4.octets[3] = 100;
    ep.port = 51820;
    endpoints.push_back(ep);

    view.update_endpoints(member1_id, endpoints);
    auto with_ep = view.get_member(member1_id);
    if (with_ep.has_value()) {
        std::cout << "   Member 1 endpoints: " << with_ep->endpoints.size() << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 10: Revoke a member
    // ==========================================================================
    std::cout << "10. Revoking a member...\n";

    std::cout << "   Member 3 is member before: " << (view.is_member(member3_id) ? "YES" : "NO") << "\n";

    bool removed = view.remove_member(member3_id);
    std::cout << "   Revocation result: " << (removed ? "SUCCESS" : "FAILED") << "\n";
    std::cout << "   Member 3 is member after: " << (view.is_member(member3_id) ? "YES" : "NO") << "\n";

    auto revoked_info = view.get_member(member3_id);
    if (revoked_info.has_value()) {
        std::cout << "   Member 3 status: " << status_to_string(revoked_info->status) << "\n";
    }
    std::cout << "   Active member count: " << view.member_count() << "\n\n";

    // ==========================================================================
    // Step 11: Reject a proposal
    // ==========================================================================
    std::cout << "11. Creating and rejecting a proposal...\n";

    auto [reject_ed_priv, reject_ed_pub] = crypto::generate_ed25519_keypair();
    auto [reject_x_priv, reject_x_pub] = crypto::generate_x25519_keypair();
    NodeId reject_id = crypto::node_id_from_pubkey(reject_ed_pub);

    JoinProposal reject_proposal;
    reject_proposal.candidate_id = reject_id;
    reject_proposal.candidate_ed25519 = reject_ed_pub;
    reject_proposal.candidate_x25519 = reject_x_pub;
    reject_proposal.sponsor_id = member1_id;

    (void)view.create_proposal(reject_proposal);
    std::cout << "   Proposal created for rejection test\n";

    auto reject_result = view.reject_proposal(reject_id);
    std::cout << "   Rejection result: " << (reject_result.is_ok() ? "SUCCESS" : "FAILED") << "\n";
    std::cout << "   Rejected node is member: " << (view.is_member(reject_id) ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 12: List all pending proposals
    // ==========================================================================
    std::cout << "12. Managing multiple pending proposals...\n";

    // Create two more proposals
    auto [p1_ed_priv, p1_ed_pub] = crypto::generate_ed25519_keypair();
    auto [p1_x_priv, p1_x_pub] = crypto::generate_x25519_keypair();
    NodeId p1_id = crypto::node_id_from_pubkey(p1_ed_pub);

    auto [p2_ed_priv, p2_ed_pub] = crypto::generate_ed25519_keypair();
    auto [p2_x_priv, p2_x_pub] = crypto::generate_x25519_keypair();
    NodeId p2_id = crypto::node_id_from_pubkey(p2_ed_pub);

    JoinProposal jp1;
    jp1.candidate_id = p1_id;
    jp1.candidate_ed25519 = p1_ed_pub;
    jp1.candidate_x25519 = p1_x_pub;
    jp1.sponsor_id = member1_id;

    JoinProposal jp2;
    jp2.candidate_id = p2_id;
    jp2.candidate_ed25519 = p2_ed_pub;
    jp2.candidate_x25519 = p2_x_pub;
    jp2.sponsor_id = member2_id;

    (void)view.create_proposal(jp1);
    (void)view.create_proposal(jp2);

    auto all_pending = view.get_all_pending();
    std::cout << "   Total pending proposals: " << all_pending.size() << "\n";
    for (const auto& pend : all_pending) {
        std::cout << "   - Candidate: ";
        String hex = crypto::node_id_to_hex(pend.candidate_id);
        std::cout << hex.substr(0, 16).c_str() << "...\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 13: Summary
    // ==========================================================================
    std::cout << "13. Final summary...\n";
    std::cout << "   Active members: " << view.member_count() << "\n";
    std::cout << "   Pending proposals: " << view.get_all_pending().size() << "\n\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
