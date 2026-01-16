/* SPDX-License-Identifier: MIT */
/*
 * Botlink Chain Sync Demo
 * Demonstrates trust chain synchronization between peers
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

// Helper to print separator
void print_separator() { std::cout << "----------------------------------------\n"; }

auto main() -> int {
    // Initialize the library
    auto init_result = botlink::init();
    if (init_result.is_err()) {
        std::cerr << "Failed to initialize botlink: " << init_result.error().message.c_str() << "\n";
        return 1;
    }

    std::cout << "Botlink Chain Sync Demo\n";
    std::cout << "=======================\n\n";

    // Create identities for two nodes
    std::cout << "Creating identities for two nodes...\n";
    auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
    auto [x_priv1, x_pub1] = crypto::generate_x25519_keypair();
    NodeId node1_id = crypto::node_id_from_pubkey(ed_pub1);

    auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
    auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();
    NodeId node2_id = crypto::node_id_from_pubkey(ed_pub2);

    std::cout << "Node 1 ID: " << crypto::node_id_to_hex(node1_id).substr(0, 16).c_str() << "...\n";
    std::cout << "Node 2 ID: " << crypto::node_id_to_hex(node2_id).substr(0, 16).c_str() << "...\n\n";

    print_separator();

    // Create trust chains for both nodes
    // Node 1 is the genesis node
    std::cout << "Creating trust chain with Node 1 as genesis...\n";
    TrustChain chain1("botlink_chain", node1_id, ed_pub1, x_pub1);
    chain1.set_local_node(node1_id);
    chain1.set_local_keys(ed_priv1, ed_pub1);

    std::cout << "Chain 1 length: " << chain1.length() << "\n";
    std::cout << "Chain 1 valid: " << (chain1.is_valid() ? "yes" : "no") << "\n";
    std::cout << "Node 1 is member: " << (chain1.is_member(node1_id) ? "yes" : "no") << "\n\n";

    print_separator();

    // Node 1 proposes Node 2 for membership
    std::cout << "Node 1 proposing Node 2 for membership...\n";

    JoinProposal proposal;
    proposal.candidate_id = node2_id;
    proposal.candidate_ed25519 = ed_pub2;
    proposal.candidate_x25519 = x_pub2;
    proposal.sponsor_id = node1_id;
    proposal.timestamp_ms = time::now_ms();
    proposal.justification = "New member joining network";

    auto propose_res = chain1.propose_join(proposal);
    if (propose_res.is_err()) {
        std::cerr << "Failed to propose: " << propose_res.error().message.c_str() << "\n";
        return 1;
    }
    std::cout << "Proposal added to chain.\n";
    std::cout << "Chain 1 length: " << chain1.length() << "\n\n";

    print_separator();

    // Node 1 casts a vote
    std::cout << "Node 1 voting YES for Node 2...\n";

    VoteCastEvent vote;
    vote.candidate_id = node2_id;
    vote.voter_id = node1_id;
    vote.vote = Vote::Yes;
    vote.timestamp_ms = time::now_ms();
    vote.reason = "Verified identity";

    auto vote_res = chain1.cast_vote(vote);
    if (vote_res.is_err()) {
        std::cerr << "Failed to cast vote: " << vote_res.error().message.c_str() << "\n";
        return 1;
    }
    std::cout << "Vote recorded in chain.\n";
    std::cout << "Chain 1 length: " << chain1.length() << "\n\n";

    print_separator();

    // Record the decision (approval)
    std::cout << "Recording membership decision (approval)...\n";

    MembershipDecision decision;
    decision.candidate_id = node2_id;
    decision.candidate_ed25519 = ed_pub2;
    decision.candidate_x25519 = x_pub2;
    decision.approved = true;
    decision.yes_votes = 1;
    decision.no_votes = 0;
    decision.abstain_votes = 0;
    decision.timestamp_ms = time::now_ms();

    auto decision_res = chain1.record_decision(decision);
    if (decision_res.is_err()) {
        std::cerr << "Failed to record decision: " << decision_res.error().message.c_str() << "\n";
        return 1;
    }
    std::cout << "Decision recorded.\n";
    std::cout << "Chain 1 length: " << chain1.length() << "\n";
    std::cout << "Node 2 is now member: " << (chain1.is_member(node2_id) ? "yes" : "no") << "\n\n";

    print_separator();

    // Create a ChainSyncRequest (what Node 2 would send to sync)
    std::cout << "Simulating chain sync request from Node 2...\n";

    net::ChainSyncRequest sync_req;
    sync_req.requester_id = node2_id;
    sync_req.known_height = 0; // Node 2 has no chain data
    sync_req.timestamp_ms = time::now_ms();

    std::cout << "Node 2 requesting sync from height: " << sync_req.known_height << "\n";
    std::cout << "Node 1 has chain height: " << chain1.length() << "\n\n";

    print_separator();

    // Build sync response
    std::cout << "Building chain sync response...\n";

    net::ChainSyncResponse sync_resp;
    sync_resp.chain_height = chain1.length();
    sync_resp.start_height = sync_req.known_height;
    sync_resp.timestamp_ms = time::now_ms();

    // Get all events to sync
    auto all_events = chain1.get_all_nodes_with_latest_event();
    for (const auto &[nid, evt] : all_events) {
        sync_resp.events.push_back(evt);
    }

    std::cout << "Sync response contains " << sync_resp.events.size() << " events\n";
    std::cout << "Sync response chain height: " << sync_resp.chain_height << "\n\n";

    print_separator();

    // Get all members from chain
    std::cout << "Final chain state:\n";
    auto members = chain1.get_members();
    std::cout << "Total members: " << members.size() << "\n";
    for (const auto &member_id : members) {
        std::cout << "  - " << crypto::node_id_to_hex(member_id).substr(0, 16).c_str() << "...\n";
    }

    std::cout << "\nChain sync demo completed successfully!\n";
    return 0;
}
