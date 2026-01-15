/* SPDX-License-Identifier: MIT */
/*
 * Botlink Sponsor Daemon Example
 * Collects join requests and submits proposals to the trust chain
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

int main() {
    // Initialize libsodium
    if (botlink::init().is_err()) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    echo::info("=== Botlink Sponsor Daemon ===").cyan();

    // Generate sponsor identity
    auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
    NodeId sponsor_id = crypto::node_id_from_pubkey(ed_pub);

    String sponsor_hex = crypto::node_id_to_hex(sponsor_id);
    echo::info("Sponsor ID: ", sponsor_hex.substr(0, 16).c_str(), "...");

    // Create sponsor instance
    Sponsor sponsor(sponsor_id, ed_priv);

    echo::info("Sponsor daemon initialized").green();

    // Simulate receiving a join request from a candidate
    echo::info("");
    echo::info("Simulating candidate join request...").yellow();

    // Generate candidate keys (simulating a remote candidate)
    auto [cand_ed_priv, cand_ed_pub] = crypto::generate_ed25519_keypair();
    auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();
    NodeId candidate_id = crypto::node_id_from_pubkey(cand_ed_pub);

    // Create join request using the free function (candidate would do this)
    OverlayAddr requested_addr("10.42.0.50", 24);

    JoinRequest request = sponsor::create_join_request(cand_ed_priv, cand_ed_pub, cand_x_pub, requested_addr);

    String cand_hex = crypto::node_id_to_hex(candidate_id);
    echo::info("Received join request from candidate: ", cand_hex.substr(0, 16).c_str(), "...");

    // Sponsor receives and validates the request
    auto receive_res = sponsor.receive_request(request);
    if (receive_res.is_err()) {
        echo::error("Join request validation failed: ", receive_res.error().message.c_str());
        return 1;
    }

    echo::info("Join request validated and queued").green();

    // Create a JoinProposal to show what would be submitted
    JoinProposal proposal;
    proposal.candidate_id = request.candidate_id;
    proposal.sponsor_id = sponsor_id;
    proposal.candidate_ed25519 = request.candidate_ed25519;
    proposal.candidate_x25519 = request.candidate_x25519;
    proposal.timestamp_ms = time::now_ms();
    proposal.justification = "Candidate verified by sponsor";

    echo::info("");
    echo::info("Proposal Details:").yellow();
    echo::info("  Candidate ID:  ", cand_hex.substr(0, 32).c_str(), "...");
    echo::info("  Sponsor ID:    ", sponsor_hex.substr(0, 32).c_str(), "...");
    echo::info("  Requested Addr:", requested_addr.addr.c_str(), "/", requested_addr.prefix_len);
    echo::info("  Timestamp:     ", proposal.timestamp_ms);

    // In a real application, you would:
    // 1. Submit the proposal to the trust chain
    // 2. Broadcast to other members for voting
    // 3. Track voting progress

    echo::info("");
    echo::info("Next steps in production:").yellow();
    echo::info("  1. sponsor.submit_proposal(candidate_id, trust_chain)");
    echo::info("  2. Broadcast proposal to members");
    echo::info("  3. Collect votes and finalize");

    // Demonstrate voting setup
    VotingPolicy policy;
    policy.min_yes_votes = 2;
    policy.vote_timeout_ms = 15000;

    VotingManager voting(policy, sponsor_id);
    voting.add_proposal(proposal);

    echo::info("");
    echo::info("Voting configured:").yellow();
    echo::info("  Min yes votes: ", policy.min_yes_votes);
    echo::info("  Vote timeout:  ", policy.vote_timeout_ms, " ms");

    // Simulate casting a vote
    auto vote_res = voting.cast_vote(candidate_id, Vote::Yes, "Candidate verified");
    if (vote_res.is_ok()) {
        echo::info("  Vote cast: Yes").green();
    }

    echo::info("");
    echo::info("=== Sponsor Daemon Ready ===").cyan();

    return 0;
}
