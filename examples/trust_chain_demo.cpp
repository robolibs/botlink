/* SPDX-License-Identifier: MIT */
/*
 * Trust Chain Demo
 * Demonstrates blockchain-backed membership tracking
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
    std::cout << "=== Trust Chain Demo ===\n\n";

    // ==========================================================================
    // Step 1: Create genesis node identity
    // ==========================================================================
    std::cout << "1. Creating genesis node identity...\n";

    auto [genesis_ed_priv, genesis_ed_pub] = crypto::generate_ed25519_keypair();
    auto [genesis_x_priv, genesis_x_pub] = crypto::generate_x25519_keypair();
    NodeId genesis_id = crypto::node_id_from_pubkey(genesis_ed_pub);

    print_node_id("   Genesis node ID: ", genesis_id);
    std::cout << "\n";

    // ==========================================================================
    // Step 2: Initialize trust chain with genesis block
    // ==========================================================================
    std::cout << "2. Initializing trust chain with genesis block...\n";

    TrustChain chain("demo-network", genesis_id, genesis_ed_pub, genesis_x_pub);
    chain.set_local_node(genesis_id);
    chain.set_local_keys(genesis_ed_priv, genesis_ed_pub);

    std::cout << "   Chain ID: " << chain.chain_id().c_str() << "\n";
    std::cout << "   Chain length: " << chain.length() << " block(s)\n";
    std::cout << "   Genesis is member: " << (chain.is_member(genesis_id) ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 3: Query genesis events
    // ==========================================================================
    std::cout << "3. Querying genesis node events...\n";

    auto events = chain.get_events_for_node(genesis_id);
    std::cout << "   Events for genesis: " << events.size() << "\n";
    if (!events.empty()) {
        std::cout << "   First event kind: ";
        switch (events[0].kind) {
            case TrustEventKind::JoinProposed: std::cout << "JoinProposed\n"; break;
            case TrustEventKind::VoteCast: std::cout << "VoteCast\n"; break;
            case TrustEventKind::JoinApproved: std::cout << "JoinApproved\n"; break;
            case TrustEventKind::JoinRejected: std::cout << "JoinRejected\n"; break;
            case TrustEventKind::MemberRevoked: std::cout << "MemberRevoked\n"; break;
        }
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 4: Get list of members
    // ==========================================================================
    std::cout << "4. Listing all members...\n";

    auto members = chain.get_members();
    std::cout << "   Total members: " << members.size() << "\n";
    for (const auto& member : members) {
        print_node_id("   - Member: ", member);
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 5: Create a candidate node
    // ==========================================================================
    std::cout << "5. Creating candidate node identity...\n";

    auto [candidate_ed_priv, candidate_ed_pub] = crypto::generate_ed25519_keypair();
    auto [candidate_x_priv, candidate_x_pub] = crypto::generate_x25519_keypair();
    NodeId candidate_id = crypto::node_id_from_pubkey(candidate_ed_pub);

    print_node_id("   Candidate node ID: ", candidate_id);
    std::cout << "   Candidate is member: " << (chain.is_member(candidate_id) ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 6: Sign and verify event
    // ==========================================================================
    std::cout << "6. Testing event signing and verification...\n";

    TrustEvent test_evt;
    test_evt.kind = TrustEventKind::JoinProposed;
    test_evt.subject_id = candidate_id;
    test_evt.actor_id = genesis_id;
    test_evt.subject_pubkey = candidate_ed_pub;
    test_evt.subject_x25519 = candidate_x_pub;
    test_evt.timestamp_ms = time::now_ms();
    test_evt.metadata = "Candidate registration";

    Vector<u8> signature = chain.sign_event(test_evt);
    std::cout << "   Event signed, signature size: " << signature.size() << " bytes\n";

    bool valid = chain.verify_event_signature(test_evt, signature, genesis_ed_pub);
    std::cout << "   Signature verification: " << (valid ? "VALID" : "INVALID") << "\n";

    // Try with wrong key
    bool invalid = chain.verify_event_signature(test_evt, signature, candidate_ed_pub);
    std::cout << "   Verification with wrong key: " << (invalid ? "VALID" : "INVALID") << "\n\n";

    // ==========================================================================
    // Step 7: Get latest event for node
    // ==========================================================================
    std::cout << "7. Getting latest event for genesis node...\n";

    auto latest = chain.get_latest_event_for_node(genesis_id);
    if (latest.has_value()) {
        std::cout << "   Latest event found\n";
        std::cout << "   Event kind: JoinApproved\n";
        std::cout << "   Timestamp: " << latest->timestamp_ms << " ms\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 8: Register member pubkey for verification
    // ==========================================================================
    std::cout << "8. Registering candidate pubkey for future verification...\n";

    chain.register_member_pubkey(candidate_id, candidate_ed_pub);
    std::cout << "   Pubkey registered for candidate node\n";
    std::cout << "   (This allows verifying signatures from candidate in the future)\n\n";

    // ==========================================================================
    // Step 9: Get all nodes with latest events
    // ==========================================================================
    std::cout << "9. Getting all nodes with their latest events...\n";

    auto all_nodes = chain.get_all_nodes_with_latest_event();
    std::cout << "   Total nodes with events: " << all_nodes.size() << "\n";
    for (const auto& [node_id, evt] : all_nodes) {
        std::cout << "   - ";
        String hex = crypto::node_id_to_hex(node_id);
        std::cout << hex.substr(0, 16).c_str() << "... : ";
        switch (evt.kind) {
            case TrustEventKind::JoinProposed: std::cout << "JoinProposed"; break;
            case TrustEventKind::VoteCast: std::cout << "VoteCast"; break;
            case TrustEventKind::JoinApproved: std::cout << "JoinApproved"; break;
            case TrustEventKind::JoinRejected: std::cout << "JoinRejected"; break;
            case TrustEventKind::MemberRevoked: std::cout << "MemberRevoked"; break;
        }
        std::cout << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 10: Summary
    // ==========================================================================
    std::cout << "10. Final chain summary...\n";
    std::cout << "   Chain ID: " << chain.chain_id().c_str() << "\n";
    std::cout << "   Chain length: " << chain.length() << " block(s)\n";
    std::cout << "   Total members: " << chain.get_members().size() << "\n\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
