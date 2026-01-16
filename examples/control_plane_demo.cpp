/* SPDX-License-Identifier: MIT */
/*
 * Control Plane Demo
 * Demonstrates control plane message structures and serialization
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>

namespace bl = botlink;
using namespace bl::net;

int main() {
    std::cout << "=== Control Plane Demo ===\n\n";

    std::cout << "The control plane handles membership management messages:\n";
    std::cout << "join requests, proposals, votes, and endpoint advertisements.\n\n";

    // ==========================================================================
    // Step 1: Control message types
    // ==========================================================================
    std::cout << "1. Control message types...\n";

    std::cout << "   JoinRequest:        0x" << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(ControlMsgType::JoinRequest) << "\n";
    std::cout << "   JoinProposal:       0x" << std::setw(2)
              << static_cast<int>(ControlMsgType::JoinProposal) << "\n";
    std::cout << "   VoteCast:           0x" << std::setw(2)
              << static_cast<int>(ControlMsgType::VoteCast) << "\n";
    std::cout << "   MembershipUpdate:   0x" << std::setw(2)
              << static_cast<int>(ControlMsgType::MembershipUpdate) << "\n";
    std::cout << "   EndpointAdvert:     0x" << std::setw(2)
              << static_cast<int>(ControlMsgType::EndpointAdvert) << "\n";
    std::cout << "   MembershipSnapshot: 0x" << std::setw(2)
              << static_cast<int>(ControlMsgType::MembershipSnapshot) << "\n";
    std::cout << std::dec << "\n";

    // ==========================================================================
    // Step 2: EndpointAdvert structure
    // ==========================================================================
    std::cout << "2. EndpointAdvert structure...\n";

    auto [ed_priv, ed_pub] = bl::crypto::generate_ed25519_keypair();
    bl::NodeId node_id = bl::crypto::node_id_from_pubkey(ed_pub);

    EndpointAdvert advert;
    advert.node_id = node_id;
    advert.timestamp_ms = bl::time::now_ms();

    // Add some endpoints
    bl::Endpoint ep1;
    ep1.family = bl::AddrFamily::IPv4;
    ep1.ipv4.octets[0] = 192;
    ep1.ipv4.octets[1] = 168;
    ep1.ipv4.octets[2] = 1;
    ep1.ipv4.octets[3] = 100;
    ep1.port = 51820;
    advert.endpoints.push_back(ep1);

    bl::Endpoint ep2;
    ep2.family = bl::AddrFamily::IPv4;
    ep2.ipv4.octets[0] = 10;
    ep2.ipv4.octets[1] = 0;
    ep2.ipv4.octets[2] = 0;
    ep2.ipv4.octets[3] = 1;
    ep2.port = 51820;
    advert.endpoints.push_back(ep2);

    std::cout << "   Node ID: " << bl::crypto::node_id_to_hex(advert.node_id).substr(0, 16).c_str() << "...\n";
    std::cout << "   Endpoints: " << advert.endpoints.size() << "\n";
    for (dp::usize i = 0; i < advert.endpoints.size(); ++i) {
        std::cout << "     [" << i << "] " << bl::net::format_endpoint(advert.endpoints[i]).c_str() << "\n";
    }
    std::cout << "   Timestamp: " << advert.timestamp_ms << " ms\n";
    std::cout << "   Has relay: " << (advert.relay_id.has_value() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 3: EndpointAdvert with relay
    // ==========================================================================
    std::cout << "3. EndpointAdvert with relay...\n";

    auto [relay_priv, relay_pub] = bl::crypto::generate_ed25519_keypair();
    bl::NodeId relay_id = bl::crypto::node_id_from_pubkey(relay_pub);

    EndpointAdvert advert_with_relay;
    advert_with_relay.node_id = node_id;
    advert_with_relay.relay_id = relay_id;
    advert_with_relay.timestamp_ms = bl::time::now_ms();

    std::cout << "   Node ID: " << bl::crypto::node_id_to_hex(advert_with_relay.node_id).substr(0, 16).c_str() << "...\n";
    std::cout << "   Has relay: " << (advert_with_relay.relay_id.has_value() ? "YES" : "NO") << "\n";
    std::cout << "   Relay ID: " << bl::crypto::node_id_to_hex(advert_with_relay.relay_id.value()).substr(0, 16).c_str() << "...\n\n";

    // ==========================================================================
    // Step 4: MembershipUpdate structure
    // ==========================================================================
    std::cout << "4. MembershipUpdate structure...\n";

    auto [cand_priv, cand_pub] = bl::crypto::generate_ed25519_keypair();
    bl::NodeId candidate_id = bl::crypto::node_id_from_pubkey(cand_pub);

    MembershipUpdate update;
    update.candidate_id = candidate_id;
    update.approved = true;
    update.chain_height = 42;
    update.timestamp_ms = bl::time::now_ms();

    std::cout << "   Candidate: " << bl::crypto::node_id_to_hex(update.candidate_id).substr(0, 16).c_str() << "...\n";
    std::cout << "   Approved: " << (update.approved ? "YES" : "NO") << "\n";
    std::cout << "   Chain height: " << update.chain_height << "\n";
    std::cout << "   Timestamp: " << update.timestamp_ms << " ms\n\n";

    // ==========================================================================
    // Step 5: MembershipSnapshotRequest
    // ==========================================================================
    std::cout << "5. MembershipSnapshotRequest...\n";

    MembershipSnapshotRequest snap_req;
    snap_req.requester_id = node_id;
    snap_req.known_height = 10;
    snap_req.timestamp_ms = bl::time::now_ms();

    std::cout << "   Requester: " << bl::crypto::node_id_to_hex(snap_req.requester_id).substr(0, 16).c_str() << "...\n";
    std::cout << "   Known height: " << snap_req.known_height << "\n";
    std::cout << "   Timestamp: " << snap_req.timestamp_ms << " ms\n\n";

    // ==========================================================================
    // Step 6: MembershipSnapshotResponse
    // ==========================================================================
    std::cout << "6. MembershipSnapshotResponse...\n";

    MembershipSnapshotResponse snap_resp;
    snap_resp.chain_height = 50;
    snap_resp.timestamp_ms = bl::time::now_ms();

    // Add some member entries
    auto [m1_priv, m1_pub] = bl::crypto::generate_ed25519_keypair();
    auto [m1_x_priv, m1_x_pub] = bl::crypto::generate_x25519_keypair();

    bl::net::MemberSnapshotEntry entry1;
    entry1.node_id = bl::crypto::node_id_from_pubkey(m1_pub);
    entry1.ed25519_pubkey = m1_pub;
    entry1.x25519_pubkey = m1_x_pub;
    entry1.status = bl::MemberStatus::Approved;
    entry1.joined_at_ms = bl::time::now_ms() - 3600000; // 1 hour ago
    snap_resp.member_entries.push_back(entry1);

    auto [m2_priv, m2_pub] = bl::crypto::generate_ed25519_keypair();
    auto [m2_x_priv, m2_x_pub] = bl::crypto::generate_x25519_keypair();

    bl::net::MemberSnapshotEntry entry2;
    entry2.node_id = bl::crypto::node_id_from_pubkey(m2_pub);
    entry2.ed25519_pubkey = m2_pub;
    entry2.x25519_pubkey = m2_x_pub;
    entry2.status = bl::MemberStatus::Approved;
    entry2.joined_at_ms = bl::time::now_ms() - 1800000; // 30 min ago
    snap_resp.member_entries.push_back(entry2);

    std::cout << "   Chain height: " << snap_resp.chain_height << "\n";
    std::cout << "   Member entries: " << snap_resp.member_entries.size() << "\n";
    for (dp::usize i = 0; i < snap_resp.member_entries.size(); ++i) {
        std::cout << "     [" << i << "] " << bl::crypto::node_id_to_hex(snap_resp.member_entries[i].node_id).substr(0, 16).c_str()
                  << "... (" << bl::status_to_string(snap_resp.member_entries[i].status) << ")\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 7: ChainSyncRequest
    // ==========================================================================
    std::cout << "7. ChainSyncRequest...\n";

    ChainSyncRequest sync_req;
    sync_req.requester_id = node_id;
    sync_req.known_height = 25;
    sync_req.timestamp_ms = bl::time::now_ms();

    std::cout << "   Requester: " << bl::crypto::node_id_to_hex(sync_req.requester_id).substr(0, 16).c_str() << "...\n";
    std::cout << "   Known height: " << sync_req.known_height << "\n";
    std::cout << "   Timestamp: " << sync_req.timestamp_ms << " ms\n\n";

    // ==========================================================================
    // Step 8: ChainSyncResponse
    // ==========================================================================
    std::cout << "8. ChainSyncResponse...\n";

    ChainSyncResponse sync_resp;
    sync_resp.chain_height = 30;
    sync_resp.start_height = 26;
    sync_resp.timestamp_ms = bl::time::now_ms();

    // Add some trust events
    bl::TrustEvent evt1;
    evt1.kind = bl::TrustEventKind::JoinApproved;
    evt1.timestamp_ms = bl::time::now_ms() - 10000;
    evt1.subject_id = candidate_id;
    sync_resp.events.push_back(evt1);

    bl::TrustEvent evt2;
    evt2.kind = bl::TrustEventKind::VoteCast;
    evt2.timestamp_ms = bl::time::now_ms() - 5000;
    evt2.subject_id = candidate_id;
    evt2.vote = bl::Vote::Yes;
    sync_resp.events.push_back(evt2);

    std::cout << "   Chain height: " << sync_resp.chain_height << "\n";
    std::cout << "   Start height: " << sync_resp.start_height << "\n";
    std::cout << "   Events in response: " << sync_resp.events.size() << "\n";
    for (dp::usize i = 0; i < sync_resp.events.size(); ++i) {
        std::cout << "     [" << i << "] Event kind: " << static_cast<int>(sync_resp.events[i].kind)
                  << " (timestamp: " << sync_resp.events[i].timestamp_ms << ")\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 9: Serialization roundtrip
    // ==========================================================================
    std::cout << "9. Serialization roundtrip...\n";

    // Serialize EndpointAdvert
    auto advert_bytes = bl::serial::serialize(advert);
    std::cout << "   EndpointAdvert serialized: " << advert_bytes.size() << " bytes\n";

    auto advert_result = bl::serial::deserialize<EndpointAdvert>(advert_bytes);
    if (advert_result.is_ok()) {
        auto& parsed = advert_result.value();
        std::cout << "   EndpointAdvert deserialized: " << parsed.endpoints.size() << " endpoints\n";
        std::cout << "   Roundtrip matches: " << (parsed.node_id == advert.node_id ? "YES" : "NO") << "\n";
    }

    // Serialize MembershipUpdate
    auto update_bytes = bl::serial::serialize(update);
    std::cout << "   MembershipUpdate serialized: " << update_bytes.size() << " bytes\n";

    auto update_result = bl::serial::deserialize<MembershipUpdate>(update_bytes);
    if (update_result.is_ok()) {
        auto& parsed = update_result.value();
        std::cout << "   MembershipUpdate approved: " << (parsed.approved ? "YES" : "NO") << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 10: Creating signed control envelope
    // ==========================================================================
    std::cout << "10. Creating signed control envelope...\n";

    // Serialize the advert as payload
    auto payload = bl::serial::serialize(advert);

    // Create a signed envelope for the control message
    bl::Envelope env = bl::crypto::create_signed_envelope(
        bl::MsgType::JoinRequest,  // Using JoinRequest type as placeholder
        node_id,
        ed_priv,
        payload
    );

    std::cout << "   Envelope version: " << static_cast<int>(env.version) << "\n";
    std::cout << "   Envelope type: " << static_cast<int>(env.msg_type) << "\n";
    std::cout << "   Payload size: " << env.payload.size() << " bytes\n";

    bool valid = bl::crypto::verify_envelope(env, ed_pub);
    std::cout << "   Signature valid: " << (valid ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 11: Summary
    // ==========================================================================
    std::cout << "11. Summary...\n";
    std::cout << "   Control plane message types:\n";
    std::cout << "   - EndpointAdvert:           Advertise reachable addresses\n";
    std::cout << "   - MembershipUpdate:         Notify of membership changes\n";
    std::cout << "   - MembershipSnapshotRequest: Request full member list\n";
    std::cout << "   - MembershipSnapshotResponse: Full member list response\n";
    std::cout << "   - ChainSyncRequest:         Request trust chain events\n";
    std::cout << "   - ChainSyncResponse:        Trust chain events response\n\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
