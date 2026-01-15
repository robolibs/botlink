/* SPDX-License-Identifier: MIT */
/*
 * Botlink Join Candidate Example
 * Demonstrates a candidate sending a join request to a sponsor
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

int main(int argc, char* argv[]) {
    // Initialize libsodium
    if (botlink::init().is_err()) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    echo::info("=== Botlink Join Candidate ===").cyan();

    // Generate candidate identity
    auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
    auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
    NodeId candidate_id = crypto::node_id_from_pubkey(ed_pub);

    echo::info("Candidate ID: ", crypto::node_id_to_hex(candidate_id).substr(0, 16).c_str(), "...");

    // Create a join request using the helper function
    OverlayAddr requested_addr("10.42.0.100", 24);
    JoinRequest request = sponsor::create_join_request(ed_priv, ed_pub, x_pub, requested_addr);

    echo::info("Created join request with identity proof").green();

    // In a real application, you would:
    // 1. Serialize the request
    // 2. Create a signed envelope
    // 3. Send to sponsor endpoint

    // Serialize the request
    auto serialized = serial::serialize(request);
    echo::info("Serialized request size: ", serialized.size(), " bytes");

    // Create envelope
    Envelope env;
    env.version = 1;
    env.msg_type = MsgType::JoinRequest;
    env.timestamp_ms = time::now_ms();
    env.sender_id = candidate_id;
    env.payload = serialized;

    // Sign the envelope
    crypto::sign_envelope(env, ed_priv);

    echo::info("Signed envelope created").green();

    // Display what would be sent
    echo::info("").yellow();
    echo::info("Join Request Details:").yellow();
    String cand_hex = crypto::node_id_to_hex(candidate_id);
    echo::info("  Candidate ID:     ", cand_hex.substr(0, 32).c_str(), "...");
    echo::info("  Requested Addr:   ", requested_addr.addr.c_str(), "/", requested_addr.prefix_len);
    echo::info("  Timestamp:        ", request.timestamp_ms);
    echo::info("  Proof Size:       64 bytes (Ed25519 signature)");

    echo::info("");
    echo::info("To send to sponsor, connect to sponsor's endpoint and send the envelope.");
    echo::info("Example: udp://192.168.1.1:51820");

    echo::info("");
    echo::info("=== Candidate Ready to Join ===").cyan();

    return 0;
}
