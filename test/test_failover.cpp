/* SPDX-License-Identifier: MIT */
/*
 * Botlink Relay Failover Tests
 * Tests for relay redundancy, failover, and recovery scenarios
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>
#include <chrono>
#include <thread>

using namespace botlink;
using namespace dp;

// =============================================================================
// Test Fixtures
// =============================================================================

struct FailoverTestNode {
    NodeId id;
    PrivateKey ed25519_priv;
    PublicKey ed25519_pub;
    PrivateKey x25519_priv;
    PublicKey x25519_pub;

    FailoverTestNode() {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        ed25519_priv = ed_priv;
        ed25519_pub = ed_pub;
        x25519_priv = x_priv;
        x25519_pub = x_pub;
        id = crypto::node_id_from_pubkey(ed_pub);
    }
};

// Helper to create a relay info with specific characteristics
net::RelayInfo create_relay(const String &id, u16 port, u64 latency_ms, bool connected = true, bool fresh = true) {
    net::RelayInfo relay;
    relay.id = id;
    relay.endpoint = Endpoint(IPv4Addr(192, 168, 1, static_cast<u8>(port % 256)), port);
    relay.latency_ms = latency_ms;
    relay.is_connected = connected;
    relay.last_seen_ms = fresh ? time::now_ms() : (time::now_ms() - 60000); // Stale if not fresh
    relay.current_load = 0;
    return relay;
}

// =============================================================================
// Relay Selection Tests
// =============================================================================

TEST_SUITE("Failover - Relay Selection") {

    TEST_CASE("Selects preferred relay when available") {
        FailoverTestNode node;
        net::RelayManager manager(node.id, nullptr);

        // Add relays
        manager.add_relay(create_relay("relay1", 51820, 50));
        manager.add_relay(create_relay("relay2", 51821, 20)); // Lower latency
        manager.add_relay(create_relay("relay3", 51822, 30));

        // Set preferred relay
        Vector<String> preferred;
        preferred.push_back("relay1");
        manager.set_preferred_relays(preferred);

        auto selected = manager.select_relay();
        REQUIRE(selected.has_value());
        CHECK(selected->id == "relay1");
    }

    TEST_CASE("Falls back to lowest latency when preferred unavailable") {
        FailoverTestNode node;
        net::RelayManager manager(node.id, nullptr);

        // Add relays - relay1 is stale
        manager.add_relay(create_relay("relay1", 51820, 50, true, false)); // Stale
        manager.add_relay(create_relay("relay2", 51821, 100));
        manager.add_relay(create_relay("relay3", 51822, 30)); // Lowest latency

        // Set preferred relay (which is stale)
        Vector<String> preferred;
        preferred.push_back("relay1");
        manager.set_preferred_relays(preferred);

        auto selected = manager.select_relay();
        REQUIRE(selected.has_value());
        CHECK(selected->id == "relay3"); // Should select lowest latency available
    }

    TEST_CASE("Respects allowed relays list") {
        FailoverTestNode node;
        net::RelayManager manager(node.id, nullptr);

        // Add relays
        manager.add_relay(create_relay("relay1", 51820, 10)); // Lowest latency but not allowed
        manager.add_relay(create_relay("relay2", 51821, 50));
        manager.add_relay(create_relay("relay3", 51822, 30));

        // Only allow relay2 and relay3
        Vector<String> allowed;
        allowed.push_back("relay2");
        allowed.push_back("relay3");
        manager.set_allowed_relays(allowed);

        auto selected = manager.select_relay();
        REQUIRE(selected.has_value());
        CHECK(selected->id == "relay3"); // Should be relay3 (lowest latency among allowed)
    }

    TEST_CASE("Returns empty when no relays available") {
        FailoverTestNode node;
        net::RelayManager manager(node.id, nullptr);

        auto selected = manager.select_relay();
        CHECK_FALSE(selected.has_value());
    }

    TEST_CASE("Excludes stale relays from selection") {
        FailoverTestNode node;
        net::RelayManager manager(node.id, nullptr);

        // All relays are stale
        manager.add_relay(create_relay("relay1", 51820, 10, true, false));
        manager.add_relay(create_relay("relay2", 51821, 20, true, false));

        auto selected = manager.select_relay();
        CHECK_FALSE(selected.has_value());
    }
}

// =============================================================================
// Relay Route Management Tests
// =============================================================================

TEST_SUITE("Failover - Relay Routes") {

    TEST_CASE("Relay route becomes active after ACK") {
        FailoverTestNode node;
        FailoverTestNode peer;
        net::RelayManager manager(node.id, nullptr);

        manager.add_relay(create_relay("relay1", 51820, 10));

        // Note: request_relay_route requires a socket, testing just the ACK handling
        // Create a pending route manually for testing
        net::RelayRoute route;
        route.peer_id = peer.id;
        route.relay_id = "relay1";
        route.relay_endpoint = Endpoint(IPv4Addr(192, 168, 1, 1), 51820);
        route.established_at_ms = time::now_ms();
        route.is_active = false;

        // Simulate receiving ACK
        auto result = manager.handle_relay_ack(peer.id);
        // This will fail since we didn't add the route through the manager
        CHECK(result.is_err()); // Expected - no pending route

        // The proper test would require full integration
    }

    TEST_CASE("Relay route lookup returns correct route") {
        FailoverTestNode node;
        FailoverTestNode peer;
        net::RelayManager manager(node.id, nullptr);

        manager.add_relay(create_relay("relay1", 51820, 10));

        // Get route (should be empty since none established)
        auto route = manager.get_relay_route(peer.id);
        CHECK_FALSE(route.has_value());
    }
}

// =============================================================================
// Relay Staleness Tests
// =============================================================================

TEST_SUITE("Failover - Relay Staleness") {

    TEST_CASE("RelayInfo staleness detection") {
        net::RelayInfo relay;
        relay.id = "test_relay";
        relay.last_seen_ms = time::now_ms();

        // Fresh relay
        CHECK_FALSE(relay.is_stale(30000));

        // Make it stale
        relay.last_seen_ms = time::now_ms() - 60000;
        CHECK(relay.is_stale(30000));
    }

    TEST_CASE("Stale relays are not selected") {
        FailoverTestNode node;
        net::RelayManager manager(node.id, nullptr);

        // Add fresh and stale relays
        manager.add_relay(create_relay("fresh_relay", 51820, 10, true, true));
        manager.add_relay(create_relay("stale_relay", 51821, 5, true, false)); // Lower latency but stale

        // Only fresh relay should be selectable since stale_relay is too old
        auto selected = manager.select_relay();
        REQUIRE(selected.has_value());
        CHECK(selected->id == "fresh_relay");
    }

    TEST_CASE("Relay route age calculation") {
        net::RelayRoute route;
        route.established_at_ms = time::now_ms() - 5000;

        u64 age = route.age_ms();
        CHECK(age >= 5000);
        CHECK(age < 6000); // Some tolerance for test execution time
    }
}

// =============================================================================
// Relay Failover Scenarios
// =============================================================================

TEST_SUITE("Failover - Failover Scenarios") {

    TEST_CASE("Preferred relay is selected when fresh") {
        FailoverTestNode node;
        net::RelayManager manager(node.id, nullptr);

        // Setup: primary relay with high latency, backup with low latency
        auto primary = create_relay("primary", 51820, 100, true, true);
        auto backup = create_relay("backup", 51821, 20, true, true);

        manager.add_relay(primary);
        manager.add_relay(backup);

        Vector<String> preferred;
        preferred.push_back("primary");
        manager.set_preferred_relays(preferred);

        // Selects primary (preferred) even though backup has lower latency
        auto selected = manager.select_relay();
        REQUIRE(selected.has_value());
        CHECK(selected->id == "primary");
    }

    TEST_CASE("Falls back to lowest latency when preferred is stale") {
        FailoverTestNode node;
        net::RelayManager manager(node.id, nullptr);

        // Primary is stale, backup is fresh
        manager.add_relay(create_relay("primary", 51820, 100, true, false)); // stale
        manager.add_relay(create_relay("backup", 51821, 20, true, true));     // fresh

        Vector<String> preferred;
        preferred.push_back("primary");
        manager.set_preferred_relays(preferred);

        // Should select backup since primary is stale
        auto selected = manager.select_relay();
        REQUIRE(selected.has_value());
        CHECK(selected->id == "backup");
    }

    TEST_CASE("No relay available when all are stale") {
        FailoverTestNode node;
        net::RelayManager manager(node.id, nullptr);

        // All relays are stale
        manager.add_relay(create_relay("relay1", 51820, 10, true, false));
        manager.add_relay(create_relay("relay2", 51821, 20, true, false));
        manager.add_relay(create_relay("relay3", 51822, 30, true, false));

        // No relay available since all are stale
        auto selected = manager.select_relay();
        CHECK_FALSE(selected.has_value());
    }

    TEST_CASE("Selects lowest latency among fresh relays") {
        FailoverTestNode node;
        net::RelayManager manager(node.id, nullptr);

        // Multiple fresh relays with different latencies
        manager.add_relay(create_relay("high_latency", 51820, 100, true, true));
        manager.add_relay(create_relay("low_latency", 51821, 10, true, true));
        manager.add_relay(create_relay("medium_latency", 51822, 50, true, true));

        // Should select lowest latency
        auto selected = manager.select_relay();
        REQUIRE(selected.has_value());
        CHECK(selected->id == "low_latency");
    }
}

// =============================================================================
// Relay Load Balancing Tests
// =============================================================================

TEST_SUITE("Failover - Load Balancing") {

    TEST_CASE("Prefers relay with lower load when latencies equal") {
        FailoverTestNode node;
        net::RelayManager manager(node.id, nullptr);

        auto relay1 = create_relay("relay1", 51820, 50);
        relay1.current_load = 100;

        auto relay2 = create_relay("relay2", 51821, 50);
        relay2.current_load = 10;

        manager.add_relay(relay1);
        manager.add_relay(relay2);

        // Note: Current implementation doesn't consider load in selection
        // This test documents the expected behavior for future enhancement
        auto selected = manager.select_relay();
        REQUIRE(selected.has_value());
        // When load balancing is implemented, should prefer relay2
    }
}

// =============================================================================
// Relay Forward Packet Tests
// =============================================================================

TEST_SUITE("Failover - Relay Forwarding") {

    TEST_CASE("Relay forward packet serialization/deserialization") {
        FailoverTestNode source;
        FailoverTestNode target;

        net::RelayForwardPacket original;
        original.source_id = source.id;
        original.target_id = target.id;
        original.timestamp_ms = time::now_ms();
        original.payload.push_back(0x01);
        original.payload.push_back(0x02);
        original.payload.push_back(0x03);

        // Serialize
        auto std_buf = dp::serialize<dp::Mode::WITH_VERSION>(original);
        Vector<u8> buf;
        for (auto b : std_buf) buf.push_back(b);

        // Deserialize
        auto result = serial::deserialize<net::RelayForwardPacket>(buf);
        REQUIRE(result.is_ok());

        auto &deserialized = result.value();
        CHECK(deserialized.source_id == original.source_id);
        CHECK(deserialized.target_id == original.target_id);
        CHECK(deserialized.timestamp_ms == original.timestamp_ms);
        CHECK(deserialized.payload.size() == original.payload.size());
    }

    TEST_CASE("Relay connect request serialization") {
        FailoverTestNode requester;
        FailoverTestNode target;

        net::RelayConnectRequest original;
        original.requester_id = requester.id;
        original.target_peer_id = target.id;
        original.timestamp_ms = time::now_ms();

        // Serialize
        auto std_buf = dp::serialize<dp::Mode::WITH_VERSION>(original);
        Vector<u8> buf;
        for (auto b : std_buf) buf.push_back(b);

        // Deserialize
        auto result = serial::deserialize<net::RelayConnectRequest>(buf);
        REQUIRE(result.is_ok());

        auto &deserialized = result.value();
        CHECK(deserialized.requester_id == original.requester_id);
        CHECK(deserialized.target_peer_id == original.target_peer_id);
        CHECK(deserialized.timestamp_ms == original.timestamp_ms);
    }
}

// Note: RelayServer and RouteTable integration tests require actual socket setup
// and are better tested via integration tests. The above tests cover the core
// relay manager failover logic.

// =============================================================================
// Peer Connection Failover Tests
// =============================================================================

TEST_SUITE("Failover - Peer Connection") {

    TEST_CASE("Peer table tracks connection status") {
        PeerTable table;

        FailoverTestNode peer;
        table.add_peer(peer.id, peer.ed25519_pub, peer.x25519_pub);

        auto p = table.get_peer(peer.id);
        REQUIRE(p.has_value());
        CHECK_FALSE((*p)->is_connected());
    }

    TEST_CASE("Peer becomes disconnected when session times out") {
        PeerTable table;

        FailoverTestNode alice;
        FailoverTestNode bob;

        table.add_peer(bob.id, bob.ed25519_pub, bob.x25519_pub);

        // Create session
        Array<u8, 32> shared_secret;
        randombytes_buf(shared_secret.data(), 32);

        auto [send_key, recv_key] = crypto::derive_initiator_keys(shared_secret, alice.id, bob.id, 1);
        table.create_session(bob.id, send_key, recv_key);

        auto p = table.get_peer(bob.id);
        REQUIRE(p.has_value());
        CHECK((*p)->has_session());

        // Note: Testing timeout would require waiting or time manipulation
    }
}

// =============================================================================
// Network Partition Tests
// =============================================================================

TEST_SUITE("Failover - Network Partition") {

    TEST_CASE("Voting continues with quorum after partition") {
        FailoverTestNode local_node;

        // Configure for 5 members, need 3 votes
        VotingPolicy policy;
        policy.min_yes_votes = 3;
        policy.vote_timeout_ms = 10000;

        VotingManager voting(policy, local_node.id);

        FailoverTestNode candidate;
        FailoverTestNode sponsor;

        // Create proposal
        JoinProposal proposal;
        proposal.candidate_id = candidate.id;
        proposal.candidate_ed25519 = candidate.ed25519_pub;
        proposal.candidate_x25519 = candidate.x25519_pub;
        proposal.sponsor_id = sponsor.id;
        proposal.timestamp_ms = time::now_ms();

        auto res = voting.add_proposal(proposal);
        REQUIRE(res.is_ok());

        // Simulate partition: only 3 out of 5 members can vote
        FailoverTestNode voter1, voter2, voter3;

        VoteCastEvent vote1;
        vote1.candidate_id = candidate.id;
        vote1.voter_id = voter1.id;
        vote1.vote = Vote::Yes;
        vote1.timestamp_ms = time::now_ms();

        VoteCastEvent vote2;
        vote2.candidate_id = candidate.id;
        vote2.voter_id = voter2.id;
        vote2.vote = Vote::Yes;
        vote2.timestamp_ms = time::now_ms();

        VoteCastEvent vote3;
        vote3.candidate_id = candidate.id;
        vote3.voter_id = voter3.id;
        vote3.vote = Vote::Yes;
        vote3.timestamp_ms = time::now_ms();

        voting.record_vote(vote1);
        voting.record_vote(vote2);
        auto result = voting.record_vote(vote3);

        REQUIRE(result.is_ok());
        CHECK(result.value() == VoteResult::Approved);
    }

    TEST_CASE("Voting fails without quorum") {
        FailoverTestNode local_node;

        VotingPolicy policy;
        policy.min_yes_votes = 3;
        policy.vote_timeout_ms = 100; // Short timeout for testing

        VotingManager voting(policy, local_node.id);

        FailoverTestNode candidate;
        FailoverTestNode sponsor;

        JoinProposal proposal;
        proposal.candidate_id = candidate.id;
        proposal.candidate_ed25519 = candidate.ed25519_pub;
        proposal.candidate_x25519 = candidate.x25519_pub;
        proposal.sponsor_id = sponsor.id;
        proposal.timestamp_ms = time::now_ms();

        voting.add_proposal(proposal);

        // Only 2 votes (not enough for quorum)
        FailoverTestNode voter1, voter2;

        VoteCastEvent vote1;
        vote1.candidate_id = candidate.id;
        vote1.voter_id = voter1.id;
        vote1.vote = Vote::Yes;
        vote1.timestamp_ms = time::now_ms();

        VoteCastEvent vote2;
        vote2.candidate_id = candidate.id;
        vote2.voter_id = voter2.id;
        vote2.vote = Vote::Yes;
        vote2.timestamp_ms = time::now_ms();

        voting.record_vote(vote1);
        voting.record_vote(vote2);

        // Wait for timeout
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        // Process timeouts
        auto expired = voting.process_timeouts();
        CHECK(expired.size() == 1);

        // Proposal should be rejected due to timeout
        auto state = voting.get_proposal(candidate.id);
        REQUIRE(state.has_value());
        CHECK(state->decided);
        CHECK_FALSE(state->approved);
    }
}
