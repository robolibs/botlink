/* SPDX-License-Identifier: MIT */
/*
 * Botlink Relay Tests
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Relay - RelayInfo") {

    TEST_CASE("RelayInfo default values") {
        net::RelayInfo relay;

        CHECK(relay.id.empty());
        CHECK(relay.last_seen_ms == 0);
        CHECK(relay.latency_ms == 0);
        CHECK(relay.is_connected == false);
        CHECK(relay.current_load == 0);
    }

    TEST_CASE("RelayInfo stale check with fresh relay") {
        net::RelayInfo relay;
        relay.id = "relay1";
        relay.last_seen_ms = time::now_ms();
        relay.is_connected = true;

        // Fresh relay should not be stale
        CHECK_FALSE(relay.is_stale(30000));
    }

    TEST_CASE("RelayInfo stale check with old relay") {
        net::RelayInfo relay;
        relay.id = "relay1";
        relay.last_seen_ms = time::now_ms() - 60000; // 60 seconds ago
        relay.is_connected = true;

        // Old relay should be stale with 30 second threshold
        CHECK(relay.is_stale(30000));
    }

    TEST_CASE("RelayInfo stale check edge case") {
        net::RelayInfo relay;
        relay.last_seen_ms = time::now_ms() - 29999;

        // Just under threshold
        CHECK_FALSE(relay.is_stale(30000));

        relay.last_seen_ms = time::now_ms() - 30001;
        // Just over threshold
        CHECK(relay.is_stale(30000));
    }

}

TEST_SUITE("Relay - RelayRoute") {

    TEST_CASE("RelayRoute default values") {
        net::RelayRoute route;

        CHECK(route.relay_id.empty());
        CHECK(route.established_at_ms == 0);
        CHECK(route.last_used_ms == 0);
        CHECK(route.is_active == false);
    }

    TEST_CASE("RelayRoute age calculation") {
        net::RelayRoute route;
        route.established_at_ms = time::now_ms() - 5000;

        u64 age = route.age_ms();
        CHECK(age >= 5000);
        CHECK(age < 6000); // Should not be much more than 5 seconds
    }

    TEST_CASE("RelayRoute with peer and relay info") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId peer_id = crypto::node_id_from_pubkey(ed_pub);

        net::RelayRoute route;
        route.peer_id = peer_id;
        route.relay_id = "relay_server_1";
        route.relay_endpoint = Endpoint(IPv4Addr(10, 0, 0, 1), 51820);
        route.established_at_ms = time::now_ms();
        route.last_used_ms = time::now_ms();
        route.is_active = true;

        CHECK(route.peer_id == peer_id);
        CHECK(route.relay_id == "relay_server_1");
        CHECK(route.is_active == true);
        CHECK(route.age_ms() < 1000);
    }

}

TEST_SUITE("Relay - RelayConnectRequest") {

    TEST_CASE("RelayConnectRequest structure") {
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId requester = crypto::node_id_from_pubkey(ed_pub1);
        NodeId target = crypto::node_id_from_pubkey(ed_pub2);

        net::RelayConnectRequest req;
        req.requester_id = requester;
        req.target_peer_id = target;
        req.timestamp_ms = time::now_ms();

        CHECK(req.requester_id == requester);
        CHECK(req.target_peer_id == target);
        CHECK(req.timestamp_ms > 0);
    }

    TEST_CASE("RelayConnectRequest serialization roundtrip") {
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId requester = crypto::node_id_from_pubkey(ed_pub1);
        NodeId target = crypto::node_id_from_pubkey(ed_pub2);

        net::RelayConnectRequest original;
        original.requester_id = requester;
        original.target_peer_id = target;
        original.timestamp_ms = time::now_ms();

        // Serialize
        auto buf = dp::serialize<dp::Mode::WITH_VERSION>(original);
        Vector<u8> payload;
        for (const auto &b : buf) {
            payload.push_back(b);
        }

        // Deserialize
        auto result = serial::deserialize<net::RelayConnectRequest>(payload);
        REQUIRE(result.is_ok());

        auto &deserialized = result.value();
        CHECK(deserialized.requester_id == original.requester_id);
        CHECK(deserialized.target_peer_id == original.target_peer_id);
        CHECK(deserialized.timestamp_ms == original.timestamp_ms);
    }

}

TEST_SUITE("Relay - RelayForwardPacket") {

    TEST_CASE("RelayForwardPacket structure") {
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId source = crypto::node_id_from_pubkey(ed_pub1);
        NodeId target = crypto::node_id_from_pubkey(ed_pub2);

        net::RelayForwardPacket fwd;
        fwd.source_id = source;
        fwd.target_id = target;
        fwd.payload.push_back(0xDE);
        fwd.payload.push_back(0xAD);
        fwd.payload.push_back(0xBE);
        fwd.payload.push_back(0xEF);
        fwd.timestamp_ms = time::now_ms();

        CHECK(fwd.source_id == source);
        CHECK(fwd.target_id == target);
        CHECK(fwd.payload.size() == 4);
        CHECK(fwd.payload[0] == 0xDE);
        CHECK(fwd.payload[3] == 0xEF);
    }

    TEST_CASE("RelayForwardPacket with large payload") {
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId source = crypto::node_id_from_pubkey(ed_pub1);
        NodeId target = crypto::node_id_from_pubkey(ed_pub2);

        net::RelayForwardPacket fwd;
        fwd.source_id = source;
        fwd.target_id = target;
        fwd.timestamp_ms = time::now_ms();

        // Add 1KB payload
        for (int i = 0; i < 1024; ++i) {
            fwd.payload.push_back(static_cast<u8>(i % 256));
        }

        CHECK(fwd.payload.size() == 1024);
    }

    TEST_CASE("RelayForwardPacket serialization roundtrip") {
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId source = crypto::node_id_from_pubkey(ed_pub1);
        NodeId target = crypto::node_id_from_pubkey(ed_pub2);

        net::RelayForwardPacket original;
        original.source_id = source;
        original.target_id = target;
        original.payload = {0x01, 0x02, 0x03, 0x04};
        original.timestamp_ms = time::now_ms();

        // Serialize
        auto buf = dp::serialize<dp::Mode::WITH_VERSION>(original);
        Vector<u8> payload;
        for (const auto &b : buf) {
            payload.push_back(b);
        }

        // Deserialize
        auto result = serial::deserialize<net::RelayForwardPacket>(payload);
        REQUIRE(result.is_ok());

        auto &deserialized = result.value();
        CHECK(deserialized.source_id == original.source_id);
        CHECK(deserialized.target_id == original.target_id);
        CHECK(deserialized.payload.size() == 4);
        CHECK(deserialized.timestamp_ms == original.timestamp_ms);
    }

}

TEST_SUITE("Relay - RelayMsgType") {

    TEST_CASE("RelayMsgType enum values") {
        CHECK(static_cast<u8>(net::RelayMsgType::RelayConnect) == 0x10);
        CHECK(static_cast<u8>(net::RelayMsgType::RelayDisconnect) == 0x11);
        CHECK(static_cast<u8>(net::RelayMsgType::RelayForward) == 0x12);
        CHECK(static_cast<u8>(net::RelayMsgType::RelayAck) == 0x13);
        CHECK(static_cast<u8>(net::RelayMsgType::RelayError) == 0x14);
    }

}

TEST_SUITE("Relay - RelayManager") {

    TEST_CASE("RelayManager initialization") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);

        net::RelayManager manager(local_id, nullptr);

        CHECK(manager.get_relays().empty());
    }

    TEST_CASE("RelayManager add relay") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);

        net::RelayManager manager(local_id, nullptr);

        net::RelayInfo relay;
        relay.id = "relay1";
        relay.endpoint = Endpoint(IPv4Addr(10, 0, 0, 1), 51820);
        relay.last_seen_ms = time::now_ms();
        relay.is_connected = true;

        manager.add_relay(relay);

        CHECK(manager.get_relays().size() == 1);
        CHECK(manager.get_relays()[0].id == "relay1");
    }

    TEST_CASE("RelayManager select relay prefers non-stale") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);

        net::RelayManager manager(local_id, nullptr);

        // Add stale relay
        net::RelayInfo stale_relay;
        stale_relay.id = "stale";
        stale_relay.last_seen_ms = time::now_ms() - 60000;
        stale_relay.latency_ms = 10;
        manager.add_relay(stale_relay);

        // Add fresh relay
        net::RelayInfo fresh_relay;
        fresh_relay.id = "fresh";
        fresh_relay.last_seen_ms = time::now_ms();
        fresh_relay.latency_ms = 100;
        manager.add_relay(fresh_relay);

        auto selected = manager.select_relay();
        REQUIRE(selected.has_value());
        CHECK(selected->id == "fresh");
    }

    TEST_CASE("RelayManager has_relay_route") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);
        NodeId peer_id = crypto::node_id_from_pubkey(ed_pub2);

        net::RelayManager manager(local_id, nullptr);

        // No route initially
        CHECK_FALSE(manager.has_relay_route(peer_id));
    }

    TEST_CASE("RelayManager get_relay_route returns empty for unknown peer") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);
        NodeId peer_id = crypto::node_id_from_pubkey(ed_pub2);

        net::RelayManager manager(local_id, nullptr);

        auto route = manager.get_relay_route(peer_id);
        CHECK_FALSE(route.has_value());
    }

    TEST_CASE("RelayManager update_relay") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);

        net::RelayManager manager(local_id, nullptr);

        net::RelayInfo relay;
        relay.id = "relay1";
        relay.latency_ms = 100;
        relay.is_connected = false;
        manager.add_relay(relay);

        // Update relay
        manager.update_relay("relay1", 50, true);

        const auto &relays = manager.get_relays();
        REQUIRE(relays.size() == 1);
        CHECK(relays[0].latency_ms == 50);
        CHECK(relays[0].is_connected == true);
    }

    TEST_CASE("RelayManager remove_relay_route") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);
        NodeId peer_id = crypto::node_id_from_pubkey(ed_pub2);

        net::RelayManager manager(local_id, nullptr);

        // Remove non-existent route (should not crash)
        manager.remove_relay_route(peer_id);
        CHECK_FALSE(manager.has_relay_route(peer_id));
    }

    TEST_CASE("RelayManager set_preferred_relays") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);

        net::RelayManager manager(local_id, nullptr);

        Vector<String> preferred;
        preferred.push_back("relay1");
        preferred.push_back("relay2");
        manager.set_preferred_relays(preferred);

        // Add relays
        net::RelayInfo relay1;
        relay1.id = "relay1";
        relay1.last_seen_ms = time::now_ms();
        relay1.latency_ms = 200;
        manager.add_relay(relay1);

        net::RelayInfo relay2;
        relay2.id = "relay2";
        relay2.last_seen_ms = time::now_ms();
        relay2.latency_ms = 50;
        manager.add_relay(relay2);

        net::RelayInfo relay3;
        relay3.id = "relay3";
        relay3.last_seen_ms = time::now_ms();
        relay3.latency_ms = 10; // Lowest latency but not preferred
        manager.add_relay(relay3);

        auto selected = manager.select_relay();
        REQUIRE(selected.has_value());
        // Should select first preferred relay (relay1) despite higher latency
        CHECK(selected->id == "relay1");
    }

}
