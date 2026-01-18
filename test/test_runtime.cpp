/* SPDX-License-Identifier: MIT */
/*
 * Botlink Runtime Tests
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Runtime - PeerTable") {

    TEST_CASE("Add peer") {
        PeerTable table(25000, 120000, 180000);

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        table.add_peer(node_id, ed_pub, x_pub);

        CHECK(table.peer_count() == 1);
        CHECK(table.has_peer(node_id));
    }

    TEST_CASE("Get peer") {
        PeerTable table(25000, 120000, 180000);

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        table.add_peer(node_id, ed_pub, x_pub);

        auto peer = table.get_peer(node_id);
        REQUIRE(peer.has_value());
        CHECK((*peer)->node_id == node_id);
        CHECK((*peer)->ed25519_pubkey == ed_pub);
        CHECK((*peer)->x25519_pubkey == x_pub);
    }

    TEST_CASE("Remove peer") {
        PeerTable table(25000, 120000, 180000);

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        table.add_peer(node_id, ed_pub, x_pub);
        CHECK(table.peer_count() == 1);

        table.remove_peer(node_id);
        CHECK(table.peer_count() == 0);
        CHECK_FALSE(table.has_peer(node_id));
    }

    TEST_CASE("Create session") {
        PeerTable table(25000, 120000, 180000);

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        table.add_peer(node_id, ed_pub, x_pub);

        crypto::SessionKey send_key, recv_key;
        auto r1 = keylock::crypto::Common::generate_random_bytes(32);
        auto r2 = keylock::crypto::Common::generate_random_bytes(32);
        for (usize i = 0; i < 32; ++i) {
            send_key.data[i] = r1[i];
            recv_key.data[i] = r2[i];
        }
        send_key.key_id = 1;
        recv_key.key_id = 1;

        table.create_session(node_id, send_key, recv_key);

        CHECK(table.connected_count() == 1);

        auto peer = table.get_peer(node_id);
        REQUIRE(peer.has_value());
        CHECK((*peer)->is_connected());
    }

    TEST_CASE("Update peer endpoints") {
        PeerTable table(25000, 120000, 180000);

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        table.add_peer(node_id, ed_pub, x_pub);

        Endpoint ep(IPv4Addr(192, 168, 1, 1), 51820);
        Vector<Endpoint> endpoints;
        endpoints.push_back(ep);
        table.update_endpoints(node_id, endpoints);

        auto peer = table.get_peer(node_id);
        REQUIRE(peer.has_value());
        CHECK((*peer)->endpoints.size() == 1);
        CHECK((*peer)->endpoints[0] == ep);
    }

    TEST_CASE("Connected peers list") {
        PeerTable table(25000, 120000, 180000);

        // Add two peers
        auto [ed_priv1, ed_pub1] = crypto::generate_ed25519_keypair();
        auto [x_priv1, x_pub1] = crypto::generate_x25519_keypair();
        NodeId node1 = crypto::node_id_from_pubkey(ed_pub1);
        table.add_peer(node1, ed_pub1, x_pub1);

        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        auto [x_priv2, x_pub2] = crypto::generate_x25519_keypair();
        NodeId node2 = crypto::node_id_from_pubkey(ed_pub2);
        table.add_peer(node2, ed_pub2, x_pub2);

        // Connect only one
        crypto::SessionKey send_key, recv_key;
        auto r1 = keylock::crypto::Common::generate_random_bytes(32);
        auto r2 = keylock::crypto::Common::generate_random_bytes(32);
        for (usize i = 0; i < 32; ++i) {
            send_key.data[i] = r1[i];
            recv_key.data[i] = r2[i];
        }
        table.create_session(node1, send_key, recv_key);

        auto connected = table.get_connected_peers();
        CHECK(connected.size() == 1);
        CHECK(connected[0]->node_id == node1);
    }

    TEST_CASE("Peer status tracking") {
        PeerTable table(25000, 120000, 180000);

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        table.add_peer(node_id, ed_pub, x_pub);

        auto peer = table.get_peer(node_id);
        REQUIRE(peer.has_value());
        CHECK((*peer)->status == PeerStatus::Unknown);

        // After creating session, status should change
        crypto::SessionKey send_key, recv_key;
        auto r1 = keylock::crypto::Common::generate_random_bytes(32);
        auto r2 = keylock::crypto::Common::generate_random_bytes(32);
        for (usize i = 0; i < 32; ++i) {
            send_key.data[i] = r1[i];
            recv_key.data[i] = r2[i];
        }
        table.create_session(node_id, send_key, recv_key);

        auto peer_after = table.get_peer(node_id);
        CHECK((*peer_after)->is_connected());
    }

}

TEST_SUITE("Runtime - Scheduler") {

    TEST_CASE("Create oneshot timer") {
        runtime::Scheduler scheduler;

        bool fired = false;
        auto id = scheduler.create_oneshot("test", 10, [&fired]() { fired = true; });

        CHECK(id != runtime::INVALID_TIMER_ID);
        CHECK(scheduler.timer_count() == 1);
        CHECK(scheduler.active_timer_count() == 1);

        // Wait and process
        time::sleep_ms(15);
        usize count = scheduler.process();

        CHECK(count == 1);
        CHECK(fired);
        CHECK(scheduler.active_timer_count() == 0);
    }

    TEST_CASE("Create repeating timer") {
        runtime::Scheduler scheduler;

        int fire_count = 0;
        auto id = scheduler.create_repeating("test", 10, [&fire_count]() { fire_count++; });

        CHECK(id != runtime::INVALID_TIMER_ID);

        // Wait and process multiple times
        time::sleep_ms(25);
        scheduler.process();
        time::sleep_ms(15);
        scheduler.process();

        CHECK(fire_count >= 2);
        CHECK(scheduler.active_timer_count() == 1); // Still active
    }

    TEST_CASE("Cancel timer") {
        runtime::Scheduler scheduler;

        bool fired = false;
        auto id = scheduler.create_oneshot("test", 100, [&fired]() { fired = true; });

        bool cancelled = scheduler.cancel(id);
        CHECK(cancelled);
        CHECK(scheduler.active_timer_count() == 0);

        time::sleep_ms(150);
        scheduler.process();
        CHECK_FALSE(fired);
    }

    TEST_CASE("Reset timer") {
        runtime::Scheduler scheduler;

        bool fired = false;
        auto id = scheduler.create_oneshot("test", 50, [&fired]() { fired = true; });

        time::sleep_ms(30);
        scheduler.reset(id);

        time::sleep_ms(30);
        scheduler.process();
        CHECK_FALSE(fired); // Should not have fired yet

        time::sleep_ms(30);
        scheduler.process();
        CHECK(fired); // Now it should fire
    }

    TEST_CASE("Time until next timer") {
        runtime::Scheduler scheduler;

        CHECK(scheduler.time_until_next_ms() == -1); // No timers

        scheduler.create_oneshot("test", 100, []() {});

        i64 time_until = scheduler.time_until_next_ms();
        CHECK(time_until >= 0);
        CHECK(time_until <= 100);
    }

    TEST_CASE("Cleanup inactive timers") {
        runtime::Scheduler scheduler;

        auto id = scheduler.create_oneshot("test", 10, []() {});

        time::sleep_ms(15);
        scheduler.process();

        CHECK(scheduler.timer_count() == 1);
        CHECK(scheduler.active_timer_count() == 0);

        usize removed = scheduler.cleanup();
        CHECK(removed == 1);
        CHECK(scheduler.timer_count() == 0);
    }

}

TEST_SUITE("Runtime - BotlinkNode") {

    TEST_CASE("BotlinkNode creation with generated identity") {
        Config config = cfg::default_config();
        config.version = 1;
        config.node.name = "test_node";
        config.node.interface = InterfaceName("bot0");
        config.node.overlay.addr.addr = "10.42.0.1";
        config.node.overlay.addr.prefix_len = 24;
        config.node.overlay.listen.push_back(Endpoint(IPv4Addr(0, 0, 0, 0), 51820));

        // Generate keys
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

        config.identity.ed25519_private = ed_priv;
        config.identity.ed25519_public = ed_pub;
        config.identity.x25519_private = x_priv;
        config.identity.x25519_public = x_pub;

        // Add bootstrap peer (required by validation)
        BootstrapEntry bootstrap;
        bootstrap.type = BootstrapType::Member;
        bootstrap.id = "bootstrap1";
        bootstrap.endpoint = Endpoint(IPv4Addr(192, 168, 1, 1), 51820);
        bootstrap.pubkey = ed_pub;  // Use self as bootstrap for testing
        config.trust.bootstraps.push_back(bootstrap);

        runtime::BotlinkNode node;
        auto res = node.configure(config);
        REQUIRE(res.is_ok());

        CHECK_FALSE(node.local_node_id().is_zero());
    }

}
