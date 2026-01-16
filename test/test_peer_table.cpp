/* SPDX-License-Identifier: MIT */
/*
 * Botlink Peer Table Tests
 * Tests for runtime peer connection tracking
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

// Helper to create a test NodeId
static NodeId make_node_id(u8 seed) {
    NodeId id;
    for (usize i = 0; i < NODE_ID_SIZE; ++i) {
        id.data[i] = static_cast<u8>(seed + i);
    }
    return id;
}

// Helper to create a test PublicKey
static PublicKey make_pubkey(u8 seed) {
    PublicKey key;
    for (usize i = 0; i < KEY_SIZE; ++i) {
        key.data[i] = static_cast<u8>(seed + i);
    }
    return key;
}

TEST_SUITE("PeerTable - PeerSession") {

    TEST_CASE("PeerSession default values") {
        PeerSession session;
        CHECK(session.send_nonce == 0);
        CHECK(session.established_at_ms == 0);
        CHECK(session.last_send_ms == 0);
        CHECK(session.last_recv_ms == 0);
        CHECK(session.rekey_count == 0);
    }

    TEST_CASE("PeerSession next_send_nonce increments") {
        PeerSession session;

        CHECK(session.next_send_nonce() == 0);
        CHECK(session.next_send_nonce() == 1);
        CHECK(session.next_send_nonce() == 2);
        CHECK(session.send_nonce == 3);
    }

    TEST_CASE("PeerSession age_ms") {
        PeerSession session;
        session.established_at_ms = time::now_ms() - 5000;

        CHECK(session.age_ms() >= 4900);
        CHECK(session.age_ms() <= 6000);
    }

    TEST_CASE("PeerSession idle times") {
        PeerSession session;
        session.last_send_ms = time::now_ms() - 1000;
        session.last_recv_ms = time::now_ms() - 2000;

        CHECK(session.idle_send_ms() >= 900);
        CHECK(session.idle_recv_ms() >= 1900);
    }

}

TEST_SUITE("PeerTable - PeerEntry") {

    TEST_CASE("PeerEntry default values") {
        PeerEntry entry;
        CHECK(entry.status == PeerStatus::Unknown);
        CHECK(entry.endpoints.empty());
        CHECK(entry.preferred_endpoint_idx == 0);
        CHECK(entry.rx_bytes == 0);
        CHECK(entry.tx_bytes == 0);
    }

    TEST_CASE("PeerEntry is_connected") {
        PeerEntry entry;

        entry.status = PeerStatus::Unknown;
        CHECK(entry.is_connected() == false);

        entry.status = PeerStatus::Direct;
        CHECK(entry.is_connected() == true);

        entry.status = PeerStatus::Relayed;
        CHECK(entry.is_connected() == true);
    }

    TEST_CASE("PeerEntry has_session") {
        PeerEntry entry;
        CHECK(entry.has_session() == false);

        entry.session = PeerSession();
        CHECK(entry.has_session() == true);
    }

    TEST_CASE("PeerEntry preferred_endpoint") {
        PeerEntry entry;

        // No endpoints
        auto no_ep = entry.preferred_endpoint();
        CHECK(no_ep.has_value() == false);

        // Add endpoints
        Endpoint ep1;
        ep1.family = AddrFamily::IPv4;
        ep1.port = 5000;
        entry.endpoints.push_back(ep1);

        Endpoint ep2;
        ep2.family = AddrFamily::IPv4;
        ep2.port = 6000;
        entry.endpoints.push_back(ep2);

        entry.preferred_endpoint_idx = 0;
        auto pref0 = entry.preferred_endpoint();
        REQUIRE(pref0.has_value());
        CHECK(pref0->port == 5000);

        entry.preferred_endpoint_idx = 1;
        auto pref1 = entry.preferred_endpoint();
        REQUIRE(pref1.has_value());
        CHECK(pref1->port == 6000);
    }

}

TEST_SUITE("PeerTable - Basic Operations") {

    TEST_CASE("PeerTable default constructor") {
        PeerTable table;
        CHECK(table.peer_count() == 0);
        CHECK(table.connected_count() == 0);
    }

    TEST_CASE("PeerTable custom intervals") {
        PeerTable table(10000, 60000, 90000);
        CHECK(table.peer_count() == 0);
    }

    TEST_CASE("add_peer creates new entry") {
        PeerTable table;

        NodeId id = make_node_id(1);
        PublicKey ed = make_pubkey(10);
        PublicKey x = make_pubkey(20);

        auto* peer = table.add_peer(id, ed, x);

        REQUIRE(peer != nullptr);
        CHECK(peer->node_id == id);
        CHECK(peer->ed25519_pubkey == ed);
        CHECK(peer->x25519_pubkey == x);
        CHECK(table.peer_count() == 1);
    }

    TEST_CASE("add_peer updates existing entry") {
        PeerTable table;

        NodeId id = make_node_id(1);
        PublicKey ed1 = make_pubkey(10);
        PublicKey x1 = make_pubkey(20);

        table.add_peer(id, ed1, x1);

        PublicKey ed2 = make_pubkey(30);
        PublicKey x2 = make_pubkey(40);

        auto* peer = table.add_peer(id, ed2, x2);

        // Should update, not create new
        CHECK(table.peer_count() == 1);
        CHECK(peer->ed25519_pubkey == ed2);
        CHECK(peer->x25519_pubkey == x2);
    }

    TEST_CASE("has_peer") {
        PeerTable table;

        NodeId id1 = make_node_id(1);
        NodeId id2 = make_node_id(2);

        table.add_peer(id1, make_pubkey(10), make_pubkey(20));

        CHECK(table.has_peer(id1) == true);
        CHECK(table.has_peer(id2) == false);
    }

    TEST_CASE("get_peer") {
        PeerTable table;

        NodeId id = make_node_id(1);
        table.add_peer(id, make_pubkey(10), make_pubkey(20));

        auto peer_opt = table.get_peer(id);
        CHECK(peer_opt.has_value());

        NodeId unknown = make_node_id(99);
        auto no_peer = table.get_peer(unknown);
        CHECK(no_peer.has_value() == false);
    }

    TEST_CASE("remove_peer") {
        PeerTable table;

        NodeId id = make_node_id(1);
        table.add_peer(id, make_pubkey(10), make_pubkey(20));

        CHECK(table.peer_count() == 1);

        boolean removed = table.remove_peer(id);
        CHECK(removed == true);
        CHECK(table.peer_count() == 0);
        CHECK(table.has_peer(id) == false);

        // Remove non-existent
        boolean removed_again = table.remove_peer(id);
        CHECK(removed_again == false);
    }

}

TEST_SUITE("PeerTable - Peer Lists") {

    TEST_CASE("get_all_peers") {
        PeerTable table;

        table.add_peer(make_node_id(1), make_pubkey(10), make_pubkey(20));
        table.add_peer(make_node_id(2), make_pubkey(30), make_pubkey(40));
        table.add_peer(make_node_id(3), make_pubkey(50), make_pubkey(60));

        auto all = table.get_all_peers();
        CHECK(all.size() == 3);
    }

    TEST_CASE("get_connected_peers") {
        PeerTable table;

        NodeId id1 = make_node_id(1);
        NodeId id2 = make_node_id(2);

        table.add_peer(id1, make_pubkey(10), make_pubkey(20));
        table.add_peer(id2, make_pubkey(30), make_pubkey(40));

        table.set_status(id1, PeerStatus::Direct);
        // id2 remains Unknown

        auto connected = table.get_connected_peers();
        CHECK(connected.size() == 1);
        CHECK(connected[0]->node_id == id1);

        CHECK(table.connected_count() == 1);
    }

}

TEST_SUITE("PeerTable - Endpoint Management") {

    TEST_CASE("update_endpoints") {
        PeerTable table;

        NodeId id = make_node_id(1);
        table.add_peer(id, make_pubkey(10), make_pubkey(20));

        Vector<Endpoint> endpoints;
        Endpoint ep;
        ep.family = AddrFamily::IPv4;
        ep.port = 8080;
        endpoints.push_back(ep);

        table.update_endpoints(id, endpoints);

        auto peer = table.get_peer(id);
        REQUIRE(peer.has_value());
        CHECK(peer.value()->endpoints.size() == 1);
        CHECK(peer.value()->endpoints[0].port == 8080);
    }

    TEST_CASE("set_status") {
        PeerTable table;

        NodeId id = make_node_id(1);
        table.add_peer(id, make_pubkey(10), make_pubkey(20));

        table.set_status(id, PeerStatus::Direct);

        auto peer = table.get_peer(id);
        CHECK(peer.value()->status == PeerStatus::Direct);
    }

}

TEST_SUITE("PeerTable - Session Management") {

    TEST_CASE("create_session") {
        PeerTable table;

        NodeId id = make_node_id(1);
        table.add_peer(id, make_pubkey(10), make_pubkey(20));

        crypto::SessionKey send_key, recv_key;
        send_key.key_id = 1;
        recv_key.key_id = 1;

        boolean created = table.create_session(id, send_key, recv_key);
        CHECK(created == true);

        auto peer = table.get_peer(id);
        CHECK(peer.value()->has_session() == true);
        CHECK(peer.value()->status == PeerStatus::Direct);
    }

    TEST_CASE("create_session for non-existent peer fails") {
        PeerTable table;

        NodeId unknown = make_node_id(99);
        crypto::SessionKey send_key, recv_key;

        boolean created = table.create_session(unknown, send_key, recv_key);
        CHECK(created == false);
    }

    TEST_CASE("clear_session") {
        PeerTable table;

        NodeId id = make_node_id(1);
        table.add_peer(id, make_pubkey(10), make_pubkey(20));

        crypto::SessionKey send_key, recv_key;
        table.create_session(id, send_key, recv_key);

        table.clear_session(id);

        auto peer = table.get_peer(id);
        CHECK(peer.value()->has_session() == false);
        CHECK(peer.value()->status == PeerStatus::Unknown);
    }

    TEST_CASE("rekey_session") {
        PeerTable table;

        NodeId id = make_node_id(1);
        table.add_peer(id, make_pubkey(10), make_pubkey(20));

        crypto::SessionKey send_key, recv_key;
        send_key.key_id = 1;
        recv_key.key_id = 1;
        for (usize i = 0; i < crypto::SESSION_KEY_SIZE; ++i) {
            send_key.data[i] = static_cast<u8>(i);
            recv_key.data[i] = static_cast<u8>(i + 100);
        }

        table.create_session(id, send_key, recv_key);

        boolean rekeyed = table.rekey_session(id);
        CHECK(rekeyed == true);

        auto peer = table.get_peer(id);
        CHECK(peer.value()->session->rekey_count == 1);
        // Key IDs should increment
        CHECK(peer.value()->session->send_key.key_id == 2);
        CHECK(peer.value()->session->recv_key.key_id == 2);
    }

}

TEST_SUITE("PeerTable - Data Recording") {

    TEST_CASE("record_send") {
        PeerTable table;

        NodeId id = make_node_id(1);
        table.add_peer(id, make_pubkey(10), make_pubkey(20));

        crypto::SessionKey send_key, recv_key;
        table.create_session(id, send_key, recv_key);

        table.record_send(id, 1000);
        table.record_send(id, 500);

        auto peer = table.get_peer(id);
        CHECK(peer.value()->tx_bytes == 1500);
    }

    TEST_CASE("record_recv") {
        PeerTable table;

        NodeId id = make_node_id(1);
        table.add_peer(id, make_pubkey(10), make_pubkey(20));

        crypto::SessionKey send_key, recv_key;
        table.create_session(id, send_key, recv_key);

        table.record_recv(id, 2000);

        auto peer = table.get_peer(id);
        CHECK(peer.value()->rx_bytes == 2000);
    }

}
