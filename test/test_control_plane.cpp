/* SPDX-License-Identifier: MIT */
/*
 * Botlink Control Plane Tests
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("ControlPlane - Message Structures") {

    TEST_CASE("EndpointAdvert structure") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        net::EndpointAdvert advert;
        advert.node_id = node_id;
        advert.timestamp_ms = time::now_ms();
        advert.endpoints.push_back(Endpoint(IPv4Addr(192, 168, 1, 1), 51820));
        advert.endpoints.push_back(Endpoint(IPv4Addr(10, 0, 0, 1), 51821));

        CHECK(advert.node_id == node_id);
        CHECK(advert.endpoints.size() == 2);
        CHECK(advert.timestamp_ms > 0);
        CHECK_FALSE(advert.relay_id.has_value());
    }

    TEST_CASE("EndpointAdvert with relay") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [ed_priv2, ed_pub2] = crypto::generate_ed25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);
        NodeId relay_id = crypto::node_id_from_pubkey(ed_pub2);

        net::EndpointAdvert advert;
        advert.node_id = node_id;
        advert.timestamp_ms = time::now_ms();
        advert.relay_id = relay_id;

        CHECK(advert.relay_id.has_value());
        CHECK(advert.relay_id.value() == relay_id);
    }

    TEST_CASE("MembershipUpdate structure") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId candidate_id = crypto::node_id_from_pubkey(ed_pub);

        net::MembershipUpdate update;
        update.candidate_id = candidate_id;
        update.approved = true;
        update.chain_height = 42;
        update.timestamp_ms = time::now_ms();

        CHECK(update.candidate_id == candidate_id);
        CHECK(update.approved == true);
        CHECK(update.chain_height == 42);
        CHECK(update.timestamp_ms > 0);
    }

    TEST_CASE("MembershipSnapshotRequest structure") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId requester_id = crypto::node_id_from_pubkey(ed_pub);

        net::MembershipSnapshotRequest req;
        req.requester_id = requester_id;
        req.known_height = 10;
        req.timestamp_ms = time::now_ms();

        CHECK(req.requester_id == requester_id);
        CHECK(req.known_height == 10);
    }

    TEST_CASE("MembershipSnapshotResponse structure") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        MemberEntry entry;
        entry.node_id = node_id;
        entry.ed25519_pubkey = ed_pub;
        entry.x25519_pubkey = x_pub;
        entry.status = MemberStatus::Approved;
        entry.joined_at_ms = time::now_ms();

        net::MembershipSnapshotResponse resp;
        resp.member_entries.push_back(entry);
        resp.chain_height = 5;
        resp.timestamp_ms = time::now_ms();

        CHECK(resp.member_entries.size() == 1);
        CHECK(resp.chain_height == 5);
    }

    TEST_CASE("ChainSyncRequest structure") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId requester_id = crypto::node_id_from_pubkey(ed_pub);

        net::ChainSyncRequest req;
        req.requester_id = requester_id;
        req.known_height = 100;
        req.timestamp_ms = time::now_ms();

        CHECK(req.requester_id == requester_id);
        CHECK(req.known_height == 100);
    }

    TEST_CASE("ChainSyncResponse structure") {
        net::ChainSyncResponse resp;
        resp.chain_height = 150;
        resp.start_height = 100;
        resp.timestamp_ms = time::now_ms();

        // Add some events
        TrustEvent evt;
        evt.kind = TrustEventKind::JoinApproved;
        evt.timestamp_ms = time::now_ms();
        resp.events.push_back(evt);

        CHECK(resp.chain_height == 150);
        CHECK(resp.start_height == 100);
        CHECK(resp.events.size() == 1);
    }

}

TEST_SUITE("ControlPlane - Serialization") {

    TEST_CASE("EndpointAdvert serialization roundtrip") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        net::EndpointAdvert original;
        original.node_id = node_id;
        original.timestamp_ms = time::now_ms();
        original.endpoints.push_back(Endpoint(IPv4Addr(192, 168, 1, 1), 51820));

        // Serialize
        auto buf = dp::serialize<dp::Mode::WITH_VERSION>(original);
        Vector<u8> payload;
        for (const auto &b : buf) {
            payload.push_back(b);
        }

        // Deserialize
        auto result = serial::deserialize<net::EndpointAdvert>(payload);
        REQUIRE(result.is_ok());

        auto &deserialized = result.value();
        CHECK(deserialized.node_id == original.node_id);
        CHECK(deserialized.timestamp_ms == original.timestamp_ms);
        CHECK(deserialized.endpoints.size() == 1);
    }

    TEST_CASE("MembershipUpdate serialization roundtrip") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId candidate_id = crypto::node_id_from_pubkey(ed_pub);

        net::MembershipUpdate original;
        original.candidate_id = candidate_id;
        original.approved = true;
        original.chain_height = 42;
        original.timestamp_ms = time::now_ms();

        // Serialize
        auto buf = dp::serialize<dp::Mode::WITH_VERSION>(original);
        Vector<u8> payload;
        for (const auto &b : buf) {
            payload.push_back(b);
        }

        // Deserialize
        auto result = serial::deserialize<net::MembershipUpdate>(payload);
        REQUIRE(result.is_ok());

        auto &deserialized = result.value();
        CHECK(deserialized.candidate_id == original.candidate_id);
        CHECK(deserialized.approved == true);
        CHECK(deserialized.chain_height == 42);
    }

    TEST_CASE("ChainSyncRequest serialization roundtrip") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId requester_id = crypto::node_id_from_pubkey(ed_pub);

        net::ChainSyncRequest original;
        original.requester_id = requester_id;
        original.known_height = 100;
        original.timestamp_ms = time::now_ms();

        // Serialize
        auto buf = dp::serialize<dp::Mode::WITH_VERSION>(original);
        Vector<u8> payload;
        for (const auto &b : buf) {
            payload.push_back(b);
        }

        // Deserialize
        auto result = serial::deserialize<net::ChainSyncRequest>(payload);
        REQUIRE(result.is_ok());

        auto &deserialized = result.value();
        CHECK(deserialized.requester_id == original.requester_id);
        CHECK(deserialized.known_height == 100);
    }

}

TEST_SUITE("ControlPlane - ControlMsgType") {

    TEST_CASE("ControlMsgType enum values") {
        CHECK(static_cast<u8>(net::ControlMsgType::JoinRequest) == 0x01);
        CHECK(static_cast<u8>(net::ControlMsgType::JoinProposal) == 0x02);
        CHECK(static_cast<u8>(net::ControlMsgType::VoteCast) == 0x03);
        CHECK(static_cast<u8>(net::ControlMsgType::MembershipUpdate) == 0x04);
        CHECK(static_cast<u8>(net::ControlMsgType::EndpointAdvert) == 0x05);
        CHECK(static_cast<u8>(net::ControlMsgType::MembershipSnapshot) == 0x06);
        CHECK(static_cast<u8>(net::ControlMsgType::ChainSyncRequest) == 0x07);
        CHECK(static_cast<u8>(net::ControlMsgType::ChainSyncResponse) == 0x08);
    }

}
