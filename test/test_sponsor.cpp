/* SPDX-License-Identifier: MIT */
/*
 * Botlink Sponsor Tests
 * Tests for sponsor flow and join request handling
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Sponsor - JoinRequest") {

    TEST_CASE("JoinRequest default values") {
        JoinRequest req;
        CHECK(req.timestamp_ms == 0);
        CHECK(req.metadata.empty());
    }

    TEST_CASE("JoinRequest get_identity_proof_data produces non-empty data") {
        JoinRequest req;
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

        req.candidate_id = crypto::node_id_from_pubkey(ed_pub);
        req.candidate_ed25519 = ed_pub;
        req.candidate_x25519 = x_pub;
        req.timestamp_ms = time::now_ms();

        auto proof_data = req.get_identity_proof_data();
        CHECK(proof_data.size() > 0);
        // Should contain: prefix(16) + ed25519(32) + x25519(32) + timestamp(8) = 88 bytes
        CHECK(proof_data.size() == 88);
    }

    TEST_CASE("create_join_request produces valid signed request") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

        JoinRequest req = sponsor::create_join_request(ed_priv, ed_pub, x_pub);

        // Verify candidate_id matches pubkey
        NodeId expected_id = crypto::node_id_from_pubkey(ed_pub);
        CHECK(req.candidate_id == expected_id);

        // Verify signature is valid
        auto proof_data = req.get_identity_proof_data();
        CHECK(crypto::ed25519_verify(ed_pub, proof_data, req.identity_proof));
    }

    TEST_CASE("create_join_request with metadata") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

        OverlayAddr addr;
        addr.addr = "10.42.0.5";
        addr.prefix_len = 24;

        JoinRequest req = sponsor::create_join_request(ed_priv, ed_pub, x_pub, addr, "test node");

        CHECK(req.metadata == "test node");
        CHECK(req.requested_addr.addr == "10.42.0.5");
    }

}

TEST_SUITE("Sponsor - SponsorSession") {

    TEST_CASE("SponsorSession default values") {
        SponsorSession session;
        CHECK(session.received_at_ms == 0);
        CHECK(session.submitted_to_chain == false);
        CHECK(session.submitted_at_ms == 0);
    }

    TEST_CASE("SponsorSession is_stale") {
        SponsorSession session;
        session.received_at_ms = time::now_ms() - 10000;  // 10 seconds ago

        CHECK(session.is_stale(5000) == true);   // 5 second timeout
        CHECK(session.is_stale(15000) == false); // 15 second timeout
    }

    TEST_CASE("SponsorSession age_ms") {
        SponsorSession session;
        session.received_at_ms = time::now_ms() - 5000;  // 5 seconds ago

        // Age should be approximately 5000ms (allow some tolerance)
        CHECK(session.age_ms() >= 4900);
        CHECK(session.age_ms() <= 6000);
    }

}

TEST_SUITE("Sponsor - Sponsor Class") {

    TEST_CASE("Sponsor constructor") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        NodeId local_id = crypto::node_id_from_pubkey(ed_pub);

        Sponsor sponsor(local_id, ed_priv);
        CHECK(sponsor.pending_count() == 0);
    }

    TEST_CASE("Sponsor receive valid request") {
        auto [sponsor_priv, sponsor_pub] = crypto::generate_ed25519_keypair();
        NodeId sponsor_id = crypto::node_id_from_pubkey(sponsor_pub);

        Sponsor sponsor(sponsor_id, sponsor_priv);

        // Create candidate request
        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();

        JoinRequest req = sponsor::create_join_request(cand_priv, cand_pub, cand_x_pub);

        auto result = sponsor.receive_request(req);
        CHECK(result.is_ok());
        CHECK(sponsor.pending_count() == 1);
        CHECK(sponsor.has_pending(req.candidate_id) == true);
    }

    TEST_CASE("Sponsor reject request with zero candidate ID") {
        auto [sponsor_priv, sponsor_pub] = crypto::generate_ed25519_keypair();
        NodeId sponsor_id = crypto::node_id_from_pubkey(sponsor_pub);

        Sponsor sponsor(sponsor_id, sponsor_priv);

        JoinRequest req;
        // candidate_id is zero by default

        auto result = sponsor.receive_request(req);
        CHECK(result.is_err());
    }

    TEST_CASE("Sponsor reject request with mismatched ID") {
        auto [sponsor_priv, sponsor_pub] = crypto::generate_ed25519_keypair();
        NodeId sponsor_id = crypto::node_id_from_pubkey(sponsor_pub);

        Sponsor sponsor(sponsor_id, sponsor_priv);

        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();

        JoinRequest req = sponsor::create_join_request(cand_priv, cand_pub, cand_x_pub);

        // Tamper with candidate_id
        req.candidate_id.data[0] ^= 0xFF;

        auto result = sponsor.receive_request(req);
        CHECK(result.is_err());
    }

    TEST_CASE("Sponsor reject duplicate request") {
        auto [sponsor_priv, sponsor_pub] = crypto::generate_ed25519_keypair();
        NodeId sponsor_id = crypto::node_id_from_pubkey(sponsor_pub);

        Sponsor sponsor(sponsor_id, sponsor_priv);

        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();

        JoinRequest req = sponsor::create_join_request(cand_priv, cand_pub, cand_x_pub);

        auto r1 = sponsor.receive_request(req);
        CHECK(r1.is_ok());

        auto r2 = sponsor.receive_request(req);
        CHECK(r2.is_err());  // Duplicate
    }

    TEST_CASE("Sponsor get_pending") {
        auto [sponsor_priv, sponsor_pub] = crypto::generate_ed25519_keypair();
        NodeId sponsor_id = crypto::node_id_from_pubkey(sponsor_pub);

        Sponsor sponsor(sponsor_id, sponsor_priv);

        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();

        JoinRequest req = sponsor::create_join_request(cand_priv, cand_pub, cand_x_pub);
        sponsor.receive_request(req);

        auto pending = sponsor.get_pending(req.candidate_id);
        CHECK(pending.has_value());
        CHECK(pending->request.candidate_id == req.candidate_id);
    }

    TEST_CASE("Sponsor remove_request") {
        auto [sponsor_priv, sponsor_pub] = crypto::generate_ed25519_keypair();
        NodeId sponsor_id = crypto::node_id_from_pubkey(sponsor_pub);

        Sponsor sponsor(sponsor_id, sponsor_priv);

        auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
        auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();

        JoinRequest req = sponsor::create_join_request(cand_priv, cand_pub, cand_x_pub);
        sponsor.receive_request(req);

        CHECK(sponsor.pending_count() == 1);

        sponsor.remove_request(req.candidate_id);

        CHECK(sponsor.pending_count() == 0);
        CHECK(sponsor.has_pending(req.candidate_id) == false);
    }

    TEST_CASE("Sponsor get_all_pending") {
        auto [sponsor_priv, sponsor_pub] = crypto::generate_ed25519_keypair();
        NodeId sponsor_id = crypto::node_id_from_pubkey(sponsor_pub);

        Sponsor sponsor(sponsor_id, sponsor_priv);

        // Add two requests
        for (int i = 0; i < 2; ++i) {
            auto [cand_priv, cand_pub] = crypto::generate_ed25519_keypair();
            auto [cand_x_priv, cand_x_pub] = crypto::generate_x25519_keypair();
            JoinRequest req = sponsor::create_join_request(cand_priv, cand_pub, cand_x_pub);
            sponsor.receive_request(req);
        }

        auto all_pending = sponsor.get_all_pending();
        CHECK(all_pending.size() == 2);
    }

}

TEST_SUITE("Sponsor - Serialization") {

    TEST_CASE("JoinRequest serialize/deserialize roundtrip") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

        JoinRequest original = sponsor::create_join_request(ed_priv, ed_pub, x_pub, {}, "test");

        auto bytes = sponsor::serialize_join_request(original);
        CHECK(bytes.size() > 0);

        auto result = sponsor::deserialize_join_request(bytes);
        REQUIRE(result.is_ok());

        JoinRequest& parsed = result.value();
        CHECK(parsed.candidate_id == original.candidate_id);
        CHECK(parsed.metadata == original.metadata);
    }

}
