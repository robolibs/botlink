/* SPDX-License-Identifier: MIT */
/*
 * Botlink Config Tests
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Config - DefaultConfig") {

    TEST_CASE("Default config has sensible values") {
        Config config = cfg::default_config();

        CHECK(config.node.name == "botlink_node");
        CHECK(config.node.role == Role::Member);
        CHECK(config.node.mtu == DEFAULT_MTU);
        CHECK(config.node.overlay.addr.prefix_len == 24);

        CHECK(config.trust.policy.min_yes_votes == 2);
        CHECK(config.trust.policy.vote_timeout_ms == 15000);
        CHECK(config.trust.policy.require_sponsor);
    }

}

TEST_SUITE("Config - NodeConfig") {

    TEST_CASE("NodeConfig defaults") {
        NodeConfig node;

        CHECK(node.mtu == DEFAULT_MTU);
    }

    TEST_CASE("NodeConfig serialization members") {
        NodeConfig node;
        node.name = "test_node";
        node.role = Role::Member;

        // Check that members() works (for dp serialization)
        auto m = node.members();
        CHECK(std::get<0>(m) == "test_node");
    }

}

TEST_SUITE("Config - IdentityConfig") {

    TEST_CASE("IdentityConfig with generated keys") {
        IdentityConfig identity;

        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

        identity.ed25519_private = ed_priv;
        identity.ed25519_public = ed_pub;
        identity.x25519_private = x_priv;
        identity.x25519_public = x_pub;
        identity.ed25519_id = crypto::node_id_to_hex(crypto::node_id_from_pubkey(ed_pub));

        CHECK_FALSE(identity.ed25519_private.is_zero());
        CHECK_FALSE(identity.ed25519_public.is_zero());
        CHECK_FALSE(identity.x25519_private.is_zero());
        CHECK_FALSE(identity.x25519_public.is_zero());
        CHECK_FALSE(identity.ed25519_id.empty());
    }

}

TEST_SUITE("Config - TrustConfig") {

    TEST_CASE("TrustConfig defaults") {
        TrustConfig trust;

        CHECK(trust.policy.min_yes_votes == 2);
        CHECK(trust.policy.vote_timeout_ms == 15000);
    }

    TEST_CASE("BootstrapEntry") {
        BootstrapEntry entry;
        entry.type = BootstrapType::Member;
        entry.id = "bootstrap1";
        entry.endpoint = Endpoint(IPv4Addr(192, 168, 1, 1), 51820);

        CHECK(entry.type == BootstrapType::Member);
        CHECK(entry.id == "bootstrap1");
        CHECK(entry.endpoint.port == 51820);
    }

    TEST_CASE("Add bootstrap peers") {
        TrustConfig trust;

        BootstrapEntry entry1;
        entry1.type = BootstrapType::Member;
        entry1.id = "peer1";

        BootstrapEntry entry2;
        entry2.type = BootstrapType::Relay;
        entry2.id = "relay1";

        trust.bootstraps.push_back(entry1);
        trust.bootstraps.push_back(entry2);

        CHECK(trust.bootstraps.size() == 2);
    }

}

TEST_SUITE("Config - OverlayConfig") {

    TEST_CASE("OverlayConfig defaults") {
        OverlayConfig overlay;

        CHECK(overlay.addr.prefix_len == 24);
        CHECK(overlay.listen.empty());
    }

    TEST_CASE("Add listen endpoints") {
        OverlayConfig overlay;

        overlay.listen.push_back(Endpoint(IPv4Addr(0, 0, 0, 0), 51820));
        overlay.listen.push_back(Endpoint(IPv4Addr(0, 0, 0, 0), 51821));

        CHECK(overlay.listen.size() == 2);
    }

}

TEST_SUITE("Config - VotingPolicy") {

    TEST_CASE("VotingPolicy defaults") {
        VotingPolicy policy;

        CHECK(policy.min_yes_votes == 2);
        CHECK(policy.min_no_votes == 2);
        CHECK(policy.vote_timeout_ms == 15000);
        CHECK(policy.require_sponsor);
    }

    TEST_CASE("Custom VotingPolicy") {
        VotingPolicy policy;
        policy.min_yes_votes = 3;
        policy.min_no_votes = 1;
        policy.vote_timeout_ms = 30000;
        policy.require_sponsor = false;

        CHECK(policy.min_yes_votes == 3);
        CHECK(policy.min_no_votes == 1);
        CHECK(policy.vote_timeout_ms == 30000);
        CHECK_FALSE(policy.require_sponsor);
    }

}

TEST_SUITE("Config - Full Config") {

    TEST_CASE("Full config construction") {
        Config config;

        // Node config
        config.node.name = "my_robot";
        config.node.role = Role::Member;
        config.node.interface = InterfaceName("bot0");
        config.node.mtu = 1400;
        config.node.overlay.addr.addr = "10.42.0.1";
        config.node.overlay.addr.prefix_len = 24;
        config.node.overlay.listen.push_back(Endpoint(IPv4Addr(0, 0, 0, 0), 51820));

        // Identity config
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        config.identity.ed25519_private = ed_priv;
        config.identity.ed25519_public = ed_pub;
        config.identity.x25519_private = x_priv;
        config.identity.x25519_public = x_pub;
        config.identity.ed25519_id = crypto::node_id_to_hex(crypto::node_id_from_pubkey(ed_pub));

        // Trust config
        config.trust.chain.chain_name = "swarm_trust";
        config.trust.chain.path = "./trust_data";
        config.trust.policy.min_yes_votes = 2;

        // Verify
        CHECK(config.node.name == "my_robot");
        CHECK(config.node.role == Role::Member);
        CHECK(config.node.mtu == 1400);
        CHECK_FALSE(config.identity.ed25519_public.is_zero());
        CHECK(config.trust.chain.chain_name == "swarm_trust");
    }

}

TEST_SUITE("Config - Wizard") {

    TEST_CASE("cfg::WizardOptions defaults") {
        cfg::WizardOptions options;

        CHECK(options.generate_keys);
        CHECK(options.interactive);
        CHECK(options.default_interface == "botlink0");
        CHECK(options.default_port == DEFAULT_PORT);
    }

}

TEST_SUITE("Config - ConfigParser") {

    TEST_CASE("Parse simple key=value") {
        cfg::ConfigParser parser;
        auto res = parser.parse("[node]\nname = \"mynode\"\nmtu = 1420\n");
        REQUIRE(res.is_ok());

        auto name = parser.get("node", "name");
        REQUIRE(name.has_value());
        CHECK(name.value() == "mynode");

        auto mtu = parser.get("node", "mtu");
        REQUIRE(mtu.has_value());
        CHECK(mtu.value() == "1420");
    }

    TEST_CASE("Parse with comments") {
        cfg::ConfigParser parser;
        auto res = parser.parse("# This is a comment\n[node]\nname = \"test\"\n; Another comment\n");
        REQUIRE(res.is_ok());

        auto name = parser.get("node", "name");
        REQUIRE(name.has_value());
        CHECK(name.value() == "test");
    }

    TEST_CASE("Parse multiple sections") {
        cfg::ConfigParser parser;
        auto res = parser.parse("[node]\nname = \"test\"\n\n[overlay]\naddr = \"10.0.0.1/24\"\n");
        REQUIRE(res.is_ok());

        CHECK(parser.has_section("node"));
        CHECK(parser.has_section("overlay"));
        CHECK_FALSE(parser.has_section("nonexistent"));

        auto addr = parser.get("overlay", "addr");
        REQUIRE(addr.has_value());
        CHECK(addr.value() == "10.0.0.1/24");
    }

    TEST_CASE("get_or returns default") {
        cfg::ConfigParser parser;
        auto res = parser.parse("[node]\nname = \"test\"\n");
        REQUIRE(res.is_ok());

        CHECK(parser.get_or("node", "name", "default") == "test");
        CHECK(parser.get_or("node", "missing", "default") == "default");
        CHECK(parser.get_or("missing_section", "key", "default") == "default");
    }

    TEST_CASE("Parse error on missing equals") {
        cfg::ConfigParser parser;
        auto res = parser.parse("[node]\ninvalid line without equals\n");
        CHECK(res.is_err());
    }

    TEST_CASE("Parse error on unclosed bracket") {
        cfg::ConfigParser parser;
        auto res = parser.parse("[node\nname = \"test\"\n");
        CHECK(res.is_err());
    }

}

TEST_SUITE("Config - ConfigFile") {

    TEST_CASE("Generate config template") {
        String template_str = cfg::generate_config_template(true);

        CHECK(template_str.find("[node]") != String::npos);
        CHECK(template_str.find("[overlay]") != String::npos);
        CHECK(template_str.find("[identity]") != String::npos);
        CHECK(template_str.find("[trust]") != String::npos);
        CHECK(template_str.find("[logging]") != String::npos);
    }

    TEST_CASE("Generate config with keys") {
        auto res = cfg::generate_config_with_keys("test_node", "10.42.0.1/24", "0.0.0.0:51820");
        REQUIRE(res.is_ok());

        Config config = res.value();
        CHECK(config.node.name == "test_node");
        CHECK(config.node.overlay.addr.addr == "10.42.0.1");
        CHECK(config.node.overlay.addr.prefix_len == 24);
        CHECK(config.node.overlay.listen.size() == 1);
        CHECK(config.node.overlay.listen[0].port == 51820);

        // Keys should be generated
        CHECK_FALSE(config.identity.ed25519_private.is_zero());
        CHECK_FALSE(config.identity.ed25519_public.is_zero());
        CHECK_FALSE(config.identity.x25519_private.is_zero());
        CHECK_FALSE(config.identity.x25519_public.is_zero());
    }

    TEST_CASE("Serialize and parse config roundtrip") {
        // Create a config
        auto gen_res = cfg::generate_config_with_keys("roundtrip_test", "10.42.0.5/24", "0.0.0.0:51821");
        REQUIRE(gen_res.is_ok());
        Config original = gen_res.value();
        original.trust.chain.path = "./test_chain";
        original.trust.chain.chain_name = "test_mesh";
        original.trust.policy.min_yes_votes = 3;
        original.logging.level = "debug";

        // Serialize it
        String serialized = cfg::serialize_config(original);

        // Parse it back
        cfg::ConfigParser parser;
        auto parse_res = parser.parse(serialized);
        REQUIRE(parse_res.is_ok());

        // Check values were preserved
        CHECK(parser.get_or("node", "name", "") == "roundtrip_test");
        CHECK(parser.get_or("overlay", "addr", "") == "10.42.0.5/24");
        CHECK(parser.get_or("trust", "chain_name", "") == "test_mesh");
        CHECK(parser.get_or("trust", "min_yes_votes", "") == "3");
        CHECK(parser.get_or("logging", "level", "") == "debug");
    }

}
