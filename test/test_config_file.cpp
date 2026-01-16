/* SPDX-License-Identifier: MIT */
/*
 * Botlink Config File Tests
 * Tests for config file parsing and generation
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("ConfigFile - ConfigParser") {

    TEST_CASE("Parse empty content") {
        cfg::ConfigParser parser;
        auto result = parser.parse("");
        CHECK(result.is_ok());
    }

    TEST_CASE("Parse comments") {
        cfg::ConfigParser parser;
        String content = "# This is a comment\n; Another comment\n";
        auto result = parser.parse(content);
        CHECK(result.is_ok());
    }

    TEST_CASE("Parse section header") {
        cfg::ConfigParser parser;
        String content = "[section1]\nkey1 = value1\n";
        auto result = parser.parse(content);
        CHECK(result.is_ok());
        CHECK(parser.has_section("section1"));
    }

    TEST_CASE("Parse key-value pair") {
        cfg::ConfigParser parser;
        String content = "[test]\nname = myvalue\n";
        auto result = parser.parse(content);
        CHECK(result.is_ok());

        auto val = parser.get("test", "name");
        CHECK(val.has_value());
        CHECK(val.value() == "myvalue");
    }

    TEST_CASE("Parse quoted values") {
        cfg::ConfigParser parser;
        String content = "[test]\nname = \"quoted value\"\nother = 'single quotes'\n";
        auto result = parser.parse(content);
        CHECK(result.is_ok());

        auto name = parser.get("test", "name");
        CHECK(name.has_value());
        CHECK(name.value() == "quoted value");

        auto other = parser.get("test", "other");
        CHECK(other.has_value());
        CHECK(other.value() == "single quotes");
    }

    TEST_CASE("get_or returns default") {
        cfg::ConfigParser parser;
        String content = "[test]\nkey1 = value1\n";
        parser.parse(content);

        CHECK(parser.get_or("test", "key1", "default") == "value1");
        CHECK(parser.get_or("test", "missing", "default") == "default");
        CHECK(parser.get_or("missing_section", "key", "default") == "default");
    }

    TEST_CASE("keys returns all keys in section") {
        cfg::ConfigParser parser;
        String content = "[section]\na = 1\nb = 2\nc = 3\n";
        parser.parse(content);

        auto keys = parser.keys("section");
        CHECK(keys.size() == 3);
    }

    TEST_CASE("Parse global section (no header)") {
        cfg::ConfigParser parser;
        String content = "key = value\n[section]\nother = data\n";
        parser.parse(content);

        auto global_val = parser.get("global", "key");
        CHECK(global_val.has_value());
        CHECK(global_val.value() == "value");

        auto section_val = parser.get("section", "other");
        CHECK(section_val.has_value());
        CHECK(section_val.value() == "data");
    }

    TEST_CASE("Parse with whitespace") {
        cfg::ConfigParser parser;
        String content = "[test]\n  key   =   value  \n";
        parser.parse(content);

        auto val = parser.get("test", "key");
        CHECK(val.has_value());
        CHECK(val.value() == "value");
    }

    TEST_CASE("Parse error on unclosed bracket") {
        cfg::ConfigParser parser;
        String content = "[unclosed\nkey = value\n";
        auto result = parser.parse(content);
        CHECK(result.is_err());
    }

    TEST_CASE("Parse error on missing equals") {
        cfg::ConfigParser parser;
        String content = "[test]\ninvalid_line\n";
        auto result = parser.parse(content);
        CHECK(result.is_err());
    }

}

TEST_SUITE("ConfigFile - Template Generation") {

    TEST_CASE("generate_config_template produces content") {
        String tmpl = cfg::generate_config_template(true);
        CHECK(tmpl.size() > 0);
        // Should contain section headers
        CHECK(tmpl.find("[node]") != String::npos);
        CHECK(tmpl.find("[overlay]") != String::npos);
        CHECK(tmpl.find("[identity]") != String::npos);
        CHECK(tmpl.find("[trust]") != String::npos);
    }

    TEST_CASE("generate_config_template without comments") {
        String with_comments = cfg::generate_config_template(true);
        String without_comments = cfg::generate_config_template(false);

        // Without comments should be shorter
        CHECK(without_comments.size() < with_comments.size());
        // Should not contain comment character at start of line
        CHECK(without_comments.find("# ") == String::npos);
    }

}

TEST_SUITE("ConfigFile - Config Serialization") {

    TEST_CASE("serialize_config produces valid content") {
        Config config = cfg::default_config();
        config.node.name = "test_node";
        config.node.role = Role::Member;

        String serialized = cfg::serialize_config(config);
        CHECK(serialized.size() > 0);
        CHECK(serialized.find("[node]") != String::npos);
        CHECK(serialized.find("test_node") != String::npos);
    }

    TEST_CASE("serialize_config includes all sections") {
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

        Config config = cfg::default_config();
        config.identity.ed25519_private = ed_priv;
        config.identity.ed25519_public = ed_pub;
        config.identity.x25519_private = x_priv;
        config.identity.x25519_public = x_pub;

        String serialized = cfg::serialize_config(config);

        CHECK(serialized.find("[node]") != String::npos);
        CHECK(serialized.find("[overlay]") != String::npos);
        CHECK(serialized.find("[identity]") != String::npos);
        CHECK(serialized.find("[trust]") != String::npos);
        CHECK(serialized.find("[logging]") != String::npos);
    }

    TEST_CASE("serialize_config with bootstraps") {
        Config config = cfg::default_config();

        BootstrapEntry boot;
        boot.id = "genesis";
        boot.type = BootstrapType::Member;
        config.trust.bootstraps.push_back(boot);

        String serialized = cfg::serialize_config(config);
        CHECK(serialized.find("[bootstrap.0]") != String::npos);
        CHECK(serialized.find("genesis") != String::npos);
    }

}

TEST_SUITE("ConfigFile - Config Generation") {

    TEST_CASE("generate_config_with_keys creates valid config") {
        auto result = cfg::generate_config_with_keys("my_node", "10.42.0.1/24", "0.0.0.0:51820");
        REQUIRE(result.is_ok());

        Config config = result.value();
        CHECK(config.node.name == "my_node");
        CHECK(config.node.overlay.addr.addr == "10.42.0.1");
        CHECK(config.node.overlay.addr.prefix_len == 24);
        CHECK(config.node.overlay.listen.size() == 1);

        // Should have generated keys
        CHECK_FALSE(config.identity.ed25519_private.is_zero());
        CHECK_FALSE(config.identity.ed25519_public.is_zero());
        CHECK_FALSE(config.identity.x25519_private.is_zero());
        CHECK_FALSE(config.identity.x25519_public.is_zero());
    }

    TEST_CASE("generate_config_with_keys invalid endpoint fails") {
        auto result = cfg::generate_config_with_keys("node", "10.42.0.1/24", "invalid");
        CHECK(result.is_err());
    }

    TEST_CASE("generate_config_with_keys overlay without prefix") {
        auto result = cfg::generate_config_with_keys("node", "10.42.0.1", "0.0.0.0:51820");
        REQUIRE(result.is_ok());

        // Default prefix should be 24
        CHECK(result.value().node.overlay.addr.prefix_len == 24);
    }

}

TEST_SUITE("ConfigFile - Default Config") {

    TEST_CASE("default_config values") {
        Config config = cfg::default_config();

        CHECK(config.version == 1);
        CHECK(config.node.name == "botlink_node");
        CHECK(config.node.role == Role::Member);
        CHECK(config.node.mtu == DEFAULT_MTU);
        // chain_name is not set in default_config
        CHECK(config.logging.level == "info");
    }

}
