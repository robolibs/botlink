/* SPDX-License-Identifier: MIT */
/*
 * Botlink Config Copy Tests
 *
 * Tests to ensure Config struct copies correctly, especially with heap-allocated strings.
 * This was added after fixing a buffer overflow bug in datapod's String copy constructor.
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Config Copy") {

    TEST_CASE("Empty Config copy") {
        Config c1;
        CHECK(c1.version == 1);

        Config c2 = c1;
        CHECK(c2.version == 1);
    }

    TEST_CASE("Config with node settings copy") {
        Config c1;
        c1.node.name = "test_node";
        c1.node.role = Role::Member;

        Config c2 = c1;
        CHECK(c2.node.name == "test_node");
        CHECK(c2.node.role == Role::Member);
    }

    TEST_CASE("Config with identity and long hex string copy") {
        Config c1;
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();

        c1.identity.ed25519_private = ed_priv;
        c1.identity.ed25519_public = ed_pub;
        c1.identity.x25519_private = x_priv;
        c1.identity.x25519_public = x_pub;

        // This 64-char hex string exceeds SSO size (23 chars) and uses heap allocation
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);
        c1.identity.ed25519_id = crypto::node_id_to_hex(node_id);

        CHECK(c1.identity.ed25519_id.size() == 64);

        // This copy previously crashed due to buffer overflow in String copy constructor
        Config c2 = c1;
        CHECK(c2.identity.ed25519_id.size() == 64);
        CHECK(c2.identity.ed25519_id == c1.identity.ed25519_id);
    }

    TEST_CASE("Config from generate_default_config copy") {
        Config c1 = cfg::generate_default_config();
        CHECK_FALSE(c1.identity.ed25519_id.empty());

        Config c2 = c1;
        CHECK(c2.node.name == c1.node.name);
        CHECK(c2.identity.ed25519_id == c1.identity.ed25519_id);
    }

    TEST_CASE("Config from ConfigWizard run_defaults copy") {
        cfg::WizardOptions options;
        options.interactive = false;
        options.generate_keys = true;

        cfg::ConfigWizard wizard(options);
        Config c1 = wizard.run_defaults();

        CHECK(c1.identity.ed25519_id.size() == 64);

        Config c2 = c1;
        CHECK(c2.identity.ed25519_id == c1.identity.ed25519_id);
    }

}
