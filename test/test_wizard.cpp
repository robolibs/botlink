/* SPDX-License-Identifier: MIT */
/*
 * Botlink Config Wizard Tests
 */

#include <doctest/doctest.h>

#include <botlink/botlink.hpp>

using namespace botlink;
using namespace dp;

TEST_SUITE("Wizard - WizardOptions") {

    TEST_CASE("WizardOptions default values") {
        cfg::WizardOptions options;

        CHECK(options.generate_keys == true);
        CHECK(options.interactive == true);
        CHECK(options.default_interface == "botlink0");
        CHECK(options.default_port == DEFAULT_PORT);
        CHECK(options.default_overlay == "10.42.0.1/24");
    }

    TEST_CASE("WizardOptions custom values") {
        cfg::WizardOptions options;
        options.generate_keys = false;
        options.interactive = false;
        options.default_interface = "tun0";
        options.default_port = 12345;
        options.default_overlay = "192.168.100.1/16";

        CHECK(options.generate_keys == false);
        CHECK(options.interactive == false);
        CHECK(options.default_interface == "tun0");
        CHECK(options.default_port == 12345);
        CHECK(options.default_overlay == "192.168.100.1/16");
    }

}

TEST_SUITE("Wizard - ConfigWizard Non-Interactive") {

    TEST_CASE("Generate default config") {
        Config config = cfg::generate_default_config();

        // Check node config
        CHECK(config.node.name == "botlink_node");
        CHECK(config.node.role == Role::Member);
        CHECK(config.node.mtu == DEFAULT_MTU);

        // Check identity was generated
        CHECK_FALSE(config.identity.ed25519_id.empty());
    }

    TEST_CASE("ConfigWizard run_defaults generates keys") {
        cfg::WizardOptions options;
        options.interactive = false;
        options.generate_keys = true;

        cfg::ConfigWizard wizard(options);
        Config config = wizard.run_defaults();

        // Keys should be generated
        // Ed25519 ID should be a hex string
        CHECK(config.identity.ed25519_id.size() == 64); // 32 bytes = 64 hex chars
    }

    TEST_CASE("ConfigWizard creates valid trust config") {
        cfg::WizardOptions options;
        options.interactive = false;

        cfg::ConfigWizard wizard(options);
        Config config = wizard.run_defaults();

        CHECK(config.trust.chain.chain_name == "swarm_trust");
        CHECK(config.trust.chain.path == "./botlink_trust");
        CHECK(config.trust.policy.min_yes_votes == 2);
        CHECK(config.trust.policy.vote_timeout_ms == 15000);
        CHECK(config.trust.policy.require_sponsor == true);
    }

    TEST_CASE("ConfigWizard creates valid network config") {
        cfg::WizardOptions options;
        options.interactive = false;

        cfg::ConfigWizard wizard(options);
        Config config = wizard.run_defaults();

        CHECK(config.node.overlay.addr.addr == "10.42.0.1");
        CHECK(config.node.overlay.addr.prefix_len == 24);
        CHECK(config.node.overlay.listen.size() >= 1);
    }

}

TEST_SUITE("Wizard - Prompt Functions") {

    TEST_CASE("prompt_string returns default in non-interactive mode") {
        cfg::WizardOptions options;
        options.interactive = false;

        cfg::ConfigWizard wizard(options);

        String result = wizard.prompt_string("Enter name", "default_name");
        CHECK(result == "default_name");
    }

    TEST_CASE("prompt_bool returns default in non-interactive mode") {
        cfg::WizardOptions options;
        options.interactive = false;

        cfg::ConfigWizard wizard(options);

        boolean result_true = wizard.prompt_bool("Enable feature", true);
        CHECK(result_true == true);

        boolean result_false = wizard.prompt_bool("Disable feature", false);
        CHECK(result_false == false);
    }

    TEST_CASE("prompt_number returns default in non-interactive mode") {
        cfg::WizardOptions options;
        options.interactive = false;

        cfg::ConfigWizard wizard(options);

        u32 result = wizard.prompt_number("Enter port", 51820);
        CHECK(result == 51820);
    }

    TEST_CASE("prompt_choice returns default in non-interactive mode") {
        cfg::WizardOptions options;
        options.interactive = false;

        cfg::ConfigWizard wizard(options);

        Vector<String> choices;
        choices.push_back("option1");
        choices.push_back("option2");
        choices.push_back("option3");

        usize result = wizard.prompt_choice("Select option", choices, 1);
        CHECK(result == 1);
    }

}

TEST_SUITE("Wizard - Config Access") {

    TEST_CASE("ConfigWizard config() returns generated config") {
        cfg::WizardOptions options;
        options.interactive = false;

        cfg::ConfigWizard wizard(options);
        wizard.run_defaults();

        const Config &config = wizard.config();
        CHECK(config.node.name == "botlink_node");
    }

}

TEST_SUITE("Wizard - run_wizard convenience function") {

    TEST_CASE("run_wizard with non-interactive options") {
        cfg::WizardOptions options;
        options.interactive = false;

        Config config = cfg::run_wizard(options);

        CHECK_FALSE(config.identity.ed25519_id.empty());
        CHECK(config.node.name == "botlink_node");
    }

}
