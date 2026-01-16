/* SPDX-License-Identifier: MIT */
/*
 * Botlink Config Wizard Demo
 * Demonstrates non-interactive config generation
 */

#include <botlink/botlink.hpp>
#include <iostream>

using namespace botlink;
using namespace dp;

// Helper to print separator
void print_separator() { std::cout << "----------------------------------------\n"; }

auto main() -> int {
    // Initialize the library
    auto init_result = botlink::init();
    if (init_result.is_err()) {
        std::cerr << "Failed to initialize botlink: " << init_result.error().message.c_str() << "\n";
        return 1;
    }

    std::cout << "Botlink Config Wizard Demo\n";
    std::cout << "==========================\n\n";

    // Generate default configuration
    std::cout << "Generating default configuration...\n\n";
    Config config = cfg::generate_default_config();

    print_separator();

    // Display node configuration
    std::cout << "Node Configuration:\n";
    std::cout << "  Name:      " << config.node.name.c_str() << "\n";
    std::cout << "  Role:      " << (config.node.role == Role::Member ? "member" : "relay") << "\n";
    std::cout << "  Interface: " << config.node.interface.c_str() << "\n";
    std::cout << "  MTU:       " << config.node.mtu << "\n\n";

    print_separator();

    // Display network configuration
    std::cout << "Network Configuration:\n";
    std::cout << "  Overlay IP:    " << config.node.overlay.addr.addr.c_str() << "/" << (int)config.node.overlay.addr.prefix_len << "\n";
    std::cout << "  Listen count:  " << config.node.overlay.listen.size() << "\n";
    if (!config.node.overlay.listen.empty()) {
        std::cout << "  First listen:  " << net::format_endpoint(config.node.overlay.listen[0]).c_str() << "\n";
    }
    std::cout << "\n";

    print_separator();

    // Display identity configuration
    std::cout << "Identity Configuration:\n";
    std::cout << "  Ed25519 ID: " << config.identity.ed25519_id.substr(0, 32).c_str() << "...\n";

    // Display key info (base64 encoded)
    KeyB64 ed_pub_b64 = crypto::key_to_base64(config.identity.ed25519_public);
    KeyB64 x_pub_b64 = crypto::key_to_base64(config.identity.x25519_public);
    std::cout << "  Ed25519 Public: " << String(ed_pub_b64.c_str()).substr(0, 20).c_str() << "...\n";
    std::cout << "  X25519 Public:  " << String(x_pub_b64.c_str()).substr(0, 20).c_str() << "...\n\n";

    print_separator();

    // Display trust configuration
    std::cout << "Trust Configuration:\n";
    std::cout << "  Chain Name:      " << config.trust.chain.chain_name.c_str() << "\n";
    std::cout << "  Chain Path:      " << config.trust.chain.path.c_str() << "\n";
    std::cout << "  Min Yes Votes:   " << config.trust.policy.min_yes_votes << "\n";
    std::cout << "  Vote Timeout:    " << config.trust.policy.vote_timeout_ms << "ms\n";
    std::cout << "  Require Sponsor: " << (config.trust.policy.require_sponsor ? "yes" : "no") << "\n";
    std::cout << "  Bootstraps:      " << config.trust.bootstraps.size() << "\n\n";

    print_separator();

    // Demonstrate custom wizard options
    std::cout << "Creating custom configuration...\n\n";

    cfg::WizardOptions custom_opts;
    custom_opts.interactive = false;
    custom_opts.generate_keys = true;
    custom_opts.default_interface = "botlink1";
    custom_opts.default_port = 12345;
    custom_opts.default_overlay = "172.16.0.1/16";

    cfg::ConfigWizard wizard(custom_opts);
    Config custom_config = wizard.run_defaults();

    std::cout << "Custom Configuration:\n";
    std::cout << "  Interface: " << custom_config.node.interface.c_str() << "\n";
    std::cout << "  Overlay:   " << custom_config.node.overlay.addr.addr.c_str() << "/"
              << (int)custom_config.node.overlay.addr.prefix_len << "\n";
    if (!custom_config.node.overlay.listen.empty()) {
        std::cout << "  Listen:    " << net::format_endpoint(custom_config.node.overlay.listen[0]).c_str() << "\n";
    }
    std::cout << "\n";

    print_separator();

    // Demonstrate prompt functions (non-interactive mode)
    std::cout << "Testing prompt functions in non-interactive mode:\n";

    cfg::WizardOptions prompt_opts;
    prompt_opts.interactive = false;
    cfg::ConfigWizard prompt_wizard(prompt_opts);

    String str_result = prompt_wizard.prompt_string("Enter name", "default_value");
    std::cout << "  prompt_string: \"" << str_result.c_str() << "\"\n";

    boolean bool_result = prompt_wizard.prompt_bool("Enable feature", true);
    std::cout << "  prompt_bool:   " << (bool_result ? "true" : "false") << "\n";

    u32 num_result = prompt_wizard.prompt_number("Enter port", 51820);
    std::cout << "  prompt_number: " << num_result << "\n";

    Vector<String> choices;
    choices.push_back("Option A");
    choices.push_back("Option B");
    choices.push_back("Option C");
    usize choice_result = prompt_wizard.prompt_choice("Select option", choices, 1);
    std::cout << "  prompt_choice: " << choice_result << " (" << choices[choice_result].c_str() << ")\n\n";

    print_separator();

    // Demonstrate NodeId derivation
    std::cout << "Verifying identity derivation...\n";
    NodeId derived_id = crypto::node_id_from_pubkey(config.identity.ed25519_public);
    String derived_hex = crypto::node_id_to_hex(derived_id);

    std::cout << "  Stored ID:  " << config.identity.ed25519_id.c_str() << "\n";
    std::cout << "  Derived ID: " << derived_hex.c_str() << "\n";
    std::cout << "  Match:      " << (config.identity.ed25519_id == derived_hex ? "yes" : "no") << "\n\n";

    print_separator();

    // Demonstrate key encoding
    std::cout << "Key encoding demonstration:\n";

    // Encode to base64
    KeyB64 priv_b64 = crypto::key_to_base64(config.identity.ed25519_private);
    std::cout << "  Private key (base64): " << String(priv_b64.c_str()).substr(0, 20).c_str() << "...\n";

    // Decode from base64
    auto decoded = crypto::private_key_from_base64(priv_b64);
    if (decoded.is_ok()) {
        std::cout << "  Base64 decode: success\n";
        // Compare key bytes manually
        bool match = true;
        for (usize i = 0; i < KEY_SIZE; ++i) {
            if (decoded.value().data[i] != config.identity.ed25519_private.data[i]) {
                match = false;
                break;
            }
        }
        std::cout << "  Roundtrip match: " << (match ? "yes" : "no") << "\n";
    }

    std::cout << "\nConfig wizard demo completed successfully!\n";
    return 0;
}
