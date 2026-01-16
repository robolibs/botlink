/* SPDX-License-Identifier: MIT */
/*
 * Botlink Key Generation Tool
 * Generates Ed25519 and X25519 keys for botlink configuration
 *
 * Usage:
 *   ./keygen             # Generate a full identity (Ed25519 + X25519 keypairs)
 *   ./keygen --ed25519   # Generate only Ed25519 keypair
 *   ./keygen --x25519    # Generate only X25519 keypair
 *   ./keygen --config    # Output in config file format
 *   ./keygen --json      # Output in JSON format
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>
#include <cstring>

using namespace botlink;
using namespace dp;

// Convert bytes to hex string
String bytes_to_hex(const u8 *data, usize len) {
    String hex;
    hex.reserve(len * 2);
    const char *digits = "0123456789abcdef";
    for (usize i = 0; i < len; ++i) {
        hex.push_back(digits[(data[i] >> 4) & 0x0F]);
        hex.push_back(digits[data[i] & 0x0F]);
    }
    return hex;
}

void print_usage(const char *prog) {
    std::cout << "Botlink Key Generation Tool\n\n";
    std::cout << "Usage: " << prog << " [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --help, -h     Show this help message\n";
    std::cout << "  --ed25519      Generate only Ed25519 keypair (for signing)\n";
    std::cout << "  --x25519       Generate only X25519 keypair (for key exchange)\n";
    std::cout << "  --config       Output in config file format (default)\n";
    std::cout << "  --json         Output in JSON format\n";
    std::cout << "  --base64       Output public keys in base64 format\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << prog << "                    # Generate full identity\n";
    std::cout << "  " << prog << " --config > keys.conf  # Save to file\n";
    std::cout << "  " << prog << " --json              # JSON output for scripting\n";
}

void output_config_format(const PrivateKey &ed_priv, const PublicKey &ed_pub,
                          const PrivateKey &x_priv, const PublicKey &x_pub,
                          const NodeId &node_id) {
    std::cout << "# Botlink Identity - Generated Keys\n";
    std::cout << "# Node ID: " << crypto::node_id_to_hex(node_id).c_str() << "\n\n";

    std::cout << "[identity]\n";
    std::cout << "# Ed25519 signing keypair\n";
    std::cout << "ed25519_private = \"" << bytes_to_hex(ed_priv.data.data(), ed_priv.data.size()).c_str() << "\"\n";
    std::cout << "ed25519_public = \"" << bytes_to_hex(ed_pub.data.data(), ed_pub.data.size()).c_str() << "\"\n";
    std::cout << "ed25519_id = \"" << crypto::node_id_to_hex(node_id).c_str() << "\"\n";
    std::cout << "\n# X25519 key exchange keypair\n";
    std::cout << "x25519_private = \"" << bytes_to_hex(x_priv.data.data(), x_priv.data.size()).c_str() << "\"\n";
    std::cout << "x25519_public = \"" << bytes_to_hex(x_pub.data.data(), x_pub.data.size()).c_str() << "\"\n";
}

void output_json_format(const PrivateKey &ed_priv, const PublicKey &ed_pub,
                        const PrivateKey &x_priv, const PublicKey &x_pub,
                        const NodeId &node_id, boolean with_base64) {
    std::cout << "{\n";
    std::cout << "  \"node_id\": \"" << crypto::node_id_to_hex(node_id).c_str() << "\",\n";
    std::cout << "  \"ed25519\": {\n";
    std::cout << "    \"private\": \"" << bytes_to_hex(ed_priv.data.data(), ed_priv.data.size()).c_str() << "\",\n";
    std::cout << "    \"public\": \"" << bytes_to_hex(ed_pub.data.data(), ed_pub.data.size()).c_str() << "\"";
    if (with_base64) {
        std::cout << ",\n    \"public_base64\": \"" << crypto::key_to_base64(ed_pub).c_str() << "\"";
    }
    std::cout << "\n  },\n";
    std::cout << "  \"x25519\": {\n";
    std::cout << "    \"private\": \"" << bytes_to_hex(x_priv.data.data(), x_priv.data.size()).c_str() << "\",\n";
    std::cout << "    \"public\": \"" << bytes_to_hex(x_pub.data.data(), x_pub.data.size()).c_str() << "\"";
    if (with_base64) {
        std::cout << ",\n    \"public_base64\": \"" << crypto::key_to_base64(x_pub).c_str() << "\"";
    }
    std::cout << "\n  }\n";
    std::cout << "}\n";
}

void output_ed25519_only(boolean json, boolean base64) {
    auto [priv, pub] = crypto::generate_ed25519_keypair();
    NodeId node_id = crypto::node_id_from_pubkey(pub);

    if (json) {
        std::cout << "{\n";
        std::cout << "  \"node_id\": \"" << crypto::node_id_to_hex(node_id).c_str() << "\",\n";
        std::cout << "  \"private\": \"" << bytes_to_hex(priv.data.data(), priv.data.size()).c_str() << "\",\n";
        std::cout << "  \"public\": \"" << bytes_to_hex(pub.data.data(), pub.data.size()).c_str() << "\"";
        if (base64) {
            std::cout << ",\n  \"public_base64\": \"" << crypto::key_to_base64(pub).c_str() << "\"";
        }
        std::cout << "\n}\n";
    } else {
        std::cout << "# Ed25519 Keypair (for signing)\n";
        std::cout << "# Node ID: " << crypto::node_id_to_hex(node_id).c_str() << "\n\n";
        std::cout << "ed25519_private = \"" << bytes_to_hex(priv.data.data(), priv.data.size()).c_str() << "\"\n";
        std::cout << "ed25519_public = \"" << bytes_to_hex(pub.data.data(), pub.data.size()).c_str() << "\"\n";
        if (base64) {
            std::cout << "ed25519_public_base64 = \"" << crypto::key_to_base64(pub).c_str() << "\"\n";
        }
    }
}

void output_x25519_only(boolean json, boolean base64) {
    auto [priv, pub] = crypto::generate_x25519_keypair();

    if (json) {
        std::cout << "{\n";
        std::cout << "  \"private\": \"" << bytes_to_hex(priv.data.data(), priv.data.size()).c_str() << "\",\n";
        std::cout << "  \"public\": \"" << bytes_to_hex(pub.data.data(), pub.data.size()).c_str() << "\"";
        if (base64) {
            std::cout << ",\n  \"public_base64\": \"" << crypto::key_to_base64(pub).c_str() << "\"";
        }
        std::cout << "\n}\n";
    } else {
        std::cout << "# X25519 Keypair (for key exchange)\n\n";
        std::cout << "x25519_private = \"" << bytes_to_hex(priv.data.data(), priv.data.size()).c_str() << "\"\n";
        std::cout << "x25519_public = \"" << bytes_to_hex(pub.data.data(), pub.data.size()).c_str() << "\"\n";
        if (base64) {
            std::cout << "x25519_public_base64 = \"" << crypto::key_to_base64(pub).c_str() << "\"\n";
        }
    }
}

auto main(int argc, char *argv[]) -> int {
    // Parse arguments
    boolean ed25519_only = false;
    boolean x25519_only = false;
    boolean json_output = false;
    boolean base64_output = false;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--ed25519") == 0) {
            ed25519_only = true;
        } else if (strcmp(argv[i], "--x25519") == 0) {
            x25519_only = true;
        } else if (strcmp(argv[i], "--json") == 0) {
            json_output = true;
        } else if (strcmp(argv[i], "--config") == 0) {
            json_output = false;
        } else if (strcmp(argv[i], "--base64") == 0) {
            base64_output = true;
        } else {
            std::cerr << "Unknown option: " << argv[i] << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // Initialize botlink crypto
    auto init_result = botlink::init();
    if (init_result.is_err()) {
        std::cerr << "Failed to initialize: " << init_result.error().message.c_str() << "\n";
        return 1;
    }

    // Generate and output keys based on options
    if (ed25519_only) {
        output_ed25519_only(json_output, base64_output);
    } else if (x25519_only) {
        output_x25519_only(json_output, base64_output);
    } else {
        // Generate full identity
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        NodeId node_id = crypto::node_id_from_pubkey(ed_pub);

        if (json_output) {
            output_json_format(ed_priv, ed_pub, x_priv, x_pub, node_id, base64_output);
        } else {
            output_config_format(ed_priv, ed_pub, x_priv, x_pub, node_id);
        }
    }

    return 0;
}
