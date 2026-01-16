/* SPDX-License-Identifier: MIT */
/*
 * Result Demo
 * Demonstrates Result type usage and error handling patterns
 */

#include <botlink/botlink.hpp>
#include <iostream>

// Use botlink namespace explicitly to avoid ambiguity with dp::Res
namespace bl = botlink;

int main() {
    std::cout << "=== Result Demo ===\n\n";

    std::cout << "The Result type provides a safe way to handle operations\n";
    std::cout << "that can fail, avoiding exceptions and null checks.\n\n";

    // Define helper functions as lambdas
    auto divide = [](dp::i32 a, dp::i32 b) -> bl::Res<dp::i32> {
        if (b == 0) {
            return bl::result::err(bl::err::invalid("Division by zero"));
        }
        return bl::result::ok(a / b);
    };

    auto validate_port = [](dp::u16 port) -> bl::VoidRes {
        if (port == 0) {
            return bl::result::err(bl::err::invalid("Port cannot be zero"));
        }
        if (port < 1024) {
            return bl::result::err(bl::err::permission("Port requires root privileges"));
        }
        return bl::result::ok();
    };

    auto parse_and_validate = [&validate_port](const dp::String& port_str) -> bl::Res<dp::u16> {
        auto port_res = bl::net::parse_port(port_str);
        if (port_res.is_err()) {
            return bl::result::err(port_res.error());
        }

        auto valid_res = validate_port(port_res.value());
        if (valid_res.is_err()) {
            return bl::result::err(valid_res.error());
        }

        return bl::result::ok(port_res.value());
    };

    // ==========================================================================
    // Step 1: Basic Result usage
    // ==========================================================================
    std::cout << "1. Basic Result usage...\n";

    auto result1 = divide(10, 2);
    std::cout << "   divide(10, 2):\n";
    std::cout << "     is_ok: " << (result1.is_ok() ? "YES" : "NO") << "\n";
    std::cout << "     is_err: " << (result1.is_err() ? "YES" : "NO") << "\n";
    if (result1.is_ok()) {
        std::cout << "     value: " << result1.value() << "\n";
    }

    auto result2 = divide(10, 0);
    std::cout << "   divide(10, 0):\n";
    std::cout << "     is_ok: " << (result2.is_ok() ? "YES" : "NO") << "\n";
    std::cout << "     is_err: " << (result2.is_err() ? "YES" : "NO") << "\n";
    if (result2.is_err()) {
        std::cout << "     error: " << result2.error().message.c_str() << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 2: VoidRes for operations without return value
    // ==========================================================================
    std::cout << "2. VoidRes for void operations...\n";

    auto void_ok = validate_port(51820);
    std::cout << "   validate_port(51820): " << (void_ok.is_ok() ? "OK" : "ERROR") << "\n";

    auto void_err1 = validate_port(0);
    std::cout << "   validate_port(0): " << (void_err1.is_ok() ? "OK" : "ERROR") << "\n";
    if (void_err1.is_err()) {
        std::cout << "     reason: " << void_err1.error().message.c_str() << "\n";
    }

    auto void_err2 = validate_port(80);
    std::cout << "   validate_port(80): " << (void_err2.is_ok() ? "OK" : "ERROR") << "\n";
    if (void_err2.is_err()) {
        std::cout << "     reason: " << void_err2.error().message.c_str() << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 3: Error creation helpers
    // ==========================================================================
    std::cout << "3. Error creation helpers...\n";

    auto io_err = bl::err::io("File not found");
    std::cout << "   err::io: " << io_err.message.c_str() << "\n";

    auto invalid_err = bl::err::invalid("Invalid argument");
    std::cout << "   err::invalid: " << invalid_err.message.c_str() << "\n";

    auto not_found_err = bl::err::not_found("Resource missing");
    std::cout << "   err::not_found: " << not_found_err.message.c_str() << "\n";

    auto perm_err = bl::err::permission("Access denied");
    std::cout << "   err::permission: " << perm_err.message.c_str() << "\n";

    auto timeout_err = bl::err::timeout("Operation timed out");
    std::cout << "   err::timeout: " << timeout_err.message.c_str() << "\n";

    auto crypto_err = bl::err::crypto("Decryption failed");
    std::cout << "   err::crypto: " << crypto_err.message.c_str() << "\n";

    auto net_err = bl::err::network("Connection refused");
    std::cout << "   err::network: " << net_err.message.c_str() << "\n";

    auto trust_err = bl::err::trust("Not a member");
    std::cout << "   err::trust: " << trust_err.message.c_str() << "\n";

    auto config_err = bl::err::config("Invalid configuration");
    std::cout << "   err::config: " << config_err.message.c_str() << "\n\n";

    // ==========================================================================
    // Step 4: Chaining operations
    // ==========================================================================
    std::cout << "4. Chaining operations...\n";

    auto chain1 = parse_and_validate("51820");
    std::cout << "   parse_and_validate(\"51820\"): "
              << (chain1.is_ok() ? std::to_string(chain1.value()).c_str() : chain1.error().message.c_str()) << "\n";

    auto chain2 = parse_and_validate("80");
    std::cout << "   parse_and_validate(\"80\"): "
              << (chain2.is_ok() ? std::to_string(chain2.value()).c_str() : chain2.error().message.c_str()) << "\n";

    auto chain3 = parse_and_validate("invalid");
    std::cout << "   parse_and_validate(\"invalid\"): "
              << (chain3.is_ok() ? std::to_string(chain3.value()).c_str() : chain3.error().message.c_str()) << "\n\n";

    // ==========================================================================
    // Step 5: Real-world examples from botlink
    // ==========================================================================
    std::cout << "5. Real-world botlink examples...\n";

    // Endpoint parsing
    auto ep_ok = bl::net::parse_endpoint("192.168.1.1:51820");
    std::cout << "   parse_endpoint(\"192.168.1.1:51820\"): "
              << (ep_ok.is_ok() ? "OK" : "ERROR") << "\n";

    auto ep_err = bl::net::parse_endpoint("invalid");
    std::cout << "   parse_endpoint(\"invalid\"): "
              << (ep_err.is_ok() ? "OK" : "ERROR") << "\n";

    // Key decoding
    dp::String valid_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    auto key_ok = bl::crypto::public_key_from_hex(valid_hex);
    std::cout << "   public_key_from_hex(valid): "
              << (key_ok.is_ok() ? "OK" : "ERROR") << "\n";

    auto key_err = bl::crypto::public_key_from_hex("invalid");
    std::cout << "   public_key_from_hex(\"invalid\"): "
              << (key_err.is_ok() ? "OK" : "ERROR") << "\n\n";

    // ==========================================================================
    // Step 6: Serialization helpers
    // ==========================================================================
    std::cout << "6. Serialization helpers...\n";

    // Create a simple struct to serialize
    bl::Endpoint ep;
    ep.family = bl::AddrFamily::IPv4;
    ep.ipv4.octets[0] = 10;
    ep.ipv4.octets[1] = 0;
    ep.ipv4.octets[2] = 0;
    ep.ipv4.octets[3] = 1;
    ep.port = 51820;

    dp::Vector<dp::u8> serialized = bl::serial::serialize(ep);
    std::cout << "   Serialized endpoint size: " << serialized.size() << " bytes\n";

    auto deser_result = bl::serial::deserialize<bl::Endpoint>(serialized);
    if (deser_result.is_ok()) {
        std::cout << "   Deserialized: " << bl::net::format_endpoint(deser_result.value()).c_str() << "\n";
        std::cout << "   Roundtrip matches: " << (deser_result.value() == ep ? "YES" : "NO") << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 7: Pattern: Early return on error
    // ==========================================================================
    std::cout << "7. Pattern: Early return on error...\n";

    auto process = [&validate_port](const dp::String& addr) -> bl::VoidRes {
        auto ep_res = bl::net::parse_endpoint(addr);
        if (ep_res.is_err()) {
            return bl::result::err(ep_res.error());
        }

        auto valid_res = validate_port(ep_res.value().port);
        if (valid_res.is_err()) {
            return bl::result::err(valid_res.error());
        }

        return bl::result::ok();
    };

    std::cout << "   process(\"192.168.1.1:51820\"): "
              << (process("192.168.1.1:51820").is_ok() ? "OK" : "ERROR") << "\n";
    std::cout << "   process(\"192.168.1.1:80\"): "
              << (process("192.168.1.1:80").is_ok() ? "OK" : "ERROR") << "\n";
    std::cout << "   process(\"invalid\"): "
              << (process("invalid").is_ok() ? "OK" : "ERROR") << "\n\n";

    // ==========================================================================
    // Step 8: Using value_or for defaults
    // ==========================================================================
    std::cout << "8. Handling results with defaults...\n";

    auto get_port = [](const dp::String& s) -> dp::u16 {
        auto res = bl::net::parse_port(s);
        if (res.is_ok()) {
            return res.value();
        }
        return bl::DEFAULT_PORT; // Return default on error
    };

    std::cout << "   get_port(\"8080\"): " << get_port("8080") << "\n";
    std::cout << "   get_port(\"invalid\"): " << get_port("invalid") << " (default)\n\n";

    // ==========================================================================
    // Step 9: Summary
    // ==========================================================================
    std::cout << "9. Summary...\n";
    std::cout << "   Result<T> - Result with value or error\n";
    std::cout << "   Res<T>    - Alias for Result<T, Error>\n";
    std::cout << "   VoidRes   - For operations without return value\n";
    std::cout << "   result::ok(value) - Create success result\n";
    std::cout << "   result::err(error) - Create error result\n";
    std::cout << "   err::* helpers - Create specific error types\n\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
