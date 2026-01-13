/* Example usage of the C++ WireGuard library */

#include <wireguard/wireguard.hpp>
#include <iostream>
#include <arpa/inet.h>

using namespace wg;
using namespace dp;

auto print_key(const Key& key) -> void {
    KeyB64 b64;
    key::to_base64(b64, key);
    std::cout << b64.c_str();
}

auto print_device(const Device& dev) -> void {
    std::cout << "Interface: " << dev.get_name() << "\n";

    if (dev.has_public_key()) {
        std::cout << "  Public key: ";
        print_key(dev.public_key);
        std::cout << "\n";
    }

    if (dev.has_listen_port()) {
        std::cout << "  Listen port: " << dev.listen_port << "\n";
    }

    if (dev.has_fwmark()) {
        std::cout << "  Fwmark: 0x" << std::hex << dev.fwmark << std::dec << "\n";
    }

    std::cout << "\n  Peers:\n";
    for (const auto& peer : dev.peers) {
        std::cout << "    Peer: ";
        print_key(peer.public_key);
        std::cout << "\n";

        if (peer.endpoint.is_ipv4()) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &peer.endpoint.addr4.sin_addr, ip_str, sizeof(ip_str));
            std::cout << "      Endpoint: " << ip_str << ":"
                      << ntohs(peer.endpoint.addr4.sin_port) << "\n";
        } else if (peer.endpoint.is_ipv6()) {
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &peer.endpoint.addr6.sin6_addr, ip_str, sizeof(ip_str));
            std::cout << "      Endpoint: [" << ip_str << "]:"
                      << ntohs(peer.endpoint.addr6.sin6_port) << "\n";
        }

        if (has_flag(peer.flags, PeerFlags::HasPersistentKeepaliveInterval) &&
            peer.persistent_keepalive_interval > 0) {
            std::cout << "      Persistent keepalive: "
                      << peer.persistent_keepalive_interval << "s\n";
        }

        std::cout << "      Transfer: rx=" << peer.rx_bytes
                  << " tx=" << peer.tx_bytes << "\n";

        if (!peer.allowed_ips.empty()) {
            std::cout << "      Allowed IPs:\n";
            for (const auto& ip : peer.allowed_ips) {
                char ip_str[INET6_ADDRSTRLEN];
                if (ip.is_ipv4()) {
                    inet_ntop(AF_INET, &ip.ip4, ip_str, sizeof(ip_str));
                } else {
                    inet_ntop(AF_INET6, &ip.ip6, ip_str, sizeof(ip_str));
                }
                std::cout << "        " << ip_str << "/" << static_cast<int>(ip.cidr) << "\n";
            }
        }
    }
}

auto example_list_devices() -> void {
    std::cout << "=== Listing WireGuard devices ===\n";

    auto result = api::list_device_names();
    if (result.is_err()) {
        std::cerr << "Error listing devices: " << result.error().message << "\n";
        return;
    }

    const auto& devices = result.value();
    if (devices.empty()) {
        std::cout << "No WireGuard devices found.\n";
        return;
    }

    for (const auto& name : devices) {
        std::cout << "  - " << name.c_str() << "\n";
    }
}

auto example_get_device(const char* name) -> void {
    std::cout << "\n=== Getting device: " << name << " ===\n";

    auto result = api::get_device(name);
    if (result.is_err()) {
        std::cerr << "Error getting device: " << result.error().message << "\n";
        return;
    }

    print_device(result.value());
}

auto example_generate_keys() -> void {
    std::cout << "\n=== Generating keys ===\n";

    // Generate a keypair
    auto [private_key, public_key] = key::generate_keypair();

    KeyB64 private_b64, public_b64;
    key::to_base64(private_b64, private_key);
    key::to_base64(public_b64, public_key);

    std::cout << "Private key: " << private_b64.c_str() << "\n";
    std::cout << "Public key:  " << public_b64.c_str() << "\n";

    // Test base64 round-trip
    Key decoded_private;
    auto decode_result = key::from_base64(decoded_private, private_b64);
    if (decode_result.is_ok()) {
        std::cout << "Base64 round-trip: " << (private_key == decoded_private ? "OK" : "FAIL") << "\n";
    }

    // Generate preshared key
    Key psk;
    key::generate_preshared(psk);
    KeyB64 psk_b64;
    key::to_base64(psk_b64, psk);
    std::cout << "Preshared key: " << psk_b64.c_str() << "\n";
}

auto example_create_config() -> void {
    std::cout << "\n=== Creating device configuration ===\n";

    // Create a new device configuration
    Device device("wg-test");

    // Generate keys for the device
    auto [priv, pub] = key::generate_keypair();
    device.private_key = priv;
    device.public_key = pub;
    device.flags |= DeviceFlags::HasPrivateKey;
    device.flags |= DeviceFlags::HasPublicKey;

    // Set listen port
    device.listen_port = 51820;
    device.flags |= DeviceFlags::HasListenPort;

    // Add a peer
    Peer peer;
    auto [peer_priv, peer_pub] = key::generate_keypair();
    peer.public_key = peer_pub;
    peer.flags |= PeerFlags::HasPublicKey;

    // Set peer endpoint
    peer.endpoint.addr4.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.1.1", &peer.endpoint.addr4.sin_addr);
    peer.endpoint.addr4.sin_port = htons(51820);

    // Add allowed IP (10.0.0.0/24)
    AllowedIp allowed;
    allowed.family = AF_INET;
    inet_pton(AF_INET, "10.0.0.0", &allowed.ip4);
    allowed.cidr = 24;
    peer.allowed_ips.push_back(allowed);

    // Add peer to device
    device.peers.push_back(std::move(peer));

    // Print the config
    print_device(device);

    // Note: To actually apply this config, you would call:
    // auto result = api::add_device("wg-test");
    // if (result.is_ok()) {
    //     auto set_result = api::set_device(device);
    //     ...
    // }
}

auto main(int argc, char* argv[]) -> int {
    // Always show key generation example (doesn't require root)
    example_generate_keys();

    // Show configuration creation example
    example_create_config();

    // List devices (requires root, will fail gracefully)
    example_list_devices();

    // If device name provided, get its details
    if (argc > 1) {
        example_get_device(argv[1]);
    }

    return 0;
}
