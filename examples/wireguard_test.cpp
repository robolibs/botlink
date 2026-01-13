/* WireGuard C++ library test program */

#include <wireguard/wireguard.hpp>
#include <arpa/inet.h>
#include <iostream>
#include <unistd.h>

using namespace wg;
using namespace dp;

void list_devices() {
    std::cout << "=== Listing WireGuard devices ===\n";

    auto result = api::list_device_names();
    if (result.is_err()) {
        std::cerr << "Unable to get device names: " << result.error().message << "\n";
        return;
    }

    const auto& device_names = result.value();
    if (device_names.empty()) {
        std::cout << "  No WireGuard devices found\n";
        return;
    }

    for (const auto& name : device_names) {
        std::cout << "\nDevice: " << name.c_str() << "\n";

        auto dev_result = api::get_device(name.c_str());
        if (dev_result.is_err()) {
            std::cout << "  Unable to get device info\n";
            continue;
        }

        const auto& device = dev_result.value();
        KeyB64 key_str;

        if (device.has_public_key()) {
            key::to_base64(key_str, device.public_key);
            std::cout << "  Public key: " << key_str.c_str() << "\n";
        } else {
            std::cout << "  No public key\n";
        }

        if (device.has_private_key()) {
            key::to_base64(key_str, device.private_key);
            std::cout << "  Private key: " << key_str.c_str() << "\n";
        }

        if (device.listen_port > 0) {
            std::cout << "  Listen port: " << device.listen_port << "\n";
        }

        if (device.fwmark > 0) {
            std::cout << "  Fwmark: " << device.fwmark << "\n";
        }

        int peer_count = 0;
        for (const auto& peer : device.peers) {
            peer_count++;
            key::to_base64(key_str, peer.public_key);
            std::cout << "  Peer " << peer_count << ": " << key_str.c_str() << "\n";

            if (peer.endpoint.family() != 0) {
                char addr_str[128];
                if (peer.endpoint.is_ipv4()) {
                    inet_ntop(AF_INET, &peer.endpoint.addr4.sin_addr, addr_str, sizeof(addr_str));
                    std::cout << "    Endpoint: " << addr_str << ":"
                              << ntohs(peer.endpoint.addr4.sin_port) << "\n";
                } else if (peer.endpoint.is_ipv6()) {
                    inet_ntop(AF_INET6, &peer.endpoint.addr6.sin6_addr, addr_str, sizeof(addr_str));
                    std::cout << "    Endpoint: [" << addr_str << "]:"
                              << ntohs(peer.endpoint.addr6.sin6_port) << "\n";
                }
            }

            if (peer.persistent_keepalive_interval > 0) {
                std::cout << "    Keepalive: " << peer.persistent_keepalive_interval << " seconds\n";
            }

            if (!peer.allowed_ips.empty()) {
                std::cout << "    Allowed IPs:\n";
                for (const auto& ip : peer.allowed_ips) {
                    char addr_str[INET6_ADDRSTRLEN];
                    if (ip.is_ipv4()) {
                        inet_ntop(AF_INET, &ip.ip4, addr_str, sizeof(addr_str));
                    } else {
                        inet_ntop(AF_INET6, &ip.ip6, addr_str, sizeof(addr_str));
                    }
                    std::cout << "      " << addr_str << "/" << static_cast<int>(ip.cidr) << "\n";
                }
            }

            std::cout << "    Transfer: rx=" << peer.rx_bytes << " tx=" << peer.tx_bytes << "\n";
        }

        if (peer_count == 0) {
            std::cout << "  No peers configured\n";
        }
    }
}

auto create_test_device() -> int {
    std::cout << "=== Creating test WireGuard device ===\n";

    const char* device_name = "wgtest0";

    // Generate keys
    std::cout << "Generating keys...\n";
    auto [device_priv, device_pub] = key::generate_keypair();
    auto [peer_priv, peer_pub] = key::generate_keypair();

    KeyB64 key_str;
    key::to_base64(key_str, peer_priv);
    std::cout << "  Generated temp private key: " << key_str.c_str() << "\n";
    key::to_base64(key_str, peer_pub);
    std::cout << "  Generated peer public key: " << key_str.c_str() << "\n";
    key::to_base64(key_str, device_priv);
    std::cout << "  Generated device private key: " << key_str.c_str() << "\n";

    // Create device
    std::cout << "\nAdding device '" << device_name << "' to system...\n";
    auto add_result = api::add_device(device_name);
    if (add_result.is_err()) {
        std::cerr << "Unable to add device: " << add_result.error().message << "\n";
        std::cout << "\nThis usually means:\n";
        std::cout << "  - WireGuard kernel module is not loaded\n";
        std::cout << "  - WireGuard tools are not installed\n";
        std::cout << "  - A device with this name already exists\n";
        std::cout << "\nYou can clean up with: sudo wireguard_test cleanup\n";
        return 1;
    }
    std::cout << "Device created successfully.\n";

    // Configure device
    Device device(device_name);
    device.private_key = device_priv;
    device.flags |= DeviceFlags::HasPrivateKey;
    device.listen_port = 1234;
    device.flags |= DeviceFlags::HasListenPort;

    // Add peer
    Peer peer;
    peer.public_key = peer_pub;
    peer.flags |= PeerFlags::HasPublicKey;
    peer.flags |= PeerFlags::ReplaceAllowedIps;
    device.peers.push_back(std::move(peer));

    std::cout << "\nSetting device configuration...\n";
    auto set_result = api::set_device(device);
    if (set_result.is_err()) {
        std::cerr << "Unable to set device: " << set_result.error().message << "\n";
        (void)api::del_device(device_name);
        return 1;
    }
    std::cout << "Device configured successfully.\n";

    std::cout << "\nDevice '" << device_name << "' has been created and configured.\n";
    std::cout << "It can be viewed with: ip link show type wireguard\n";
    std::cout << "You can configure it further using the wg tool or wg-quick.\n";

    return 0;
}

auto cleanup_test_device() -> int {
    std::cout << "=== Cleaning up test WireGuard device ===\n";

    const char* device_name = "wgtest0";

    std::cout << "Deleting device '" << device_name << "'...\n";
    auto result = api::del_device(device_name);
    if (result.is_err()) {
        std::cerr << "Unable to delete device: " << result.error().message << "\n";
        std::cout << "This may mean:\n";
        std::cout << "  - The device does not exist\n";
        std::cout << "  - You don't have permission\n";
        return 1;
    }
    std::cout << "Device deleted successfully.\n";

    return 0;
}

auto main(int argc, char* argv[]) -> int {
    const char* progname = argv[0];

    std::cout << "WireGuard C++ library test program\n";
    std::cout << "===================================\n\n";

    // Check if running as root for privileged operations
    if (geteuid() != 0 && (argc == 1 || (argc > 1 && std::string(argv[1]) != "list"))) {
        std::cout << "ERROR: This operation requires root privileges.\n";
        std::cout << "Please run with sudo.\n\n";
        std::cout << "Usage: sudo " << progname << " <command>\n";
        std::cout << "\nAvailable commands:\n";
        std::cout << "  create   - Create a test WireGuard device\n";
        std::cout << "  list     - List existing WireGuard devices\n";
        std::cout << "  cleanup  - Remove the test WireGuard device\n";
        return 1;
    }

    // Show usage if no command provided
    if (argc < 2) {
        std::cout << "Usage: sudo " << progname << " <command>\n";
        std::cout << "\nAvailable commands:\n";
        std::cout << "  create   - Create a test WireGuard device (wgtest0)\n";
        std::cout << "              Generates keys and configures the interface\n";
        std::cout << "              Leaves it running while you develop/test\n\n";
        std::cout << "  list     - List existing WireGuard devices (read-only)\n";
        std::cout << "              Shows detailed device and peer information\n";
        std::cout << "              Can run without sudo\n\n";
        std::cout << "  cleanup  - Remove the test WireGuard device\n";
        std::cout << "              Use when you're done testing\n\n";
        std::cout << "Examples:\n";
        std::cout << "  sudo " << progname << " create   # Create test device\n";
        std::cout << "  " << progname << " list          # List devices\n";
        std::cout << "  sudo " << progname << " cleanup  # Remove test device\n";
        return 1;
    }

    std::string cmd = argv[1];

    // Handle 'list' command (no root required)
    if (cmd == "list") {
        list_devices();
        return 0;
    }

    // Check root for other commands
    if (geteuid() != 0) {
        std::cout << "ERROR: '" << cmd << "' command requires root privileges.\n";
        std::cout << "Please run with: sudo " << progname << " " << cmd << "\n";
        return 1;
    }

    // Handle 'create' command
    if (cmd == "create") {
        std::cout << "Listing existing devices before creation:\n";
        list_devices();
        std::cout << "\n";
        return create_test_device();
    }

    // Handle 'cleanup' command
    if (cmd == "cleanup") {
        return cleanup_test_device();
    }

    // Unknown command
    std::cout << "Unknown command: " << cmd << "\n";
    std::cout << "\nAvailable commands: create, list, cleanup\n";
    return 1;
}
