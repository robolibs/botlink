#include "wireguard/wireguard.hpp"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void list_devices(void) {
    char *device_names, *device_name;
    size_t len;

    printf("=== Listing WireGuard devices ===\n");
    device_names = wg_list_device_names();
    if (!device_names) {
        perror("Unable to get device names");
        return;
    }

    int found_devices = 0;
    wg_for_each_device_name(device_names, device_name, len) {
        wg_device *device;
        wg_peer *peer;
        wg_key_b64_string key;

        found_devices = 1;
        printf("\nDevice: %s\n", device_name);

        if (wg_get_device(&device, device_name) < 0) {
            printf("  Unable to get device info\n");
            continue;
        }

        if (device->flags & WGDEVICE_HAS_PUBLIC_KEY) {
            wg_key_to_base64(key, device->public_key);
            printf("  Public key: %s\n", key);
        } else {
            printf("  No public key\n");
        }

        if (device->flags & WGDEVICE_HAS_PRIVATE_KEY) {
            wg_key_to_base64(key, device->private_key);
            printf("  Private key: %s\n", key);
        }

        if (device->listen_port > 0) {
            printf("  Listen port: %d\n", device->listen_port);
        }

        if (device->fwmark > 0) {
            printf("  Fwmark: %u\n", device->fwmark);
        }

        int peer_count = 0;
        wg_for_each_peer(device, peer) {
            peer_count++;
            wg_key_to_base64(key, peer->public_key);
            printf("  Peer %d: %s\n", peer_count, key);
            if (peer->endpoint.addr.sa_family != 0) {
                char addr_str[128];
                if (peer->endpoint.addr.sa_family == AF_INET) {
                    inet_ntop(AF_INET, &peer->endpoint.addr4.sin_addr, addr_str, sizeof(addr_str));
                    printf("    Endpoint: %s:%d\n", addr_str, ntohs(peer->endpoint.addr4.sin_port));
                } else if (peer->endpoint.addr.sa_family == AF_INET6) {
                    inet_ntop(AF_INET6, &peer->endpoint.addr6.sin6_addr, addr_str, sizeof(addr_str));
                    printf("    Endpoint: [%s]:%d\n", addr_str, ntohs(peer->endpoint.addr6.sin6_port));
                }
            }
            if (peer->persistent_keepalive_interval > 0) {
                printf("    Keepalive: %d seconds\n", peer->persistent_keepalive_interval);
            }
        }

        if (peer_count == 0) {
            printf("  No peers configured\n");
        }

        wg_free_device(device);
    }
    free(device_names);

    if (!found_devices) {
        printf("  No WireGuard devices found\n");
    }
}

int create_test_device(void) {
    printf("=== Creating test WireGuard device ===\n");

    wg_peer new_peer = {.flags = (enum wg_peer_flags)(WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS)};
    wg_device new_device = {.name = "wgtest0",
                            .flags = (enum wg_device_flags)(WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT),
                            .listen_port = 1234,
                            .first_peer = &new_peer,
                            .last_peer = &new_peer};
    wg_key temp_private_key;
    wg_key_b64_string key;

    printf("Generating keys...\n");
    wg_generate_private_key(temp_private_key);
    wg_generate_public_key(new_peer.public_key, temp_private_key);
    wg_generate_private_key(new_device.private_key);

    wg_key_to_base64(key, temp_private_key);
    printf("  Generated temp private key: %s\n", key);
    wg_key_to_base64(key, new_peer.public_key);
    printf("  Generated peer public key: %s\n", key);
    wg_key_to_base64(key, new_device.private_key);
    printf("  Generated device private key: %s\n", key);

    printf("\nAdding device '%s' to system...\n", new_device.name);
    if (wg_add_device(new_device.name) < 0) {
        perror("Unable to add device");
        printf("\nThis usually means:\n");
        printf("  - WireGuard kernel module is not loaded\n");
        printf("  - WireGuard tools are not installed\n");
        printf("  - A device with this name already exists\n");
        printf("\nYou can clean up with: sudo wireguard_test cleanup\n");
        return 1;
    }
    printf("Device created successfully.\n");

    printf("\nSetting device configuration...\n");
    if (wg_set_device(&new_device) < 0) {
        perror("Unable to set device");
        wg_del_device(new_device.name);
        return 1;
    }
    printf("Device configured successfully.\n");

    printf("\nDevice '%s' has been created and configured.\n", new_device.name);
    printf("It can be viewed with: ip link show type wireguard\n");
    printf("You can configure it further using the wg tool or wg-quick.\n");

    return 0;
}

int cleanup_test_device(void) {
    printf("=== Cleaning up test WireGuard device ===\n");

    const char *device_name = "wgtest0";

    printf("Deleting device '%s'...\n", device_name);
    if (wg_del_device(device_name) < 0) {
        perror("Unable to delete device");
        printf("This may mean:\n");
        printf("  - The device does not exist\n");
        printf("  - You don't have permission\n");
        return 1;
    }
    printf("Device deleted successfully.\n");

    return 0;
}

int main(int argc, char *argv[]) {
    const char *progname = argv[0];

    printf("WireGuard library test program\n");
    printf("================================\n\n");

    // Check if running as root for privileged operations
    if (geteuid() != 0 && (argc == 1 || (argc > 1 && strcmp(argv[1], "list") != 0))) {
        printf("ERROR: This operation requires root privileges.\n");
        printf("Please run with sudo.\n\n");
        printf("Usage: sudo %s <command>\n", progname);
        printf("\nAvailable commands:\n");
        printf("  create   - Create a test WireGuard device\n");
        printf("  list     - List existing WireGuard devices\n");
        printf("  cleanup  - Remove the test WireGuard device\n");
        return 1;
    }

    // Show usage if no command provided
    if (argc < 2) {
        printf("Usage: sudo %s <command>\n", progname);
        printf("\nAvailable commands:\n");
        printf("  create   - Create a test WireGuard device (wgtest0)\n");
        printf("              Generates keys and configures the interface\n");
        printf("              Leaves it running while you develop/test\n\n");
        printf("  list     - List existing WireGuard devices (read-only)\n");
        printf("              Shows detailed device and peer information\n");
        printf("              Can run without sudo\n\n");
        printf("  cleanup  - Remove the test WireGuard device\n");
        printf("              Use when you're done testing\n\n");
        printf("Examples:\n");
        printf("  sudo %s create   # Create test device\n", progname);
        printf("  %s list          # List devices\n", progname);
        printf("  sudo %s cleanup  # Remove test device\n", progname);
        return 1;
    }

    // Handle 'list' command (no root required)
    if (strcmp(argv[1], "list") == 0) {
        list_devices();
        return 0;
    }

    // Check root for other commands
    if (geteuid() != 0) {
        printf("ERROR: '%s' command requires root privileges.\n", argv[1]);
        printf("Please run with: sudo %s %s\n", progname, argv[1]);
        return 1;
    }

    // Handle 'create' command
    if (strcmp(argv[1], "create") == 0) {
        // First, list existing devices
        printf("Listing existing devices before creation:\n");
        list_devices();
        printf("\n");

        return create_test_device();
    }

    // Handle 'cleanup' command
    if (strcmp(argv[1], "cleanup") == 0) {
        return cleanup_test_device();
    }

    // Unknown command
    printf("Unknown command: %s\n", argv[1]);
    printf("\nAvailable commands: create, list, cleanup\n");
    return 1;
}
