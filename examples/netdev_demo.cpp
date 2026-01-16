/* SPDX-License-Identifier: MIT */
/*
 * Netdev Demo
 * Demonstrates network device abstraction for TUN/TAP operations
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>

namespace bl = botlink;
using namespace bl::netdev;

int main() {
    std::cout << "=== Netdev Demo ===\n\n";

    std::cout << "The netdev module provides an abstract interface for\n";
    std::cout << "TUN/TAP operations. The NullBackend allows testing\n";
    std::cout << "without root privileges.\n\n";

    // ==========================================================================
    // Step 1: Create a NullBackend
    // ==========================================================================
    std::cout << "1. Creating NullBackend...\n";

    NullBackend backend;
    std::cout << "   Backend created (no privileges required)\n\n";

    // ==========================================================================
    // Step 2: Create an interface
    // ==========================================================================
    std::cout << "2. Creating network interface...\n";

    bl::InterfaceName iface_name("botlink0");
    auto create_result = backend.create_interface(iface_name);
    std::cout << "   create_interface(\"botlink0\"): "
              << (create_result.is_ok() ? "OK" : "ERROR") << "\n";
    std::cout << "   Interface name: " << backend.info().name.c_str() << "\n";
    std::cout << "   Initial state: "
              << (backend.info().state == InterfaceState::Down ? "Down" : "Up") << "\n";
    std::cout << "   File descriptor: " << backend.info().fd << "\n\n";

    // ==========================================================================
    // Step 3: Configure the interface
    // ==========================================================================
    std::cout << "3. Configuring interface...\n";

    // Set MTU
    auto mtu_result = backend.set_mtu(iface_name, 1420);
    std::cout << "   set_mtu(1420): " << (mtu_result.is_ok() ? "OK" : "ERROR") << "\n";
    std::cout << "   Current MTU: " << backend.info().mtu << "\n";

    // Assign IP address
    bl::OverlayAddr addr;
    addr.addr = "10.42.0.1";
    addr.prefix_len = 24;

    auto addr_result = backend.assign_addr(iface_name, addr);
    std::cout << "   assign_addr(10.42.0.1/24): " << (addr_result.is_ok() ? "OK" : "ERROR") << "\n";
    std::cout << "   Current addr: " << backend.info().addr.addr.c_str()
              << "/" << static_cast<int>(backend.info().addr.prefix_len) << "\n\n";

    // ==========================================================================
    // Step 4: Bring interface up
    // ==========================================================================
    std::cout << "4. Bringing interface up...\n";

    auto up_result = backend.up(iface_name);
    std::cout << "   up(): " << (up_result.is_ok() ? "OK" : "ERROR") << "\n";
    std::cout << "   Interface is_up: " << (backend.info().is_up() ? "YES" : "NO") << "\n";
    std::cout << "   Interface is_valid: " << (backend.info().is_valid() ? "YES" : "NO") << "\n";
    std::cout << "   can_write: " << (backend.can_write() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 5: Create IP packets
    // ==========================================================================
    std::cout << "5. Creating IP packets...\n";

    // Create an IPv4 packet
    dp::Vector<dp::u8> ipv4_data;
    // IPv4 header: version (4) + IHL (5) = 0x45
    ipv4_data.push_back(0x45);  // Version + IHL
    ipv4_data.push_back(0x00);  // DSCP + ECN
    ipv4_data.push_back(0x00);  // Total length (high)
    ipv4_data.push_back(0x14);  // Total length (low) = 20 bytes
    // Fill minimum header
    for (int i = 4; i < 20; ++i) {
        ipv4_data.push_back(0x00);
    }

    IpPacket ipv4_pkt(ipv4_data);
    std::cout << "   Created IPv4 packet:\n";
    std::cout << "     Size: " << ipv4_pkt.size() << " bytes\n";
    std::cout << "     IP version: " << static_cast<int>(ipv4_pkt.ip_version()) << "\n";
    std::cout << "     is_ipv4: " << (ipv4_pkt.is_ipv4() ? "YES" : "NO") << "\n";
    std::cout << "     is_ipv6: " << (ipv4_pkt.is_ipv6() ? "YES" : "NO") << "\n";

    // Create an IPv6 packet
    dp::Vector<dp::u8> ipv6_data;
    // IPv6 header: version (6) = 0x60
    ipv6_data.push_back(0x60);  // Version + Traffic class (high)
    ipv6_data.push_back(0x00);  // Traffic class (low) + Flow label
    ipv6_data.push_back(0x00);  // Flow label
    ipv6_data.push_back(0x00);  // Flow label
    // Fill minimum header (40 bytes)
    for (int i = 4; i < 40; ++i) {
        ipv6_data.push_back(0x00);
    }

    IpPacket ipv6_pkt(ipv6_data);
    std::cout << "   Created IPv6 packet:\n";
    std::cout << "     Size: " << ipv6_pkt.size() << " bytes\n";
    std::cout << "     IP version: " << static_cast<int>(ipv6_pkt.ip_version()) << "\n";
    std::cout << "     is_ipv4: " << (ipv6_pkt.is_ipv4() ? "YES" : "NO") << "\n";
    std::cout << "     is_ipv6: " << (ipv6_pkt.is_ipv6() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 6: Write packets
    // ==========================================================================
    std::cout << "6. Writing packets to interface...\n";

    auto write1 = backend.write_packet(ipv4_pkt);
    std::cout << "   write_packet(IPv4): " << (write1.is_ok() ? "OK" : "ERROR") << "\n";

    auto write2 = backend.write_packet(ipv6_pkt);
    std::cout << "   write_packet(IPv6): " << (write2.is_ok() ? "OK" : "ERROR") << "\n";

    std::cout << "   TX queue size: " << backend.get_tx_queue().size() << "\n\n";

    // ==========================================================================
    // Step 7: Inject and read packets
    // ==========================================================================
    std::cout << "7. Injecting and reading packets (NullBackend test feature)...\n";

    // Check can_read before injection
    std::cout << "   can_read (before): " << (backend.can_read() ? "YES" : "NO") << "\n";

    // Inject a packet
    backend.inject_packet(ipv4_pkt);
    std::cout << "   Injected IPv4 packet\n";
    std::cout << "   can_read (after): " << (backend.can_read() ? "YES" : "NO") << "\n";

    // Read the packet back
    auto read_result = backend.read_packet();
    if (read_result.is_ok()) {
        auto& pkt = read_result.value();
        std::cout << "   Read packet: " << pkt.size() << " bytes, IPv"
                  << static_cast<int>(pkt.ip_version()) << "\n";
    }

    // Try to read when empty
    auto empty_read = backend.read_packet();
    std::cout << "   Read empty queue: " << (empty_read.is_ok() ? "OK" : "timeout (expected)") << "\n\n";

    // ==========================================================================
    // Step 8: Examine transmitted packets
    // ==========================================================================
    std::cout << "8. Examining TX queue...\n";

    auto& tx_queue = backend.get_tx_queue();
    std::cout << "   Packets in TX queue: " << tx_queue.size() << "\n";
    for (dp::usize i = 0; i < tx_queue.size(); ++i) {
        std::cout << "   [" << i << "] " << tx_queue[i].size() << " bytes, IPv"
                  << static_cast<int>(tx_queue[i].ip_version()) << "\n";
    }
    std::cout << "\n";

    // ==========================================================================
    // Step 9: Bring interface down
    // ==========================================================================
    std::cout << "9. Bringing interface down...\n";

    auto down_result = backend.down(iface_name);
    std::cout << "   down(): " << (down_result.is_ok() ? "OK" : "ERROR") << "\n";
    std::cout << "   Interface is_up: " << (backend.info().is_up() ? "YES" : "NO") << "\n";
    std::cout << "   can_write: " << (backend.can_write() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 10: Destroy interface
    // ==========================================================================
    std::cout << "10. Destroying interface...\n";

    auto destroy_result = backend.destroy(iface_name);
    std::cout << "   destroy(): " << (destroy_result.is_ok() ? "OK" : "ERROR") << "\n";
    std::cout << "   is_valid: " << (backend.info().is_valid() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 11: InterfaceInfo details
    // ==========================================================================
    std::cout << "11. InterfaceInfo structure...\n";

    InterfaceInfo info;
    info.name = bl::InterfaceName("test0");
    info.addr.addr = "192.168.100.1";
    info.addr.prefix_len = 32;
    info.mtu = 1500;
    info.state = InterfaceState::Up;
    info.fd = 42;

    std::cout << "   Name: " << info.name.c_str() << "\n";
    std::cout << "   Address: " << info.addr.addr.c_str() << "/" << static_cast<int>(info.addr.prefix_len) << "\n";
    std::cout << "   MTU: " << info.mtu << "\n";
    std::cout << "   State: ";
    switch (info.state) {
        case InterfaceState::Down: std::cout << "Down\n"; break;
        case InterfaceState::Up: std::cout << "Up\n"; break;
        case InterfaceState::Error: std::cout << "Error\n"; break;
    }
    std::cout << "   FD: " << info.fd << "\n";
    std::cout << "   is_up: " << (info.is_up() ? "YES" : "NO") << "\n";
    std::cout << "   is_valid: " << (info.is_valid() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 12: Empty packet handling
    // ==========================================================================
    std::cout << "12. Empty packet handling...\n";

    IpPacket empty_pkt;
    std::cout << "   Empty packet size: " << empty_pkt.size() << "\n";
    std::cout << "   Empty packet empty(): " << (empty_pkt.empty() ? "YES" : "NO") << "\n";
    std::cout << "   Empty packet ip_version: " << static_cast<int>(empty_pkt.ip_version()) << "\n";
    std::cout << "   Empty packet is_ipv4: " << (empty_pkt.is_ipv4() ? "YES" : "NO") << "\n";
    std::cout << "   Empty packet is_ipv6: " << (empty_pkt.is_ipv6() ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 13: Summary
    // ==========================================================================
    std::cout << "13. Summary...\n";
    std::cout << "   NetdevBackend - Abstract interface for TUN/TAP\n";
    std::cout << "   NullBackend   - Test backend (no privileges)\n";
    std::cout << "   InterfaceInfo - Interface metadata\n";
    std::cout << "   IpPacket      - Raw IP packet wrapper\n";
    std::cout << "   InterfaceState - Down, Up, Error\n\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
