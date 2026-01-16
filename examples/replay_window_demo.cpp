/* SPDX-License-Identifier: MIT */
/*
 * Replay Window Demo
 * Demonstrates replay attack protection using sliding window
 */

#include <botlink/botlink.hpp>
#include <iostream>
#include <iomanip>

using namespace botlink;
using namespace dp;

int main() {
    std::cout << "=== Replay Window Demo ===\n\n";

    std::cout << "The replay window protects against replay attacks by tracking\n";
    std::cout << "which nonces/counters have been seen. It uses a sliding window\n";
    std::cout << "of size 64 to allow for out-of-order packet delivery.\n\n";

    // ==========================================================================
    // Step 1: Create a replay window
    // ==========================================================================
    std::cout << "1. Creating replay window...\n";

    crypto::ReplayWindow window;

    std::cout << "   Window size: 64 nonces\n";
    std::cout << "   Initial last_seen: " << window.last_seen << "\n\n";

    // ==========================================================================
    // Step 2: Accept first packet
    // ==========================================================================
    std::cout << "2. Accepting first packet (nonce=1)...\n";

    bool accepted = window.check_and_update(1);
    std::cout << "   Nonce 1 accepted: " << (accepted ? "YES" : "NO") << "\n";
    std::cout << "   last_seen is now: " << window.last_seen << "\n\n";

    // ==========================================================================
    // Step 3: Try replaying same packet
    // ==========================================================================
    std::cout << "3. Attempting to replay same packet (nonce=1)...\n";

    accepted = window.check_and_update(1);
    std::cout << "   Nonce 1 accepted: " << (accepted ? "YES" : "NO (replay detected!)" ) << "\n\n";

    // ==========================================================================
    // Step 4: Accept higher nonces
    // ==========================================================================
    std::cout << "4. Accepting packets with increasing nonces...\n";

    for (u64 nonce = 2; nonce <= 10; ++nonce) {
        accepted = window.check_and_update(nonce);
        std::cout << "   Nonce " << nonce << " accepted: " << (accepted ? "YES" : "NO") << "\n";
    }
    std::cout << "   last_seen is now: " << window.last_seen << "\n\n";

    // ==========================================================================
    // Step 5: Out-of-order delivery (within window)
    // ==========================================================================
    std::cout << "5. Simulating out-of-order packet delivery...\n";

    // Jump ahead
    accepted = window.check_and_update(50);
    std::cout << "   Nonce 50 accepted: " << (accepted ? "YES" : "NO") << "\n";
    std::cout << "   last_seen is now: " << window.last_seen << "\n";

    // Receive earlier packets that were delayed
    accepted = window.check_and_update(45);
    std::cout << "   Nonce 45 (delayed) accepted: " << (accepted ? "YES" : "NO") << "\n";

    accepted = window.check_and_update(48);
    std::cout << "   Nonce 48 (delayed) accepted: " << (accepted ? "YES" : "NO") << "\n";

    // Try replay of earlier packet
    accepted = window.check_and_update(45);
    std::cout << "   Nonce 45 (replay) accepted: " << (accepted ? "YES" : "NO (replay detected!)") << "\n\n";

    // ==========================================================================
    // Step 6: Packet too old (outside window)
    // ==========================================================================
    std::cout << "6. Testing packet too old (outside window)...\n";

    // Jump far ahead to make old nonces expire from window
    accepted = window.check_and_update(200);
    std::cout << "   Nonce 200 accepted: " << (accepted ? "YES" : "NO") << "\n";
    std::cout << "   last_seen is now: " << window.last_seen << "\n";

    // Try an old nonce that's now outside the window (200 - 64 = 136, so 100 is too old)
    accepted = window.check_and_update(100);
    std::cout << "   Nonce 100 (too old) accepted: " << (accepted ? "YES" : "NO (too old!)") << "\n\n";

    // ==========================================================================
    // Step 7: Window bitmap demonstration
    // ==========================================================================
    std::cout << "7. Window bitmap state...\n";

    crypto::ReplayWindow demo_window;

    // Accept some nonces
    (void)demo_window.check_and_update(10);
    (void)demo_window.check_and_update(12);
    (void)demo_window.check_and_update(15);
    (void)demo_window.check_and_update(11);

    std::cout << "   Accepted nonces: 10, 11, 12, 15\n";
    std::cout << "   last_seen: " << demo_window.last_seen << "\n";
    std::cout << "   window_bitmap (hex): 0x" << std::hex << demo_window.window_bitmap << std::dec << "\n";

    // Check which nonces would be accepted
    std::cout << "   Would accept nonce 13: " << (demo_window.check_and_update(13) ? "YES" : "NO") << "\n";
    std::cout << "   Would accept nonce 14: " << (demo_window.check_and_update(14) ? "YES" : "NO") << "\n";
    std::cout << "   Would accept nonce 10 again: " << (demo_window.check_and_update(10) ? "YES" : "NO") << "\n\n";

    // ==========================================================================
    // Step 8: Create fresh window
    // ==========================================================================
    std::cout << "8. Creating fresh window...\n";

    crypto::ReplayWindow fresh_window;
    std::cout << "   Fresh window created\n";
    std::cout << "   last_seen: " << fresh_window.last_seen << "\n";
    std::cout << "   window_bitmap: " << fresh_window.window_bitmap << "\n\n";

    // ==========================================================================
    // Step 9: Practical usage with encrypted packets
    // ==========================================================================
    std::cout << "9. Practical usage with encrypted packets...\n";

    // Generate a session key
    crypto::SessionKey key;
    auto random = keylock::utils::Common::generate_random_bytes(32);
    for (usize i = 0; i < 32; ++i) {
        key.data[i] = random[i];
    }
    key.key_id = 1;

    // Create a new replay window for this session
    crypto::ReplayWindow session_window;

    // Simulate receiving packets (start from 1 to avoid edge case with last_seen=0)
    std::cout << "   Simulating packet reception:\n";

    for (u64 counter = 1; counter <= 5; ++counter) {
        // Create and encrypt packet
        Vector<u8> plaintext;
        plaintext.push_back(static_cast<u8>('A' + counter));

        auto pkt_result = crypto::encrypt_packet(key, counter, plaintext);
        if (pkt_result.is_ok()) {
            auto& pkt = pkt_result.value();

            // Check replay protection before decrypting
            if (session_window.check_and_update(pkt.nonce_counter)) {
                auto decrypted = crypto::decrypt_packet(key, pkt);
                if (decrypted.is_ok()) {
                    std::cout << "   Packet " << counter << ": accepted, decrypted '"
                              << static_cast<char>(decrypted.value()[0]) << "'\n";
                }
            } else {
                std::cout << "   Packet " << counter << ": rejected (replay)\n";
            }
        }
    }

    // Try replaying packet 2
    Vector<u8> replay_plaintext;
    replay_plaintext.push_back('X');
    auto replay_pkt = crypto::encrypt_packet(key, 2, replay_plaintext);
    if (replay_pkt.is_ok()) {
        auto& pkt = replay_pkt.value();
        if (session_window.check_and_update(pkt.nonce_counter)) {
            std::cout << "   Replay packet 2: accepted (BAD!)\n";
        } else {
            std::cout << "   Replay packet 2: rejected (replay protection works!)\n";
        }
    }
    std::cout << "\n";

    std::cout << "=== Demo Complete ===\n";

    return 0;
}
