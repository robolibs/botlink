/* SPDX-License-Identifier: MIT */
/*
 * Botlink Trust Event
 * POD structures for trust chain events
 */

#pragma once

#include <botlink/core/result.hpp>
#include <botlink/core/types.hpp>
#include <datapod/datapod.hpp>

namespace botlink {

    using namespace dp;

    // =============================================================================
    // Trust Event - Records membership changes on the trust chain
    // =============================================================================

    struct TrustEvent {
        TrustEventKind kind = TrustEventKind::JoinProposed;
        NodeId subject_id;        // Node being acted upon
        NodeId actor_id;          // Node performing the action
        PublicKey subject_pubkey; // Subject's Ed25519 public key
        PublicKey subject_x25519; // Subject's X25519 public key
        u64 timestamp_ms = 0;
        Vote vote = Vote::Abstain; // For VoteCast events
        String metadata;           // Additional JSON metadata

        TrustEvent() = default;

        // Required by blockit::Transaction
        [[nodiscard]] auto to_string() const -> std::string {
            return "TrustEvent{kind=" + std::to_string(static_cast<u8>(kind)) + ",ts=" + std::to_string(timestamp_ms) +
                   "}";
        }

        auto members() noexcept {
            return std::tie(kind, subject_id, actor_id, subject_pubkey, subject_x25519, timestamp_ms, vote, metadata);
        }
        auto members() const noexcept {
            return std::tie(kind, subject_id, actor_id, subject_pubkey, subject_x25519, timestamp_ms, vote, metadata);
        }
    };

    // =============================================================================
    // Join Proposal Event
    // =============================================================================

    struct JoinProposal {
        NodeId candidate_id;
        PublicKey candidate_ed25519;
        PublicKey candidate_x25519;
        NodeId sponsor_id;
        u64 timestamp_ms = 0;
        String justification;

        JoinProposal() = default;

        [[nodiscard]] auto to_event() const -> TrustEvent {
            TrustEvent evt;
            evt.kind = TrustEventKind::JoinProposed;
            evt.subject_id = candidate_id;
            evt.actor_id = sponsor_id;
            evt.subject_pubkey = candidate_ed25519;
            evt.subject_x25519 = candidate_x25519;
            evt.timestamp_ms = timestamp_ms;
            evt.metadata = justification;
            return evt;
        }

        auto members() noexcept {
            return std::tie(candidate_id, candidate_ed25519, candidate_x25519, sponsor_id, timestamp_ms, justification);
        }
        auto members() const noexcept {
            return std::tie(candidate_id, candidate_ed25519, candidate_x25519, sponsor_id, timestamp_ms, justification);
        }
    };

    // =============================================================================
    // Vote Cast Event
    // =============================================================================

    struct VoteCastEvent {
        NodeId candidate_id;
        NodeId voter_id;
        Vote vote = Vote::Abstain;
        u64 timestamp_ms = 0;
        String reason;

        VoteCastEvent() = default;

        [[nodiscard]] auto to_event() const -> TrustEvent {
            TrustEvent evt;
            evt.kind = TrustEventKind::VoteCast;
            evt.subject_id = candidate_id;
            evt.actor_id = voter_id;
            evt.vote = vote;
            evt.timestamp_ms = timestamp_ms;
            evt.metadata = reason;
            return evt;
        }

        auto members() noexcept { return std::tie(candidate_id, voter_id, vote, timestamp_ms, reason); }
        auto members() const noexcept { return std::tie(candidate_id, voter_id, vote, timestamp_ms, reason); }
    };

    // =============================================================================
    // Membership Decision Event
    // =============================================================================

    struct MembershipDecision {
        NodeId candidate_id;
        PublicKey candidate_ed25519;
        PublicKey candidate_x25519;
        boolean approved = false;
        u32 yes_votes = 0;
        u32 no_votes = 0;
        u32 abstain_votes = 0;
        u64 timestamp_ms = 0;

        MembershipDecision() = default;

        [[nodiscard]] auto to_event() const -> TrustEvent {
            TrustEvent evt;
            evt.kind = approved ? TrustEventKind::JoinApproved : TrustEventKind::JoinRejected;
            evt.subject_id = candidate_id;
            evt.subject_pubkey = candidate_ed25519;
            evt.subject_x25519 = candidate_x25519;
            evt.timestamp_ms = timestamp_ms;
            // Store vote counts in metadata
            String meta;
            meta = "yes:" + String(std::to_string(yes_votes).c_str()) +
                   ",no:" + String(std::to_string(no_votes).c_str()) +
                   ",abstain:" + String(std::to_string(abstain_votes).c_str());
            evt.metadata = meta;
            return evt;
        }

        auto members() noexcept {
            return std::tie(candidate_id, candidate_ed25519, candidate_x25519, approved, yes_votes, no_votes,
                            abstain_votes, timestamp_ms);
        }
        auto members() const noexcept {
            return std::tie(candidate_id, candidate_ed25519, candidate_x25519, approved, yes_votes, no_votes,
                            abstain_votes, timestamp_ms);
        }
    };

    // =============================================================================
    // Revocation Event
    // =============================================================================

    struct RevocationEvent {
        NodeId subject_id;
        NodeId revoker_id;
        u64 timestamp_ms = 0;
        String reason;

        RevocationEvent() = default;

        [[nodiscard]] auto to_event() const -> TrustEvent {
            TrustEvent evt;
            evt.kind = TrustEventKind::MemberRevoked;
            evt.subject_id = subject_id;
            evt.actor_id = revoker_id;
            evt.timestamp_ms = timestamp_ms;
            evt.metadata = reason;
            return evt;
        }

        auto members() noexcept { return std::tie(subject_id, revoker_id, timestamp_ms, reason); }
        auto members() const noexcept { return std::tie(subject_id, revoker_id, timestamp_ms, reason); }
    };

    // =============================================================================
    // Trust Event Serialization
    // =============================================================================

    namespace trust {

        // Serialize TrustEvent to bytes
        inline auto serialize_event(const TrustEvent &evt) -> Vector<u8> {
            auto buf = dp::serialize<dp::Mode::WITH_VERSION>(const_cast<TrustEvent &>(evt));
            Vector<u8> result;
            result.reserve(buf.size());
            for (const auto &byte : buf) {
                result.push_back(byte);
            }
            return result;
        }

        // Deserialize TrustEvent from bytes
        inline auto deserialize_event(const Vector<u8> &data) -> Res<TrustEvent> {
            return serial::deserialize<TrustEvent>(data);
        }

    } // namespace trust

} // namespace botlink
