/* SPDX-License-Identifier: MIT */
/*
 * Botlink Trust Chain
 * Blockchain-backed membership tracking using blockit
 */

#pragma once

#include <blockit/blockit.hpp>
#include <botlink/core/result.hpp>
#include <botlink/core/time.hpp>
#include <botlink/core/types.hpp>
#include <botlink/crypto/identity.hpp>
#include <botlink/trust/trust_event.hpp>
#include <datapod/datapod.hpp>

namespace botlink {

    using namespace dp;

    // =============================================================================
    // Trust Chain - Wraps blockit::Chain<TrustEvent>
    // =============================================================================

    class TrustChain {
      private:
        blockit::Chain<TrustEvent> chain_;
        String chain_id_;
        NodeId local_node_id_;

      public:
        TrustChain() = default;

        // Initialize a new trust chain with genesis event
        explicit TrustChain(const String &chain_id, const NodeId &genesis_node_id, const PublicKey &genesis_ed25519,
                            const PublicKey &genesis_x25519)
            : chain_id_(chain_id), local_node_id_(genesis_node_id) {

            // Create genesis event - first member is automatically approved
            TrustEvent genesis_evt;
            genesis_evt.kind = TrustEventKind::JoinApproved;
            genesis_evt.subject_id = genesis_node_id;
            genesis_evt.actor_id = genesis_node_id; // Self-signed genesis
            genesis_evt.subject_pubkey = genesis_ed25519;
            genesis_evt.subject_x25519 = genesis_x25519;
            genesis_evt.timestamp_ms = time::now_ms();
            genesis_evt.metadata = "genesis";

            // Initialize chain with genesis block
            std::string uuid = std::string(chain_id.c_str());
            std::string tx_uuid = "genesis-" + uuid;
            chain_ = blockit::Chain<TrustEvent>(uuid, tx_uuid, genesis_evt);
        }

        // Set local node ID
        auto set_local_node(const NodeId &id) -> void { local_node_id_ = id; }

        // Get chain ID
        [[nodiscard]] auto chain_id() const -> const String & { return chain_id_; }

        // =============================================================================
        // Membership Operations (Unsigned - for local use)
        // =============================================================================

        // Add an event to the chain (for local chains, uses placeholder signature)
        auto add_event(const TrustEvent &evt) -> VoidRes {
            std::string tx_uuid =
                "evt-" + std::to_string(evt.timestamp_ms) + "-" + std::to_string(static_cast<u8>(evt.kind));

            blockit::Transaction<TrustEvent> tx(tx_uuid, evt);
            // Add placeholder signature for local chain validation
            // (blockit requires non-empty signature but doesn't verify it for basic addBlock)
            tx.signature_ = dp::Vector<u8>{0x00};
            blockit::Block<TrustEvent> block({tx});

            auto add_result = chain_.addBlock(block);
            if (!add_result.is_ok()) {
                return result::err(err::trust(add_result.error().message.c_str()));
            }

            return result::ok();
        }

        // Propose a new member for joining
        auto propose_join(const JoinProposal &proposal) -> VoidRes {
            TrustEvent evt = proposal.to_event();
            return add_event(evt);
        }

        // Cast a vote on a pending proposal
        auto cast_vote(const VoteCastEvent &vote_evt) -> VoidRes {
            TrustEvent evt = vote_evt.to_event();
            return add_event(evt);
        }

        // Record membership decision (approval or rejection)
        auto record_decision(const MembershipDecision &decision) -> VoidRes {
            TrustEvent evt = decision.to_event();
            return add_event(evt);
        }

        // Record member revocation
        auto record_revocation(const RevocationEvent &revocation) -> VoidRes {
            TrustEvent evt = revocation.to_event();
            return add_event(evt);
        }

        // =============================================================================
        // Chain Queries
        // =============================================================================

        // Check if chain is valid
        [[nodiscard]] auto is_valid() const -> boolean {
            auto result = chain_.isValid();
            return result.is_ok() && result.value();
        }

        // Get chain length
        [[nodiscard]] auto length() const -> usize { return chain_.getChainLength(); }

        // Get all events for a specific node
        [[nodiscard]] auto get_events_for_node(const NodeId &node_id) const -> Vector<TrustEvent> {
            Vector<TrustEvent> events;

            for (const auto &block : chain_.blocks_) {
                for (const auto &tx : block.transactions_) {
                    if (tx.function_.subject_id == node_id) {
                        events.push_back(tx.function_);
                    }
                }
            }

            return events;
        }

        // Get the latest event for a node
        [[nodiscard]] auto get_latest_event_for_node(const NodeId &node_id) const -> Optional<TrustEvent> {
            Optional<TrustEvent> latest;

            for (const auto &block : chain_.blocks_) {
                for (const auto &tx : block.transactions_) {
                    if (tx.function_.subject_id == node_id) {
                        if (!latest.has_value() || tx.function_.timestamp_ms > latest->timestamp_ms) {
                            latest = tx.function_;
                        }
                    }
                }
            }

            return latest;
        }

        // Check if a node is an approved member
        [[nodiscard]] auto is_member(const NodeId &node_id) const -> boolean {
            auto latest = get_latest_event_for_node(node_id);
            if (!latest.has_value()) {
                return false;
            }

            // Member is approved if latest event is JoinApproved and not subsequently revoked
            return latest->kind == TrustEventKind::JoinApproved;
        }

        // Get all approved members
        [[nodiscard]] auto get_members() const -> Vector<NodeId> {
            Map<NodeId, TrustEvent> latest_events;

            // Build map of latest events per node
            for (const auto &block : chain_.blocks_) {
                for (const auto &tx : block.transactions_) {
                    auto it = latest_events.find(tx.function_.subject_id);
                    if (it == latest_events.end() || tx.function_.timestamp_ms > it->second.timestamp_ms) {
                        latest_events[tx.function_.subject_id] = tx.function_;
                    }
                }
            }

            // Collect approved members
            Vector<NodeId> members;
            for (const auto &[node_id, evt] : latest_events) {
                if (evt.kind == TrustEventKind::JoinApproved) {
                    members.push_back(node_id);
                }
            }

            return members;
        }

        // Get all nodes with their latest events (for sync_from_chain)
        [[nodiscard]] auto get_all_nodes_with_latest_event() const -> Vector<Pair<NodeId, TrustEvent>> {
            Map<NodeId, TrustEvent> latest_events;

            // Build map of latest events per node
            for (const auto &block : chain_.blocks_) {
                for (const auto &tx : block.transactions_) {
                    auto it = latest_events.find(tx.function_.subject_id);
                    if (it == latest_events.end() || tx.function_.timestamp_ms > it->second.timestamp_ms) {
                        latest_events[tx.function_.subject_id] = tx.function_;
                    }
                }
            }

            // Convert to vector
            Vector<Pair<NodeId, TrustEvent>> result;
            for (const auto &[node_id, evt] : latest_events) {
                result.push_back({node_id, evt});
            }

            return result;
        }

        // =============================================================================
        // Persistence
        // =============================================================================

        // Save chain to file
        auto save_to_file(const String &path) const -> VoidRes {
            auto result = chain_.saveToFile(std::string(path.c_str()));
            if (!result.is_ok()) {
                return result::err(err::io(result.error().message.c_str()));
            }
            return result::ok();
        }

        // Load chain from file
        auto load_from_file(const String &path) -> VoidRes {
            auto result = chain_.loadFromFile(std::string(path.c_str()));
            if (!result.is_ok()) {
                return result::err(err::io(result.error().message.c_str()));
            }
            chain_id_ = chain_.uuid_;
            return result::ok();
        }

        // =============================================================================
        // Debug
        // =============================================================================

        auto print_summary() const -> void { chain_.printChainSummary(); }
    };

} // namespace botlink
