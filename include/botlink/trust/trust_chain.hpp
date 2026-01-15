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
#include <botlink/crypto/sign.hpp>
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
        PrivateKey local_ed25519_priv_;
        PublicKey local_ed25519_pub_;
        Map<NodeId, PublicKey> member_pubkeys_; // Cache of member public keys for verification

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

        // Set local signing keys
        auto set_local_keys(const PrivateKey &priv, const PublicKey &pub) -> void {
            local_ed25519_priv_ = priv;
            local_ed25519_pub_ = pub;
        }

        // Register a member's public key for signature verification
        auto register_member_pubkey(const NodeId &node_id, const PublicKey &pubkey) -> void {
            member_pubkeys_[node_id] = pubkey;
        }

        // Get chain ID
        [[nodiscard]] auto chain_id() const -> const String & { return chain_id_; }

        // =============================================================================
        // Membership Operations (with Ed25519 Signatures)
        // =============================================================================

        // Sign event data and return signature
        auto sign_event(const TrustEvent &evt) -> Vector<u8> {
            // Serialize event for signing
            Vector<u8> data = trust::serialize_event(evt);

            // Sign with local Ed25519 key
            Signature sig = crypto::ed25519_sign(local_ed25519_priv_, data);

            // Convert signature to vector
            Vector<u8> sig_vec;
            sig_vec.reserve(SIGNATURE_SIZE);
            for (usize i = 0; i < SIGNATURE_SIZE; ++i) {
                sig_vec.push_back(sig.data[i]);
            }
            return sig_vec;
        }

        // Verify event signature
        auto verify_event_signature(const TrustEvent &evt, const Vector<u8> &sig_vec, const PublicKey &pubkey)
            -> boolean {
            if (sig_vec.size() != SIGNATURE_SIZE) {
                return false;
            }

            // Convert vector to Signature
            Signature sig;
            for (usize i = 0; i < SIGNATURE_SIZE; ++i) {
                sig.data[i] = sig_vec[i];
            }

            // Serialize event for verification
            Vector<u8> data = trust::serialize_event(evt);

            return crypto::ed25519_verify(pubkey, data, sig);
        }

        // Add an event to the chain with proper Ed25519 signature
        auto add_event(const TrustEvent &evt) -> VoidRes {
            std::string tx_uuid =
                "evt-" + std::to_string(evt.timestamp_ms) + "-" + std::to_string(static_cast<u8>(evt.kind));

            blockit::Transaction<TrustEvent> tx(tx_uuid, evt);

            // Sign the event with local Ed25519 key
            tx.signature_ = sign_event(evt);

            blockit::Block<TrustEvent> block({tx});

            auto add_result = chain_.addBlock(block);
            if (!add_result.is_ok()) {
                return result::err(err::trust(add_result.error().message.c_str()));
            }

            // Register the subject's public key for future verification if this is an approval
            if (evt.kind == TrustEventKind::JoinApproved) {
                member_pubkeys_[evt.subject_id] = evt.subject_pubkey;
            }

            return result::ok();
        }

        // Add an event from a remote peer (with signature verification)
        auto add_remote_event(const TrustEvent &evt, const Vector<u8> &signature) -> VoidRes {
            // Look up the actor's public key
            auto it = member_pubkeys_.find(evt.actor_id);
            if (it == member_pubkeys_.end()) {
                // For genesis events, actor is self-signed
                if (evt.kind == TrustEventKind::JoinApproved && evt.actor_id == evt.subject_id) {
                    // Genesis self-approval - verify against subject's pubkey
                    if (!verify_event_signature(evt, signature, evt.subject_pubkey)) {
                        return result::err(err::crypto("Invalid signature on genesis event"));
                    }
                } else {
                    return result::err(err::not_found("Unknown actor - cannot verify signature"));
                }
            } else {
                // Verify signature against known member's public key
                if (!verify_event_signature(evt, signature, it->second)) {
                    return result::err(err::crypto("Invalid event signature"));
                }
            }

            std::string tx_uuid =
                "evt-" + std::to_string(evt.timestamp_ms) + "-" + std::to_string(static_cast<u8>(evt.kind));

            blockit::Transaction<TrustEvent> tx(tx_uuid, evt);
            tx.signature_ = signature;

            blockit::Block<TrustEvent> block({tx});

            auto add_result = chain_.addBlock(block);
            if (!add_result.is_ok()) {
                return result::err(err::trust(add_result.error().message.c_str()));
            }

            // Register the subject's public key for future verification if this is an approval
            if (evt.kind == TrustEventKind::JoinApproved) {
                member_pubkeys_[evt.subject_id] = evt.subject_pubkey;
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
