/* SPDX-License-Identifier: MIT */
/*
 * Botlink Interactive Trust Voting Demo
 * Uses Echo for progress UI and Scan for input
 */

#include <botlink/botlink.hpp>
#include <echo/echo.hpp>
#include <echo/widget.hpp>
#include <scan/scan.hpp>

#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

using namespace botlink;
using namespace dp;

struct MemberIdentity {
    PrivateKey ed_priv;
    PublicKey ed_pub;
    PrivateKey x_priv;
    PublicKey x_pub;
    NodeId node_id;
    String name;

    static MemberIdentity generate(const String &name) {
        MemberIdentity id;
        id.name = name;
        auto [ed_priv, ed_pub] = crypto::generate_ed25519_keypair();
        auto [x_priv, x_pub] = crypto::generate_x25519_keypair();
        id.ed_priv = ed_priv;
        id.ed_pub = ed_pub;
        id.x_priv = x_priv;
        id.x_pub = x_pub;
        id.node_id = crypto::node_id_from_pubkey(ed_pub);
        return id;
    }

    String short_id() const { return crypto::node_id_to_hex(node_id).substr(0, 8); }
};

void add_member_direct(TrustView &view, const MemberIdentity &member) {
    MemberEntry entry;
    entry.node_id = member.node_id;
    entry.ed25519_pubkey = member.ed_pub;
    entry.x25519_pubkey = member.x_pub;
    entry.status = MemberStatus::Approved;
    entry.joined_at_ms = time::now_ms();
    view.add_member(entry);
}

void show_vote_progress(const String &voter_name, int duration_ms) {
    const int steps = 30;
    const int step_delay = duration_ms / steps;

    echo::progress_bar bar(steps);
    bar.set_bar_style(echo::BarStyle::Smooth);
    bar.set_prefix(voter_name.c_str());
    bar.set_show_elapsed(true);

    for (int i = 0; i <= steps; ++i) {
        bar.set_progress(i);
        std::this_thread::sleep_for(std::chrono::milliseconds(step_delay));
    }
    bar.finish();
}

void list_members(const std::vector<MemberIdentity> &members) {
    echo::separator("Current Members", '-');
    for (const auto &member : members) {
        echo::info("- ", member.name.c_str(), " (", member.short_id().c_str(), ")");
    }
}

std::vector<MemberIdentity> collect_founders(TrustView &view) {
    std::vector<MemberIdentity> members;

    echo::separator("Add Founding Members", '=');
    echo::info("Add at least two founding members before voting.");

    while (true) {
        auto name = scan::TextInput().prompt("Founding member name: ").placeholder("Press Enter to start voting").run();

        if (!name || name->empty()) {
            if (members.size() < 2) {
                echo::warn("Need at least two members before voting.");
                continue;
            }
            break;
        }

        String member_name = name->c_str();
        MemberIdentity member = MemberIdentity::generate(member_name);
        add_member_direct(view, member);
        members.push_back(member);

        echo::info("Added founder: ", member.name.c_str(), " (", member.short_id().c_str(), ")");
    }

    return members;
}

size_t choose_sponsor_index(const std::vector<MemberIdentity> &members) {
    std::vector<std::string> items;
    items.reserve(members.size());
    for (const auto &member : members) {
        items.push_back(member.name.c_str());
    }

    auto selection = scan::List().items(items).cursor("→ ").run();
    if (!selection) {
        return 0;
    }

    for (size_t i = 0; i < items.size(); ++i) {
        if (items[i] == *selection) {
            return i;
        }
    }

    return 0;
}

void run_membership_vote(TrustView &view, const MemberIdentity &candidate, const std::vector<MemberIdentity> &voters) {
    echo::separator("Voting In Progress", '=');

    for (const auto &voter : voters) {
        echo::info(voter.name.c_str(), " is reviewing the request...");
        show_vote_progress(voter.name, 2000);
        view.record_vote(candidate.node_id, voter.node_id, Vote::Yes);
    }

    auto [has_quorum, is_approved, yes_votes, no_votes] = view.check_proposal_status(candidate.node_id);
    echo::info("Vote tally: yes=", yes_votes, ", no=", no_votes, ", quorum=", (has_quorum ? "yes" : "no"));
    echo::info("Decision: ", (is_approved ? "APPROVED" : "REJECTED"));
}

auto main() -> int {
    auto init_result = botlink::init();
    if (init_result.is_err()) {
        std::cerr << "Failed to initialize: " << init_result.error().message.c_str() << "\n";
        return 1;
    }

    echo::separator("Botlink Interactive Trust Voting", '=');
    echo::info("Use Scan prompts to add members and vote.");

    TrustView view(2, 10000);
    echo::info("TrustView policy: min_yes_votes=2, vote_timeout=10s");

    std::vector<MemberIdentity> members = collect_founders(view);
    list_members(members);

    while (true) {
        auto name = scan::TextInput().prompt("New member name: ").placeholder("Press Enter to finish").run();

        if (!name || name->empty()) {
            break;
        }

        String candidate_name = name->c_str();
        MemberIdentity candidate = MemberIdentity::generate(candidate_name);

        echo::separator("New Join Request", '-');
        echo::info("Candidate: ", candidate.name.c_str(), " (", candidate.short_id().c_str(), ")");

        size_t sponsor_index = choose_sponsor_index(members);
        const MemberIdentity &sponsor = members[sponsor_index];
        echo::info("Sponsor: ", sponsor.name.c_str());

        JoinProposal proposal;
        proposal.candidate_id = candidate.node_id;
        proposal.candidate_ed25519 = candidate.ed_pub;
        proposal.candidate_x25519 = candidate.x_pub;
        proposal.sponsor_id = sponsor.node_id;
        proposal.timestamp_ms = time::now_ms();

        auto create_res = view.create_proposal(proposal);
        if (create_res.is_err()) {
            echo::error("Failed to create proposal: ", create_res.error().message.c_str());
            continue;
        }

        run_membership_vote(view, candidate, members);

        auto [has_quorum, is_approved, yes_votes, no_votes] = view.check_proposal_status(candidate.node_id);
        if (has_quorum && is_approved) {
            auto approve_res = view.approve_proposal(candidate.node_id);
            if (approve_res.is_ok()) {
                echo::info("Member approved and added to the swarm!");
                members.push_back(candidate);
            } else {
                echo::error("Approval failed: ", approve_res.error().message.c_str());
            }
        } else {
            echo::warn("Member was not approved.");
        }

        list_members(members);
    }

    echo::separator("Session Complete", '=');
    echo::info("Final member count: ", view.member_count());
    return 0;
}
