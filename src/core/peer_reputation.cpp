#include "core/peer_reputation.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>

namespace p2p {
namespace fs = std::filesystem;
namespace {
std::int64_t NowUnixPeerRep() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

fs::path ReputationPath(const std::string& localNodeId) {
    return fs::path("profile") / "reputation" / (localNodeId + ".tsv");
}
}

PeerReputationRecord& PeerReputationStore::Touch(const NodeId& nodeId) {
    auto& rec = records_[nodeId];
    rec.nodeId = nodeId;
    rec.updatedAtUnix = NowUnixPeerRep();
    return rec;
}

void PeerReputationStore::ClampAndFlag(PeerReputationRecord& rec) {
    if (rec.score > 100) rec.score = 100;
    if (rec.score < -100) rec.score = -100;
    if (rec.score <= -60 || rec.signatureFailures >= 3 || rec.invalidPackets >= 6 || rec.rateLimitViolations >= 10) {
        rec.blocked = true;
    }
}

bool PeerReputationStore::Load(const std::string& localNodeId, std::string* error) {
    records_.clear();
    try {
        std::ifstream in(ReputationPath(localNodeId));
        if (!in) return true;
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty() || line[0] == '#') continue;
            std::stringstream ss(line);
            PeerReputationRecord rec{};
            std::string field;
            std::vector<std::string> parts;
            while (std::getline(ss, field, '\t')) parts.push_back(field);
            if (parts.size() < 9) continue;
            try {
                rec.nodeId = parts[0];
                rec.score = std::stoi(parts[1]);
                rec.goodEvents = static_cast<std::uint32_t>(std::stoul(parts[2]));
                rec.rateLimitViolations = static_cast<std::uint32_t>(std::stoul(parts[3]));
                rec.invalidPackets = static_cast<std::uint32_t>(std::stoul(parts[4]));
                rec.signatureFailures = static_cast<std::uint32_t>(std::stoul(parts[5]));
                rec.disconnects = static_cast<std::uint32_t>(std::stoul(parts[6]));
                rec.manualTrustBoosts = static_cast<std::uint32_t>(std::stoul(parts[7]));
                rec.updatedAtUnix = static_cast<std::int64_t>(std::stoll(parts[8]));
                rec.blocked = (parts.size() >= 10 && (parts[9] == "1" || parts[9] == "true"));
            } catch (...) {
                continue;
            }
            records_[rec.nodeId] = rec;
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

bool PeerReputationStore::Save(const std::string& localNodeId, std::string* error) const {
    try {
        fs::path path = ReputationPath(localNodeId);
        fs::create_directories(path.parent_path());
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error) *error = "failed to open reputation file";
            return false;
        }
        out << "# nodeId\tscore\tgoodEvents\trateLimitViolations\tinvalidPackets\tsignatureFailures\tdisconnects\tmanualTrustBoosts\tupdatedAt\tblocked\n";
        for (const auto& rec : GetAllSorted()) {
            out << rec.nodeId << '\t' << rec.score << '\t' << rec.goodEvents << '\t' << rec.rateLimitViolations << '\t'
                << rec.invalidPackets << '\t' << rec.signatureFailures << '\t' << rec.disconnects << '\t'
                << rec.manualTrustBoosts << '\t' << rec.updatedAtUnix << '\t' << (rec.blocked ? 1 : 0) << '\n';
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

void PeerReputationStore::NoteGoodEvent(const NodeId& nodeId, int delta) {
    if (nodeId.empty()) return;
    auto& rec = Touch(nodeId);
    rec.goodEvents += 1;
    rec.score += delta;
    ClampAndFlag(rec);
}

void PeerReputationStore::NoteRateLimitViolation(const NodeId& nodeId, int delta) {
    if (nodeId.empty()) return;
    auto& rec = Touch(nodeId);
    rec.rateLimitViolations += 1;
    rec.score += delta;
    ClampAndFlag(rec);
}

void PeerReputationStore::NoteInvalidPacket(const NodeId& nodeId, int delta) {
    if (nodeId.empty()) return;
    auto& rec = Touch(nodeId);
    rec.invalidPackets += 1;
    rec.score += delta;
    ClampAndFlag(rec);
}

void PeerReputationStore::NoteSignatureFailure(const NodeId& nodeId, int delta) {
    if (nodeId.empty()) return;
    auto& rec = Touch(nodeId);
    rec.signatureFailures += 1;
    rec.score += delta;
    ClampAndFlag(rec);
}

void PeerReputationStore::NoteDisconnect(const NodeId& nodeId, int delta) {
    if (nodeId.empty()) return;
    auto& rec = Touch(nodeId);
    rec.disconnects += 1;
    rec.score += delta;
    ClampAndFlag(rec);
}

void PeerReputationStore::NoteTrustedContact(const NodeId& nodeId, int delta) {
    if (nodeId.empty()) return;
    auto& rec = Touch(nodeId);
    rec.manualTrustBoosts += 1;
    rec.score += delta;
    if (rec.score > -20) rec.blocked = false;
    ClampAndFlag(rec);
}

const PeerReputationRecord* PeerReputationStore::Find(const NodeId& nodeId) const {
    auto it = records_.find(nodeId);
    return it == records_.end() ? nullptr : &it->second;
}

bool PeerReputationStore::ShouldBlock(const NodeId& nodeId) const {
    auto it = records_.find(nodeId);
    return it != records_.end() && it->second.blocked;
}

std::vector<PeerReputationRecord> PeerReputationStore::GetAllSorted() const {
    std::vector<PeerReputationRecord> out;
    out.reserve(records_.size());
    for (const auto& kv : records_) out.push_back(kv.second);
    std::sort(out.begin(), out.end(), [](const PeerReputationRecord& a, const PeerReputationRecord& b) {
        if (a.score != b.score) return a.score > b.score;
        return a.nodeId < b.nodeId;
    });
    return out;
}

} // namespace p2p
