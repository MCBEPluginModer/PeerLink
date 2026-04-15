#include "core/overlay_state.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace p2p {
namespace fs = std::filesystem;
namespace {

std::string Sanitize(const std::string& in) {
    std::string out = in;
    for (char& ch : out) {
        if (ch == '|' || ch == '\n' || ch == '\r' || ch == '\t') ch = ' ';
    }
    return out;
}

std::vector<std::string> Split(const std::string& line, char delim) {
    std::vector<std::string> parts;
    std::stringstream ss(line);
    std::string item;
    while (std::getline(ss, item, delim)) parts.push_back(item);
    return parts;
}

std::int64_t ToI64(const std::string& s) {
    try { return std::stoll(s); } catch (...) { return 0; }
}
std::uint64_t ToU64(const std::string& s) {
    try { return static_cast<std::uint64_t>(std::stoull(s)); } catch (...) { return 0; }
}

} // namespace

std::string ToString(GroupRole role) {
    switch (role) {
        case GroupRole::Owner: return "owner";
        case GroupRole::Admin: return "admin";
        default: return "member";
    }
}

std::optional<GroupRole> ParseGroupRole(const std::string& text) {
    if (text == "owner") return GroupRole::Owner;
    if (text == "admin") return GroupRole::Admin;
    if (text == "member") return GroupRole::Member;
    return std::nullopt;
}

bool LoadOverlayState(const std::string& rootDir,
                      const NodeId& localNodeId,
                      OverlayState& out,
                      std::string* error) {
    out = {};
    try {
        fs::create_directories(rootDir);
        const fs::path path = fs::path(rootDir) / (localNodeId + ".overlay.txt");
        if (!fs::exists(path)) return true;
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            if (error) *error = "Failed to open overlay state";
            return false;
        }
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            auto parts = Split(line, '|');
            if (parts.empty()) continue;
            if (parts[0] == "DEVICE" && parts.size() >= 9) {
                DeviceEntry d{};
                d.nodeId = parts[1]; d.nickname = parts[2]; d.label = parts[3]; d.fingerprint = parts[4];
                d.approved = parts[5] == "1"; d.revoked = parts[6] == "1";
                d.linkedAtUnix = ToI64(parts[7]); d.revokedAtUnix = ToI64(parts[8]);
                out.devices[d.nodeId] = d;
            } else if (parts[0] == "GROUP" && parts.size() >= 5) {
                GroupEntry g{};
                g.groupId = parts[1]; g.name = parts[2]; g.ownerNodeId = parts[3]; g.version = ToU64(parts[4]);
                out.groups[g.groupId] = g;
            } else if (parts[0] == "GMEMBER" && parts.size() >= 5) {
                auto it = out.groups.find(parts[1]);
                if (it == out.groups.end()) continue;
                GroupMemberEntry m{}; m.nodeId = parts[2]; m.nickname = parts[3];
                m.role = ParseGroupRole(parts[4]).value_or(GroupRole::Member);
                it->second.members.push_back(m);
            } else if (parts[0] == "GEVENT" && parts.size() >= 7) {
                auto it = out.groups.find(parts[1]);
                if (it == out.groups.end()) continue;
                GroupEventEntry ev{};
                ev.version = ToU64(parts[2]); ev.type = parts[3]; ev.actorNodeId = parts[4]; ev.targetNodeId = parts[5];
                ev.detail = parts.size() >= 8 ? parts[6] : std::string{};
                ev.createdAtUnix = ToI64(parts.back());
                it->second.events.push_back(ev);
            }
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

bool SaveOverlayState(const std::string& rootDir,
                      const NodeId& localNodeId,
                      const OverlayState& state,
                      std::string* error) {
    try {
        fs::create_directories(rootDir);
        const fs::path path = fs::path(rootDir) / (localNodeId + ".overlay.txt");
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error) *error = "Failed to write overlay state";
            return false;
        }
        for (const auto& [_, d] : state.devices) {
            out << "DEVICE|" << Sanitize(d.nodeId) << '|' << Sanitize(d.nickname) << '|' << Sanitize(d.label)
                << '|' << Sanitize(d.fingerprint) << '|' << (d.approved ? '1' : '0') << '|' << (d.revoked ? '1' : '0')
                << '|' << d.linkedAtUnix << '|' << d.revokedAtUnix << "\n";
        }
        for (const auto& [_, g] : state.groups) {
            out << "GROUP|" << Sanitize(g.groupId) << '|' << Sanitize(g.name) << '|' << Sanitize(g.ownerNodeId)
                << '|' << g.version << "\n";
            for (const auto& m : g.members) {
                out << "GMEMBER|" << Sanitize(g.groupId) << '|' << Sanitize(m.nodeId) << '|' << Sanitize(m.nickname)
                    << '|' << ToString(m.role) << "\n";
            }
            for (const auto& ev : g.events) {
                out << "GEVENT|" << Sanitize(g.groupId) << '|' << ev.version << '|' << Sanitize(ev.type) << '|'
                    << Sanitize(ev.actorNodeId) << '|' << Sanitize(ev.targetNodeId) << '|' << Sanitize(ev.detail)
                    << '|' << ev.createdAtUnix << "\n";
            }
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

} // namespace p2p
