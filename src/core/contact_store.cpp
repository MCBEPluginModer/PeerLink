#include "core/contact_store.h"
#include "core/fingerprint_utils.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>
#include <ctime>
#include <algorithm>

namespace p2p {
namespace fs = std::filesystem;
namespace {
std::string HexEncode(const ByteVector& bytes) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto b : bytes) {
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

bool HexNibble(char c, std::uint8_t& out) {
    if (c >= '0' && c <= '9') { out = static_cast<std::uint8_t>(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { out = static_cast<std::uint8_t>(10 + c - 'a'); return true; }
    if (c >= 'A' && c <= 'F') { out = static_cast<std::uint8_t>(10 + c - 'A'); return true; }
    return false;
}

bool HexDecode(const std::string& hex, ByteVector& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        std::uint8_t hi = 0, lo = 0;
        if (!HexNibble(hex[i], hi) || !HexNibble(hex[i + 1], lo)) return false;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return true;
}

std::string HexEncodeString(const std::string& value) {
    return HexEncode(ByteVector(value.begin(), value.end()));
}

bool HexDecodeString(const std::string& hex, std::string& out) {
    ByteVector tmp;
    if (!HexDecode(hex, tmp)) return false;
    out.assign(tmp.begin(), tmp.end());
    return true;
}

bool IsLikelyHex(const std::string& s) {
    if (s.empty() || (s.size() % 2) != 0) return false;
    for (char ch : s) {
        std::uint8_t nibble = 0;
        if (!HexNibble(ch, nibble)) return false;
    }
    return true;
}

bool DecodeMaybeHexString(const std::string& in, std::string& out) {
    if (in.empty()) { out.clear(); return true; }
    if (IsLikelyHex(in)) {
        if (HexDecodeString(in, out)) return true;
    }
    out = in;
    return true;
}

bool IsPrintableAscii(const std::string& s) {
    for (unsigned char ch : s) {
        if (ch < 32 || ch > 126) return false;
    }
    return true;
}

fs::path ContactPath(const std::string& rootDir, const NodeId& localNodeId) {
    return fs::path(rootDir) / (localNodeId + ".contacts.txt");
}

std::vector<std::string> SplitTab(const std::string& line) {
    std::vector<std::string> parts;
    std::stringstream ss(line);
    std::string part;
    while (std::getline(ss, part, '\t')) parts.push_back(part);
    return parts;
}
} // namespace

bool ContactStore::Load(const std::string& rootDir, const NodeId& localNodeId,
                        std::unordered_map<NodeId, ContactEntry>& out,
                        std::string* error) {
    out.clear();
    try {
        fs::create_directories(rootDir);
        auto path = ContactPath(rootDir, localNodeId);
        if (!fs::exists(path)) return true;
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            if (error) *error = "failed to open contact file";
            return false;
        }
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty() || line[0] == '#') continue;
            auto parts = SplitTab(line);
            if (parts.size() < 3) continue;
            ContactEntry c{};
            std::string nodeId;
            if (!DecodeMaybeHexString(parts[0], nodeId) || nodeId.empty()) continue;
            c.nodeId = nodeId;
            if (parts.size() >= 2) {
                if (!DecodeMaybeHexString(parts[1], c.nickname)) c.nickname.clear();
            }
            if (parts.size() >= 3 && !parts[2].empty()) {
                if (!HexDecode(parts[2], c.publicKeyBlob)) c.publicKeyBlob.clear();
            }
            if (parts.size() >= 4) {
                DecodeMaybeHexString(parts[3], c.fingerprint);
            }
            if (!c.publicKeyBlob.empty()) {
                auto computed = ComputeFingerprint(c.publicKeyBlob);
                if (c.fingerprint.empty() || !IsPrintableAscii(c.fingerprint) || c.fingerprint.find(':') == std::string::npos) {
                    c.fingerprint = computed;
                }
            } else if (!IsPrintableAscii(c.fingerprint)) {
                c.fingerprint.clear();
            }
            c.trusted = parts.size() >= 5 ? (parts[4] == "1" || parts[4] == "true") : false;
            c.blocked = parts.size() >= 6 ? (parts[5] == "1" || parts[5] == "true") : false;
            if (parts.size() >= 7) {
                try { c.addedAtUnix = std::stoll(parts[6]); } catch (...) { c.addedAtUnix = 0; }
            }
            if (parts.size() >= 8) DecodeMaybeHexString(parts[7], c.lastKnownIp);
            if (parts.size() >= 9) {
                try { c.lastKnownPort = static_cast<std::uint16_t>(std::stoul(parts[8])); } catch (...) { c.lastKnownPort = 0; }
            }
            if (parts.size() >= 10) DecodeMaybeHexString(parts[9], c.preferredRelayNodeId);
            out[c.nodeId] = std::move(c);
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

bool ContactStore::Save(const std::string& rootDir, const NodeId& localNodeId,
                        const std::unordered_map<NodeId, ContactEntry>& contacts,
                        std::string* error) {
    try {
        fs::create_directories(rootDir);
        auto path = ContactPath(rootDir, localNodeId);
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error) *error = "failed to open contact file for write";
            return false;
        }
        out << "# nodeId\tnickname\tpubkey\tfingerprint\ttrusted\tblocked\taddedAt\tip\tport\tpreferredRelay\n";
        std::vector<NodeId> ids;
        ids.reserve(contacts.size());
        for (const auto& [id, _] : contacts) ids.push_back(id);
        std::sort(ids.begin(), ids.end());
        for (const auto& id : ids) {
            const auto& c = contacts.at(id);
            out << HexEncodeString(c.nodeId) << '\t'
                << HexEncodeString(c.nickname) << '\t'
                << HexEncode(c.publicKeyBlob) << '\t'
                << HexEncodeString(c.fingerprint) << '\t'
                << (c.trusted ? '1' : '0') << '\t'
                << (c.blocked ? '1' : '0') << '\t'
                << c.addedAtUnix << '\t'
                << HexEncodeString(c.lastKnownIp) << '\t'
                << c.lastKnownPort << '\t'
                << HexEncodeString(c.preferredRelayNodeId) << '\n';
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

std::string ContactStore::BuildInviteCode(const LocalNodeInfo& local, const ByteVector& publicKeyBlob) {
    return std::string("peerlink:1:") + HexEncodeString(local.nodeId) + ":" + HexEncodeString(local.nickname) + ":" + HexEncode(publicKeyBlob);
}

bool ContactStore::ParseInviteCode(const std::string& code, ContactEntry& out, std::string* error) {
    out = ContactEntry{};
    const std::string prefix = "peerlink:1:";
    if (code.rfind(prefix, 0) != 0) {
        if (error) *error = "invite code must start with peerlink:1:";
        return false;
    }
    auto rest = code.substr(prefix.size());
    std::vector<std::string> parts;
    std::stringstream ss(rest);
    std::string part;
    while (std::getline(ss, part, ':')) parts.push_back(part);
    if (parts.size() != 3) {
        if (error) *error = "invalid invite format";
        return false;
    }
    if (!HexDecodeString(parts[0], out.nodeId)) {
        if (error) *error = "invalid node id in invite";
        return false;
    }
    if (!HexDecodeString(parts[1], out.nickname)) {
        if (error) *error = "invalid nickname in invite";
        return false;
    }
    if (!HexDecode(parts[2], out.publicKeyBlob) || out.publicKeyBlob.empty()) {
        if (error) *error = "invalid public key in invite";
        return false;
    }
    out.trusted = true;
    out.blocked = false;
    out.addedAtUnix = static_cast<std::int64_t>(std::time(nullptr));
    return true;
}

} // namespace p2p
