#include "core/contact_store.h"
#include "core/fingerprint_utils.h"

#include <algorithm>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

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
        const auto path = ContactPath(rootDir, localNodeId);
        if (!fs::exists(path)) return true;

        std::ifstream in(path, std::ios::binary);
        if (!in) {
            if (error) *error = "failed to open contact file";
            return false;
        }

        std::string line;
        while (std::getline(in, line)) {
            if (line.empty() || line[0] == '#') continue;
            const auto parts = SplitTab(line);
            ContactEntry c{};

            // New format with persisted encrypt/migration fields.
            if (parts.size() >= 17) {
                std::string nodeId;
                if (!HexDecodeString(parts[0], nodeId)) continue;
                c.nodeId = nodeId;
                if (!HexDecodeString(parts[1], c.nickname)) continue;
                if (!HexDecode(parts[2], c.publicKeyBlob)) continue;
                HexDecode(parts[3], c.encryptPublicKeyBlob);
                HexDecodeString(parts[4], c.fingerprint);
                HexDecodeString(parts[5], c.previousFingerprint);
                c.trusted = (parts[6] == "1");
                c.blocked = (parts[7] == "1");
                c.keyMismatch = (parts[8] == "1");
                try { c.addedAtUnix = std::stoll(parts[9]); } catch (...) { c.addedAtUnix = 0; }
                HexDecodeString(parts[10], c.lastKnownIp);
                try { c.lastKnownPort = static_cast<std::uint16_t>(std::stoul(parts[11])); } catch (...) { c.lastKnownPort = 0; }
                HexDecodeString(parts[12], c.preferredRelayNodeId);
                HexDecode(parts[13], c.pendingPublicKeyBlob);
                HexDecode(parts[14], c.pendingEncryptPublicKeyBlob);
                HexDecodeString(parts[15], c.pendingFingerprint);
                try { c.lastIdentityMigrationUnix = std::stoll(parts[16]); } catch (...) { c.lastIdentityMigrationUnix = 0; }
            } else if (parts.size() >= 13) {
                // Older mismatch-aware format.
                std::string nodeId;
                if (!HexDecodeString(parts[0], nodeId)) continue;
                c.nodeId = nodeId;
                if (!HexDecodeString(parts[1], c.nickname)) continue;
                if (!HexDecode(parts[2], c.publicKeyBlob)) continue;
                HexDecodeString(parts[3], c.fingerprint);
                c.trusted = (parts[4] == "1");
                c.blocked = (parts[5] == "1");
                try { c.addedAtUnix = std::stoll(parts[6]); } catch (...) { c.addedAtUnix = 0; }
                HexDecodeString(parts[7], c.lastKnownIp);
                try { c.lastKnownPort = static_cast<std::uint16_t>(std::stoul(parts[8])); } catch (...) { c.lastKnownPort = 0; }
                HexDecodeString(parts[9], c.preferredRelayNodeId);
                c.keyMismatch = (parts[10] == "1");
                HexDecode(parts[11], c.pendingPublicKeyBlob);
                HexDecodeString(parts[12], c.pendingFingerprint);
            } else if (parts.size() >= 10) {
                // Very old format.
                std::string nodeId;
                if (!HexDecodeString(parts[0], nodeId)) continue;
                c.nodeId = nodeId;
                if (!HexDecodeString(parts[1], c.nickname)) continue;
                if (!HexDecode(parts[2], c.publicKeyBlob)) continue;
                HexDecodeString(parts[3], c.fingerprint);
                c.trusted = (parts[4] == "1");
                c.blocked = (parts[5] == "1");
                try { c.addedAtUnix = std::stoll(parts[6]); } catch (...) { c.addedAtUnix = 0; }
                HexDecodeString(parts[7], c.lastKnownIp);
                try { c.lastKnownPort = static_cast<std::uint16_t>(std::stoul(parts[8])); } catch (...) { c.lastKnownPort = 0; }
                HexDecodeString(parts[9], c.preferredRelayNodeId);
            } else {
                continue;
            }

            if (c.fingerprint.empty() && !c.publicKeyBlob.empty()) c.fingerprint = ComputeFingerprint(c.publicKeyBlob);
            if (c.pendingFingerprint.empty() && !c.pendingPublicKeyBlob.empty()) c.pendingFingerprint = ComputeFingerprint(c.pendingPublicKeyBlob);
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
        const auto path = ContactPath(rootDir, localNodeId);
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error) *error = "failed to open contact file for write";
            return false;
        }

        out << "# nodeId\tnickname\tverifyPubKey\tencryptPubKey\tfingerprint\tpreviousFingerprint\ttrusted\tblocked\tkeyMismatch\taddedAt\tip\tport\tpreferredRelay\tpendingVerifyPubKey\tpendingEncryptPubKey\tpendingFingerprint\tlastIdentityMigration\n";

        std::vector<NodeId> ids;
        ids.reserve(contacts.size());
        for (const auto& [id, _] : contacts) ids.push_back(id);
        std::sort(ids.begin(), ids.end());

        for (const auto& id : ids) {
            const auto& c = contacts.at(id);
            out << HexEncodeString(c.nodeId) << '\t'
                << HexEncodeString(c.nickname) << '\t'
                << HexEncode(c.publicKeyBlob) << '\t'
                << HexEncode(c.encryptPublicKeyBlob) << '\t'
                << HexEncodeString(c.fingerprint) << '\t'
                << HexEncodeString(c.previousFingerprint) << '\t'
                << (c.trusted ? '1' : '0') << '\t'
                << (c.blocked ? '1' : '0') << '\t'
                << (c.keyMismatch ? '1' : '0') << '\t'
                << c.addedAtUnix << '\t'
                << HexEncodeString(c.lastKnownIp) << '\t'
                << c.lastKnownPort << '\t'
                << HexEncodeString(c.preferredRelayNodeId) << '\t'
                << HexEncode(c.pendingPublicKeyBlob) << '\t'
                << HexEncode(c.pendingEncryptPublicKeyBlob) << '\t'
                << HexEncodeString(c.pendingFingerprint) << '\t'
                << c.lastIdentityMigrationUnix << '\n';
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
    out.fingerprint = ComputeFingerprint(out.publicKeyBlob);
    out.trusted = true;
    out.keyMismatch = false;
    out.blocked = false;
    out.addedAtUnix = static_cast<std::int64_t>(std::time(nullptr));
    return true;
}

} // namespace p2p
