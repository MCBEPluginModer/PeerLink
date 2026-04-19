#pragma once
#include "core/types.h"

#include <optional>

namespace p2p {

struct ContactEntry {
    NodeId nodeId;
    std::string nickname;
    ByteVector publicKeyBlob;
    std::string fingerprint;
    bool trusted = true;
    bool blocked = false;
    std::int64_t addedAtUnix = 0;
    std::string lastKnownIp;
    std::uint16_t lastKnownPort = 0;
    NodeId preferredRelayNodeId;
    bool keyVerified = false;
    std::string safetyNumber;
    std::int64_t verifiedAtUnix = 0;
};

class ContactStore {
public:
    static bool Load(const std::string& rootDir, const NodeId& localNodeId,
                     std::unordered_map<NodeId, ContactEntry>& out,
                     std::string* error = nullptr);
    static bool Save(const std::string& rootDir, const NodeId& localNodeId,
                     const std::unordered_map<NodeId, ContactEntry>& contacts,
                     std::string* error = nullptr);

    static std::string BuildInviteCode(const LocalNodeInfo& local, const ByteVector& publicKeyBlob);
    static bool ParseInviteCode(const std::string& code, ContactEntry& out, std::string* error = nullptr);
};

} // namespace p2p
