#pragma once
#include "core/types.h"

#include <optional>

namespace p2p {

struct ContactEntry {
    NodeId nodeId;
    std::string nickname;
    ByteVector publicKeyBlob;
    ByteVector encryptPublicKeyBlob;
    std::string fingerprint;
    std::string previousFingerprint;
    bool trusted = true;
    bool blocked = false;
    bool keyMismatch = false;
    std::int64_t addedAtUnix = 0;
    std::string lastKnownIp;
    std::uint16_t lastKnownPort = 0;
    NodeId preferredRelayNodeId;
    ByteVector pendingPublicKeyBlob;
    ByteVector pendingEncryptPublicKeyBlob;
    std::string pendingFingerprint;
    std::int64_t lastIdentityMigrationUnix = 0;
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
