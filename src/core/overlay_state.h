#pragma once

#include "core/types.h"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace p2p {

enum class GroupRole {
    Owner,
    Admin,
    Member
};

struct DeviceEntry {
    NodeId nodeId;
    std::string nickname;
    std::string label;
    std::string fingerprint;
    bool approved = false;
    bool revoked = false;
    std::int64_t linkedAtUnix = 0;
    std::int64_t revokedAtUnix = 0;
};

struct GroupMemberEntry {
    NodeId nodeId;
    std::string nickname;
    GroupRole role = GroupRole::Member;
};

struct GroupEventEntry {
    std::uint64_t version = 0;
    std::string type;
    NodeId actorNodeId;
    NodeId targetNodeId;
    std::string detail;
    std::int64_t createdAtUnix = 0;
};

struct GroupEntry {
    std::string groupId;
    std::string name;
    NodeId ownerNodeId;
    std::uint64_t version = 0;
    std::vector<GroupMemberEntry> members;
    std::vector<GroupEventEntry> events;
};

struct OverlayState {
    std::unordered_map<NodeId, DeviceEntry> devices;
    std::unordered_map<std::string, GroupEntry> groups;
};

std::string ToString(GroupRole role);
std::optional<GroupRole> ParseGroupRole(const std::string& text);

bool LoadOverlayState(const std::string& rootDir,
                      const NodeId& localNodeId,
                      OverlayState& out,
                      std::string* error = nullptr);

bool SaveOverlayState(const std::string& rootDir,
                      const NodeId& localNodeId,
                      const OverlayState& state,
                      std::string* error = nullptr);

} // namespace p2p
