#pragma once

#include "core/types.h"

namespace p2p {

class KnownNodeTable {
public:
    void Upsert(const KnownNode& node);
    void UpsertMany(const std::vector<KnownNode>& nodes);
    std::vector<KnownNode> GetAll() const;
    std::vector<KnownNode> GetAllExcept(const NodeId& selfId) const;
    bool Exists(const NodeId& nodeId) const;
    std::optional<NodeId> FindNodeIdByNickname(const std::string& nickname) const;
    std::optional<KnownNode> FindByNodeId(const NodeId& nodeId) const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<NodeId, KnownNode> nodes_;
};

} // namespace p2p