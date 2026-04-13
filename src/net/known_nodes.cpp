#include "net/known_nodes.h"

namespace p2p {

void KnownNodeTable::Upsert(const KnownNode& node) {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_[node.nodeId] = node;
}

void KnownNodeTable::UpsertMany(const std::vector<KnownNode>& nodes) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& node : nodes) {
        nodes_[node.nodeId] = node;
    }
}

std::vector<KnownNode> KnownNodeTable::GetAll() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<KnownNode> result;
    result.reserve(nodes_.size());

    for (const auto& [_, node] : nodes_) {
        result.push_back(node);
    }

    return result;
}

std::vector<KnownNode> KnownNodeTable::GetAllExcept(const NodeId& selfId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<KnownNode> result;

    for (const auto& [id, node] : nodes_) {
        if (id != selfId) {
            result.push_back(node);
        }
    }

    return result;
}

bool KnownNodeTable::Exists(const NodeId& nodeId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return nodes_.find(nodeId) != nodes_.end();
}

std::optional<NodeId> KnownNodeTable::FindNodeIdByNickname(const std::string& nickname) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [id, node] : nodes_) {
        if (node.nickname == nickname) {
            return id;
        }
    }
    return std::nullopt;
}

std::optional<KnownNode> KnownNodeTable::FindByNodeId(const NodeId& nodeId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(nodeId);
    if (it == nodes_.end()) {
        return std::nullopt;
    }
    return it->second;
}

} // namespace p2p