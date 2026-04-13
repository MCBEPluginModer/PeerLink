#pragma once

#include "core/types.h"

namespace p2p {

class PeerConnection;

class PeerManager {
public:
    bool AddPeer(const std::shared_ptr<PeerConnection>& peer);
    void RemoveBySocket(SOCKET socket);
    std::shared_ptr<PeerConnection> FindByNodeId(const NodeId& nodeId) const;
    std::shared_ptr<PeerConnection> FindBySocket(SOCKET socket) const;
    std::vector<std::shared_ptr<PeerConnection>> GetAllPeers() const;
    std::vector<PeerConnectionInfo> Snapshot() const;
    bool HasNode(const NodeId& nodeId) const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<NodeId, std::shared_ptr<PeerConnection>> byNodeId_;
    std::unordered_map<SOCKET, std::shared_ptr<PeerConnection>> bySocket_;
};

} // namespace p2p