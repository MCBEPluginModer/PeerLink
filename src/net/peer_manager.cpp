#include "net/peer_manager.h"
#include "net/peer_connection.h"

namespace p2p {

bool PeerManager::AddPeer(const std::shared_ptr<PeerConnection>& peer) {
    if (!peer) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    const NodeId nodeId = peer->GetRemoteNodeId();
    const SOCKET socket = peer->GetSocket();

    if (nodeId.empty() || socket == INVALID_SOCKET) {
        return false;
    }

    if (byNodeId_.contains(nodeId)) {
        return false;
    }

    byNodeId_[nodeId] = peer;
    bySocket_[socket] = peer;
    return true;
}

void PeerManager::RemoveBySocket(SOCKET socket) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = bySocket_.find(socket);
    if (it == bySocket_.end()) {
        return;
    }

    auto peer = it->second;
    if (peer) {
        byNodeId_.erase(peer->GetRemoteNodeId());
    }

    bySocket_.erase(it);
}

std::shared_ptr<PeerConnection> PeerManager::FindByNodeId(const NodeId& nodeId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = byNodeId_.find(nodeId);
    return it != byNodeId_.end() ? it->second : nullptr;
}

std::shared_ptr<PeerConnection> PeerManager::FindBySocket(SOCKET socket) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = bySocket_.find(socket);
    return it != bySocket_.end() ? it->second : nullptr;
}

std::vector<std::shared_ptr<PeerConnection>> PeerManager::GetAllPeers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<PeerConnection>> result;
    result.reserve(byNodeId_.size());

    for (const auto& [_, peer] : byNodeId_) {
        result.push_back(peer);
    }

    return result;
}

std::vector<PeerConnectionInfo> PeerManager::Snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PeerConnectionInfo> result;
    result.reserve(byNodeId_.size());

    for (const auto& [_, peer] : byNodeId_) {
        PeerConnectionInfo info{};
        info.socket = peer->GetSocket();
        info.remoteNodeId = peer->GetRemoteNodeId();
        info.remoteNickname = peer->GetRemoteNickname();
        info.remoteIp = peer->GetRemoteIp();
        info.remotePort = peer->GetAdvertisedListenPort();
        info.incoming = peer->IsIncoming();
        result.push_back(std::move(info));
    }

    return result;
}

bool PeerManager::HasNode(const NodeId& nodeId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return byNodeId_.contains(nodeId);
}

} // namespace p2p