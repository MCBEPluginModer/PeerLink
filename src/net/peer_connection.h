#pragma once
#include "core/types.h"

namespace p2p {

class P2PNode;

enum class PeerState : std::uint8_t {
    PendingHandshake = 0,
    Active = 1,
    Closing = 2,
    Closed = 3
};

class PeerConnection : public std::enable_shared_from_this<PeerConnection> {
public:
    PeerConnection(P2PNode* owner, SOCKET socket, std::string remoteIp, std::uint16_t remotePort, bool incoming);
    ~PeerConnection();

    void Start();
    void RequestClose();
    void FinalizeClose();

    void EnqueuePacket(ByteVector packet);

    SOCKET GetSocket() const;
    bool IsIncoming() const;
    bool IsAlive() const;

    void SetRemoteIdentity(const NodeId& nodeId, const std::string& nickname, std::uint16_t listenPort);
    NodeId GetRemoteNodeId() const;
    std::string GetRemoteNickname() const;
    std::string GetRemoteIp() const;
    std::uint16_t GetRemotePort() const;
    std::uint16_t GetAdvertisedListenPort() const;

    bool TrySetActive();
    bool TryBeginClosing();
    bool IsActive() const;

    void MarkReceivedActivity();
    bool ShouldSendPing(std::chrono::steady_clock::time_point now, std::chrono::seconds interval);
    bool IsHeartbeatTimedOut(std::chrono::steady_clock::time_point now, std::chrono::seconds timeout) const;

private:
    void RecvLoop();
    void SendLoop();

private:
    P2PNode* owner_ = nullptr;
    SOCKET socket_ = INVALID_SOCKET;
    std::string remoteIp_;
    std::uint16_t remotePort_ = 0;
    std::uint16_t advertisedListenPort_ = 0;
    bool incoming_ = false;

    std::atomic<bool> alive_{true};
    std::atomic<PeerState> state_{PeerState::PendingHandshake};

    mutable std::mutex identityMutex_;
    NodeId remoteNodeId_;
    std::string remoteNickname_;

    std::mutex queueMutex_;
    std::condition_variable queueCv_;
    std::queue<ByteVector> sendQueue_;

    std::thread recvThread_;
    std::thread sendThread_;

    std::atomic<std::uint64_t> lastReceivedActivityMs_{0};
    std::atomic<std::uint64_t> lastPingSentMs_{0};
};

} // namespace p2p
