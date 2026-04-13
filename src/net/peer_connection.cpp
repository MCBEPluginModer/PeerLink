#include "net/peer_connection.h"
#include "net/p2p_node.h"
#include "net/packet_protocol.h"
#include "core/utils.h"

namespace p2p {

PeerConnection::PeerConnection(P2PNode* owner, SOCKET socket, std::string remoteIp, std::uint16_t remotePort, bool incoming)
    : owner_(owner), socket_(socket), remoteIp_(std::move(remoteIp)), remotePort_(remotePort), incoming_(incoming) {
    const auto nowMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    lastReceivedActivityMs_.store(nowMs, std::memory_order_release);
    lastPingSentMs_.store(nowMs, std::memory_order_release);
}

PeerConnection::~PeerConnection() {
    RequestClose();
    FinalizeClose();
}

void PeerConnection::Start() {
    recvThread_ = std::thread(&PeerConnection::RecvLoop, this);
    sendThread_ = std::thread(&PeerConnection::SendLoop, this);
}

void PeerConnection::RequestClose() {
    if (!TryBeginClosing()) return;

    bool expected = true;
    alive_.compare_exchange_strong(expected, false);

    SOCKET s = socket_;
    socket_ = INVALID_SOCKET;
    if (s != INVALID_SOCKET) {
        shutdown(s, SD_BOTH);
        closesocket(s);
    }
    queueCv_.notify_all();
}

void PeerConnection::FinalizeClose() {
    auto self = std::this_thread::get_id();
    if (recvThread_.joinable()) {
        if (recvThread_.get_id() == self) recvThread_.detach();
        else recvThread_.join();
    }
    if (sendThread_.joinable()) {
        if (sendThread_.get_id() == self) sendThread_.detach();
        else sendThread_.join();
    }
    state_.store(PeerState::Closed, std::memory_order_release);
}

void PeerConnection::EnqueuePacket(ByteVector packet) {
    if (!alive_) return;
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        sendQueue_.push(std::move(packet));
    }
    queueCv_.notify_one();
}

SOCKET PeerConnection::GetSocket() const { return socket_; }
bool PeerConnection::IsIncoming() const { return incoming_; }
bool PeerConnection::IsAlive() const { return alive_; }

void PeerConnection::SetRemoteIdentity(const NodeId& nodeId, const std::string& nickname, std::uint16_t listenPort) {
    std::lock_guard<std::mutex> lock(identityMutex_);
    remoteNodeId_ = nodeId;
    remoteNickname_ = nickname;
    advertisedListenPort_ = listenPort;
}

NodeId PeerConnection::GetRemoteNodeId() const {
    std::lock_guard<std::mutex> lock(identityMutex_);
    return remoteNodeId_;
}

std::string PeerConnection::GetRemoteNickname() const {
    std::lock_guard<std::mutex> lock(identityMutex_);
    return remoteNickname_;
}

std::string PeerConnection::GetRemoteIp() const { return remoteIp_; }
std::uint16_t PeerConnection::GetRemotePort() const { return remotePort_; }
std::uint16_t PeerConnection::GetAdvertisedListenPort() const { return advertisedListenPort_; }

bool PeerConnection::TrySetActive() {
    PeerState expected = PeerState::PendingHandshake;
    return state_.compare_exchange_strong(expected, PeerState::Active);
}

bool PeerConnection::IsActive() const { return state_.load(std::memory_order_acquire) == PeerState::Active; }

void PeerConnection::MarkReceivedActivity() {
    const auto nowMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    lastReceivedActivityMs_.store(nowMs, std::memory_order_release);
}

bool PeerConnection::ShouldSendPing(std::chrono::steady_clock::time_point now, std::chrono::seconds interval) {
    const auto nowMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
    auto prev = lastPingSentMs_.load(std::memory_order_acquire);
    const auto intervalMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(interval).count());
    while (true) {
        if (nowMs < prev + intervalMs) return false;
        if (lastPingSentMs_.compare_exchange_weak(prev, nowMs)) return true;
    }
}

bool PeerConnection::IsHeartbeatTimedOut(std::chrono::steady_clock::time_point now, std::chrono::seconds timeout) const {
    const auto nowMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
    const auto lastRx = lastReceivedActivityMs_.load(std::memory_order_acquire);
    const auto timeoutMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count());
    return nowMs > lastRx + timeoutMs;
}

bool PeerConnection::TryBeginClosing() {
    PeerState s = state_.load(std::memory_order_acquire);
    while (true) {
        if (s == PeerState::Closing || s == PeerState::Closed) return false;
        if (state_.compare_exchange_weak(s, PeerState::Closing)) return true;
    }
}

void PeerConnection::RecvLoop() {
    const SOCKET owned = socket_;
    while (alive_) {
        PacketHeader header{};
        ByteVector payload;
        if (!protocol::ReadPacket(owned, header, payload)) break;
        if (owner_) owner_->OnPacket(shared_from_this(), static_cast<PacketType>(header.type), header.packetId, payload);
    }
    if (owner_) owner_->OnPeerDisconnected(owned);
}

void PeerConnection::SendLoop() {
    const SOCKET owned = socket_;
    while (alive_) {
        ByteVector packet;
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCv_.wait(lock, [&]() { return !alive_ || !sendQueue_.empty(); });
            if (!alive_ && sendQueue_.empty()) break;
            if (sendQueue_.empty()) continue;
            packet = std::move(sendQueue_.front());
            sendQueue_.pop();
        }
        if (!utils::SendAll(owned, packet.data(), packet.size())) break;
    }
    if (owner_) owner_->OnPeerDisconnected(owned);
}

} // namespace p2p
