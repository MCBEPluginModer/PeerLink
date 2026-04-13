#include "net/p2p_node.h"

#include "core/utils.h"
#include "net/packet_protocol.h"
#include "net/peer_connection.h"

#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <array>
#include <cctype>
#include <ctime>

namespace p2p {

P2PNode::P2PNode(std::string nickname, std::uint16_t listenPort) {
    local_.nickname = std::move(nickname);
    local_.listenPort = listenPort;
    if (!LoadOrCreateLocalIdentity()) {
        local_.nodeId = utils::GenerateNodeId();
    }

    KnownNode self{};
    self.nodeId = local_.nodeId;
    self.nickname = local_.nickname;
    self.ip = "127.0.0.1";
    self.port = local_.listenPort;
    self.observedUdpPort = local_.listenPort;
    self.lastSeen = std::chrono::steady_clock::now();
    knownNodes_.Upsert(self);
}

P2PNode::~P2PNode() { Stop(); }



namespace fs = std::filesystem;
namespace {
std::string BytesToHexLocal(const p2p::ByteVector& bytes) {
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

std::string TrimCopy(std::string value) {
    auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

MessageId GenerateMessageIdForNode(const NodeId& nodeId) {
    static std::atomic<std::uint64_t> counter{1};
    const auto now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    const auto nodeHash = static_cast<std::uint64_t>(std::hash<std::string>{}(nodeId));
    return (now << 16) ^ (counter.fetch_add(1, std::memory_order_relaxed) & 0xFFFFull) ^ (nodeHash & 0xFFFFull);
}

bool HexToBytesLocal(const std::string& hex, p2p::ByteVector& out) {
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

std::string RelayMsgPath(const fs::path& root, const p2p::NodeId& targetNodeId, p2p::MessageId messageId) {
    return (root / (std::string("msg_") + targetNodeId + "_" + std::to_string(messageId) + ".spool")).string();
}

std::string RelayAckPath(const fs::path& root, const p2p::NodeId& targetNodeId, p2p::MessageId messageId) {
    return (root / (std::string("ack_") + targetNodeId + "_" + std::to_string(messageId) + ".spool")).string();
}
}

bool P2PNode::LoadOrCreateLocalIdentity() {
    try {
        fs::create_directories("profile");
        const fs::path identityPath = fs::path("profile") / (local_.nickname + ".identity.json");

        if (fs::exists(identityPath)) {
            std::ifstream in(identityPath, std::ios::binary);
            std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            const std::string marker = "\"node_id\":\"";
            auto pos = text.find(marker);
            if (pos != std::string::npos) {
                pos += marker.size();
                auto end = text.find('"', pos);
                if (end != std::string::npos) {
                    local_.nodeId = text.substr(pos, end - pos);
                    return !local_.nodeId.empty();
                }
            }
        }

        local_.nodeId = utils::GenerateNodeId();
        std::ofstream out(identityPath, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out << "{\n  \"nickname\": \"" << local_.nickname << "\",\n  \"node_id\":\"" << local_.nodeId << "\"\n}\n";
        return true;
    } catch (...) {
        return false;
    }
}

void P2PNode::RestorePrivateSessionsFromHistory() {
    std::vector<StoredConversationMessage> latestMessages;
    std::string error;
    if (!ConversationStore::EnumerateLatestSessions(historyRootDir_, local_.nodeId, signer_, latestMessages, &error)) {
        utils::LogError("Failed to restore private sessions from history: " + error);
        return;
    }

    std::size_t restored = 0;
    for (const auto& msg : latestMessages) {
        const NodeId peerNodeId = (msg.fromNodeId == local_.nodeId) ? msg.toNodeId : msg.fromNodeId;
        const std::string peerNickname = (msg.fromNodeId == local_.nodeId) ? peerNodeId : msg.fromNickname;
        if (peerNodeId.empty()) continue;
        EnsureSessionForPeer(peerNodeId, peerNickname, msg.sessionId);
        ++restored;
    }

    if (restored > 0) {
        utils::LogSystem("Restored " + std::to_string(restored) + " private session(s) from local history");
    }
}


bool P2PNode::InitWinSock() {
    if (winsockInitialized_) return true;
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return false;
    winsockInitialized_ = true;
    return true;
}

void P2PNode::CleanupWinSock() {
    if (winsockInitialized_) {
        WSACleanup();
        winsockInitialized_ = false;
    }
}

bool P2PNode::Start() {
    if (!InitWinSock()) return false;

    std::wstring cont = L"MessengerKey_" + std::wstring(local_.nodeId.begin(), local_.nodeId.end());
    if (!signer_.Initialize(cont)) {
        utils::LogError("Crypto signer init failed");
        return false;
    }

    if (!signer_.ExportPublicKey(localPublicKeyBlob_)) {
        utils::LogError("Failed to export local public key");
        return false;
    }

    std::vector<std::string> historyProblems;
    if (!ConversationStore::VerifyAllForLocalNode(historyRootDir_, local_.nodeId, signer_, &historyProblems)) {
        for (const auto& problem : historyProblems) {
            utils::LogError("History integrity problem: " + problem);
        }
    }

    RestorePrivateSessionsFromHistory();
    LoadRelaySpoolFromDisk();
    LoadBootstrapNodes();

    listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket_ == INVALID_SOCKET) return false;

    int opt = 1;
    setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(local_.listenPort);

    if (bind(listenSocket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) return false;
    if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) return false;

    udpSocket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSocket_ == INVALID_SOCKET) return false;
    setsockopt(udpSocket_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
    if (bind(udpSocket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) return false;

    running_ = true;
    acceptThread_ = std::thread(&P2PNode::AcceptLoop, this);
    discoveryThread_ = std::thread(&P2PNode::DiscoveryLoop, this);
    udpThread_ = std::thread(&P2PNode::UdpRecvLoop, this);

    utils::LogSystem("Node started");
    PrintInfo();
    return true;
}

void P2PNode::Stop() {
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false)) return;

    if (listenSocket_ != INVALID_SOCKET) {
        shutdown(listenSocket_, SD_BOTH);
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
    }
    if (udpSocket_ != INVALID_SOCKET) {
        closesocket(udpSocket_);
        udpSocket_ = INVALID_SOCKET;
    }

    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        for (auto& [_, peer] : pendingPeers_) peer->RequestClose();
        for (auto& [_, peer] : pendingPeers_) peer->FinalizeClose();
        pendingPeers_.clear();
    }

    auto peers = peerManager_.GetAllPeers();
    for (auto& p : peers) p->RequestClose();
    for (auto& p : peers) p->FinalizeClose();

    if (acceptThread_.joinable()) acceptThread_.join();
    if (discoveryThread_.joinable()) discoveryThread_.join();
    if (udpThread_.joinable()) udpThread_.join();

    signer_.Cleanup();
    CleanupWinSock();
}

bool P2PNode::ConnectToPeer(const std::string& ip, std::uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        closesocket(s);
        return false;
    }

    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return false;
    }

    auto peer = std::make_shared<PeerConnection>(this, s, ip, port, false);
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingPeers_[s] = peer;
    }
    peer->Start();
    SendHello(peer);
    utils::LogSystem("Connected to " + ip + ":" + std::to_string(port));
    return true;
}

void P2PNode::AcceptLoop() {
    while (running_) {
        sockaddr_in addr{};
        int len = sizeof(addr);
        SOCKET client = accept(listenSocket_, reinterpret_cast<sockaddr*>(&addr), &len);
        if (client == INVALID_SOCKET) break;

        auto ip = utils::SocketAddressToIp(addr);
        auto port = ntohs(addr.sin_port);

        auto peer = std::make_shared<PeerConnection>(this, client, ip, port, true);
        {
            std::lock_guard<std::mutex> lock(pendingMutex_);
            pendingPeers_[client] = peer;
        }
        peer->Start();
        utils::LogSystem("Incoming connection: " + ip + ":" + std::to_string(port));
    }
}

void P2PNode::DiscoveryLoop() {
    using namespace std::chrono_literals;
    while (running_) {
        std::this_thread::sleep_for(2s);
        if (!running_) break;
        BroadcastPeerListToAll();
        RunHeartbeatChecks();
        CleanupExpiredRelayQueues();
        SendUdpProbeToKnownNodes();
        TryAutoConnectKnownNodes();
        TryConnectBootstrapNodes();
        RetryRelayQueues();
    }
}

void P2PNode::SendHello(const std::shared_ptr<PeerConnection>& peer) {
    HelloPayload hello{};
    hello.nodeId = local_.nodeId;
    hello.nickname = local_.nickname;
    hello.listenPort = local_.listenPort;
    hello.observedIpForRemote.clear();
    hello.observedPortForRemote = 0;
    signer_.ExportPublicKey(hello.publicKeyBlob);

    auto body = protocol::SerializeHello(hello);
    auto packet = protocol::MakePacket(PacketType::Hello, utils::GeneratePacketId(), body);
    peer->EnqueuePacket(std::move(packet));
}

void P2PNode::SendHelloAck(const std::shared_ptr<PeerConnection>& peer) {
    HelloPayload hello{};
    hello.nodeId = local_.nodeId;
    hello.nickname = local_.nickname;
    hello.listenPort = local_.listenPort;
    hello.observedIpForRemote = peer->GetRemoteIp();
    hello.observedPortForRemote = peer->GetRemotePort();
    signer_.ExportPublicKey(hello.publicKeyBlob);

    auto body = protocol::SerializeHello(hello);
    auto packet = protocol::MakePacket(PacketType::HelloAck, utils::GeneratePacketId(), body);
    peer->EnqueuePacket(std::move(packet));
}

void P2PNode::SendPeerList(const std::shared_ptr<PeerConnection>& peer) {
    auto nodes = knownNodes_.GetAllExcept(local_.nodeId);
    auto body = protocol::SerializePeerList(nodes);
    auto packet = protocol::MakePacket(PacketType::PeerList, utils::GeneratePacketId(), body);
    peer->EnqueuePacket(std::move(packet));
}

void P2PNode::BroadcastPeerListToAll() {
    for (auto& p : peerManager_.GetAllPeers()) SendPeerList(p);
}

void P2PNode::SendPing(const std::shared_ptr<PeerConnection>& peer) {
    if (!peer || !peer->IsAlive()) return;
    auto packet = protocol::MakePacket(PacketType::Ping, utils::GeneratePacketId(), {});
    peer->EnqueuePacket(std::move(packet));
}

void P2PNode::SendPong(const std::shared_ptr<PeerConnection>& peer) {
    auto packet = protocol::MakePacket(PacketType::Pong, utils::GeneratePacketId(), {});
    peer->EnqueuePacket(std::move(packet));
}

void P2PNode::RunHeartbeatChecks() {
    auto now = std::chrono::steady_clock::now();
    for (const auto& peer : peerManager_.GetAllPeers()) {
        if (!peer || !peer->IsAlive() || !peer->IsActive()) continue;
        if (peer->IsHeartbeatTimedOut(now, heartbeatTimeout_)) {
            const auto name = peer->GetRemoteNickname().empty() ? peer->GetRemoteNodeId() : peer->GetRemoteNickname();
            utils::LogSystem("Heartbeat timeout for peer: " + name);
            SafeClosePeer(peer);
            continue;
        }
        if (peer->ShouldSendPing(now, heartbeatInterval_)) {
            SendPing(peer);
        }
    }
}

void P2PNode::CleanupExpiredRelayQueues() {
    const auto now = std::chrono::system_clock::now();
    bool mutated = false;
    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        for (auto it = relayQueuesByTarget_.begin(); it != relayQueuesByTarget_.end();) {
            auto& q = it->second;
            const auto before = q.size();
            q.erase(std::remove_if(q.begin(), q.end(), [&](const QueuedRelayMessage& msg) {
                return now - msg.queuedAt > relayMessageTtl_;
            }), q.end());
            mutated = mutated || (q.size() != before);
            if (q.empty()) it = relayQueuesByTarget_.erase(it); else ++it;
        }
        for (auto it = relayAckQueuesByTarget_.begin(); it != relayAckQueuesByTarget_.end();) {
            auto& q = it->second;
            const auto before = q.size();
            q.erase(std::remove_if(q.begin(), q.end(), [&](const QueuedRelayAck& msg) {
                return now - msg.queuedAt > relayAckTtl_;
            }), q.end());
            mutated = mutated || (q.size() != before);
            if (q.empty()) it = relayAckQueuesByTarget_.erase(it); else ++it;
        }
    }
    if (mutated) {
        SaveRelaySpoolToDisk();
        utils::LogSystem("Expired relay queue entries were cleaned up");
    }
}

bool P2PNode::CheckIncomingRateLimit(const std::shared_ptr<PeerConnection>& peer, PacketType type) {
    if (!peer) return true;

    const bool isMessageHeavy = (
        type == PacketType::ChatMessage ||
        type == PacketType::PrivateMessage ||
        type == PacketType::RelayPrivateMessage ||
        type == PacketType::HistorySyncResponse);

    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(rateLimitMutex_);
    auto& state = rateLimitBySocket_[peer->GetSocket()];
    const auto elapsed = std::chrono::duration<double>(now - state.lastRefill).count();
    state.lastRefill = now;

    state.generalTokens = std::min(generalBurst_, state.generalTokens + elapsed * generalRatePerSecond_);
    state.messageTokens = std::min(messageBurst_, state.messageTokens + elapsed * messageRatePerSecond_);

    if (state.generalTokens < 1.0 || (isMessageHeavy && state.messageTokens < 1.0)) {
        ++state.violations;
        if (state.violations == 1 || state.violations % 5 == 0) {
            const auto remote = peer->GetRemoteNickname().empty() ? peer->GetRemoteNodeId() : peer->GetRemoteNickname();
            utils::LogError("Rate limit exceeded for peer: " + remote);
        }
        if (state.violations >= maxRateViolations_) {
            utils::LogError("Closing peer due to repeated rate-limit violations");
            SafeClosePeer(peer);
        }
        return false;
    }

    state.generalTokens -= 1.0;
    if (isMessageHeavy) state.messageTokens -= 1.0;
    if (state.violations > 0) --state.violations;
    return true;
}

void P2PNode::OnPacket(const std::shared_ptr<PeerConnection>& peer, PacketType type, PacketId packetId, const ByteVector& payload) {
    if (peer) {
        peer->MarkReceivedActivity();
        if (!CheckIncomingRateLimit(peer, type)) return;
        const auto remoteId = peer->GetRemoteNodeId();
        if (!remoteId.empty()) {
            if (auto known = knownNodes_.FindByNodeId(remoteId)) {
                known->lastSeen = std::chrono::steady_clock::now();
                knownNodes_.Upsert(*known);
            }
        }
    }
    switch (type) {
        case PacketType::Hello: HandleHello(peer, payload); break;
        case PacketType::HelloAck: HandleHelloAck(peer, payload); break;
        case PacketType::ChatMessage: HandleChat(peer, packetId, payload); break;
        case PacketType::PeerList: HandlePeerList(payload); break;
        case PacketType::Ping: SendPong(peer); break;
        case PacketType::Pong: break;
        case PacketType::InviteRequest: HandleInviteRequest(peer, packetId, payload); break;
        case PacketType::InviteAccept: HandleInviteAccept(peer, packetId, payload); break;
        case PacketType::InviteReject: HandleInviteReject(peer, packetId, payload); break;
        case PacketType::PrivateMessage: HandlePrivateMessage(peer, packetId, payload); break;
        case PacketType::MessageAck: HandleMessageAck(peer, packetId, payload); break;
        case PacketType::ConnectRequest: HandleConnectRequest(peer, packetId, payload); break;
        case PacketType::UdpPunchRequest: HandleUdpPunchRequest(peer, packetId, payload); break;
        case PacketType::RelayPrivateMessage: HandleRelayPrivateMessage(peer, packetId, payload); break;
        case PacketType::RelayMessageAck: HandleRelayMessageAck(peer, packetId, payload); break;
        case PacketType::HistorySyncRequest: HandleHistorySyncRequest(peer, packetId, payload); break;
        case PacketType::HistorySyncResponse: HandleHistorySyncResponse(peer, packetId, payload); break;
        default: break;
    }
}

void P2PNode::HandleHello(const std::shared_ptr<PeerConnection>& peer, const ByteVector& payload) {
    HelloPayload hello{};
    if (!protocol::DeserializeHello(payload, hello)) { SafeClosePeer(peer); return; }
    if (!FinalizePeerAfterHandshake(peer, hello)) return;
    SendHelloAck(peer);
    SendPeerList(peer);
}

void P2PNode::HandleHelloAck(const std::shared_ptr<PeerConnection>& peer, const ByteVector& payload) {
    HelloPayload hello{};
    if (!protocol::DeserializeHello(payload, hello)) { SafeClosePeer(peer); return; }
    if (!FinalizePeerAfterHandshake(peer, hello)) return;
    SendPeerList(peer);
}

bool P2PNode::FinalizePeerAfterHandshake(const std::shared_ptr<PeerConnection>& peer, const HelloPayload& hello) {
    if (!peer) return false;
    if (hello.nodeId == local_.nodeId) { SafeClosePeer(peer); return false; }

    peer->SetRemoteIdentity(hello.nodeId, hello.nickname, hello.listenPort);

    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        publicKeys_[hello.nodeId] = hello.publicKeyBlob;
    }

    if (!hello.observedIpForRemote.empty() && hello.observedPortForRemote != 0) {
        std::lock_guard<std::mutex> lock(observedEndpointMutex_);
        localObservedIp_ = hello.observedIpForRemote;
        localObservedPort_ = hello.observedPortForRemote;
    }

    KnownNode known{};
    if (auto existingKnown = knownNodes_.FindByNodeId(hello.nodeId)) known = *existingKnown;
    known.nodeId = hello.nodeId;
    known.nickname = hello.nickname;
    known.ip = peer->GetRemoteIp();
    known.port = hello.listenPort;
    known.observedPort = peer->GetRemotePort();
    known.lastSeen = std::chrono::steady_clock::now();
    const bool wasKnown = knownNodes_.Exists(hello.nodeId);
    knownNodes_.Upsert(known);
    ResetReconnectState(hello.nodeId);

    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingPeers_.erase(peer->GetSocket());
    }

    auto existing = peerManager_.FindByNodeId(hello.nodeId);
    if (existing) {
        const bool keepIncoming = PreferIncomingFor(hello.nodeId);
        const bool newIsPreferred = (peer->IsIncoming() == keepIncoming);
        if (newIsPreferred) {
            peerManager_.RemoveBySocket(existing->GetSocket());
            SafeClosePeer(existing);
        } else {
            SafeClosePeer(peer);
            return false;
        }
    }

    if (!peer->TrySetActive()) { SafeClosePeer(peer); return false; }
    if (!peerManager_.AddPeer(peer)) { SafeClosePeer(peer); return false; }

    utils::LogSystem("Connected with " + hello.nickname);
    FlushRelayQueueForTarget(hello.nodeId);
    FlushRelayAckQueueForTarget(hello.nodeId);
    RequestHistorySync(hello.nodeId);
    if (!wasKnown) BroadcastPeerListToAll();
    return true;
}

void P2PNode::HandleChat(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;
    ChatPayload chat{};
    if (!protocol::DeserializeChat(payload, chat)) return;
    utils::LogGlobal(chat.originNickname, chat.text);
    auto packet = protocol::MakePacket(PacketType::ChatMessage, packetId, payload);
    BroadcastRaw(packet, peer->GetRemoteNodeId());
}

void P2PNode::HandlePeerList(const ByteVector& payload) {
    std::vector<KnownNode> nodes;
    if (!protocol::DeserializePeerList(payload, nodes)) return;
    for (auto& node : nodes) {
        if (node.nodeId == local_.nodeId) continue;
        if (node.ip.empty() || (node.port == 0 && node.observedPort == 0)) continue;
        node.lastSeen = std::chrono::steady_clock::now();
        knownNodes_.Upsert(node);
    }
}

ByteVector P2PNode::BuildInviteRequestSignedData(const InviteRequestPayload& p) const {
    ByteVector out;
    utils::WriteUint64(out, p.inviteId);
    utils::WriteString(out, p.fromNodeId);
    utils::WriteString(out, p.fromNickname);
    utils::WriteString(out, p.toNodeId);
    return out;
}

ByteVector P2PNode::BuildInviteAcceptSignedData(const InviteAcceptPayload& p) const {
    ByteVector out;
    utils::WriteUint64(out, p.inviteId);
    utils::WriteUint64(out, p.sessionId);
    utils::WriteString(out, p.fromNodeId);
    utils::WriteString(out, p.fromNickname);
    utils::WriteString(out, p.toNodeId);
    return out;
}

ByteVector P2PNode::BuildInviteRejectSignedData(const InviteRejectPayload& p) const {
    ByteVector out;
    utils::WriteUint64(out, p.inviteId);
    utils::WriteString(out, p.fromNodeId);
    utils::WriteString(out, p.fromNickname);
    utils::WriteString(out, p.toNodeId);
    utils::WriteString(out, p.reason);
    return out;
}

ByteVector P2PNode::BuildPrivateMessageSignedData(const PrivateMessagePayload& p) const {
    ByteVector out;
    utils::WriteUint64(out, p.messageId);
    utils::WriteUint64(out, p.sessionId);
    utils::WriteUint64(out, p.sequenceNumber);
    utils::WriteString(out, p.fromNodeId);
    utils::WriteString(out, p.fromNickname);
    utils::WriteString(out, p.toNodeId);
    utils::WriteString(out, p.text);
    return out;
}

ByteVector P2PNode::BuildMessageAckSignedData(const MessageAckPayload& p) const {
    ByteVector out;
    utils::WriteUint64(out, p.messageId);
    utils::WriteUint64(out, p.sessionId);
    utils::WriteString(out, p.fromNodeId);
    utils::WriteString(out, p.toNodeId);
    utils::WriteUint64(out, p.ackedRelayPacketId);
    return out;
}

ByteVector P2PNode::BuildConnectRequestSignedData(const ConnectRequestPayload& p) const {
    ByteVector out;
    utils::WriteString(out, p.requesterNodeId);
    utils::WriteString(out, p.requesterNickname);
    utils::WriteString(out, p.targetNodeId);
    utils::WriteString(out, p.requesterObservedIp);
    utils::WriteUint16(out, p.requesterAdvertisedPort);
    utils::WriteUint16(out, p.requesterObservedPort);
    return out;
}


ByteVector P2PNode::BuildUdpPunchRequestSignedData(const UdpPunchRequestPayload& p) const {
    ByteVector out;
    utils::WriteString(out, p.requesterNodeId);
    utils::WriteString(out, p.requesterNickname);
    utils::WriteString(out, p.targetNodeId);
    utils::WriteString(out, p.requesterObservedUdpIp);
    utils::WriteUint16(out, p.requesterAdvertisedTcpPort);
    utils::WriteUint16(out, p.requesterObservedUdpPort);
    return out;
}


ByteVector P2PNode::BuildHistorySyncRequestSignedData(const HistorySyncRequestPayload& p) const {
    ByteVector out;
    utils::WriteString(out, p.requesterNodeId);
    utils::WriteString(out, p.targetNodeId);
    utils::WriteUint64(out, p.afterMessageId);
    return out;
}

ByteVector P2PNode::BuildHistorySyncResponseSignedData(const HistorySyncResponsePayload& p) const {
    ByteVector out;
    utils::WriteString(out, p.responderNodeId);
    utils::WriteString(out, p.targetNodeId);
    utils::WriteBytes(out, p.messagesBlob);
    return out;
}

void P2PNode::SendInvite(const NodeId& targetNodeId) {
    InviteRequestPayload payload{};
    payload.inviteId = utils::GeneratePacketId();
    payload.fromNodeId = local_.nodeId;
    payload.fromNickname = local_.nickname;
    payload.toNodeId = targetNodeId;
    signer_.Sign(BuildInviteRequestSignedData(payload), payload.signature);

    PendingInvite inv{payload.inviteId, payload.fromNodeId, payload.fromNickname, payload.toNodeId};
    {
        std::lock_guard<std::mutex> lock(invitesMutex_);
        outgoingInvites_[payload.inviteId] = inv;
    }

    const PacketId packetId = utils::GeneratePacketId();
    router_.MarkSeen(packetId);
    auto body = protocol::SerializeInviteRequest(payload);
    auto packet = protocol::MakePacket(PacketType::InviteRequest, packetId, body);
    utils::LogSystem("Private invite sent");
    BroadcastRaw(packet);
}

void P2PNode::HandleInviteRequest(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;
    InviteRequestPayload p{};
    if (!protocol::DeserializeInviteRequest(payload, p)) return;

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(p.fromNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }
    if (!signer_.Verify(BuildInviteRequestSignedData(p), p.signature, pub)) {
        utils::LogError("Invite signature invalid");
        return;
    }

    if (p.toNodeId == local_.nodeId) {
        PendingInvite inv{p.inviteId, p.fromNodeId, p.fromNickname, p.toNodeId};
        {
            std::lock_guard<std::mutex> lock(invitesMutex_);
            incomingInvites_[p.inviteId] = inv;
        }
        utils::LogSystem(p.fromNickname + " invites you to private chat");
        return;
    }

    auto packet = protocol::MakePacket(PacketType::InviteRequest, packetId, payload);
    BroadcastRaw(packet, peer->GetRemoteNodeId());
}

void P2PNode::AcceptInvite(const NodeId& fromNodeId) {
    auto inviteOpt = FindIncomingInviteByFromNodeId(fromNodeId);
    if (!inviteOpt) { utils::LogError("No invite from this user"); return; }
    auto invite = *inviteOpt;
    SessionId sessionId = utils::GeneratePacketId();

    InviteAcceptPayload payload{};
    payload.inviteId = invite.inviteId;
    payload.sessionId = sessionId;
    payload.fromNodeId = local_.nodeId;
    payload.fromNickname = local_.nickname;
    payload.toNodeId = invite.fromNodeId;
    signer_.Sign(BuildInviteAcceptSignedData(payload), payload.signature);

    {
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        sessionsById_[sessionId] = {sessionId, invite.fromNodeId, invite.fromNickname, true};
        sessionByPeer_[invite.fromNodeId] = sessionId;
    }
    {
        std::lock_guard<std::mutex> lock(invitesMutex_);
        incomingInvites_.erase(invite.inviteId);
    }

    PacketId packetId = utils::GeneratePacketId();
    router_.MarkSeen(packetId);
    auto body = protocol::SerializeInviteAccept(payload);
    auto packet = protocol::MakePacket(PacketType::InviteAccept, packetId, body);
    utils::LogSystem("Private chat opened with " + invite.fromNickname);
    PrintStoredConversation(invite.fromNodeId, invite.fromNickname);
    BroadcastRaw(packet);
}

void P2PNode::HandleInviteAccept(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;
    InviteAcceptPayload p{};
    if (!protocol::DeserializeInviteAccept(payload, p)) return;

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(p.fromNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }
    if (!signer_.Verify(BuildInviteAcceptSignedData(p), p.signature, pub)) {
        utils::LogError("Accept signature invalid");
        return;
    }

    if (p.toNodeId == local_.nodeId) {
        {
            std::lock_guard<std::mutex> lock(invitesMutex_);
            outgoingInvites_.erase(p.inviteId);
        }
        EnsureSessionForPeer(p.fromNodeId, p.fromNickname, p.sessionId);
        utils::LogSystem("Private chat opened with " + p.fromNickname);
        PrintStoredConversation(p.fromNodeId, p.fromNickname);
        return;
    }

    auto packet = protocol::MakePacket(PacketType::InviteAccept, packetId, payload);
    BroadcastRaw(packet, peer->GetRemoteNodeId());
}

void P2PNode::BroadcastChat(const std::string& text) {
    ChatPayload payload{};
    payload.originNodeId = local_.nodeId;
    payload.originNickname = local_.nickname;
    payload.text = text;

    const PacketId packetId = utils::GeneratePacketId();
    router_.MarkSeen(packetId);

    auto body = protocol::SerializeChat(payload);
    auto packet = protocol::MakePacket(PacketType::ChatMessage, packetId, body);

    utils::LogGlobal(local_.nickname, text);
    BroadcastRaw(packet);
}

void P2PNode::RejectInvite(const NodeId& fromNodeId, const std::string& reason) {
    auto inviteOpt = FindIncomingInviteByFromNodeId(fromNodeId);
    if (!inviteOpt) { utils::LogError("No invite from this user"); return; }
    auto invite = *inviteOpt;

    InviteRejectPayload payload{};
    payload.inviteId = invite.inviteId;
    payload.fromNodeId = local_.nodeId;
    payload.fromNickname = local_.nickname;
    payload.toNodeId = invite.fromNodeId;
    payload.reason = reason;
    signer_.Sign(BuildInviteRejectSignedData(payload), payload.signature);

    {
        std::lock_guard<std::mutex> lock(invitesMutex_);
        incomingInvites_.erase(invite.inviteId);
    }

    PacketId packetId = utils::GeneratePacketId();
    router_.MarkSeen(packetId);
    auto body = protocol::SerializeInviteReject(payload);
    auto packet = protocol::MakePacket(PacketType::InviteReject, packetId, body);
    utils::LogSystem("Invite rejected");
    BroadcastRaw(packet);
}

void P2PNode::HandleInviteReject(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;
    InviteRejectPayload p{};
    if (!protocol::DeserializeInviteReject(payload, p)) return;

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(p.fromNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }
    if (!signer_.Verify(BuildInviteRejectSignedData(p), p.signature, pub)) {
        utils::LogError("Reject signature invalid");
        return;
    }

    if (p.toNodeId == local_.nodeId) {
        {
            std::lock_guard<std::mutex> lock(invitesMutex_);
            outgoingInvites_.erase(p.inviteId);
        }
        utils::LogSystem(p.fromNickname + " rejected the invite");
        return;
    }

    auto packet = protocol::MakePacket(PacketType::InviteReject, packetId, payload);
    BroadcastRaw(packet, peer->GetRemoteNodeId());
}

void P2PNode::SendPrivateMessage(const NodeId& targetNodeId, const std::string& text) {
    auto sessionIdOpt = FindSessionByPeer(targetNodeId);
    if (!sessionIdOpt) { utils::LogError("No private session with this user"); return; }

    PrivateMessagePayload payload{};
    payload.messageId = GenerateMessageIdForNode(local_.nodeId);
    payload.sessionId = *sessionIdOpt;
    payload.sequenceNumber = GetNextOutgoingSequence(targetNodeId);
    payload.fromNodeId = local_.nodeId;
    payload.fromNickname = local_.nickname;
    payload.toNodeId = targetNodeId;
    payload.text = text;
    signer_.Sign(BuildPrivateMessageSignedData(payload), payload.signature);

    bool delivered = false;
    auto body = protocol::SerializePrivateMessage(payload);
    auto packet = protocol::MakePacket(PacketType::PrivateMessage, payload.messageId, body);
    if (auto directPeer = peerManager_.FindByNodeId(targetNodeId)) {
        router_.MarkSeen(payload.messageId);
        directPeer->EnqueuePacket(packet);
        delivered = true;
    } else {
        delivered = RelayPrivateMessageToNetwork(payload);
    }

    StoredMessageState state = StoredMessageState::Failed;
    if (delivered && peerManager_.FindByNodeId(targetNodeId)) state = StoredMessageState::Sent;
    else if (delivered) state = StoredMessageState::Relayed;
    AppendStoredPrivateMessage(payload, StoredMessageDirection::Outgoing, state, localPublicKeyBlob_);
    if (!delivered) {
        utils::LogError("Target peer is not connected and there is no relay path right now");
    } else if (!peerManager_.FindByNodeId(targetNodeId)) {
        utils::LogSystem("Private message sent through relay/offline queue");
    }
    utils::LogPrivate(local_.nickname, text);
}

void P2PNode::HandlePrivateMessage(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;

    PrivateMessagePayload p{};
    if (!protocol::DeserializePrivateMessage(payload, p)) return;

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(p.fromNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }
    if (!signer_.Verify(BuildPrivateMessageSignedData(p), p.signature, pub)) {
        utils::LogError("Private message signature invalid");
        return;
    }

    if (p.toNodeId != local_.nodeId) return;
    BufferOrDeliverIncomingPrivateMessage(p, pub, 0, true);
}

void P2PNode::HandleMessageAck(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;
    MessageAckPayload ack{};
    if (!protocol::DeserializeMessageAck(payload, ack)) return;
    if (ack.toNodeId != local_.nodeId) return;

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(ack.fromNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }
    if (!signer_.Verify(BuildMessageAckSignedData(ack), ack.signature, pub)) {
        utils::LogError("Message ACK signature invalid");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(ackMutex_);
        if (!seenMessageAcks_.insert(ack.messageId).second) return;
        deliveredOutgoingMessageIds_.insert(ack.messageId);
    }

    UpdateStoredMessageState(ack.fromNodeId, ack.messageId, StoredMessageState::Delivered);
    utils::LogSystem("Message delivered: id=" + std::to_string(ack.messageId));
}

bool P2PNode::RelayPrivateMessageToNetwork(const PrivateMessagePayload& payload) {
    auto peers = peerManager_.GetAllPeers();
    if (peers.empty()) return false;

    RelayPrivateMessagePayload relay{};
    relay.relayPacketId = utils::GeneratePacketId();
    relay.relayFromNodeId = local_.nodeId;
    relay.finalTargetNodeId = payload.toNodeId;
    relay.privateMessagePacket = protocol::SerializePrivateMessage(payload);

    QueueRelayMessage(relay);

    router_.MarkSeen(relay.relayPacketId);
    auto body = protocol::SerializeRelayPrivateMessage(relay);
    auto packet = protocol::MakePacket(PacketType::RelayPrivateMessage, relay.relayPacketId, body);

    if (auto directPeer = peerManager_.FindByNodeId(payload.toNodeId)) directPeer->EnqueuePacket(packet);
    else BroadcastRaw(packet);
    return true;
}

bool P2PNode::RelayMessageAckToNetwork(const MessageAckPayload& payload) {
    auto peers = peerManager_.GetAllPeers();
    if (peers.empty()) return false;

    RelayMessageAckPayload relay{};
    relay.relayPacketId = utils::GeneratePacketId();
    relay.relayFromNodeId = local_.nodeId;
    relay.finalTargetNodeId = payload.toNodeId;
    relay.ackPacket = protocol::SerializeMessageAck(payload);

    QueueRelayAck(relay);

    router_.MarkSeen(relay.relayPacketId);
    auto body = protocol::SerializeRelayMessageAck(relay);
    auto packet = protocol::MakePacket(PacketType::RelayMessageAck, relay.relayPacketId, body);

    if (auto directPeer = peerManager_.FindByNodeId(payload.toNodeId)) directPeer->EnqueuePacket(packet);
    else BroadcastRaw(packet);
    return true;
}

void P2PNode::QueueRelayMessage(const RelayPrivateMessagePayload& payload) {
    PrivateMessagePayload inner{};
    if (!protocol::DeserializePrivateMessage(payload.privateMessagePacket, inner)) return;

    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        auto& q = relayQueuesByTarget_[payload.finalTargetNodeId];
        for (const auto& existing : q) {
            if (existing.relayPacketId == payload.relayPacketId || existing.messageId == inner.messageId) return;
        }
        QueuedRelayMessage item{};
        item.relayPacketId = payload.relayPacketId;
        item.messageId = inner.messageId;
        item.relayFromNodeId = payload.relayFromNodeId;
        item.finalTargetNodeId = payload.finalTargetNodeId;
        item.privateMessagePacket = payload.privateMessagePacket;
        item.queuedAt = std::chrono::system_clock::now();
        item.nextAttemptAt = std::chrono::steady_clock::now();
        item.attemptCount = 0;
        q.push_back(std::move(item));
    }
    SaveRelaySpoolToDisk();
}

void P2PNode::QueueRelayAck(const RelayMessageAckPayload& payload) {
    MessageAckPayload inner{};
    if (!protocol::DeserializeMessageAck(payload.ackPacket, inner)) return;

    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        auto& q = relayAckQueuesByTarget_[payload.finalTargetNodeId];
        for (const auto& existing : q) {
            if (existing.relayPacketId == payload.relayPacketId || existing.messageId == inner.messageId) return;
        }
        QueuedRelayAck item{};
        item.relayPacketId = payload.relayPacketId;
        item.messageId = inner.messageId;
        item.relayFromNodeId = payload.relayFromNodeId;
        item.finalTargetNodeId = payload.finalTargetNodeId;
        item.ackPacket = payload.ackPacket;
        item.queuedAt = std::chrono::system_clock::now();
        item.nextAttemptAt = std::chrono::steady_clock::now();
        item.attemptCount = 0;
        q.push_back(std::move(item));
    }
    SaveRelaySpoolToDisk();
}

void P2PNode::FlushRelayQueueForTarget(const NodeId& targetNodeId) {
    std::deque<QueuedRelayMessage> pending;
    bool mutated = false;
    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        auto it = relayQueuesByTarget_.find(targetNodeId);
        if (it == relayQueuesByTarget_.end() || it->second.empty()) return;
        const auto now = std::chrono::steady_clock::now();
        for (auto& msg : it->second) {
            if (msg.nextAttemptAt > now) continue;
            pending.push_back(msg);
            ++msg.attemptCount;
            auto delaySeconds = std::min<std::uint32_t>(60u, 1u << std::min<std::uint32_t>(msg.attemptCount, 5u));
            msg.nextAttemptAt = now + std::chrono::seconds(delaySeconds);
            mutated = true;
        }
    }

    auto peer = peerManager_.FindByNodeId(targetNodeId);
    if (!peer || pending.empty()) {
        if (mutated) SaveRelaySpoolToDisk();
        return;
    }

    for (const auto& msg : pending) {
        RelayPrivateMessagePayload relay{};
        relay.relayPacketId = msg.relayPacketId;
        relay.relayFromNodeId = msg.relayFromNodeId;
        relay.finalTargetNodeId = msg.finalTargetNodeId;
        relay.privateMessagePacket = msg.privateMessagePacket;
        auto body = protocol::SerializeRelayPrivateMessage(relay);
        auto packet = protocol::MakePacket(PacketType::RelayPrivateMessage, relay.relayPacketId, body);
        peer->EnqueuePacket(packet);
    }

    if (mutated) SaveRelaySpoolToDisk();
    utils::LogSystem("Flushed queued relayed messages to " + targetNodeId);
}

void P2PNode::FlushRelayAckQueueForTarget(const NodeId& targetNodeId) {
    std::deque<QueuedRelayAck> pending;
    bool mutated = false;
    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        auto it = relayAckQueuesByTarget_.find(targetNodeId);
        if (it == relayAckQueuesByTarget_.end() || it->second.empty()) return;
        const auto now = std::chrono::steady_clock::now();
        for (auto& msg : it->second) {
            if (msg.nextAttemptAt > now) continue;
            pending.push_back(msg);
            ++msg.attemptCount;
            auto delaySeconds = std::min<std::uint32_t>(60u, 1u << std::min<std::uint32_t>(msg.attemptCount, 5u));
            msg.nextAttemptAt = now + std::chrono::seconds(delaySeconds);
            mutated = true;
        }
    }

    auto peer = peerManager_.FindByNodeId(targetNodeId);
    if (!peer || pending.empty()) {
        if (mutated) SaveRelaySpoolToDisk();
        return;
    }

    for (const auto& msg : pending) {
        RelayMessageAckPayload relay{};
        relay.relayPacketId = msg.relayPacketId;
        relay.relayFromNodeId = msg.relayFromNodeId;
        relay.finalTargetNodeId = msg.finalTargetNodeId;
        relay.ackPacket = msg.ackPacket;
        auto body = protocol::SerializeRelayMessageAck(relay);
        auto packet = protocol::MakePacket(PacketType::RelayMessageAck, relay.relayPacketId, body);
        peer->EnqueuePacket(packet);
    }

    if (mutated) SaveRelaySpoolToDisk();
    utils::LogSystem("Flushed queued relayed ACKs to " + targetNodeId);
}

void P2PNode::RemoveQueuedRelayMessageByMessageId(const NodeId& targetNodeId, MessageId messageId) {
    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        auto it = relayQueuesByTarget_.find(targetNodeId);
        if (it == relayQueuesByTarget_.end()) return;
        auto& q = it->second;
        q.erase(std::remove_if(q.begin(), q.end(), [&](const QueuedRelayMessage& m) { return m.messageId == messageId; }), q.end());
        if (q.empty()) relayQueuesByTarget_.erase(it);
    }
    SaveRelaySpoolToDisk();
}

void P2PNode::RemoveQueuedRelayAckByMessageId(const NodeId& targetNodeId, MessageId messageId) {
    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        auto it = relayAckQueuesByTarget_.find(targetNodeId);
        if (it == relayAckQueuesByTarget_.end()) return;
        auto& q = it->second;
        q.erase(std::remove_if(q.begin(), q.end(), [&](const QueuedRelayAck& m) { return m.messageId == messageId; }), q.end());
        if (q.empty()) relayAckQueuesByTarget_.erase(it);
    }
    SaveRelaySpoolToDisk();
}

void P2PNode::SendDeliveryAck(const PrivateMessagePayload& message, PacketId ackedRelayPacketId) {
    MessageAckPayload ack{};
    ack.messageId = message.messageId;
    ack.sessionId = message.sessionId;
    ack.fromNodeId = local_.nodeId;
    ack.toNodeId = message.fromNodeId;
    ack.ackedRelayPacketId = ackedRelayPacketId;
    signer_.Sign(BuildMessageAckSignedData(ack), ack.signature);

    auto body = protocol::SerializeMessageAck(ack);
    auto packet = protocol::MakePacket(PacketType::MessageAck, utils::GeneratePacketId(), body);
    if (auto directPeer = peerManager_.FindByNodeId(ack.toNodeId)) {
        directPeer->EnqueuePacket(packet);
    } else {
        RelayMessageAckToNetwork(ack);
    }
}

void P2PNode::HandleRelayPrivateMessage(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;

    RelayPrivateMessagePayload relay{};
    if (!protocol::DeserializeRelayPrivateMessage(payload, relay)) return;
    if (relay.finalTargetNodeId.empty() || relay.privateMessagePacket.empty()) return;

    QueueRelayMessage(relay);

    if (relay.finalTargetNodeId == local_.nodeId) {
        {
            std::lock_guard<std::mutex> lock(relayMutex_);
            if (!deliveredRelayPackets_.insert(relay.relayPacketId).second) return;
        }
        PrivateMessagePayload inner{};
        if (!protocol::DeserializePrivateMessage(relay.privateMessagePacket, inner)) return;

        ByteVector pub;
        {
            std::lock_guard<std::mutex> lock(publicKeysMutex_);
            auto it = publicKeys_.find(inner.fromNodeId);
            if (it == publicKeys_.end()) return;
            pub = it->second;
        }
        if (!signer_.Verify(BuildPrivateMessageSignedData(inner), inner.signature, pub)) {
            utils::LogError("Private message signature invalid");
            return;
        }
        if (inner.toNodeId != local_.nodeId) return;

        if (router_.MarkSeen(inner.messageId)) {
            BufferOrDeliverIncomingPrivateMessage(inner, pub, relay.relayPacketId, true);
        }
        return;
    }

    if (auto directPeer = peerManager_.FindByNodeId(relay.finalTargetNodeId)) {
        directPeer->EnqueuePacket(protocol::MakePacket(PacketType::RelayPrivateMessage, relay.relayPacketId, payload));
        return;
    }

    BroadcastRaw(protocol::MakePacket(PacketType::RelayPrivateMessage, relay.relayPacketId, payload), peer ? peer->GetRemoteNodeId() : "");
}

void P2PNode::HandleRelayMessageAck(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;

    RelayMessageAckPayload relay{};
    if (!protocol::DeserializeRelayMessageAck(payload, relay)) return;
    if (relay.finalTargetNodeId.empty() || relay.ackPacket.empty()) return;

    QueueRelayAck(relay);

    MessageAckPayload inner{};
    if (!protocol::DeserializeMessageAck(relay.ackPacket, inner)) return;
    RemoveQueuedRelayMessageByMessageId(inner.fromNodeId, inner.messageId);

    if (relay.finalTargetNodeId == local_.nodeId) {
        {
            std::lock_guard<std::mutex> lock(relayMutex_);
            if (!deliveredRelayAckPackets_.insert(relay.relayPacketId).second) return;
        }
        RemoveQueuedRelayAckByMessageId(local_.nodeId, inner.messageId);
        HandleMessageAck(peer, utils::GeneratePacketId(), relay.ackPacket);
        return;
    }

    if (auto directPeer = peerManager_.FindByNodeId(relay.finalTargetNodeId)) {
        directPeer->EnqueuePacket(protocol::MakePacket(PacketType::RelayMessageAck, relay.relayPacketId, payload));
        return;
    }

    BroadcastRaw(protocol::MakePacket(PacketType::RelayMessageAck, relay.relayPacketId, payload), peer ? peer->GetRemoteNodeId() : "");
}



void P2PNode::RequestHistorySync(const NodeId& peerNodeId) {
    if (peerNodeId.empty()) return;
    auto peer = peerManager_.FindByNodeId(peerNodeId);
    if (!peer) return;

    MessageId afterMessageId = 0;
    std::vector<StoredConversationMessage> messages;
    std::string error;
    if (ConversationStore::LoadConversation(historyRootDir_, local_.nodeId, peerNodeId, signer_, messages, &error)) {
        if (!messages.empty()) afterMessageId = messages.back().messageId;
    }

    HistorySyncRequestPayload req{};
    req.requesterNodeId = local_.nodeId;
    req.targetNodeId = peerNodeId;
    req.afterMessageId = afterMessageId;
    signer_.Sign(BuildHistorySyncRequestSignedData(req), req.signature);

    auto body = protocol::SerializeHistorySyncRequest(req);
    peer->EnqueuePacket(protocol::MakePacket(PacketType::HistorySyncRequest, utils::GeneratePacketId(), body));
}

void P2PNode::RetryRelayQueues() {
    std::vector<NodeId> targets;
    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        for (const auto& [target, _] : relayQueuesByTarget_) targets.push_back(target);
        for (const auto& [target, _] : relayAckQueuesByTarget_) targets.push_back(target);
    }
    std::sort(targets.begin(), targets.end());
    targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
    for (const auto& target : targets) {
        FlushRelayQueueForTarget(target);
        FlushRelayAckQueueForTarget(target);
    }
}

bool P2PNode::SaveRelaySpoolToDisk() const {
    try {
        fs::path dir = fs::path(relaySpoolRootDir_) / local_.nodeId;
        fs::create_directories(dir);
        for (const auto& entry : fs::directory_iterator(dir)) {
            if (entry.is_regular_file()) fs::remove(entry.path());
        }

        std::lock_guard<std::mutex> lock(relayMutex_);
        for (const auto& [target, q] : relayQueuesByTarget_) {
            for (const auto& msg : q) {
                std::ofstream out(RelayMsgPath(dir, target, msg.messageId), std::ios::binary | std::ios::trunc);
                if (!out) continue;
                out << "type=msg\n";
                out << "target=" << target << "\n";
                out << "relay_packet_id=" << msg.relayPacketId << "\n";
                out << "message_id=" << msg.messageId << "\n";
                out << "relay_from=" << msg.relayFromNodeId << "\n";
                out << "payload_hex=" << BytesToHexLocal(msg.privateMessagePacket) << "\n";
                out << "attempt_count=" << msg.attemptCount << "\n";
                out << "queued_at_unix=" << static_cast<long long>(std::chrono::system_clock::to_time_t(msg.queuedAt)) << "\n";
            }
        }
        for (const auto& [target, q] : relayAckQueuesByTarget_) {
            for (const auto& msg : q) {
                std::ofstream out(RelayAckPath(dir, target, msg.messageId), std::ios::binary | std::ios::trunc);
                if (!out) continue;
                out << "type=ack\n";
                out << "target=" << target << "\n";
                out << "relay_packet_id=" << msg.relayPacketId << "\n";
                out << "message_id=" << msg.messageId << "\n";
                out << "relay_from=" << msg.relayFromNodeId << "\n";
                out << "payload_hex=" << BytesToHexLocal(msg.ackPacket) << "\n";
                out << "attempt_count=" << msg.attemptCount << "\n";
                out << "queued_at_unix=" << static_cast<long long>(std::chrono::system_clock::to_time_t(msg.queuedAt)) << "\n";
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

void P2PNode::LoadRelaySpoolFromDisk() {
    try {
        fs::path dir = fs::path(relaySpoolRootDir_) / local_.nodeId;
        if (!fs::exists(dir)) return;

        std::lock_guard<std::mutex> lock(relayMutex_);
        relayQueuesByTarget_.clear();
        relayAckQueuesByTarget_.clear();
        for (const auto& entry : fs::directory_iterator(dir)) {
            if (!entry.is_regular_file()) continue;
            std::ifstream in(entry.path(), std::ios::binary);
            if (!in) continue;
            std::string line, type, target, relayFrom, payloadHex;
            PacketId relayPacketId = 0;
            MessageId messageId = 0;
            std::uint32_t attemptCount = 0;
            std::time_t queuedAtUnix = 0;
            while (std::getline(in, line)) {
                auto pos = line.find('=');
                if (pos == std::string::npos) continue;
                auto k = line.substr(0, pos);
                auto v = line.substr(pos + 1);
                if (k == "type") type = v;
                else if (k == "target") target = v;
                else if (k == "relay_packet_id") relayPacketId = static_cast<PacketId>(std::stoull(v));
                else if (k == "message_id") messageId = static_cast<MessageId>(std::stoull(v));
                else if (k == "relay_from") relayFrom = v;
                else if (k == "payload_hex") payloadHex = v;
                else if (k == "attempt_count") attemptCount = static_cast<std::uint32_t>(std::stoul(v));
                else if (k == "queued_at_unix") queuedAtUnix = static_cast<std::time_t>(std::stoll(v));
            }
            ByteVector payload;
            if (target.empty() || payloadHex.empty() || !HexToBytesLocal(payloadHex, payload)) continue;
            if (type == "msg") {
                QueuedRelayMessage item{};
                item.relayPacketId = relayPacketId;
                item.messageId = messageId;
                item.relayFromNodeId = relayFrom;
                item.finalTargetNodeId = target;
                item.privateMessagePacket = std::move(payload);
                item.queuedAt = queuedAtUnix != 0 ? std::chrono::system_clock::from_time_t(queuedAtUnix) : std::chrono::system_clock::now();
                item.attemptCount = attemptCount;
                item.nextAttemptAt = std::chrono::steady_clock::now();
                relayQueuesByTarget_[target].push_back(std::move(item));
            } else if (type == "ack") {
                QueuedRelayAck item{};
                item.relayPacketId = relayPacketId;
                item.messageId = messageId;
                item.relayFromNodeId = relayFrom;
                item.finalTargetNodeId = target;
                item.ackPacket = std::move(payload);
                item.queuedAt = queuedAtUnix != 0 ? std::chrono::system_clock::from_time_t(queuedAtUnix) : std::chrono::system_clock::now();
                item.attemptCount = attemptCount;
                item.nextAttemptAt = std::chrono::steady_clock::now();
                relayAckQueuesByTarget_[target].push_back(std::move(item));
            }
        }
    } catch (...) {
    }
}

void P2PNode::HandleHistorySyncRequest(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;
    HistorySyncRequestPayload req{};
    if (!protocol::DeserializeHistorySyncRequest(payload, req)) return;
    if (req.targetNodeId != local_.nodeId) return;

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(req.requesterNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }
    if (!signer_.Verify(BuildHistorySyncRequestSignedData(req), req.signature, pub)) return;

    std::vector<StoredSignedPrivateMessage> signedMessages;
    std::string error;
    if (!ConversationStore::LoadSignedOutgoingMessagesAfter(historyRootDir_, local_.nodeId, req.requesterNodeId, req.afterMessageId, signer_, signedMessages, &error)) {
        return;
    }

    ByteVector blob;
    utils::WriteUint32(blob, static_cast<std::uint32_t>(signedMessages.size()));
    for (const auto& msg : signedMessages) {
        auto serialized = protocol::SerializePrivateMessage(msg.payload);
        utils::WriteBytes(blob, serialized);
    }

    HistorySyncResponsePayload resp{};
    resp.responderNodeId = local_.nodeId;
    resp.targetNodeId = req.requesterNodeId;
    resp.messagesBlob = std::move(blob);
    signer_.Sign(BuildHistorySyncResponseSignedData(resp), resp.signature);

    auto body = protocol::SerializeHistorySyncResponse(resp);
    if (peer) peer->EnqueuePacket(protocol::MakePacket(PacketType::HistorySyncResponse, utils::GeneratePacketId(), body));
}

void P2PNode::HandleHistorySyncResponse(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;
    HistorySyncResponsePayload resp{};
    if (!protocol::DeserializeHistorySyncResponse(payload, resp)) return;
    if (resp.targetNodeId != local_.nodeId) return;

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(resp.responderNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }
    if (!signer_.Verify(BuildHistorySyncResponseSignedData(resp), resp.signature, pub)) return;

    std::size_t offset = 0;
    std::uint32_t count = 0;
    if (!utils::ReadUint32(resp.messagesBlob, offset, count)) return;
    std::size_t imported = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        ByteVector itemBytes;
        if (!utils::ReadBytes(resp.messagesBlob, offset, itemBytes)) return;
        PrivateMessagePayload msg{};
        if (!protocol::DeserializePrivateMessage(itemBytes, msg)) continue;
        bool exists = false;
        std::string error;
        if (!ConversationStore::HasMessageId(historyRootDir_, local_.nodeId, resp.responderNodeId, msg.messageId, signer_, &exists, &error)) continue;
        if (exists) continue;
        if (!signer_.Verify(BuildPrivateMessageSignedData(msg), msg.signature, pub)) continue;
        if (msg.sequenceNumber > 0) {
            auto before = HasStoredMessageForPeer(resp.responderNodeId, msg.messageId);
            BufferOrDeliverIncomingPrivateMessage(msg, pub, 0, false);
            auto after = HasStoredMessageForPeer(resp.responderNodeId, msg.messageId);
            if (!before && after) ++imported;
        } else {
            EnsureSessionForPeer(resp.responderNodeId, peer ? peer->GetRemoteNickname() : std::string(), msg.sessionId);
            AppendStoredPrivateMessage(msg, StoredMessageDirection::Incoming, StoredMessageState::Delivered, pub);
            ++imported;
        }
    }
    if (imported > 0) {
        utils::LogSystem("History sync imported " + std::to_string(imported) + " message(s) from " + resp.responderNodeId);
    }
}

void P2PNode::HandleConnectRequest(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;

    ConnectRequestPayload p{};
    if (!protocol::DeserializeConnectRequest(payload, p)) return;

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(p.requesterNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }

    if (!signer_.Verify(BuildConnectRequestSignedData(p), p.signature, pub)) {
        utils::LogError("Connect request signature invalid");
        return;
    }

    if (p.targetNodeId == local_.nodeId) {
        if (peerManager_.HasNode(p.requesterNodeId)) return;

        KnownNode requester{};
        requester.nodeId = p.requesterNodeId;
        requester.nickname = p.requesterNickname;
        requester.ip = p.requesterObservedIp;
        requester.port = p.requesterAdvertisedPort;
        requester.observedPort = p.requesterObservedPort;
        requester.lastSeen = std::chrono::steady_clock::now();
        knownNodes_.Upsert(requester);

        utils::LogSystem("Received reverse-connect request from " + p.requesterNickname);
        if (TryConnectToKnownNode(requester)) {
            utils::LogSystem("Reverse connect attempt launched to " + p.requesterNickname);
        } else {
            utils::LogError("Reverse connect attempt failed for " + p.requesterNickname);
        }
        return;
    }

    auto packet = protocol::MakePacket(PacketType::ConnectRequest, packetId, payload);
    BroadcastRaw(packet, peer ? peer->GetRemoteNodeId() : "");
}


void P2PNode::HandleUdpPunchRequest(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;

    UdpPunchRequestPayload p{};
    if (!protocol::DeserializeUdpPunchRequest(payload, p)) return;

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(p.requesterNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }

    if (!signer_.Verify(BuildUdpPunchRequestSignedData(p), p.signature, pub)) {
        utils::LogError("UDP punch request signature invalid");
        return;
    }

    if (p.targetNodeId == local_.nodeId) {
        if (peerManager_.HasNode(p.requesterNodeId)) return;

        KnownNode requester{};
        if (auto existing = knownNodes_.FindByNodeId(p.requesterNodeId)) requester = *existing;
        requester.nodeId = p.requesterNodeId;
        requester.nickname = p.requesterNickname;
        if (!p.requesterObservedUdpIp.empty()) requester.ip = p.requesterObservedUdpIp;
        requester.port = p.requesterAdvertisedTcpPort;
        requester.observedUdpPort = p.requesterObservedUdpPort;
        requester.lastSeen = std::chrono::steady_clock::now();
        knownNodes_.Upsert(requester);

        utils::LogSystem("Received UDP hole-punch request from " + p.requesterNickname);
        SendUdpPunchBurst(requester, "target");
        TryConnectToKnownNode(requester);
        RequestReverseConnect(requester);
        return;
    }

    auto packet = protocol::MakePacket(PacketType::UdpPunchRequest, packetId, payload);
    BroadcastRaw(packet, peer ? peer->GetRemoteNodeId() : "");
}

std::uint64_t P2PNode::GetNextOutgoingSequence(const NodeId& peerNodeId) {
    std::lock_guard<std::mutex> lock(sequenceMutex_);
    auto it = nextOutgoingSequenceByPeer_.find(peerNodeId);
    if (it != nextOutgoingSequenceByPeer_.end()) {
        return it->second++;
    }

    std::vector<StoredConversationMessage> messages;
    std::string error;
    std::uint64_t maxSeq = 0;
    if (ConversationStore::LoadConversation(historyRootDir_, local_.nodeId, peerNodeId, signer_, messages, &error)) {
        for (const auto& msg : messages) {
            if (msg.direction == StoredMessageDirection::Outgoing) maxSeq = std::max(maxSeq, msg.sequenceNumber);
        }
    }
    auto& next = nextOutgoingSequenceByPeer_[peerNodeId];
    next = maxSeq + 1;
    return next++;
}

std::uint64_t P2PNode::GetExpectedIncomingSequence(const NodeId& peerNodeId) {
    std::lock_guard<std::mutex> lock(sequenceMutex_);
    auto it = expectedIncomingSequenceByPeer_.find(peerNodeId);
    if (it != expectedIncomingSequenceByPeer_.end()) return it->second;

    std::vector<StoredConversationMessage> messages;
    std::string error;
    std::uint64_t maxSeq = 0;
    if (ConversationStore::LoadConversation(historyRootDir_, local_.nodeId, peerNodeId, signer_, messages, &error)) {
        for (const auto& msg : messages) {
            if (msg.direction == StoredMessageDirection::Incoming) maxSeq = std::max(maxSeq, msg.sequenceNumber);
        }
    }
    auto& expected = expectedIncomingSequenceByPeer_[peerNodeId];
    expected = maxSeq + 1;
    if (expected == 0) expected = 1;
    return expected;
}

void P2PNode::DeliverOrderedIncomingPrivateMessage(const PrivateMessagePayload& payload, const ByteVector& signerPublicKeyBlob, PacketId ackedRelayPacketId, bool logMessage) {
    if (HasStoredMessageForPeer(payload.fromNodeId, payload.messageId)) {
        SendDeliveryAck(payload, ackedRelayPacketId);
        return;
    }
    EnsureSessionForPeer(payload.fromNodeId, payload.fromNickname, payload.sessionId);
    AppendStoredPrivateMessage(payload, StoredMessageDirection::Incoming, StoredMessageState::Delivered, signerPublicKeyBlob);
    SendDeliveryAck(payload, ackedRelayPacketId);
    if (logMessage) utils::LogPrivate(payload.fromNickname, payload.text);
}

void P2PNode::BufferOrDeliverIncomingPrivateMessage(const PrivateMessagePayload& payload, const ByteVector& signerPublicKeyBlob, PacketId ackedRelayPacketId, bool logMessage) {
    if (payload.sequenceNumber == 0) {
        DeliverOrderedIncomingPrivateMessage(payload, signerPublicKeyBlob, ackedRelayPacketId, logMessage);
        return;
    }

    std::vector<BufferedIncomingPrivateMessage> ready;
    {
        std::lock_guard<std::mutex> lock(sequenceMutex_);
        auto expectedIt = expectedIncomingSequenceByPeer_.find(payload.fromNodeId);
        if (expectedIt == expectedIncomingSequenceByPeer_.end()) {
            std::uint64_t maxSeq = 0;
            std::vector<StoredConversationMessage> messages;
            std::string error;
            if (ConversationStore::LoadConversation(historyRootDir_, local_.nodeId, payload.fromNodeId, signer_, messages, &error)) {
                for (const auto& msg : messages) {
                    if (msg.direction == StoredMessageDirection::Incoming) maxSeq = std::max(maxSeq, msg.sequenceNumber);
                }
            }
            expectedIt = expectedIncomingSequenceByPeer_.emplace(payload.fromNodeId, maxSeq + 1).first;
            if (expectedIt->second == 0) expectedIt->second = 1;
        }

        auto& expected = expectedIt->second;
        if (payload.sequenceNumber < expected) {
            // already delivered or stale retry
        } else if (payload.sequenceNumber > expected) {
            auto& buffer = reorderBufferByPeer_[payload.fromNodeId];
            buffer.try_emplace(payload.sequenceNumber, BufferedIncomingPrivateMessage{payload, signerPublicKeyBlob, ackedRelayPacketId, logMessage});
            return;
        } else {
            ready.push_back(BufferedIncomingPrivateMessage{payload, signerPublicKeyBlob, ackedRelayPacketId, logMessage});
            ++expected;
            auto bufIt = reorderBufferByPeer_.find(payload.fromNodeId);
            while (bufIt != reorderBufferByPeer_.end()) {
                auto nextIt = bufIt->second.find(expected);
                if (nextIt == bufIt->second.end()) break;
                ready.push_back(nextIt->second);
                bufIt->second.erase(nextIt);
                ++expected;
            }
            if (bufIt != reorderBufferByPeer_.end() && bufIt->second.empty()) reorderBufferByPeer_.erase(bufIt);
        }
    }

    if (ready.empty()) {
        SendDeliveryAck(payload, ackedRelayPacketId);
        return;
    }
    for (const auto& item : ready) {
        DeliverOrderedIncomingPrivateMessage(item.payload, item.signerPublicKeyBlob, item.ackedRelayPacketId, item.logMessage);
    }
}

void P2PNode::AppendStoredPrivateMessage(const PrivateMessagePayload& payload, StoredMessageDirection direction, StoredMessageState state, const ByteVector& signerPublicKeyBlob) {
    const NodeId peerNodeId = (direction == StoredMessageDirection::Outgoing) ? payload.toNodeId : payload.fromNodeId;
    std::string error;
    if (!ConversationStore::AppendPrivateMessage(historyRootDir_,
                                                 local_.nodeId,
                                                 peerNodeId,
                                                 payload,
                                                 direction,
                                                 state,
                                                 signerPublicKeyBlob,
                                                 signer_,
                                                 localPublicKeyBlob_,
                                                 &error)) {
        utils::LogError("Failed to store private message: " + error);
    }
}

bool P2PNode::HasStoredMessageForPeer(const NodeId& peerNodeId, MessageId messageId) const {
    bool exists = false;
    std::string error;
    if (!ConversationStore::HasMessageId(historyRootDir_, local_.nodeId, peerNodeId, messageId, const_cast<CryptoSigner&>(signer_), &exists, &error)) {
        if (!error.empty()) utils::LogError("Failed to check stored message id: " + error);
        return false;
    }
    return exists;
}

bool P2PNode::UpdateStoredMessageState(const NodeId& peerNodeId, MessageId messageId, StoredMessageState newState) {
    std::string error;
    if (!ConversationStore::UpdateMessageState(historyRootDir_, local_.nodeId, peerNodeId, messageId, newState, signer_, localPublicKeyBlob_, &error)) {
        if (!error.empty()) utils::LogError("Failed to update message state: " + error);
        return false;
    }
    return true;
}

void P2PNode::EnsureSessionForPeer(const NodeId& peerNodeId, const std::string& peerNickname, SessionId sessionId) {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    auto existing = sessionByPeer_.find(peerNodeId);
    if (existing != sessionByPeer_.end()) {
        auto sit = sessionsById_.find(existing->second);
        if (sit != sessionsById_.end()) {
            sit->second.active = true;
            if (!peerNickname.empty()) sit->second.peerNickname = peerNickname;
            return;
        }
    }
    sessionsById_[sessionId] = {sessionId, peerNodeId, peerNickname, true};
    sessionByPeer_[peerNodeId] = sessionId;
}

void P2PNode::PrintStoredConversation(const NodeId& peerNodeId, const std::string& peerNicknameHint) const {
    std::vector<StoredConversationMessage> messages;
    std::string error;
    if (!ConversationStore::LoadConversation(historyRootDir_, local_.nodeId, peerNodeId, const_cast<CryptoSigner&>(signer_), messages, &error)) {
        utils::LogError("Failed to load history: " + error);
        return;
    }
    const std::string caption = peerNicknameHint.empty() ? peerNodeId : peerNicknameHint;
    utils::LogRaw("=== Private history with " + caption + " ===");
    if (messages.empty()) {
        utils::LogRaw("  (empty)");
        return;
    }
    for (const auto& msg : messages) {
        const std::string author = (msg.direction == StoredMessageDirection::Outgoing) ? local_.nickname : msg.fromNickname;
        std::string suffix;
        if (msg.direction == StoredMessageDirection::Outgoing) {
            switch (msg.state) {
                case StoredMessageState::Queued: suffix = " [queued]"; break;
                case StoredMessageState::Sent: suffix = " [sent]"; break;
                case StoredMessageState::Relayed: suffix = " [relayed]"; break;
                case StoredMessageState::Delivered: suffix = " [delivered]"; break;
                case StoredMessageState::Failed: suffix = " [failed]"; break;
                default: break;
            }
        }
        utils::LogRaw("[History | " + author + suffix + "] " + msg.text);
    }
}

void P2PNode::LoadBootstrapNodes() {
    std::ifstream in(bootstrapConfigPath_);
    if (!in) return;

    std::vector<BootstrapEndpoint> parsed;
    std::string line;
    while (std::getline(in, line)) {
        line = TrimCopy(line);
        if (line.empty() || line[0] == '#') continue;
        const auto pos = line.rfind(':');
        if (pos == std::string::npos) continue;
        const auto ip = TrimCopy(line.substr(0, pos));
        const auto portText = TrimCopy(line.substr(pos + 1));
        if (ip.empty() || portText.empty()) continue;
        try {
            const int portValue = std::stoi(portText);
            if (portValue <= 0 || portValue > 65535) continue;
            parsed.push_back({ip, static_cast<std::uint16_t>(portValue), {}});
        } catch (...) {
            continue;
        }
    }

    std::size_t count = parsed.size();
    {
        std::lock_guard<std::mutex> lock(bootstrapMutex_);
        bootstrapNodes_ = std::move(parsed);
    }

    if (count > 0) {
        utils::LogSystem("Loaded " + std::to_string(count) + " bootstrap node(s) from " + bootstrapConfigPath_);
    }
}

void P2PNode::TryConnectBootstrapNodes() {
    std::vector<BootstrapEndpoint> snapshot;
    {
        std::lock_guard<std::mutex> lock(bootstrapMutex_);
        snapshot = bootstrapNodes_;
    }
    if (snapshot.empty()) return;

    auto peers = peerManager_.Snapshot();
    const auto now = std::chrono::steady_clock::now();
    bool changed = false;

    for (std::size_t i = 0; i < snapshot.size(); ++i) {
        bool alreadyConnected = false;
        for (const auto& peer : peers) {
            if (peer.remoteIp == snapshot[i].ip && (peer.remotePort == snapshot[i].port || peer.remotePort == 0)) {
                alreadyConnected = true;
                break;
            }
        }
        if (alreadyConnected) continue;
        if (snapshot[i].lastAttempt != std::chrono::steady_clock::time_point{} &&
            std::chrono::duration_cast<std::chrono::seconds>(now - snapshot[i].lastAttempt).count() < 5) {
            continue;
        }
        snapshot[i].lastAttempt = now;
        changed = true;
        if (ConnectToPeer(snapshot[i].ip, snapshot[i].port)) {
            utils::LogSystem("Bootstrap connect attempt: " + snapshot[i].ip + ":" + std::to_string(snapshot[i].port));
        }
    }

    if (changed) {
        std::lock_guard<std::mutex> lock(bootstrapMutex_);
        bootstrapNodes_ = std::move(snapshot);
    }
}

bool P2PNode::OpenPrivateChat(const NodeId& peerNodeId, const std::string& peerNickname) {
    if (peerNodeId.empty() || peerNodeId == local_.nodeId) {
        utils::LogError("Invalid private chat target");
        return false;
    }

    if (!FindSessionByPeer(peerNodeId).has_value()) {
        std::string error;
        auto restoredSessionId = ConversationStore::GetLatestSessionId(historyRootDir_, local_.nodeId, peerNodeId, signer_, &error);
        if (!restoredSessionId.has_value() && !error.empty()) {
            utils::LogError("Failed to restore history session: " + error);
            return false;
        }
        if (restoredSessionId.has_value()) {
            EnsureSessionForPeer(peerNodeId, peerNickname, *restoredSessionId);
            utils::LogSystem("Restored previous private session with " + (peerNickname.empty() ? peerNodeId : peerNickname));
        }
    }

    PrintStoredConversation(peerNodeId, peerNickname);
    return true;
}

bool P2PNode::IsPeerConnected(const NodeId& peerNodeId) const {
    if (peerNodeId.empty()) return false;
    return peerManager_.HasNode(peerNodeId);
}

bool P2PNode::DeleteConversationHistory(const NodeId& peerNodeId) {
    if (peerNodeId.empty() || peerNodeId == local_.nodeId) {
        utils::LogError("Invalid chat target for delete");
        return false;
    }

    std::string error;
    if (!ConversationStore::DeleteConversation(historyRootDir_, local_.nodeId, peerNodeId, &error)) {
        utils::LogError("Failed to delete history: " + error);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        auto it = sessionByPeer_.find(peerNodeId);
        if (it != sessionByPeer_.end()) {
            sessionsById_.erase(it->second);
            sessionByPeer_.erase(it);
        }
    }

    utils::LogSystem("Local chat history deleted for peer " + peerNodeId);
    return true;
}

void P2PNode::PrintKnownNodes() const {
    auto users = GetDisplayUsers();
    utils::LogRaw("=== Users ===");
    if (users.empty()) utils::LogRaw("  (none)");
    for (const auto& u : users) {
        std::string status = u.online ? "online" : ("last seen " + std::to_string(u.lastSeenSecondsAgo) + "s ago");
        utils::LogRaw("[" + std::to_string(u.index) + "] " + u.nickname + " " + status + " id=" + u.nodeId);
    }
}

void P2PNode::PrintInvites() const {
    std::lock_guard<std::mutex> lock(invitesMutex_);
    utils::LogRaw("=== Invites ===");
    if (incomingInvites_.empty()) utils::LogRaw("  (none)");
    for (const auto& [_, inv] : incomingInvites_) utils::LogRaw("  from " + inv.fromNickname + " id=" + inv.fromNodeId);
}

void P2PNode::PrintSessions() const {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    utils::LogRaw("=== Sessions ===");
    if (sessionsById_.empty()) utils::LogRaw("  (none)");
    for (const auto& [id, s] : sessionsById_) utils::LogRaw("  [" + std::to_string(id) + "] " + s.peerNickname + " id=" + s.peerNodeId + (s.active ? " active" : " offline"));
}

void P2PNode::PrintInfo() const {
    utils::LogRaw("========================================");
    utils::LogRaw("You: " + local_.nickname);
    utils::LogRaw("ID:  " + local_.nodeId);
    utils::LogRaw("Port: " + std::to_string(local_.listenPort));
    {
        std::lock_guard<std::mutex> lock(observedEndpointMutex_);
        if (!localObservedIp_.empty() && localObservedPort_ != 0) {
            utils::LogRaw("Observed TCP endpoint: " + localObservedIp_ + ":" + std::to_string(localObservedPort_));
        }
        if (!localObservedUdpIp_.empty() && localObservedUdpPort_ != 0) {
            utils::LogRaw("Observed UDP endpoint: " + localObservedUdpIp_ + ":" + std::to_string(localObservedUdpPort_));
        }
    }
    {
        std::lock_guard<std::mutex> lock(bootstrapMutex_);
        utils::LogRaw("Bootstrap nodes: " + std::to_string(bootstrapNodes_.size()));
    }
    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        std::size_t totalQueued = 0;
        for (const auto& [_, q] : relayQueuesByTarget_) totalQueued += q.size();
        std::size_t totalQueuedAcks = 0;
        for (const auto& [_, q] : relayAckQueuesByTarget_) totalQueuedAcks += q.size();
        utils::LogRaw("Queued relay messages: " + std::to_string(totalQueued));
        utils::LogRaw("Queued relay ACKs: " + std::to_string(totalQueuedAcks));
    }
    utils::LogRaw("========================================");
}

std::vector<DisplayUser> P2PNode::GetDisplayUsers() const {
    auto nodes = knownNodes_.GetAllExcept(local_.nodeId);
    std::unordered_set<NodeId> online;
    for (const auto& p : peerManager_.Snapshot()) online.insert(p.remoteNodeId);

    std::vector<DisplayUser> result;
    int i = 1;
    const auto now = std::chrono::steady_clock::now();
    for (const auto& n : nodes) {
        std::uint64_t lastSeenSecondsAgo = 0;
        if (now > n.lastSeen) {
            lastSeenSecondsAgo = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(now - n.lastSeen).count());
        }
        result.push_back({i++, n.nodeId, n.nickname, online.contains(n.nodeId), lastSeenSecondsAgo});
    }
    return result;
}

void P2PNode::BroadcastRaw(const ByteVector& packet, const NodeId& excludeNodeId) {
    auto peers = peerManager_.GetAllPeers();
    for (auto& p : peers) {
        if (!excludeNodeId.empty() && p->GetRemoteNodeId() == excludeNodeId) continue;
        p->EnqueuePacket(packet);
    }
}

void P2PNode::OnPeerDisconnected(SOCKET socket) {
    {
        std::lock_guard<std::mutex> lock(rateLimitMutex_);
        rateLimitBySocket_.erase(socket);
    }
    if (socket == INVALID_SOCKET) return;

    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        auto it = pendingPeers_.find(socket);
        if (it != pendingPeers_.end()) {
            auto p = it->second;
            pendingPeers_.erase(it);
            if (p) p->RequestClose();
            return;
        }
    }

    auto p = peerManager_.FindBySocket(socket);
    if (p) {
        const NodeId remoteNodeId = p->GetRemoteNodeId();
        const std::string remoteNickname = p->GetRemoteNickname();
        peerManager_.RemoveBySocket(socket);
        p->RequestClose();

        if (!remoteNodeId.empty()) {
            if (auto known = knownNodes_.FindByNodeId(remoteNodeId)) {
                known->lastSeen = std::chrono::steady_clock::now();
                knownNodes_.Upsert(*known);
            }
            NoteReconnectFailure(remoteNodeId);
            std::lock_guard<std::mutex> lock(sessionsMutex_);
            auto it = sessionByPeer_.find(remoteNodeId);
            if (it != sessionByPeer_.end()) {
                auto sit = sessionsById_.find(it->second);
                if (sit != sessionsById_.end()) {
                    sit->second.active = false;
                }
            }
            utils::LogSystem("Peer disconnected: " + (remoteNickname.empty() ? remoteNodeId : remoteNickname) + ". Active private chat with this peer was closed.");
        }
    }
}

bool P2PNode::ShouldAttemptAutoConnect(const KnownNode& node) {
    if (node.nodeId.empty() || node.ip.empty() || node.port == 0) return false;
    if (node.nodeId == local_.nodeId) return false;
    if (peerManager_.HasNode(node.nodeId)) return false;

    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(reconnectMutex_);
        auto it = reconnectStates_.find(node.nodeId);
        if (it != reconnectStates_.end() && it->second.nextAttempt != std::chrono::steady_clock::time_point{} && now < it->second.nextAttempt) {
            return false;
        }
    }
    std::lock_guard<std::mutex> lock(connectAttemptsMutex_);
    auto it = lastConnectAttempt_.find(node.nodeId);
    if (it != lastConnectAttempt_.end()) {
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
        if (diff < 2) return false;
    }
    return true;
}

void P2PNode::MarkConnectAttempt(const NodeId& nodeId) {
    std::lock_guard<std::mutex> lock(connectAttemptsMutex_);
    lastConnectAttempt_[nodeId] = std::chrono::steady_clock::now();
}

void P2PNode::NoteReconnectFailure(const NodeId& nodeId) {
    if (nodeId.empty()) return;
    std::lock_guard<std::mutex> lock(reconnectMutex_);
    auto& state = reconnectStates_[nodeId];
    state.failureCount = std::min<std::uint32_t>(state.failureCount + 1, 8u);
    const auto delaySeconds = std::min<std::uint32_t>(60u, 1u << std::min<std::uint32_t>(state.failureCount - 1, 5u));
    state.nextAttempt = std::chrono::steady_clock::now() + std::chrono::seconds(delaySeconds);
}

void P2PNode::ResetReconnectState(const NodeId& nodeId) {
    if (nodeId.empty()) return;
    std::lock_guard<std::mutex> lock(reconnectMutex_);
    reconnectStates_.erase(nodeId);
}

bool P2PNode::TryConnectToKnownNode(const KnownNode& node) {
    if (node.ip.empty()) return false;

    std::vector<std::uint16_t> ports;
    if (node.port != 0) ports.push_back(node.port);
    if (node.observedPort != 0 && node.observedPort != node.port) ports.push_back(node.observedPort);

    bool connected = false;
    MarkConnectAttempt(node.nodeId);
    for (auto port : ports) {
        if (ConnectToPeer(node.ip, port)) {
            connected = true;
            break;
        }
    }
    if (!connected) {
        NoteReconnectFailure(node.nodeId);
    }
    return connected;
}

void P2PNode::RequestReverseConnect(const KnownNode& target) {
    ConnectRequestPayload payload{};
    payload.requesterNodeId = local_.nodeId;
    payload.requesterNickname = local_.nickname;
    payload.targetNodeId = target.nodeId;
    payload.requesterAdvertisedPort = local_.listenPort;
    {
        std::lock_guard<std::mutex> lock(observedEndpointMutex_);
        payload.requesterObservedIp = localObservedIp_;
        payload.requesterObservedPort = localObservedPort_;
    }
    if (payload.requesterObservedIp.empty()) return;

    signer_.Sign(BuildConnectRequestSignedData(payload), payload.signature);

    const PacketId packetId = utils::GeneratePacketId();
    router_.MarkSeen(packetId);
    auto body = protocol::SerializeConnectRequest(payload);
    auto packet = protocol::MakePacket(PacketType::ConnectRequest, packetId, body);
    BroadcastRaw(packet);
    utils::LogSystem("Asked network to relay reverse-connect request to " + target.nickname);
}

void P2PNode::RequestUdpHolePunch(const KnownNode& target) {
    UdpPunchRequestPayload payload{};
    payload.requesterNodeId = local_.nodeId;
    payload.requesterNickname = local_.nickname;
    payload.targetNodeId = target.nodeId;
    payload.requesterAdvertisedTcpPort = local_.listenPort;
    {
        std::lock_guard<std::mutex> lock(observedEndpointMutex_);
        payload.requesterObservedUdpIp = localObservedUdpIp_;
        payload.requesterObservedUdpPort = localObservedUdpPort_;
    }

    if (payload.requesterObservedUdpIp.empty() || payload.requesterObservedUdpPort == 0) {
        utils::LogError("UDP hole punching skipped: no observed UDP endpoint yet");
        return;
    }

    signer_.Sign(BuildUdpPunchRequestSignedData(payload), payload.signature);

    SendUdpPunchBurst(target, "requester");

    const PacketId packetId = utils::GeneratePacketId();
    router_.MarkSeen(packetId);
    auto body = protocol::SerializeUdpPunchRequest(payload);
    auto packet = protocol::MakePacket(PacketType::UdpPunchRequest, packetId, body);
    BroadcastRaw(packet);
    utils::LogSystem("Asked network to coordinate UDP hole punch to " + target.nickname);
}

void P2PNode::SendUdpProbeToEndpoint(const std::string& ip, std::uint16_t port) {
    if (udpSocket_ == INVALID_SOCKET || ip.empty() || port == 0) return;

    ByteVector data;
    utils::WriteUint32(data, 0x55445031u);
    utils::WriteUint16(data, 1);
    utils::WriteString(data, local_.nodeId);
    utils::WriteString(data, local_.nickname);
    utils::WriteUint16(data, local_.listenPort);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) return;

    sendto(udpSocket_, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
}

void P2PNode::SendUdpProbeToKnownNodes() {
    for (const auto& peer : peerManager_.GetAllPeers()) {
        SendUdpProbeToEndpoint(peer->GetRemoteIp(), peer->GetAdvertisedListenPort());
        SendUdpProbeToEndpoint(peer->GetRemoteIp(), peer->GetRemotePort());
    }

    auto nodes = knownNodes_.GetAllExcept(local_.nodeId);
    for (const auto& node : nodes) {
        SendUdpProbeToEndpoint(node.ip, node.port);
        if (node.observedUdpPort != 0 && node.observedUdpPort != node.port) SendUdpProbeToEndpoint(node.ip, node.observedUdpPort);
        else if (node.observedPort != 0 && node.observedPort != node.port) SendUdpProbeToEndpoint(node.ip, node.observedPort);
    }
}

void P2PNode::SendUdpPunchBurst(const KnownNode& node, const std::string& reason) {
    if (udpSocket_ == INVALID_SOCKET || node.ip.empty()) return;

    std::vector<std::uint16_t> ports;
    if (node.observedUdpPort != 0) ports.push_back(node.observedUdpPort);
    if (node.port != 0 && node.port != node.observedUdpPort) ports.push_back(node.port);
    if (node.observedPort != 0 && node.observedPort != node.port && node.observedPort != node.observedUdpPort) ports.push_back(node.observedPort);

    ByteVector data;
    utils::WriteUint32(data, 0x55445031u);
    utils::WriteUint16(data, 3);
    utils::WriteString(data, local_.nodeId);
    utils::WriteString(data, local_.nickname);
    utils::WriteUint16(data, local_.listenPort);

    for (int burst = 0; burst < 6; ++burst) {
        for (auto port : ports) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            if (inet_pton(AF_INET, node.ip.c_str(), &addr.sin_addr) != 1) continue;
            sendto(udpSocket_, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }
    if (!ports.empty()) utils::LogSystem("UDP punch burst sent to " + node.nickname + " (" + reason + ")");
}

void P2PNode::UdpRecvLoop() {
    while (running_) {
        std::array<std::uint8_t, 2048> buffer{};
        sockaddr_in from{};
        int fromLen = sizeof(from);
        int recvd = recvfrom(udpSocket_, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0, reinterpret_cast<sockaddr*>(&from), &fromLen);
        if (recvd <= 0) break;
        ByteVector data(buffer.begin(), buffer.begin() + recvd);
        HandleUdpDatagram(utils::SocketAddressToIp(from), ntohs(from.sin_port), data);
    }
}

void P2PNode::HandleUdpDatagram(const std::string& ip, std::uint16_t port, const ByteVector& data) {
    std::size_t offset = 0;
    std::uint32_t magic = 0;
    std::uint16_t kind = 0;
    std::string nodeId;
    std::string nickname;
    std::uint16_t advertisedTcpPort = 0;

    if (!utils::ReadUint32(data, offset, magic) || magic != 0x55445031u) return;
    if (!utils::ReadUint16(data, offset, kind)) return;
    if (!utils::ReadString(data, offset, nodeId)) return;
    if (!utils::ReadString(data, offset, nickname)) return;
    if (!utils::ReadUint16(data, offset, advertisedTcpPort)) return;

    if (nodeId == local_.nodeId) return;

    KnownNode node{};
    if (auto existing = knownNodes_.FindByNodeId(nodeId)) node = *existing;
    node.nodeId = nodeId;
    if (!nickname.empty()) node.nickname = nickname;
    node.ip = ip;
    if (advertisedTcpPort != 0) node.port = advertisedTcpPort;
    node.observedUdpPort = port;
    node.lastSeen = std::chrono::steady_clock::now();
    knownNodes_.Upsert(node);

    if (kind == 1) {
        ByteVector ack;
        utils::WriteUint32(ack, 0x55445031u);
        utils::WriteUint16(ack, 2);
        utils::WriteString(ack, local_.nodeId);
        utils::WriteString(ack, local_.nickname);
        utils::WriteUint16(ack, local_.listenPort);
        utils::WriteString(ack, ip);
        utils::WriteUint16(ack, port);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) == 1) {
            sendto(udpSocket_, reinterpret_cast<const char*>(ack.data()), static_cast<int>(ack.size()), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        }
        return;
    }

    if (kind == 2) {
        std::string observedIp;
        std::uint16_t observedPort = 0;
        if (!utils::ReadString(data, offset, observedIp)) return;
        if (!utils::ReadUint16(data, offset, observedPort)) return;
        std::lock_guard<std::mutex> lock(observedEndpointMutex_);
        localObservedUdpIp_ = observedIp;
        localObservedUdpPort_ = observedPort;
        return;
    }

    if (kind == 3) {
        utils::LogSystem("UDP punch packet received from " + nickname + " at " + ip + ":" + std::to_string(port));
        if (!peerManager_.HasNode(nodeId)) {
            TryConnectToKnownNode(node);
            RequestReverseConnect(node);
        }
    }
}

void P2PNode::TryAutoConnectKnownNodes() {
    auto nodes = knownNodes_.GetAllExcept(local_.nodeId);
    for (const auto& n : nodes) {
        if (!ShouldAttemptAutoConnect(n)) continue;
        MarkConnectAttempt(n.nodeId);
        if (!TryConnectToKnownNode(n)) {
            RequestReverseConnect(n);
            RequestUdpHolePunch(n);
        }
    }
}

bool P2PNode::PreferIncomingFor(const NodeId& remoteNodeId) const {
    return local_.nodeId > remoteNodeId;
}

void P2PNode::SafeClosePeer(const std::shared_ptr<PeerConnection>& peer) {
    if (peer) peer->RequestClose();
}

std::optional<PendingInvite> P2PNode::FindIncomingInviteByFromNodeId(const NodeId& fromNodeId) const {
    std::lock_guard<std::mutex> lock(invitesMutex_);
    for (const auto& [_, inv] : incomingInvites_) if (inv.fromNodeId == fromNodeId) return inv;
    return std::nullopt;
}

std::optional<SessionId> P2PNode::FindSessionByPeer(const NodeId& peerNodeId) const {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    auto it = sessionByPeer_.find(peerNodeId);
    if (it == sessionByPeer_.end()) return std::nullopt;
    return it->second;
}

} // namespace p2p
