#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace p2p {

using NodeId = std::string;
using PacketId = std::uint64_t;
using InviteId = std::uint64_t;
using SessionId = std::uint64_t;
using MessageId = std::uint64_t;
using ByteVector = std::vector<std::uint8_t>;

constexpr std::uint16_t kProtocolVersion = 3;
constexpr std::uint32_t kMaxPacketSize = 1024u * 1024u;

enum class PacketType : std::uint16_t {
    Hello = 1,
    HelloAck = 2,
    ChatMessage = 3,
    PeerList = 4,
    Ping = 5,
    Pong = 6,
    InviteRequest = 7,
    InviteAccept = 8,
    InviteReject = 9,
    PrivateMessage = 10,
    ConnectRequest = 11,
    UdpPunchRequest = 12,
    RelayPrivateMessage = 13,
    MessageAck = 14,
    RelayMessageAck = 15,
    HistorySyncRequest = 16,
    HistorySyncResponse = 17
};

#pragma pack(push, 1)
struct PacketHeader {
    std::uint16_t version = kProtocolVersion;
    std::uint16_t type = 0;
    std::uint32_t size = 0;
    std::uint64_t packetId = 0;
};
#pragma pack(pop)

struct LocalNodeInfo {
    NodeId nodeId;
    std::string nickname;
    std::uint16_t listenPort = 0;
};

struct HelloPayload {
    NodeId nodeId;
    std::string nickname;
    std::uint16_t listenPort = 0;
    std::string observedIpForRemote;
    std::uint16_t observedPortForRemote = 0;
    ByteVector publicKeyBlob;
};

struct ChatPayload {
    NodeId originNodeId;
    std::string originNickname;
    std::string text;
};

struct KnownNode {
    NodeId nodeId;
    std::string nickname;
    std::string ip;
    std::uint16_t port = 0;
    std::uint16_t observedPort = 0;
    std::uint16_t observedUdpPort = 0;
    std::chrono::steady_clock::time_point lastSeen;
};

struct PeerConnectionInfo {
    SOCKET socket = INVALID_SOCKET;
    NodeId remoteNodeId;
    std::string remoteNickname;
    std::string remoteIp;
    std::uint16_t remotePort = 0;
    bool incoming = false;
};

struct InviteRequestPayload {
    InviteId inviteId = 0;
    NodeId fromNodeId;
    std::string fromNickname;
    NodeId toNodeId;
    ByteVector fromPublicKeyBlob;
    ByteVector fromEncryptPublicKeyBlob;
    ByteVector signature;
};

struct InviteAcceptPayload {
    InviteId inviteId = 0;
    SessionId sessionId = 0;
    NodeId fromNodeId;
    std::string fromNickname;
    NodeId toNodeId;
    ByteVector fromPublicKeyBlob;
    ByteVector fromEncryptPublicKeyBlob;
    ByteVector encryptedSessionKeyBlob;
    ByteVector signature;
};

struct InviteRejectPayload {
    InviteId inviteId = 0;
    NodeId fromNodeId;
    std::string fromNickname;
    NodeId toNodeId;
    std::string reason;
    ByteVector fromPublicKeyBlob;
    ByteVector fromEncryptPublicKeyBlob;
    ByteVector signature;
};

struct PrivateMessagePayload {
    MessageId messageId = 0;
    SessionId sessionId = 0;
    std::uint64_t sequenceNumber = 0;
    NodeId fromNodeId;
    std::string fromNickname;
    NodeId toNodeId;
    std::string text;
    ByteVector iv;
    ByteVector ciphertext;
    ByteVector signature;
};


struct ConnectRequestPayload {
    NodeId requesterNodeId;
    std::string requesterNickname;
    NodeId targetNodeId;
    std::string requesterObservedIp;
    std::uint16_t requesterAdvertisedPort = 0;
    std::uint16_t requesterObservedPort = 0;
    ByteVector signature;
};


struct UdpPunchRequestPayload {
    NodeId requesterNodeId;
    std::string requesterNickname;
    NodeId targetNodeId;
    std::string requesterObservedUdpIp;
    std::uint16_t requesterAdvertisedTcpPort = 0;
    std::uint16_t requesterObservedUdpPort = 0;
    ByteVector signature;
};



struct RelayPrivateMessagePayload {
    PacketId relayPacketId = 0;
    NodeId relayFromNodeId;
    NodeId finalTargetNodeId;
    ByteVector privateMessagePacket;
};


struct MessageAckPayload {
    MessageId messageId = 0;
    SessionId sessionId = 0;
    NodeId fromNodeId;
    NodeId toNodeId;
    PacketId ackedRelayPacketId = 0;
    ByteVector signature;
};

struct RelayMessageAckPayload {
    PacketId relayPacketId = 0;
    NodeId relayFromNodeId;
    NodeId finalTargetNodeId;
    ByteVector ackPacket;
};

struct HistorySyncRequestPayload {
    NodeId requesterNodeId;
    NodeId targetNodeId;
    MessageId afterMessageId = 0;
    ByteVector signature;
};

struct HistorySyncResponsePayload {
    NodeId responderNodeId;
    NodeId targetNodeId;
    ByteVector messagesBlob;
    ByteVector signature;
};

struct QueuedRelayMessage {
    PacketId relayPacketId = 0;
    MessageId messageId = 0;
    NodeId relayFromNodeId;
    NodeId finalTargetNodeId;
    ByteVector privateMessagePacket;
    std::chrono::system_clock::time_point queuedAt;
    std::chrono::steady_clock::time_point nextAttemptAt;
    std::uint32_t attemptCount = 0;
};

struct QueuedRelayAck {
    PacketId relayPacketId = 0;
    MessageId messageId = 0;
    NodeId relayFromNodeId;
    NodeId finalTargetNodeId;
    ByteVector ackPacket;
    std::chrono::system_clock::time_point queuedAt;
    std::chrono::steady_clock::time_point nextAttemptAt;
    std::uint32_t attemptCount = 0;
};

struct PendingInvite {
    InviteId inviteId = 0;
    NodeId fromNodeId;
    std::string fromNickname;
    NodeId toNodeId;
};

struct PrivateSession {
    SessionId sessionId = 0;
    NodeId peerNodeId;
    std::string peerNickname;
    ByteVector sessionKey;
    bool active = false;
};

struct DisplayUser {
    int index = 0;
    NodeId nodeId;
    std::string nickname;
    bool online = false;
    std::uint64_t lastSeenSecondsAgo = 0;
};

struct DisplayInvite {
    int index = 0;
    InviteId inviteId = 0;
    NodeId fromNodeId;
    std::string fromNickname;
};

struct BootstrapEndpoint {
    std::string ip;
    std::uint16_t port = 0;
    std::chrono::steady_clock::time_point lastAttempt{};
};

} // namespace p2p
