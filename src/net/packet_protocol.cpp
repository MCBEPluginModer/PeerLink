#include "net/packet_protocol.h"
#include "core/utils.h"

#include <cstring>

namespace p2p::protocol {

std::vector<std::uint8_t> SerializeHello(const HelloPayload& payload) {
    ByteVector out;
    utils::WriteString(out, payload.nodeId);
    utils::WriteString(out, payload.nickname);
    utils::WriteUint16(out, payload.listenPort);
    utils::WriteString(out, payload.observedIpForRemote);
    utils::WriteUint16(out, payload.observedPortForRemote);
    utils::WriteBytes(out, payload.publicKeyBlob);
    return out;
}

bool DeserializeHello(const ByteVector& data, HelloPayload& payload) {
    std::size_t offset = 0;
    if (!utils::ReadString(data, offset, payload.nodeId)) return false;
    if (!utils::ReadString(data, offset, payload.nickname)) return false;
    if (!utils::ReadUint16(data, offset, payload.listenPort)) return false;
    if (!utils::ReadString(data, offset, payload.observedIpForRemote)) return false;
    if (!utils::ReadUint16(data, offset, payload.observedPortForRemote)) return false;
    if (!utils::ReadBytes(data, offset, payload.publicKeyBlob)) return false;
    return offset == data.size();
}

std::vector<std::uint8_t> SerializeChat(const ChatPayload& payload) {
    ByteVector out;
    utils::WriteString(out, payload.originNodeId);
    utils::WriteString(out, payload.originNickname);
    utils::WriteString(out, payload.text);
    return out;
}

bool DeserializeChat(const ByteVector& data, ChatPayload& payload) {
    std::size_t offset = 0;
    if (!utils::ReadString(data, offset, payload.originNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.originNickname)) return false;
    if (!utils::ReadString(data, offset, payload.text)) return false;
    return offset == data.size();
}

std::vector<std::uint8_t> SerializePeerList(const std::vector<KnownNode>& nodes) {
    ByteVector out;
    utils::WriteUint32(out, static_cast<std::uint32_t>(nodes.size()));
    for (const auto& node : nodes) {
        utils::WriteString(out, node.nodeId);
        utils::WriteString(out, node.nickname);
        utils::WriteString(out, node.ip);
        utils::WriteUint16(out, node.port);
        utils::WriteUint16(out, node.observedPort);
        utils::WriteUint16(out, node.observedUdpPort);
    }
    return out;
}

bool DeserializePeerList(const ByteVector& data, std::vector<KnownNode>& nodes) {
    std::size_t offset = 0;
    std::uint32_t count = 0;
    if (!utils::ReadUint32(data, offset, count)) return false;
    nodes.clear();
    nodes.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        KnownNode node{};
        if (!utils::ReadString(data, offset, node.nodeId)) return false;
        if (!utils::ReadString(data, offset, node.nickname)) return false;
        if (!utils::ReadString(data, offset, node.ip)) return false;
        if (!utils::ReadUint16(data, offset, node.port)) return false;
        if (!utils::ReadUint16(data, offset, node.observedPort)) return false;
        if (!utils::ReadUint16(data, offset, node.observedUdpPort)) return false;
        node.lastSeen = std::chrono::steady_clock::now();
        nodes.push_back(std::move(node));
    }
    return offset == data.size();
}

std::vector<std::uint8_t> SerializeInviteRequest(const InviteRequestPayload& payload) {
    ByteVector out;
    utils::WriteUint64(out, payload.inviteId);
    utils::WriteString(out, payload.fromNodeId);
    utils::WriteString(out, payload.fromNickname);
    utils::WriteString(out, payload.toNodeId);
    utils::WriteBytes(out, payload.signature);
    return out;
}

bool DeserializeInviteRequest(const ByteVector& data, InviteRequestPayload& payload) {
    std::size_t offset = 0;
    if (!utils::ReadUint64(data, offset, payload.inviteId)) return false;
    if (!utils::ReadString(data, offset, payload.fromNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.fromNickname)) return false;
    if (!utils::ReadString(data, offset, payload.toNodeId)) return false;
    if (!utils::ReadBytes(data, offset, payload.signature)) return false;
    return offset == data.size();
}

std::vector<std::uint8_t> SerializeInviteAccept(const InviteAcceptPayload& payload) {
    ByteVector out;
    utils::WriteUint64(out, payload.inviteId);
    utils::WriteUint64(out, payload.sessionId);
    utils::WriteString(out, payload.fromNodeId);
    utils::WriteString(out, payload.fromNickname);
    utils::WriteString(out, payload.toNodeId);
    utils::WriteBytes(out, payload.signature);
    return out;
}

bool DeserializeInviteAccept(const ByteVector& data, InviteAcceptPayload& payload) {
    std::size_t offset = 0;
    if (!utils::ReadUint64(data, offset, payload.inviteId)) return false;
    if (!utils::ReadUint64(data, offset, payload.sessionId)) return false;
    if (!utils::ReadString(data, offset, payload.fromNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.fromNickname)) return false;
    if (!utils::ReadString(data, offset, payload.toNodeId)) return false;
    if (!utils::ReadBytes(data, offset, payload.signature)) return false;
    return offset == data.size();
}

std::vector<std::uint8_t> SerializeInviteReject(const InviteRejectPayload& payload) {
    ByteVector out;
    utils::WriteUint64(out, payload.inviteId);
    utils::WriteString(out, payload.fromNodeId);
    utils::WriteString(out, payload.fromNickname);
    utils::WriteString(out, payload.toNodeId);
    utils::WriteString(out, payload.reason);
    utils::WriteBytes(out, payload.signature);
    return out;
}

bool DeserializeInviteReject(const ByteVector& data, InviteRejectPayload& payload) {
    std::size_t offset = 0;
    if (!utils::ReadUint64(data, offset, payload.inviteId)) return false;
    if (!utils::ReadString(data, offset, payload.fromNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.fromNickname)) return false;
    if (!utils::ReadString(data, offset, payload.toNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.reason)) return false;
    if (!utils::ReadBytes(data, offset, payload.signature)) return false;
    return offset == data.size();
}

std::vector<std::uint8_t> SerializePrivateMessage(const PrivateMessagePayload& payload) {
    ByteVector out;
    utils::WriteUint64(out, payload.messageId);
    utils::WriteUint64(out, payload.sessionId);
    utils::WriteUint64(out, payload.sequenceNumber);
    utils::WriteString(out, payload.fromNodeId);
    utils::WriteString(out, payload.fromNickname);
    utils::WriteString(out, payload.toNodeId);
    utils::WriteString(out, payload.text);
    utils::WriteBytes(out, payload.signature);
    return out;
}

bool DeserializePrivateMessage(const ByteVector& data, PrivateMessagePayload& payload) {
    std::size_t offset = 0;
    if (!utils::ReadUint64(data, offset, payload.messageId)) return false;
    if (!utils::ReadUint64(data, offset, payload.sessionId)) return false;
    if (!utils::ReadUint64(data, offset, payload.sequenceNumber)) return false;
    if (!utils::ReadString(data, offset, payload.fromNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.fromNickname)) return false;
    if (!utils::ReadString(data, offset, payload.toNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.text)) return false;
    if (!utils::ReadBytes(data, offset, payload.signature)) return false;
    return offset == data.size();
}


std::vector<std::uint8_t> SerializeConnectRequest(const ConnectRequestPayload& payload) {
    ByteVector out;
    utils::WriteString(out, payload.requesterNodeId);
    utils::WriteString(out, payload.requesterNickname);
    utils::WriteString(out, payload.targetNodeId);
    utils::WriteString(out, payload.requesterObservedIp);
    utils::WriteUint16(out, payload.requesterAdvertisedPort);
    utils::WriteUint16(out, payload.requesterObservedPort);
    utils::WriteBytes(out, payload.signature);
    return out;
}

bool DeserializeConnectRequest(const ByteVector& data, ConnectRequestPayload& payload) {
    std::size_t offset = 0;
    if (!utils::ReadString(data, offset, payload.requesterNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.requesterNickname)) return false;
    if (!utils::ReadString(data, offset, payload.targetNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.requesterObservedIp)) return false;
    if (!utils::ReadUint16(data, offset, payload.requesterAdvertisedPort)) return false;
    if (!utils::ReadUint16(data, offset, payload.requesterObservedPort)) return false;
    if (!utils::ReadBytes(data, offset, payload.signature)) return false;
    return offset == data.size();
}

std::vector<std::uint8_t> SerializeUdpPunchRequest(const UdpPunchRequestPayload& payload) {
    ByteVector out;
    utils::WriteString(out, payload.requesterNodeId);
    utils::WriteString(out, payload.requesterNickname);
    utils::WriteString(out, payload.targetNodeId);
    utils::WriteString(out, payload.requesterObservedUdpIp);
    utils::WriteUint16(out, payload.requesterAdvertisedTcpPort);
    utils::WriteUint16(out, payload.requesterObservedUdpPort);
    utils::WriteBytes(out, payload.signature);
    return out;
}

bool DeserializeUdpPunchRequest(const ByteVector& data, UdpPunchRequestPayload& payload) {
    std::size_t offset = 0;
    if (!utils::ReadString(data, offset, payload.requesterNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.requesterNickname)) return false;
    if (!utils::ReadString(data, offset, payload.targetNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.requesterObservedUdpIp)) return false;
    if (!utils::ReadUint16(data, offset, payload.requesterAdvertisedTcpPort)) return false;
    if (!utils::ReadUint16(data, offset, payload.requesterObservedUdpPort)) return false;
    if (!utils::ReadBytes(data, offset, payload.signature)) return false;
    return offset == data.size();
}

std::vector<std::uint8_t> SerializeRelayPrivateMessage(const RelayPrivateMessagePayload& payload) {
    ByteVector out;
    utils::WriteUint64(out, payload.relayPacketId);
    utils::WriteString(out, payload.relayFromNodeId);
    utils::WriteString(out, payload.finalTargetNodeId);
    utils::WriteBytes(out, payload.privateMessagePacket);
    return out;
}

bool DeserializeRelayPrivateMessage(const ByteVector& data, RelayPrivateMessagePayload& payload) {
    std::size_t offset = 0;
    if (!utils::ReadUint64(data, offset, payload.relayPacketId)) return false;
    if (!utils::ReadString(data, offset, payload.relayFromNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.finalTargetNodeId)) return false;
    if (!utils::ReadBytes(data, offset, payload.privateMessagePacket)) return false;
    return offset == data.size();
}

std::vector<std::uint8_t> SerializeMessageAck(const MessageAckPayload& payload) {
    ByteVector out;
    utils::WriteUint64(out, payload.messageId);
    utils::WriteUint64(out, payload.sessionId);
    utils::WriteString(out, payload.fromNodeId);
    utils::WriteString(out, payload.toNodeId);
    utils::WriteUint64(out, payload.ackedRelayPacketId);
    utils::WriteBytes(out, payload.signature);
    return out;
}

bool DeserializeMessageAck(const ByteVector& data, MessageAckPayload& payload) {
    std::size_t offset = 0;
    if (!utils::ReadUint64(data, offset, payload.messageId)) return false;
    if (!utils::ReadUint64(data, offset, payload.sessionId)) return false;
    if (!utils::ReadString(data, offset, payload.fromNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.toNodeId)) return false;
    if (!utils::ReadUint64(data, offset, payload.ackedRelayPacketId)) return false;
    if (!utils::ReadBytes(data, offset, payload.signature)) return false;
    return offset == data.size();
}

std::vector<std::uint8_t> SerializeRelayMessageAck(const RelayMessageAckPayload& payload) {
    ByteVector out;
    utils::WriteUint64(out, payload.relayPacketId);
    utils::WriteString(out, payload.relayFromNodeId);
    utils::WriteString(out, payload.finalTargetNodeId);
    utils::WriteBytes(out, payload.ackPacket);
    return out;
}

bool DeserializeRelayMessageAck(const ByteVector& data, RelayMessageAckPayload& payload) {
    std::size_t offset = 0;
    if (!utils::ReadUint64(data, offset, payload.relayPacketId)) return false;
    if (!utils::ReadString(data, offset, payload.relayFromNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.finalTargetNodeId)) return false;
    if (!utils::ReadBytes(data, offset, payload.ackPacket)) return false;
    return offset == data.size();
}


std::vector<std::uint8_t> SerializeHistorySyncRequest(const HistorySyncRequestPayload& payload) {
    ByteVector out;
    utils::WriteString(out, payload.requesterNodeId);
    utils::WriteString(out, payload.targetNodeId);
    utils::WriteUint64(out, payload.afterMessageId);
    utils::WriteBytes(out, payload.signature);
    return out;
}

bool DeserializeHistorySyncRequest(const ByteVector& data, HistorySyncRequestPayload& payload) {
    std::size_t offset = 0;
    if (!utils::ReadString(data, offset, payload.requesterNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.targetNodeId)) return false;
    if (!utils::ReadUint64(data, offset, payload.afterMessageId)) return false;
    if (!utils::ReadBytes(data, offset, payload.signature)) return false;
    return offset == data.size();
}

std::vector<std::uint8_t> SerializeHistorySyncResponse(const HistorySyncResponsePayload& payload) {
    ByteVector out;
    utils::WriteString(out, payload.responderNodeId);
    utils::WriteString(out, payload.targetNodeId);
    utils::WriteBytes(out, payload.messagesBlob);
    utils::WriteBytes(out, payload.signature);
    return out;
}

bool DeserializeHistorySyncResponse(const ByteVector& data, HistorySyncResponsePayload& payload) {
    std::size_t offset = 0;
    if (!utils::ReadString(data, offset, payload.responderNodeId)) return false;
    if (!utils::ReadString(data, offset, payload.targetNodeId)) return false;
    if (!utils::ReadBytes(data, offset, payload.messagesBlob)) return false;
    if (!utils::ReadBytes(data, offset, payload.signature)) return false;
    return offset == data.size();
}

std::vector<std::uint8_t> MakePacket(PacketType type, PacketId packetId, const ByteVector& payload) {
    PacketHeader header{};
    header.version = kProtocolVersion;
    header.type = static_cast<std::uint16_t>(type);
    header.size = static_cast<std::uint32_t>(payload.size());
    header.packetId = packetId;

    ByteVector out(sizeof(PacketHeader) + payload.size());
    std::memcpy(out.data(), &header, sizeof(PacketHeader));
    if (!payload.empty()) std::memcpy(out.data() + sizeof(PacketHeader), payload.data(), payload.size());
    return out;
}

bool ReadPacket(SOCKET s, PacketHeader& header, ByteVector& payload) {
    if (!utils::RecvAll(s, reinterpret_cast<std::uint8_t*>(&header), sizeof(PacketHeader))) return false;
    if (header.version != kProtocolVersion) return false;
    if (header.size > kMaxPacketSize) return false;
    payload.clear();
    if (header.size > 0) {
        payload.resize(header.size);
        if (!utils::RecvAll(s, payload.data(), payload.size())) return false;
    }
    return true;
}

} // namespace p2p::protocol
