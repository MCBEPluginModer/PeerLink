#pragma once

#include "core/types.h"

namespace p2p::protocol {

std::vector<std::uint8_t> SerializeHello(const HelloPayload& payload);
bool DeserializeHello(const std::vector<std::uint8_t>& data, HelloPayload& payload);

std::vector<std::uint8_t> SerializeChat(const ChatPayload& payload);
bool DeserializeChat(const std::vector<std::uint8_t>& data, ChatPayload& payload);

std::vector<std::uint8_t> SerializePeerList(const std::vector<KnownNode>& nodes);
bool DeserializePeerList(const std::vector<std::uint8_t>& data, std::vector<KnownNode>& nodes);

std::vector<std::uint8_t> SerializeInviteRequest(const InviteRequestPayload& payload);
bool DeserializeInviteRequest(const std::vector<std::uint8_t>& data, InviteRequestPayload& payload);

std::vector<std::uint8_t> SerializeInviteAccept(const InviteAcceptPayload& payload);
bool DeserializeInviteAccept(const std::vector<std::uint8_t>& data, InviteAcceptPayload& payload);

std::vector<std::uint8_t> SerializeInviteReject(const InviteRejectPayload& payload);
bool DeserializeInviteReject(const std::vector<std::uint8_t>& data, InviteRejectPayload& payload);

std::vector<std::uint8_t> SerializePrivateMessage(const PrivateMessagePayload& payload);
bool DeserializePrivateMessage(const std::vector<std::uint8_t>& data, PrivateMessagePayload& payload);

std::vector<std::uint8_t> SerializeConnectRequest(const ConnectRequestPayload& payload);
bool DeserializeConnectRequest(const std::vector<std::uint8_t>& data, ConnectRequestPayload& payload);

std::vector<std::uint8_t> SerializeUdpPunchRequest(const UdpPunchRequestPayload& payload);
bool DeserializeUdpPunchRequest(const std::vector<std::uint8_t>& data, UdpPunchRequestPayload& payload);

std::vector<std::uint8_t> SerializeRelayPrivateMessage(const RelayPrivateMessagePayload& payload);
bool DeserializeRelayPrivateMessage(const std::vector<std::uint8_t>& data, RelayPrivateMessagePayload& payload);

std::vector<std::uint8_t> SerializeMessageAck(const MessageAckPayload& payload);
bool DeserializeMessageAck(const std::vector<std::uint8_t>& data, MessageAckPayload& payload);

std::vector<std::uint8_t> SerializeRelayMessageAck(const RelayMessageAckPayload& payload);
bool DeserializeRelayMessageAck(const std::vector<std::uint8_t>& data, RelayMessageAckPayload& payload);

std::vector<std::uint8_t> SerializeHistorySyncRequest(const HistorySyncRequestPayload& payload);
bool DeserializeHistorySyncRequest(const std::vector<std::uint8_t>& data, HistorySyncRequestPayload& payload);

std::vector<std::uint8_t> SerializeHistorySyncResponse(const HistorySyncResponsePayload& payload);
bool DeserializeHistorySyncResponse(const std::vector<std::uint8_t>& data, HistorySyncResponsePayload& payload);

std::vector<std::uint8_t> MakePacket(PacketType type, PacketId packetId, const std::vector<std::uint8_t>& payload);
bool ReadPacket(SOCKET s, PacketHeader& header, std::vector<std::uint8_t>& payload);

} // namespace p2p::protocol