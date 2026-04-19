#include "../net/packet_protocol.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <random>
#include <vector>

namespace {

using namespace p2p;

ByteVector RandomBytes(std::mt19937_64& rng, std::size_t maxLen) {
    std::uniform_int_distribution<std::size_t> lenDist(0, maxLen);
    std::uniform_int_distribution<int> byteDist(0, 255);

    ByteVector out(lenDist(rng));
    for (auto& b : out) {
        b = static_cast<std::uint8_t>(byteDist(rng));
    }
    return out;
}

void TryAllDeserializers(const ByteVector& data) {
    HelloPayload hello{};
    ChatPayload chat{};
    std::vector<KnownNode> peers;
    InviteRequestPayload inviteReq{};
    InviteAcceptPayload inviteAcc{};
    InviteRejectPayload inviteRej{};
    PrivateMessagePayload privateMsg{};
    ConnectRequestPayload connectReq{};
    UdpPunchRequestPayload udpPunch{};
    RelayPrivateMessagePayload relayMsg{};
    MessageAckPayload ack{};
    RelayMessageAckPayload relayAck{};
    HistorySyncRequestPayload historyReq{};
    HistorySyncResponsePayload historyResp{};

    auto run = [&](const char* name, auto&& fn) {
        try {
            (void)fn();
        } catch (const std::bad_alloc&) {
            throw std::runtime_error(std::string("bad_alloc in ") + name);
        }
    };

    run("DeserializeHello", [&] { return p2p::protocol::DeserializeHello(data, hello); });
    run("DeserializeChat", [&] { return p2p::protocol::DeserializeChat(data, chat); });
    run("DeserializePeerList", [&] { return p2p::protocol::DeserializePeerList(data, peers); });
    run("DeserializeInviteRequest", [&] { return p2p::protocol::DeserializeInviteRequest(data, inviteReq); });
    run("DeserializeInviteAccept", [&] { return p2p::protocol::DeserializeInviteAccept(data, inviteAcc); });
    run("DeserializeInviteReject", [&] { return p2p::protocol::DeserializeInviteReject(data, inviteRej); });
    run("DeserializePrivateMessage", [&] { return p2p::protocol::DeserializePrivateMessage(data, privateMsg); });
    run("DeserializeConnectRequest", [&] { return p2p::protocol::DeserializeConnectRequest(data, connectReq); });
    run("DeserializeUdpPunchRequest", [&] { return p2p::protocol::DeserializeUdpPunchRequest(data, udpPunch); });
    run("DeserializeRelayPrivateMessage", [&] { return p2p::protocol::DeserializeRelayPrivateMessage(data, relayMsg); });
    run("DeserializeMessageAck", [&] { return p2p::protocol::DeserializeMessageAck(data, ack); });
    run("DeserializeRelayMessageAck", [&] { return p2p::protocol::DeserializeRelayMessageAck(data, relayAck); });
    run("DeserializeHistorySyncRequest", [&] { return p2p::protocol::DeserializeHistorySyncRequest(data, historyReq); });
    run("DeserializeHistorySyncResponse", [&] { return p2p::protocol::DeserializeHistorySyncResponse(data, historyResp); });
}


void FuzzPacketWrapping(std::mt19937_64& rng) {
    std::uniform_int_distribution<int> typeDist(static_cast<int>(PacketType::Hello),
                                                static_cast<int>(PacketType::HistorySyncResponse));
    std::uniform_int_distribution<std::uint64_t> idDist;

    const auto payload = RandomBytes(rng, 2048);
    const auto type = static_cast<PacketType>(typeDist(rng));
    const auto packet = p2p::protocol::MakePacket(type, idDist(rng), payload);

    if (packet.size() < sizeof(PacketHeader)) {
        throw std::runtime_error("packet shorter than header");
    }

    const auto* header = reinterpret_cast<const PacketHeader*>(packet.data());
    if (header->size != payload.size()) {
        throw std::runtime_error("serialized payload size mismatch");
    }

    ByteVector body(packet.begin() + sizeof(PacketHeader), packet.end());
    TryAllDeserializers(body);
}

} // namespace

int RunPacketProtocolFuzz(int iterations) {
    if (iterations < 1) iterations = 1;
    std::random_device rd;
    std::mt19937_64 rng((static_cast<std::uint64_t>(rd()) << 32u) ^ rd());

    try {
        for (int i = 0; i < iterations; ++i) {
            const auto data = RandomBytes(rng, 4096);
            TryAllDeserializers(data);
            FuzzPacketWrapping(rng);
        }
    } catch (const std::exception& ex) {
        std::cerr << "[fuzz] fatal: " << ex.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "[fuzz] fatal: unknown exception" << std::endl;
        return 2;
    }

    std::cout << "[fuzz] ok, iterations=" << iterations << std::endl;
    return 0;
}

#ifdef P2P_FUZZ_STANDALONE
int main(int argc, char** argv) {
    int iterations = 50000;
    if (argc > 1) {
        iterations = std::atoi(argv[1]);
        if (iterations < 1) iterations = 1;
    }
    return RunPacketProtocolFuzz(iterations);
}
#endif
