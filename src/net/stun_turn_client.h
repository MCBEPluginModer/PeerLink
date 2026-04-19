#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <winsock2.h>

namespace p2p::nat {

struct ServerEndpoint {
    std::string host;
    std::uint16_t port = 0;
};

struct StunBindingResult {
    std::string mappedIp;
    std::uint16_t mappedPort = 0;
    std::string serverIp;
    std::uint16_t serverPort = 0;
};

struct TurnAllocationResult {
    bool allocated = false;
    std::string serverIp;
    std::uint16_t serverPort = 0;
    std::string relayedIp;
    std::uint16_t relayedPort = 0;
    std::string mappedIp;
    std::uint16_t mappedPort = 0;
    std::string username;
    std::string realm;
    std::string nonce;
    std::uint32_t lifetimeSeconds = 0;
};

enum class TransactionKind {
    StunBinding,
    TurnAllocateUnauth,
    TurnAllocateAuth,
    TurnRefresh,
    TurnCreatePermission,
    TurnChannelBind,
    TurnSendIndication
};

struct TransactionInfo {
    TransactionKind kind = TransactionKind::StunBinding;
    ServerEndpoint server;
    std::string peerIp;
    std::uint16_t peerPort = 0;
    std::uint16_t channelNumber = 0;
    std::string username;
    std::string realm;
    std::string nonce;
    std::vector<std::uint8_t> payload;
};

class StunTurnClient {
public:
    using SendDatagramFn = std::function<bool(const std::string&, std::uint16_t, const std::vector<std::uint8_t>&)>;

    explicit StunTurnClient(SendDatagramFn sender);

    bool QueryStunBinding(const ServerEndpoint& server);
    bool StartTurnAllocate(const ServerEndpoint& server, const std::string& username = {}, const std::string& password = {});
    bool RefreshTurnAllocation(std::uint32_t lifetimeSeconds = 600);
    bool CreatePermission(const std::string& peerIp, std::uint16_t peerPort);
    bool ChannelBind(const std::string& peerIp, std::uint16_t peerPort, std::uint16_t channelNumber);
    bool SendIndication(const std::string& peerIp, std::uint16_t peerPort, const std::vector<std::uint8_t>& data);

    bool HandleDatagram(const std::string& fromIp, std::uint16_t fromPort, const std::vector<std::uint8_t>& data);

    std::optional<StunBindingResult> GetLastBinding() const { return lastBinding_; }
    std::optional<TurnAllocationResult> GetTurnAllocation() const { return turnAllocation_; }
    bool HasActiveTurnAllocation() const { return turnAllocation_.has_value() && turnAllocation_->allocated; }
    std::size_t PendingTransactions() const { return pending_.size(); }

private:
    bool SendRequest(const ServerEndpoint& server, TransactionKind kind, const std::vector<std::uint8_t>& request, const TransactionInfo& info);
    std::vector<std::uint8_t> BuildBindingRequest(const std::array<std::uint8_t, 12>& txid) const;
    std::vector<std::uint8_t> BuildAllocateRequest(const std::array<std::uint8_t, 12>& txid, bool authenticated, const std::string& username, const std::string& realm, const std::string& nonce) const;
    std::vector<std::uint8_t> BuildRefreshRequest(const std::array<std::uint8_t, 12>& txid, std::uint32_t lifetimeSeconds) const;
    std::vector<std::uint8_t> BuildCreatePermissionRequest(const std::array<std::uint8_t, 12>& txid, const std::string& peerIp, std::uint16_t peerPort) const;
    std::vector<std::uint8_t> BuildChannelBindRequest(const std::array<std::uint8_t, 12>& txid, const std::string& peerIp, std::uint16_t peerPort, std::uint16_t channelNumber) const;
    std::vector<std::uint8_t> BuildSendIndication(const std::string& peerIp, std::uint16_t peerPort, const std::vector<std::uint8_t>& data) const;

    std::optional<StunBindingResult> ParseBindingSuccess(const std::string& fromIp, std::uint16_t fromPort, const std::vector<std::uint8_t>& data) const;
    void ParseTurnAllocationSuccess(const std::string& fromIp, std::uint16_t fromPort, const std::vector<std::uint8_t>& data, TurnAllocationResult& out) const;
    void ParseErrorAuth(const std::vector<std::uint8_t>& data, std::string& realm, std::string& nonce) const;
    std::array<std::uint8_t, 12> MakeTransactionId() const;
    std::string TxKey(const std::array<std::uint8_t, 12>& txid) const;

    SendDatagramFn sender_;
    std::unordered_map<std::string, TransactionInfo> pending_;
    std::optional<StunBindingResult> lastBinding_;
    std::optional<TurnAllocationResult> turnAllocation_;
    std::string turnPassword_;
};

bool ParseServerEndpointListFile(const std::string& path, std::vector<ServerEndpoint>& out);

} // namespace p2p::nat
