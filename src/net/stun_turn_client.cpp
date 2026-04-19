#include "net/stun_turn_client.h"

#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <random>
#include <sstream>

namespace p2p::nat {
namespace {
constexpr std::uint16_t kStunBindingRequest = 0x0001;
constexpr std::uint16_t kStunBindingSuccess = 0x0101;
constexpr std::uint16_t kStunErrorResponse = 0x0111;
constexpr std::uint16_t kTurnAllocateRequest = 0x0003;
constexpr std::uint16_t kTurnAllocateSuccess = 0x0103;
constexpr std::uint16_t kTurnRefreshRequest = 0x0004;
constexpr std::uint16_t kTurnCreatePermissionRequest = 0x0008;
constexpr std::uint16_t kTurnChannelBindRequest = 0x0009;
constexpr std::uint16_t kTurnSendIndication = 0x0016;
constexpr std::uint32_t kMagicCookie = 0x2112A442u;
constexpr std::uint16_t kAttrMappedAddress = 0x0001;
constexpr std::uint16_t kAttrUsername = 0x0006;
constexpr std::uint16_t kAttrMessageIntegrity = 0x0008; // reserved for future, not emitted
constexpr std::uint16_t kAttrErrorCode = 0x0009;
constexpr std::uint16_t kAttrRealm = 0x0014;
constexpr std::uint16_t kAttrNonce = 0x0015;
constexpr std::uint16_t kAttrXorRelayedAddress = 0x0016;
constexpr std::uint16_t kAttrRequestedTransport = 0x0019;
constexpr std::uint16_t kAttrXorMappedAddress = 0x0020;
constexpr std::uint16_t kAttrLifetime = 0x000d;
constexpr std::uint16_t kAttrXorPeerAddress = 0x0012;
constexpr std::uint16_t kAttrData = 0x0013;
constexpr std::uint16_t kAttrChannelNumber = 0x000c;

void WriteU16(std::vector<std::uint8_t>& out, std::uint16_t v) { out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF)); out.push_back(static_cast<std::uint8_t>(v & 0xFF)); }
void WriteU32(std::vector<std::uint8_t>& out, std::uint32_t v) { out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF)); out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF)); out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF)); out.push_back(static_cast<std::uint8_t>(v & 0xFF)); }
std::uint16_t ReadU16(const std::vector<std::uint8_t>& data, std::size_t off) { return static_cast<std::uint16_t>((data[off] << 8) | data[off+1]); }
std::uint32_t ReadU32(const std::vector<std::uint8_t>& data, std::size_t off) { return (static_cast<std::uint32_t>(data[off]) << 24) | (static_cast<std::uint32_t>(data[off+1]) << 16) | (static_cast<std::uint32_t>(data[off+2]) << 8) | data[off+3]; }

std::string Trim(std::string v) {
    auto ns = [](unsigned char c){ return !std::isspace(c); };
    v.erase(v.begin(), std::find_if(v.begin(), v.end(), ns));
    v.erase(std::find_if(v.rbegin(), v.rend(), ns).base(), v.end());
    return v;
}

void AddAttr(std::vector<std::uint8_t>& out, std::uint16_t type, const std::vector<std::uint8_t>& value) {
    WriteU16(out, type);
    WriteU16(out, static_cast<std::uint16_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
    while (out.size() % 4 != 0) out.push_back(0);
}

std::vector<std::uint8_t> MakeAddressValue(const std::string& ip, std::uint16_t port, const std::array<std::uint8_t,12>* txid) {
    std::vector<std::uint8_t> v;
    v.push_back(0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) return {};
    v.push_back(0x01);
    std::uint16_t xorPort = txid ? static_cast<std::uint16_t>(port ^ (kMagicCookie >> 16)) : port;
    WriteU16(v, xorPort);
    auto raw = reinterpret_cast<const std::uint8_t*>(&addr.sin_addr);
    for (int i = 0; i < 4; ++i) {
        std::uint8_t b = raw[i];
        if (txid) b ^= reinterpret_cast<const std::uint8_t*>(&kMagicCookie)[3 - i];
        v.push_back(b);
    }
    return v;
}

bool ParseAddressAttr(const std::vector<std::uint8_t>& data, std::size_t off, std::size_t len, bool xored, const std::array<std::uint8_t,12>& txid, std::string& ipOut, std::uint16_t& portOut) {
    if (len < 8 || off + len > data.size()) return false;
    if (data[off + 1] != 0x01) return false;
    portOut = ReadU16(data, off + 2);
    std::array<std::uint8_t,4> ip{};
    for (int i = 0; i < 4; ++i) ip[i] = data[off + 4 + i];
    if (xored) {
        portOut ^= static_cast<std::uint16_t>(kMagicCookie >> 16);
        const auto* mc = reinterpret_cast<const std::uint8_t*>(&kMagicCookie);
        for (int i = 0; i < 4; ++i) ip[i] ^= mc[3 - i];
    }
    char buf[INET_ADDRSTRLEN]{};
    in_addr a{};
    std::copy(ip.begin(), ip.end(), reinterpret_cast<std::uint8_t*>(&a));
    if (!inet_ntop(AF_INET, &a, buf, sizeof(buf))) return false;
    ipOut = buf;
    return true;
}
} // namespace

StunTurnClient::StunTurnClient(SendDatagramFn sender) : sender_(std::move(sender)) {}

std::array<std::uint8_t, 12> StunTurnClient::MakeTransactionId() const {
    std::array<std::uint8_t, 12> tx{};
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    for (auto& b : tx) b = static_cast<std::uint8_t>(rng() & 0xFF);
    return tx;
}

std::string StunTurnClient::TxKey(const std::array<std::uint8_t, 12>& txid) const {
    static const char* hex = "0123456789abcdef";
    std::string out; out.reserve(24);
    for (auto b : txid) { out.push_back(hex[(b >> 4) & 0xF]); out.push_back(hex[b & 0xF]); }
    return out;
}

bool StunTurnClient::SendRequest(const ServerEndpoint& server, TransactionKind kind, const std::vector<std::uint8_t>& request, const TransactionInfo& info) {
    if (!sender_ || server.host.empty() || server.port == 0 || request.empty()) return false;
    auto txid = MakeTransactionId();
    auto data = request;
    std::copy(txid.begin(), txid.end(), data.begin() + 8);
    auto key = TxKey(txid);
    pending_[key] = info;
    return sender_(server.host, server.port, data);
}

std::vector<std::uint8_t> StunTurnClient::BuildBindingRequest(const std::array<std::uint8_t, 12>& txid) const {
    std::vector<std::uint8_t> out;
    WriteU16(out, kStunBindingRequest); WriteU16(out, 0); WriteU32(out, kMagicCookie); out.resize(20); return out;
}

std::vector<std::uint8_t> StunTurnClient::BuildAllocateRequest(const std::array<std::uint8_t, 12>& txid, bool authenticated, const std::string& username, const std::string& realm, const std::string& nonce) const {
    std::vector<std::uint8_t> out;
    WriteU16(out, kTurnAllocateRequest); WriteU16(out, 0); WriteU32(out, kMagicCookie); out.resize(20);
    AddAttr(out, kAttrRequestedTransport, {17,0,0,0});
    if (authenticated) {
        if (!username.empty()) AddAttr(out, kAttrUsername, std::vector<std::uint8_t>(username.begin(), username.end()));
        if (!realm.empty()) AddAttr(out, kAttrRealm, std::vector<std::uint8_t>(realm.begin(), realm.end()));
        if (!nonce.empty()) AddAttr(out, kAttrNonce, std::vector<std::uint8_t>(nonce.begin(), nonce.end()));
    }
    auto len = static_cast<std::uint16_t>(out.size() - 20); out[2] = static_cast<std::uint8_t>((len >> 8) & 0xFF); out[3] = static_cast<std::uint8_t>(len & 0xFF); return out;
}

std::vector<std::uint8_t> StunTurnClient::BuildRefreshRequest(const std::array<std::uint8_t, 12>& txid, std::uint32_t lifetimeSeconds) const {
    std::vector<std::uint8_t> out;
    WriteU16(out, kTurnRefreshRequest); WriteU16(out, 0); WriteU32(out, kMagicCookie); out.resize(20);
    std::vector<std::uint8_t> val; WriteU32(val, lifetimeSeconds); AddAttr(out, kAttrLifetime, val);
    if (turnAllocation_) {
        if (!turnAllocation_->username.empty()) AddAttr(out, kAttrUsername, std::vector<std::uint8_t>(turnAllocation_->username.begin(), turnAllocation_->username.end()));
        if (!turnAllocation_->realm.empty()) AddAttr(out, kAttrRealm, std::vector<std::uint8_t>(turnAllocation_->realm.begin(), turnAllocation_->realm.end()));
        if (!turnAllocation_->nonce.empty()) AddAttr(out, kAttrNonce, std::vector<std::uint8_t>(turnAllocation_->nonce.begin(), turnAllocation_->nonce.end()));
    }
    auto len = static_cast<std::uint16_t>(out.size() - 20); out[2] = static_cast<std::uint8_t>((len >> 8) & 0xFF); out[3] = static_cast<std::uint8_t>(len & 0xFF); return out;
}

std::vector<std::uint8_t> StunTurnClient::BuildCreatePermissionRequest(const std::array<std::uint8_t, 12>& txid, const std::string& peerIp, std::uint16_t peerPort) const {
    std::vector<std::uint8_t> out; WriteU16(out, kTurnCreatePermissionRequest); WriteU16(out, 0); WriteU32(out, kMagicCookie); out.resize(20);
    AddAttr(out, kAttrXorPeerAddress, MakeAddressValue(peerIp, peerPort, &txid));
    if (turnAllocation_) {
        if (!turnAllocation_->username.empty()) AddAttr(out, kAttrUsername, std::vector<std::uint8_t>(turnAllocation_->username.begin(), turnAllocation_->username.end()));
        if (!turnAllocation_->realm.empty()) AddAttr(out, kAttrRealm, std::vector<std::uint8_t>(turnAllocation_->realm.begin(), turnAllocation_->realm.end()));
        if (!turnAllocation_->nonce.empty()) AddAttr(out, kAttrNonce, std::vector<std::uint8_t>(turnAllocation_->nonce.begin(), turnAllocation_->nonce.end()));
    }
    auto len = static_cast<std::uint16_t>(out.size() - 20); out[2] = static_cast<std::uint8_t>((len >> 8) & 0xFF); out[3] = static_cast<std::uint8_t>(len & 0xFF); return out;
}

std::vector<std::uint8_t> StunTurnClient::BuildChannelBindRequest(const std::array<std::uint8_t, 12>& txid, const std::string& peerIp, std::uint16_t peerPort, std::uint16_t channelNumber) const {
    std::vector<std::uint8_t> out; WriteU16(out, kTurnChannelBindRequest); WriteU16(out, 0); WriteU32(out, kMagicCookie); out.resize(20);
    std::vector<std::uint8_t> ch; WriteU16(ch, channelNumber); WriteU16(ch, 0); AddAttr(out, kAttrChannelNumber, ch);
    AddAttr(out, kAttrXorPeerAddress, MakeAddressValue(peerIp, peerPort, &txid));
    if (turnAllocation_) {
        if (!turnAllocation_->username.empty()) AddAttr(out, kAttrUsername, std::vector<std::uint8_t>(turnAllocation_->username.begin(), turnAllocation_->username.end()));
        if (!turnAllocation_->realm.empty()) AddAttr(out, kAttrRealm, std::vector<std::uint8_t>(turnAllocation_->realm.begin(), turnAllocation_->realm.end()));
        if (!turnAllocation_->nonce.empty()) AddAttr(out, kAttrNonce, std::vector<std::uint8_t>(turnAllocation_->nonce.begin(), turnAllocation_->nonce.end()));
    }
    auto len = static_cast<std::uint16_t>(out.size() - 20); out[2] = static_cast<std::uint8_t>((len >> 8) & 0xFF); out[3] = static_cast<std::uint8_t>(len & 0xFF); return out;
}

std::vector<std::uint8_t> StunTurnClient::BuildSendIndication(const std::string& peerIp, std::uint16_t peerPort, const std::vector<std::uint8_t>& data) const {
    std::array<std::uint8_t,12> tx{};
    std::vector<std::uint8_t> out; WriteU16(out, kTurnSendIndication); WriteU16(out, 0); WriteU32(out, kMagicCookie); out.resize(20);
    AddAttr(out, kAttrXorPeerAddress, MakeAddressValue(peerIp, peerPort, &tx));
    AddAttr(out, kAttrData, data);
    auto len = static_cast<std::uint16_t>(out.size() - 20); out[2] = static_cast<std::uint8_t>((len >> 8) & 0xFF); out[3] = static_cast<std::uint8_t>(len & 0xFF); return out;
}

bool StunTurnClient::QueryStunBinding(const ServerEndpoint& server) {
    TransactionInfo info{}; info.kind = TransactionKind::StunBinding; info.server = server;
    std::array<std::uint8_t,12> tx{};
    return SendRequest(server, TransactionKind::StunBinding, BuildBindingRequest(tx), info);
}

bool StunTurnClient::StartTurnAllocate(const ServerEndpoint& server, const std::string& username, const std::string& password) {
    turnPassword_ = password;
    TransactionInfo info{}; info.kind = TransactionKind::TurnAllocateUnauth; info.server = server; info.username = username;
    std::array<std::uint8_t,12> tx{};
    return SendRequest(server, info.kind, BuildAllocateRequest(tx, false, {}, {}, {}), info);
}

bool StunTurnClient::RefreshTurnAllocation(std::uint32_t lifetimeSeconds) {
    if (!turnAllocation_) return false;
    TransactionInfo info{}; info.kind = TransactionKind::TurnRefresh; info.server = {turnAllocation_->serverIp, turnAllocation_->serverPort};
    std::array<std::uint8_t,12> tx{};
    return SendRequest(info.server, info.kind, BuildRefreshRequest(tx, lifetimeSeconds), info);
}

bool StunTurnClient::CreatePermission(const std::string& peerIp, std::uint16_t peerPort) {
    if (!turnAllocation_) return false;
    TransactionInfo info{}; info.kind = TransactionKind::TurnCreatePermission; info.server = {turnAllocation_->serverIp, turnAllocation_->serverPort}; info.peerIp = peerIp; info.peerPort = peerPort;
    std::array<std::uint8_t,12> tx{};
    return SendRequest(info.server, info.kind, BuildCreatePermissionRequest(tx, peerIp, peerPort), info);
}

bool StunTurnClient::ChannelBind(const std::string& peerIp, std::uint16_t peerPort, std::uint16_t channelNumber) {
    if (!turnAllocation_) return false;
    TransactionInfo info{}; info.kind = TransactionKind::TurnChannelBind; info.server = {turnAllocation_->serverIp, turnAllocation_->serverPort}; info.peerIp = peerIp; info.peerPort = peerPort; info.channelNumber = channelNumber;
    std::array<std::uint8_t,12> tx{};
    return SendRequest(info.server, info.kind, BuildChannelBindRequest(tx, peerIp, peerPort, channelNumber), info);
}

bool StunTurnClient::SendIndication(const std::string& peerIp, std::uint16_t peerPort, const std::vector<std::uint8_t>& data) {
    if (!turnAllocation_) return false;
    return sender_(turnAllocation_->serverIp, turnAllocation_->serverPort, BuildSendIndication(peerIp, peerPort, data));
}

std::optional<StunBindingResult> StunTurnClient::ParseBindingSuccess(const std::string& fromIp, std::uint16_t fromPort, const std::vector<std::uint8_t>& data) const {
    if (data.size() < 20) return std::nullopt;
    std::array<std::uint8_t,12> tx{}; std::copy(data.begin() + 8, data.begin() + 20, tx.begin());
    std::size_t off = 20; const auto msgLen = ReadU16(data, 2);
    while (off + 4 <= data.size() && off + 4 <= 20 + msgLen) {
        auto type = ReadU16(data, off); auto len = ReadU16(data, off + 2); off += 4; if (off + len > data.size()) break;
        std::string ip; std::uint16_t port = 0;
        if ((type == kAttrXorMappedAddress && ParseAddressAttr(data, off, len, true, tx, ip, port)) ||
            (type == kAttrMappedAddress && ParseAddressAttr(data, off, len, false, tx, ip, port))) {
            return StunBindingResult{ip, port, fromIp, fromPort};
        }
        off += len; while (off % 4 != 0) ++off;
    }
    return std::nullopt;
}

void StunTurnClient::ParseTurnAllocationSuccess(const std::string& fromIp, std::uint16_t fromPort, const std::vector<std::uint8_t>& data, TurnAllocationResult& out) const {
    std::array<std::uint8_t,12> tx{}; std::copy(data.begin() + 8, data.begin() + 20, tx.begin());
    out.serverIp = fromIp; out.serverPort = fromPort; out.allocated = true;
    std::size_t off = 20; const auto msgLen = ReadU16(data, 2);
    while (off + 4 <= data.size() && off + 4 <= 20 + msgLen) {
        auto type = ReadU16(data, off); auto len = ReadU16(data, off + 2); off += 4; if (off + len > data.size()) break;
        if (type == kAttrXorRelayedAddress) {
            ParseAddressAttr(data, off, len, true, tx, out.relayedIp, out.relayedPort);
        } else if (type == kAttrXorMappedAddress) {
            ParseAddressAttr(data, off, len, true, tx, out.mappedIp, out.mappedPort);
        } else if (type == kAttrLifetime && len >= 4) {
            out.lifetimeSeconds = ReadU32(data, off);
        }
        off += len; while (off % 4 != 0) ++off;
    }
}

void StunTurnClient::ParseErrorAuth(const std::vector<std::uint8_t>& data, std::string& realm, std::string& nonce) const {
    std::size_t off = 20; const auto msgLen = ReadU16(data, 2);
    while (off + 4 <= data.size() && off + 4 <= 20 + msgLen) {
        auto type = ReadU16(data, off); auto len = ReadU16(data, off + 2); off += 4; if (off + len > data.size()) break;
        if (type == kAttrRealm) realm.assign(reinterpret_cast<const char*>(data.data() + off), len);
        else if (type == kAttrNonce) nonce.assign(reinterpret_cast<const char*>(data.data() + off), len);
        off += len; while (off % 4 != 0) ++off;
    }
}

bool StunTurnClient::HandleDatagram(const std::string& fromIp, std::uint16_t fromPort, const std::vector<std::uint8_t>& data) {
    if (data.size() < 20) return false;
    auto type = ReadU16(data, 0); auto cookie = ReadU32(data, 4); if (cookie != kMagicCookie) return false;
    std::array<std::uint8_t,12> tx{}; std::copy(data.begin() + 8, data.begin() + 20, tx.begin());
    auto key = TxKey(tx);
    auto it = pending_.find(key);
    if (it == pending_.end()) return false;
    auto info = it->second;
    pending_.erase(it);

    if (type == kStunBindingSuccess && info.kind == TransactionKind::StunBinding) {
        lastBinding_ = ParseBindingSuccess(fromIp, fromPort, data);
        return true;
    }
    if (type == kTurnAllocateSuccess && (info.kind == TransactionKind::TurnAllocateUnauth || info.kind == TransactionKind::TurnAllocateAuth)) {
        TurnAllocationResult result{}; result.username = info.username; result.realm = info.realm; result.nonce = info.nonce;
        ParseTurnAllocationSuccess(fromIp, fromPort, data, result);
        turnAllocation_ = result;
        return true;
    }
    if (type == kStunErrorResponse && info.kind == TransactionKind::TurnAllocateUnauth) {
        std::string realm, nonce; ParseErrorAuth(data, realm, nonce);
        TransactionInfo next{}; next.kind = TransactionKind::TurnAllocateAuth; next.server = info.server; next.username = info.username; next.realm = realm; next.nonce = nonce;
        if (!next.server.host.empty()) {
            if (!turnAllocation_) turnAllocation_ = TurnAllocationResult{};
            turnAllocation_->serverIp = fromIp; turnAllocation_->serverPort = fromPort; turnAllocation_->username = next.username; turnAllocation_->realm = realm; turnAllocation_->nonce = nonce;
            std::array<std::uint8_t,12> tx2{};
            return SendRequest(info.server, next.kind, BuildAllocateRequest(tx2, true, next.username, realm, nonce), next);
        }
    }
    if (type == 0x0104 && info.kind == TransactionKind::TurnRefresh) return true;
    if (type == 0x0108 && info.kind == TransactionKind::TurnCreatePermission) return true;
    if (type == 0x0109 && info.kind == TransactionKind::TurnChannelBind) return true;
    return false;
}

bool ParseServerEndpointListFile(const std::string& path, std::vector<ServerEndpoint>& out) {
    out.clear();
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        ServerEndpoint ep{}; ep.host = Trim(line.substr(0, pos));
        try { ep.port = static_cast<std::uint16_t>(std::stoul(Trim(line.substr(pos + 1)))); } catch (...) { continue; }
        if (!ep.host.empty() && ep.port != 0) out.push_back(ep);
    }
    return !out.empty();
}

} // namespace p2p::nat
