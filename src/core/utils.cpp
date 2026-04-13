#include "core/utils.h"

#include <cstring>
#include <iostream>
#include <mutex>
#include <random>
#include <sstream>

namespace p2p::utils {
namespace {
std::mutex g_log_mutex;
}

std::string GenerateNodeId() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    std::ostringstream oss;
    oss << std::hex << dist(rng) << dist(rng);
    return oss.str();
}

std::uint64_t GeneratePacketId() {
    static std::atomic<std::uint64_t> counter{1};
    return counter.fetch_add(1, std::memory_order_relaxed);
}

bool SendAll(SOCKET s, const std::uint8_t* data, std::size_t size) {
    std::size_t total = 0;
    while (total < size) {
        int sent = send(s, reinterpret_cast<const char*>(data + total), static_cast<int>(size - total), 0);
        if (sent <= 0) return false;
        total += static_cast<std::size_t>(sent);
    }
    return true;
}

bool RecvAll(SOCKET s, std::uint8_t* data, std::size_t size) {
    std::size_t total = 0;
    while (total < size) {
        int recvd = recv(s, reinterpret_cast<char*>(data + total), static_cast<int>(size - total), 0);
        if (recvd <= 0) return false;
        total += static_cast<std::size_t>(recvd);
    }
    return true;
}

void WriteUint16(ByteVector& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
}

void WriteUint32(ByteVector& out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF));
}

void WriteUint64(ByteVector& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF));
}

void WriteString(ByteVector& out, const std::string& value) {
    WriteUint32(out, static_cast<std::uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

void WriteBytes(ByteVector& out, const ByteVector& value) {
    WriteUint32(out, static_cast<std::uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

bool ReadUint16(const ByteVector& data, std::size_t& offset, std::uint16_t& value) {
    if (offset + 2 > data.size()) return false;
    value = static_cast<std::uint16_t>(data[offset]) |
            (static_cast<std::uint16_t>(data[offset + 1]) << 8);
    offset += 2;
    return true;
}

bool ReadUint32(const ByteVector& data, std::size_t& offset, std::uint32_t& value) {
    if (offset + 4 > data.size()) return false;
    value = 0;
    for (int i = 0; i < 4; ++i) value |= (static_cast<std::uint32_t>(data[offset + i]) << (8 * i));
    offset += 4;
    return true;
}

bool ReadUint64(const ByteVector& data, std::size_t& offset, std::uint64_t& value) {
    if (offset + 8 > data.size()) return false;
    value = 0;
    for (int i = 0; i < 8; ++i) value |= (static_cast<std::uint64_t>(data[offset + i]) << (8 * i));
    offset += 8;
    return true;
}

bool ReadString(const ByteVector& data, std::size_t& offset, std::string& value) {
    std::uint32_t len = 0;
    if (!ReadUint32(data, offset, len)) return false;
    if (offset + len > data.size()) return false;
    value.assign(reinterpret_cast<const char*>(data.data() + offset), len);
    offset += len;
    return true;
}

bool ReadBytes(const ByteVector& data, std::size_t& offset, ByteVector& value) {
    std::uint32_t len = 0;
    if (!ReadUint32(data, offset, len)) return false;
    if (offset + len > data.size()) return false;
    value.assign(data.begin() + offset, data.begin() + offset + len);
    offset += len;
    return true;
}

std::string SocketAddressToIp(const sockaddr_in& addr) {
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf));
    return std::string(buf);
}

void LogRaw(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::cout << line << std::endl;
}

void LogSystem(const std::string& line) { LogRaw("[System] " + line); }
void LogError(const std::string& line) { LogRaw("[Error] " + line); }
void LogGlobal(const std::string& nickname, const std::string& text) { LogRaw("[Global] " + nickname + ": " + text); }
void LogPrivate(const std::string& nickname, const std::string& text) { LogRaw("[Private | " + nickname + "] " + text); }

} // namespace p2p::utils
