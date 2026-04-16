#pragma once
#include "core/types.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace p2p::utils {

std::string GenerateNodeId();
std::uint64_t GeneratePacketId();

bool SendAll(SOCKET s, const std::uint8_t* data, std::size_t size);
bool RecvAll(SOCKET s, std::uint8_t* data, std::size_t size);

void WriteUint16(ByteVector& out, std::uint16_t value);
void WriteUint32(ByteVector& out, std::uint32_t value);
void WriteUint64(ByteVector& out, std::uint64_t value);
void WriteString(ByteVector& out, const std::string& value);
void WriteBytes(ByteVector& out, const ByteVector& value);

bool ReadUint16(const ByteVector& data, std::size_t& offset, std::uint16_t& value);
bool ReadUint32(const ByteVector& data, std::size_t& offset, std::uint32_t& value);
bool ReadUint64(const ByteVector& data, std::size_t& offset, std::uint64_t& value);
bool ReadString(const ByteVector& data, std::size_t& offset, std::string& value);
bool ReadBytes(const ByteVector& data, std::size_t& offset, ByteVector& value);

std::string SocketAddressToIp(const sockaddr_in& addr);

void LogRaw(const std::string& line);
void LogSystem(const std::string& line);
void LogWarn(const std::string& line);
void LogError(const std::string& line);
void LogDebug(const std::string& line);
void LogGlobal(const std::string& nickname, const std::string& text);
void LogPrivate(const std::string& nickname, const std::string& text);

} // namespace p2p::utils
