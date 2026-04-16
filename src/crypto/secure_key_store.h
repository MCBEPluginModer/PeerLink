#pragma once

#include <cstdint>
#include <string>

namespace p2p {

struct SecureKeyMetadata {
    std::string nodeId;
    std::wstring containerName;
    std::string signFingerprint;
    std::string encryptFingerprint;
    std::uint16_t protocolVersion = 0;
    std::int64_t updatedAtUnix = 0;
    bool revoked = false;
};

class SecureKeyStore {
public:
    static bool SaveMetadata(const SecureKeyMetadata& metadata, std::string* error);
    static bool LoadMetadata(const std::string& nodeId, SecureKeyMetadata& metadata, std::string* error);
    static bool HasMetadata(const std::string& nodeId);
};

} // namespace p2p
