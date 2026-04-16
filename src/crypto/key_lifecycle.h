#pragma once

#include <string>
#include <vector>

namespace p2p {

class CryptoSigner;

struct KeyLifecycleStatus {
    std::string nodeId;
    std::wstring containerName;
    bool containerExists = false;
    std::string signFingerprint;
    std::string encryptFingerprint;
};

class KeyLifecycleManager {
public:
    static bool GetStatus(const std::string& nodeId, CryptoSigner& signer, KeyLifecycleStatus& out);
    static bool BackupPublicMaterial(const std::string& nodeId,
                                     const std::string& nickname,
                                     CryptoSigner& signer,
                                     const std::string& backupDir,
                                     std::string* outPath,
                                     std::string* error);
    static bool RotateKeyContainer(const std::string& nodeId,
                                   CryptoSigner& signer,
                                   std::string* error);
    static bool RevokeKeyContainer(const std::string& nodeId,
                                   CryptoSigner& signer,
                                   std::string* error);
};

} // namespace p2p
