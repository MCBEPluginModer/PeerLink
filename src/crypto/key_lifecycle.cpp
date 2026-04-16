#include "crypto/key_lifecycle.h"

#include "core/fingerprint_utils.h"
#include "crypto/crypto_signer.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>

namespace p2p {
namespace fs = std::filesystem;

namespace {
std::string TimestampForFile() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y%m%d_%H%M%S");
    return out.str();
}

std::string WStringToUtf8(const std::wstring& value) {
    return std::string(value.begin(), value.end());
}

std::string BytesToHexLocal(const ByteVector& data) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (std::uint8_t b : data) {
        out.push_back(hex[(b >> 4) & 0x0F]);
        out.push_back(hex[b & 0x0F]);
    }
    return out;
}
}

bool KeyLifecycleManager::GetStatus(const std::string& nodeId, CryptoSigner& signer, KeyLifecycleStatus& out) {
    out = {};
    out.nodeId = nodeId;
    out.containerName = signer.GetContainerName().empty()
        ? CryptoSigner::MakeContainerNameForNodeId(nodeId)
        : signer.GetContainerName();
    out.containerExists = CryptoSigner::ContainerExists(out.containerName);

    ByteVector signBlob;
    if (signer.ExportPublicKey(signBlob)) out.signFingerprint = ComputeFingerprint(signBlob);
    ByteVector encBlob;
    if (signer.ExportEncryptPublicKey(encBlob)) out.encryptFingerprint = ComputeFingerprint(encBlob);
    return true;
}

bool KeyLifecycleManager::BackupPublicMaterial(const std::string& nodeId,
                                               const std::string& nickname,
                                               CryptoSigner& signer,
                                               const std::string& backupDir,
                                               std::string* outPath,
                                               std::string* error) {
    try {
        fs::create_directories(backupDir);
        const fs::path path = fs::path(backupDir) / (nodeId + "_keys_" + TimestampForFile() + ".txt");
        ByteVector signBlob;
        ByteVector encBlob;
        if (!signer.ExportPublicKey(signBlob) || !signer.ExportEncryptPublicKey(encBlob)) {
            if (error) *error = "failed to export public material for backup";
            return false;
        }
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error) *error = "failed to open backup file";
            return false;
        }
        out << "nickname=" << nickname << "\n";
        out << "node_id=" << nodeId << "\n";
        out << "container=" << WStringToUtf8(signer.GetContainerName()) << "\n";
        out << "sign_fingerprint=" << ComputeFingerprint(signBlob) << "\n";
        out << "encrypt_fingerprint=" << ComputeFingerprint(encBlob) << "\n";
        out << "sign_public_blob_hex=" << BytesToHexLocal(signBlob) << "\n";
        out << "encrypt_public_blob_hex=" << BytesToHexLocal(encBlob) << "\n";
        if (outPath) *outPath = path.string();
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    } catch (...) {
        if (error) *error = "unknown backup failure";
        return false;
    }
}

bool KeyLifecycleManager::RotateKeyContainer(const std::string& nodeId,
                                             CryptoSigner& signer,
                                             std::string* error) {
    const std::wstring container = signer.GetContainerName().empty()
        ? CryptoSigner::MakeContainerNameForNodeId(nodeId)
        : signer.GetContainerName();
    signer.Cleanup();
    if (CryptoSigner::ContainerExists(container) && !CryptoSigner::DeleteContainer(container)) {
        if (error) *error = "failed to delete existing key container";
        return false;
    }
    if (!signer.Initialize(container)) {
        if (error) *error = "failed to create new key container";
        return false;
    }
    return true;
}

bool KeyLifecycleManager::RevokeKeyContainer(const std::string& nodeId,
                                             CryptoSigner& signer,
                                             std::string* error) {
    const std::wstring container = signer.GetContainerName().empty()
        ? CryptoSigner::MakeContainerNameForNodeId(nodeId)
        : signer.GetContainerName();
    signer.Cleanup();
    if (CryptoSigner::ContainerExists(container) && !CryptoSigner::DeleteContainer(container)) {
        if (error) *error = "failed to revoke existing key container";
        return false;
    }
    return true;
}

} // namespace p2p
