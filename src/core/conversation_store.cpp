#include "core/conversation_store.h"

#include "core/utils.h"
#include "crypto/crypto_signer.h"

#include <windows.h>
#include <wincrypt.h>

#include <filesystem>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <unordered_map>
#include <cctype>

namespace p2p {
namespace fs = std::filesystem;

namespace {

constexpr std::size_t kMaxStoredJsonLine = 1024 * 1024;
constexpr std::size_t kMaxStoredHexFieldLen = 512 * 1024;

bool SafeHexField(const std::string& value, std::size_t maxLen = kMaxStoredHexFieldLen);
bool AtomicWriteTextFile(const fs::path& path, const std::string& data, std::string* error);

struct StoredRecord {
    std::uint64_t version = 1;
    bool hasStateField = false;
    std::string direction;
    std::uint64_t messageId = 0;
    std::uint64_t sessionId = 0;
    std::uint64_t sequenceNumber = 0;
    std::string fromNodeId;
    std::string fromNicknameHex;
    std::string toNodeId;
    std::string textHex;
    std::string ivHex;
    std::string ciphertextHex;
    std::string signatureHex;
    std::string signerPublicKeyHex;
    std::string storedAtUtc;
    std::string state;
    std::string prevHashHex;
    std::string recordHashHex;
};

struct ManifestRecord {
    std::uint64_t version = 1;
    std::string peerNodeId;
    std::uint64_t messageCount = 0;
    std::string latestRecordHashHex;
    std::string updatedAtUtc;
    std::string localPublicKeyHex;
    std::string signatureHex;
};

std::string BytesToHex(const ByteVector& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::uint8_t b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::optional<ByteVector> HexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    ByteVector out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        unsigned int value = 0;
        std::istringstream iss(hex.substr(i, 2));
        iss >> std::hex >> value;
        if (iss.fail()) return std::nullopt;
        out.push_back(static_cast<std::uint8_t>(value));
    }
    return out;
}

std::string StringToHex(const std::string& value) {
    return BytesToHex(ByteVector(value.begin(), value.end()));
}

std::optional<std::string> HexToString(const std::string& hex) {
    auto bytes = HexToBytes(hex);
    if (!bytes.has_value()) return std::nullopt;
    return std::string(bytes->begin(), bytes->end());
}

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

std::string CurrentUtcIso8601() {
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char buffer[64] = {};
    std::snprintf(buffer,
                  sizeof(buffer),
                  "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                  st.wYear,
                  st.wMonth,
                  st.wDay,
                  st.wHour,
                  st.wMinute,
                  st.wSecond,
                  st.wMilliseconds);
    return std::string(buffer);
}

std::string StoredMessageStateToString(StoredMessageState state) {
    switch (state) {
        case StoredMessageState::Created: return "created";
        case StoredMessageState::Queued: return "queued";
        case StoredMessageState::Sent: return "sent";
        case StoredMessageState::Relayed: return "relayed";
        case StoredMessageState::Delivered: return "delivered";
        case StoredMessageState::Failed: return "failed";
        default: return "created";
    }
}

StoredMessageState StoredMessageStateFromString(const std::string& state) {
    if (state == "queued") return StoredMessageState::Queued;
    if (state == "sent") return StoredMessageState::Sent;
    if (state == "relayed") return StoredMessageState::Relayed;
    if (state == "delivered") return StoredMessageState::Delivered;
    if (state == "failed") return StoredMessageState::Failed;
    return StoredMessageState::Created;
}

ByteVector Sha256(const ByteVector& data) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    ByteVector digest;

    if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return digest;
    }
    if (!CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        CryptReleaseContext(prov, 0);
        return digest;
    }
    if (!CryptHashData(hash, data.data(), static_cast<DWORD>(data.size()), 0)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(prov, 0);
        return digest;
    }

    DWORD size = 0;
    if (!CryptGetHashParam(hash, HP_HASHVAL, nullptr, &size, 0)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(prov, 0);
        return digest;
    }

    digest.resize(size);
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest.data(), &size, 0)) {
        digest.clear();
    } else {
        digest.resize(size);
    }

    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    return digest;
}

ByteVector BuildStoredRecordHashData(const StoredRecord& r) {
    ByteVector out;
    utils::WriteUint64(out, r.version);
    utils::WriteString(out, r.direction);
    utils::WriteUint64(out, r.messageId);
    utils::WriteUint64(out, r.sessionId);
    utils::WriteUint64(out, r.sequenceNumber);
    utils::WriteString(out, r.fromNodeId);
    utils::WriteString(out, r.fromNicknameHex);
    utils::WriteString(out, r.toNodeId);
    utils::WriteString(out, r.textHex);
    utils::WriteString(out, r.ivHex);
    utils::WriteString(out, r.ciphertextHex);
    utils::WriteString(out, r.signatureHex);
    utils::WriteString(out, r.signerPublicKeyHex);
    utils::WriteString(out, r.storedAtUtc);
    if (r.hasStateField || r.version >= 2) {
        utils::WriteString(out, r.state);
    }
    utils::WriteString(out, r.prevHashHex);
    return out;
}

ByteVector BuildManifestSignedData(const ManifestRecord& m) {
    ByteVector out;
    utils::WriteUint64(out, m.version);
    utils::WriteString(out, m.peerNodeId);
    utils::WriteUint64(out, m.messageCount);
    utils::WriteString(out, m.latestRecordHashHex);
    utils::WriteString(out, m.updatedAtUtc);
    utils::WriteString(out, m.localPublicKeyHex);
    return out;
}

std::string SerializeRecordJson(const StoredRecord& r) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"version\":" << r.version << ",";
    oss << "\"direction\":\"" << JsonEscape(r.direction) << "\",";
    oss << "\"message_id\":" << r.messageId << ",";
    oss << "\"session_id\":" << r.sessionId << ",";
    oss << "\"sequence_number\":" << r.sequenceNumber << ",";
    oss << "\"from_node_id\":\"" << JsonEscape(r.fromNodeId) << "\",";
    oss << "\"from_nickname_hex\":\"" << r.fromNicknameHex << "\",";
    oss << "\"to_node_id\":\"" << JsonEscape(r.toNodeId) << "\",";
    oss << "\"text_hex\":\"" << r.textHex << "\",";
    oss << "\"iv_hex\":\"" << r.ivHex << "\",";
    oss << "\"ciphertext_hex\":\"" << r.ciphertextHex << "\",";
    oss << "\"signature_hex\":\"" << r.signatureHex << "\",";
    oss << "\"signer_public_key_hex\":\"" << r.signerPublicKeyHex << "\",";
    oss << "\"stored_at_utc\":\"" << JsonEscape(r.storedAtUtc) << "\",";
    oss << "\"state\":\"" << JsonEscape(r.state) << "\",";
    oss << "\"prev_hash_hex\":\"" << r.prevHashHex << "\",";
    oss << "\"record_hash_hex\":\"" << r.recordHashHex << "\"";
    oss << "}";
    return oss.str();
}

std::string SerializeManifestJson(const ManifestRecord& m) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"version\":" << m.version << ",";
    oss << "\"peer_node_id\":\"" << JsonEscape(m.peerNodeId) << "\",";
    oss << "\"message_count\":" << m.messageCount << ",";
    oss << "\"latest_record_hash_hex\":\"" << m.latestRecordHashHex << "\",";
    oss << "\"updated_at_utc\":\"" << JsonEscape(m.updatedAtUtc) << "\",";
    oss << "\"local_public_key_hex\":\"" << m.localPublicKeyHex << "\",";
    oss << "\"signature_hex\":\"" << m.signatureHex << "\"";
    oss << "}";
    return oss.str();
}

std::optional<std::string> ExtractJsonString(const std::string& line, const std::string& key) {
    if (line.size() > kMaxStoredJsonLine) return std::nullopt;
    const std::string marker = "\"" + key + "\":\"";
    auto pos = line.find(marker);
    if (pos == std::string::npos) return std::nullopt;
    pos += marker.size();
    auto end = pos;
    bool escaped = false;
    while (end < line.size()) {
        char ch = line[end];
        if (!escaped && ch == '"') break;
        if (!escaped && ch == '\\') {
            escaped = true;
        } else {
            escaped = false;
        }
        ++end;
    }
    if (end >= line.size()) return std::nullopt;
    auto value = line.substr(pos, end - pos);
    if (value.size() > kMaxStoredHexFieldLen * 2) return std::nullopt;
    return value;
}

std::optional<std::uint64_t> ExtractJsonUint64(const std::string& line, const std::string& key) {
    const std::string marker = "\"" + key + "\":";
    auto pos = line.find(marker);
    if (pos == std::string::npos) return std::nullopt;
    pos += marker.size();
    auto end = line.find_first_of(",}", pos);
    if (end == std::string::npos) return std::nullopt;
    try {
        return static_cast<std::uint64_t>(std::stoull(line.substr(pos, end - pos)));
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<StoredRecord> ParseRecordJson(const std::string& line) {
    if (line.empty() || line.size() > kMaxStoredJsonLine) return std::nullopt;
    StoredRecord r{};
    auto version = ExtractJsonUint64(line, "version");
    auto direction = ExtractJsonString(line, "direction");
    auto messageId = ExtractJsonUint64(line, "message_id");
    auto sessionId = ExtractJsonUint64(line, "session_id");
    auto sequenceNumber = ExtractJsonUint64(line, "sequence_number");
    auto fromNodeId = ExtractJsonString(line, "from_node_id");
    auto fromNickHex = ExtractJsonString(line, "from_nickname_hex");
    auto toNodeId = ExtractJsonString(line, "to_node_id");
    auto textHex = ExtractJsonString(line, "text_hex");
    auto ivHex = ExtractJsonString(line, "iv_hex");
    auto ciphertextHex = ExtractJsonString(line, "ciphertext_hex");
    auto signatureHex = ExtractJsonString(line, "signature_hex");
    auto signerPubHex = ExtractJsonString(line, "signer_public_key_hex");
    auto storedAt = ExtractJsonString(line, "stored_at_utc");
    auto state = ExtractJsonString(line, "state");
    auto prevHash = ExtractJsonString(line, "prev_hash_hex");
    auto recordHash = ExtractJsonString(line, "record_hash_hex");
    if (!version || !direction || !messageId || !sessionId || !fromNodeId || !fromNickHex || !toNodeId || !textHex ||
        !ivHex || !ciphertextHex || !signatureHex || !signerPubHex || !storedAt || !prevHash || !recordHash) {
        return std::nullopt;
    }
    r.version = *version;
    r.direction = *direction;
    r.messageId = *messageId;
    r.sessionId = *sessionId;
    r.sequenceNumber = sequenceNumber.value_or(0);
    r.fromNodeId = *fromNodeId;
    r.fromNicknameHex = *fromNickHex;
    r.toNodeId = *toNodeId;
    if (!SafeHexField(*textHex) || !SafeHexField(*ivHex) || !SafeHexField(*ciphertextHex) ||
        !SafeHexField(*signatureHex) || !SafeHexField(*signerPubHex) || !SafeHexField(*fromNickHex)) {
        return std::nullopt;
    }
    r.textHex = *textHex;
    r.ivHex = *ivHex;
    r.ciphertextHex = *ciphertextHex;
    r.signatureHex = *signatureHex;
    r.signerPublicKeyHex = *signerPubHex;
    r.storedAtUtc = *storedAt;
    r.state = state.value_or("created");
    r.hasStateField = state.has_value();
    r.prevHashHex = *prevHash;
    r.recordHashHex = *recordHash;
    return r;
}

std::optional<ManifestRecord> ParseManifestJson(const std::string& line) {
    ManifestRecord m{};
    auto version = ExtractJsonUint64(line, "version");
    auto peerNodeId = ExtractJsonString(line, "peer_node_id");
    auto messageCount = ExtractJsonUint64(line, "message_count");
    auto latestHash = ExtractJsonString(line, "latest_record_hash_hex");
    auto updatedAt = ExtractJsonString(line, "updated_at_utc");
    auto localPubHex = ExtractJsonString(line, "local_public_key_hex");
    auto signatureHex = ExtractJsonString(line, "signature_hex");
    if (!version || !peerNodeId || !messageCount || !latestHash || !updatedAt || !localPubHex || !signatureHex) {
        return std::nullopt;
    }
    m.version = *version;
    m.peerNodeId = *peerNodeId;
    m.messageCount = *messageCount;
    m.latestRecordHashHex = *latestHash;
    m.updatedAtUtc = *updatedAt;
    m.localPublicKeyHex = *localPubHex;
    m.signatureHex = *signatureHex;
    return m;
}

fs::path ConversationStatePath(const fs::path& dir, const NodeId& peerNodeId) {
    return dir / (peerNodeId + ".state.json");
}

std::unordered_map<MessageId, StoredMessageState> LoadStateOverrides(const fs::path& path) {
    std::unordered_map<MessageId, StoredMessageState> out;
    std::ifstream in(path);
    if (!in) return out;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto msgId = ExtractJsonUint64(line, "message_id");
        auto state = ExtractJsonString(line, "state");
        if (!msgId || !state) continue;
        out[*msgId] = StoredMessageStateFromString(*state);
    }
    return out;
}

bool SaveStateOverrides(const fs::path& path, const std::unordered_map<MessageId, StoredMessageState>& states, std::string* error) {
    std::ostringstream out;
    for (const auto& [messageId, state] : states) {
        out << "{\"message_id\":" << messageId << ",\"state\":\"" << JsonEscape(StoredMessageStateToString(state)) << "\"}\n";
    }
    return AtomicWriteTextFile(path, out.str(), error);
}

bool ReadLastNonEmptyLine(const fs::path& path, std::string& outLine) {
    outLine.clear();
    std::ifstream in(path);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) outLine = line;
    }
    return !outLine.empty();
}

bool ReadWholeFile(const fs::path& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::ostringstream oss;
    oss << in.rdbuf();
    out = oss.str();
    return true;
}


bool SafeHexField(const std::string& value, std::size_t maxLen) {
    if (value.size() > maxLen) return false;
    if (value.size() % 2 != 0) return false;
    for (char ch : value) {
        if (!std::isxdigit(static_cast<unsigned char>(ch))) return false;
    }
    return true;
}

bool AtomicWriteTextFile(const fs::path& path, const std::string& data, std::string* error) {
    try {
        fs::create_directories(path.parent_path());
        fs::path tmp = path;
        tmp += ".tmp";
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            if (!out) {
                if (error) *error = "Failed to open temp file for write";
                return false;
            }
            out.write(data.data(), static_cast<std::streamsize>(data.size()));
            out.flush();
            if (!out) {
                if (error) *error = "Failed to write temp file";
                return false;
            }
        }
        std::error_code ec;
        fs::remove(path, ec);
        ec.clear();
        fs::rename(tmp, path, ec);
        if (ec) {
            fs::copy_file(tmp, path, fs::copy_options::overwrite_existing, ec);
            fs::remove(tmp, ec);
            if (ec) {
                if (error) *error = "Failed to replace file atomically";
                return false;
            }
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

std::string BuildConversationText(const std::vector<StoredRecord>& records) {
    std::ostringstream out;
    for (const auto& r : records) out << SerializeRecordJson(r) << "\n";
    return out.str();
}

std::string BuildManifestText(const ManifestRecord& manifest) {
    return SerializeManifestJson(manifest);
}

bool DecodeStoredRecord(const StoredRecord& r, PrivateMessagePayload& payload, ByteVector& pub, std::string* error) {
    auto nick = HexToString(r.fromNicknameHex);
    auto text = HexToString(r.textHex);
    auto iv = HexToBytes(r.ivHex);
    auto cipher = HexToBytes(r.ciphertextHex);
    auto sig = HexToBytes(r.signatureHex);
    auto signerPub = HexToBytes(r.signerPublicKeyHex);
    if (!nick || !text || !iv || !cipher || !sig || !signerPub) {
        if (error) *error = "Stored message decode failed";
        return false;
    }
    payload.messageId = r.messageId;
    payload.sessionId = r.sessionId;
    payload.sequenceNumber = r.sequenceNumber;
    payload.fromNodeId = r.fromNodeId;
    payload.fromNickname = *nick;
    payload.toNodeId = r.toNodeId;
    payload.text = *text;
    payload.iv = *iv;
    payload.ciphertext = *cipher;
    payload.signature = *sig;
    pub = *signerPub;
    return true;
}

bool ValidateStoredRecord(const StoredRecord& r, CryptoSigner& signer, const std::string& expectedPrevHash, std::string* error) {
    if (r.prevHashHex != expectedPrevHash) {
        if (error) *error = "Hash chain mismatch";
        return false;
    }
    const auto recomputed = BytesToHex(Sha256(BuildStoredRecordHashData(r)));
    if (recomputed != r.recordHashHex) {
        if (error) *error = "Stored record hash mismatch";
        return false;
    }
    PrivateMessagePayload payload{};
    ByteVector pub;
    if (!DecodeStoredRecord(r, payload, pub, error)) return false;

    ByteVector signData;
    utils::WriteUint64(signData, payload.messageId);
    utils::WriteUint64(signData, payload.sessionId);
    utils::WriteUint64(signData, payload.sequenceNumber);
    utils::WriteString(signData, payload.fromNodeId);
    utils::WriteString(signData, payload.fromNickname);
    utils::WriteString(signData, payload.toNodeId);
    utils::WriteBytes(signData, payload.iv);
    utils::WriteBytes(signData, payload.ciphertext);
    if (!signer.Verify(signData, payload.signature, pub)) {
        if (error) *error = "Stored message signature invalid";
        return false;
    }
    return true;
}

bool LoadValidConversationPrefix(const fs::path& convoPath,
                                 CryptoSigner& signer,
                                 std::vector<StoredRecord>& outRecords,
                                 bool* hadCorruption = nullptr,
                                 std::string* error = nullptr) {
    outRecords.clear();
    if (hadCorruption) *hadCorruption = false;
    std::ifstream in(convoPath);
    if (!in) {
        if (error) *error = "Failed to open conversation file";
        return false;
    }

    std::string prevHash;
    std::string line;
    std::size_t lineNo = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        if (line.empty()) continue;
        auto record = ParseRecordJson(line);
        if (!record) {
            if (hadCorruption) *hadCorruption = true;
            if (error) *error = "Conversation JSON parse failed at line " + std::to_string(lineNo);
            break;
        }
        std::string localError;
        if (!ValidateStoredRecord(*record, signer, prevHash, &localError)) {
            if (hadCorruption) *hadCorruption = true;
            if (error) *error = localError;
            break;
        }
        prevHash = record->recordHashHex;
        outRecords.push_back(*record);
    }
    return true;
}

bool RewriteConversationAndManifest(const fs::path& convoPath,
                                    const fs::path& manifestPath,
                                    const std::vector<StoredRecord>& records,
                                    const NodeId& peerNodeId,
                                    CryptoSigner& signer,
                                    const ByteVector& localPublicKeyBlob,
                                    std::string* error) {
    ManifestRecord manifest{};
    manifest.peerNodeId = peerNodeId;
    manifest.messageCount = static_cast<std::uint64_t>(records.size());
    manifest.latestRecordHashHex = records.empty() ? std::string() : records.back().recordHashHex;
    manifest.updatedAtUtc = records.empty() ? CurrentUtcIso8601() : records.back().storedAtUtc;
    manifest.localPublicKeyHex = BytesToHex(localPublicKeyBlob);
    ByteVector manifestSig;
    if (!signer.Sign(BuildManifestSignedData(manifest), manifestSig)) {
        if (error) *error = "Failed to sign manifest";
        return false;
    }
    manifest.signatureHex = BytesToHex(manifestSig);
    if (!AtomicWriteTextFile(convoPath, BuildConversationText(records), error)) return false;
    if (!AtomicWriteTextFile(manifestPath, BuildManifestText(manifest), error)) return false;
    return true;
}

bool VerifyManifest(const ManifestRecord& manifest, CryptoSigner& signer, std::string* error) {
    auto localPub = HexToBytes(manifest.localPublicKeyHex);
    auto sig = HexToBytes(manifest.signatureHex);
    if (!localPub || !sig) {
        if (error) *error = "Manifest hex decode failed";
        return false;
    }
    if (!signer.Verify(BuildManifestSignedData(manifest), *sig, *localPub)) {
        if (error) *error = "Manifest signature invalid";
        return false;
    }
    return true;
}

bool VerifyConversationFileInternal(const fs::path& convoPath,
                                    const fs::path& manifestPath,
                                    CryptoSigner& signer,
                                    std::string* error) {
    std::vector<StoredRecord> records;
    bool hadCorruption = false;
    if (!LoadValidConversationPrefix(convoPath, signer, records, &hadCorruption, error)) {
        return false;
    }
    if (hadCorruption) {
        if (error && error->empty()) *error = "Conversation contains corrupted tail";
        return false;
    }

    std::string manifestText;
    if (!ReadWholeFile(manifestPath, manifestText)) {
        if (error) *error = "Manifest missing";
        return false;
    }
    auto manifest = ParseManifestJson(manifestText);
    if (!manifest) {
        if (error) *error = "Manifest JSON parse failed";
        return false;
    }
    if (!VerifyManifest(*manifest, signer, error)) return false;
    if (manifest->messageCount != records.size()) {
        if (error) *error = "Manifest message count mismatch";
        return false;
    }
    const auto latestHash = records.empty() ? std::string() : records.back().recordHashHex;
    if (manifest->latestRecordHashHex != latestHash) {
        if (error) *error = "Manifest latest hash mismatch";
        return false;
    }
    return true;
}

} // namespace

bool ConversationStore::AppendPrivateMessage(const std::string& rootDir,
                                             const NodeId& localNodeId,
                                             const NodeId& peerNodeId,
                                             const PrivateMessagePayload& payload,
                                             StoredMessageDirection direction,
                                             StoredMessageState state,
                                             const ByteVector& signerPublicKeyBlob,
                                             CryptoSigner& signer,
                                             const ByteVector& localPublicKeyBlob,
                                             std::string* error) {
    try {
        fs::path dir = fs::path(rootDir) / localNodeId;
        fs::create_directories(dir);

        fs::path convoPath = dir / (peerNodeId + ".json");
        fs::path manifestPath = dir / (peerNodeId + ".manifest.json");
        fs::path statePath = ConversationStatePath(dir, peerNodeId);

        std::string prevHash;
        std::vector<StoredRecord> existingRecords;

        if (fs::exists(convoPath) || fs::exists(manifestPath)) {
            if (!fs::exists(convoPath) || !fs::exists(manifestPath)) {
                if (error) *error = "Conversation file or manifest missing";
                return false;
            }
            bool hadCorruption = false;
            std::string loadError;
            if (!LoadValidConversationPrefix(convoPath, signer, existingRecords, &hadCorruption, &loadError)) {
                if (error) *error = loadError;
                return false;
            }
            if (hadCorruption || !VerifyConversationFileInternal(convoPath, manifestPath, signer, nullptr)) {
                if (!RewriteConversationAndManifest(convoPath, manifestPath, existingRecords, peerNodeId, signer, localPublicKeyBlob, error)) {
                    return false;
                }
            }

            if (!existingRecords.empty()) {
                prevHash = existingRecords.back().recordHashHex;
            }
        }

        StoredRecord record{};
        record.direction = (direction == StoredMessageDirection::Outgoing) ? "out" : "in";
        record.messageId = payload.messageId;
        record.sessionId = payload.sessionId;
        record.version = 2;
        record.hasStateField = true;
        record.sequenceNumber = payload.sequenceNumber;
        record.fromNodeId = payload.fromNodeId;
        record.fromNicknameHex = StringToHex(payload.fromNickname);
        record.toNodeId = payload.toNodeId;
        record.textHex = StringToHex(payload.text);
        record.ivHex = BytesToHex(payload.iv);
        record.ciphertextHex = BytesToHex(payload.ciphertext);
        record.signatureHex = BytesToHex(payload.signature);
        record.signerPublicKeyHex = BytesToHex(signerPublicKeyBlob);
        record.storedAtUtc = CurrentUtcIso8601();
        record.state = StoredMessageStateToString(state);
        record.prevHashHex = prevHash;
        record.recordHashHex = BytesToHex(Sha256(BuildStoredRecordHashData(record)));

        existingRecords.push_back(record);
        return RewriteConversationAndManifest(convoPath, manifestPath, existingRecords, peerNodeId, signer, localPublicKeyBlob, error);
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

bool ConversationStore::LoadConversation(const std::string& rootDir,
                                      const NodeId& localNodeId,
                                      const NodeId& peerNodeId,
                                      CryptoSigner& signer,
                                      std::vector<StoredConversationMessage>& outMessages,
                                      std::string* error) {
    outMessages.clear();
    try {
        fs::path dir = fs::path(rootDir) / localNodeId;
        fs::path convoPath = dir / (peerNodeId + ".json");
        fs::path manifestPath = dir / (peerNodeId + ".manifest.json");
        if (!fs::exists(convoPath)) return true;
        std::vector<StoredRecord> records;
        bool hadCorruption = false;
        std::string loadError;
        if (!LoadValidConversationPrefix(convoPath, signer, records, &hadCorruption, &loadError)) {
            if (error) *error = loadError;
            return false;
        }
        if (hadCorruption && error && error->empty()) *error = loadError;

        auto stateOverrides = LoadStateOverrides(ConversationStatePath(dir, peerNodeId));

        for (const auto& srcRecord : records) {
            const auto& record = srcRecord;
            auto nick = HexToString(record.fromNicknameHex);
            auto text = HexToString(record.textHex);
            auto iv = HexToBytes(record.ivHex);
            auto cipher = HexToBytes(record.ciphertextHex);
            if (!nick || !text || !iv || !cipher) {
                if (error) *error = "Stored message decode failed";
                return false;
            }

            StoredConversationMessage msg{};
            msg.direction = (record.direction == "out") ? StoredMessageDirection::Outgoing : StoredMessageDirection::Incoming;
            msg.messageId = record.messageId;
            msg.sessionId = record.sessionId;
            msg.sequenceNumber = record.sequenceNumber;
            msg.fromNodeId = record.fromNodeId;
            msg.fromNickname = *nick;
            msg.toNodeId = record.toNodeId;
            msg.text = *text;
            msg.iv = *iv;
            msg.ciphertext = *cipher;
            msg.storedAtUtc = record.storedAtUtc;
            msg.state = StoredMessageStateFromString(record.state);
            auto overrideIt = stateOverrides.find(msg.messageId);
            if (overrideIt != stateOverrides.end()) msg.state = overrideIt->second;
            outMessages.push_back(std::move(msg));
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

std::optional<SessionId> ConversationStore::GetLatestSessionId(const std::string& rootDir,
                                                               const NodeId& localNodeId,
                                                               const NodeId& peerNodeId,
                                                               CryptoSigner& signer,
                                                               std::string* error) {
    std::vector<StoredConversationMessage> messages;
    if (!LoadConversation(rootDir, localNodeId, peerNodeId, signer, messages, error)) return std::nullopt;
    if (messages.empty()) return std::nullopt;
    return messages.back().sessionId;
}



bool ConversationStore::EnumerateLatestSessions(const std::string& rootDir,
                                                const NodeId& localNodeId,
                                                CryptoSigner& signer,
                                                std::vector<StoredConversationMessage>& outLatestMessages,
                                                std::string* error) {
    outLatestMessages.clear();
    try {
        fs::path dir = fs::path(rootDir) / localNodeId;
        if (!fs::exists(dir)) return true;

        for (const auto& entry : fs::directory_iterator(dir)) {
            if (!entry.is_regular_file()) continue;
            const auto path = entry.path();
            if (path.extension() != ".json") continue;
            if (path.filename().string().find(".manifest.json") != std::string::npos) continue;
            if (path.filename().string().find(".state.json") != std::string::npos) continue;

            const auto peerNodeId = path.stem().string();
            std::vector<StoredConversationMessage> messages;
            std::string loadError;
            if (!LoadConversation(rootDir, localNodeId, peerNodeId, signer, messages, &loadError)) {
                if (error) *error = loadError;
                return false;
            }
            if (!messages.empty()) {
                outLatestMessages.push_back(messages.back());
            }
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}


bool ConversationStore::DeleteConversation(const std::string& rootDir,
                                           const NodeId& localNodeId,
                                           const NodeId& peerNodeId,
                                           std::string* error) {
    try {
        fs::path dir = fs::path(rootDir) / localNodeId;
        fs::path convoPath = dir / (peerNodeId + ".json");
        fs::path manifestPath = dir / (peerNodeId + ".manifest.json");
        fs::path statePath = ConversationStatePath(dir, peerNodeId);
        std::error_code ec;
        if (fs::exists(convoPath)) fs::remove(convoPath, ec);
        if (ec) { if (error) *error = "Failed to remove conversation file"; return false; }
        if (fs::exists(manifestPath)) fs::remove(manifestPath, ec);
        if (ec) { if (error) *error = "Failed to remove manifest file"; return false; }
        if (fs::exists(statePath)) fs::remove(statePath, ec);
        if (ec) { if (error) *error = "Failed to remove state file"; return false; }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

bool ConversationStore::VerifyAllForLocalNode(const std::string& rootDir,
                                              const NodeId& localNodeId,
                                              CryptoSigner& signer,
                                              std::vector<std::string>* problems) {
    try {
        fs::path dir = fs::path(rootDir) / localNodeId;
        if (!fs::exists(dir)) return true;

        bool allOk = true;
        for (const auto& entry : fs::directory_iterator(dir)) {
            if (!entry.is_regular_file()) continue;
            const auto path = entry.path();
            if (path.extension() != ".json") continue;
            if (path.filename().string().find(".manifest.json") != std::string::npos) continue;
            if (path.filename().string().find(".state.json") != std::string::npos) continue;

            fs::path manifestPath = path.parent_path() / (path.stem().string() + ".manifest.json");
            if (!fs::exists(manifestPath)) {
                allOk = false;
                if (problems) problems->push_back(path.filename().string() + ": manifest missing");
                continue;
            }

            std::string error;
            if (!VerifyConversationFileInternal(path, manifestPath, signer, &error)) {
                allOk = false;
                if (problems) problems->push_back(path.filename().string() + ": " + error);
            }
        }
        return allOk;
    } catch (const std::exception& ex) {
        if (problems) problems->push_back(std::string("History verify failed: ") + ex.what());
        return false;
    }
}



bool ConversationStore::LoadSignedOutgoingMessagesAfter(const std::string& rootDir,
                                                        const NodeId& localNodeId,
                                                        const NodeId& peerNodeId,
                                                        MessageId afterMessageId,
                                                        CryptoSigner& signer,
                                                        std::vector<StoredSignedPrivateMessage>& outMessages,
                                                        std::string* error) {
    outMessages.clear();
    try {
        fs::path dir = fs::path(rootDir) / localNodeId;
        fs::path convoPath = dir / (peerNodeId + ".json");
        if (!fs::exists(convoPath)) return true;

        std::vector<StoredRecord> records;
        bool hadCorruption = false;
        std::string loadError;
        if (!LoadValidConversationPrefix(convoPath, signer, records, &hadCorruption, &loadError)) {
            if (error) *error = loadError;
            return false;
        }
        if (hadCorruption && error && error->empty()) *error = loadError;

        for (const auto& record : records) {
            if (record.direction != "out" || record.messageId <= afterMessageId) continue;
            auto nick = HexToString(record.fromNicknameHex);
            auto text = HexToString(record.textHex);
            auto iv = HexToBytes(record.ivHex);
            auto cipher = HexToBytes(record.ciphertextHex);
            auto sig = HexToBytes(record.signatureHex);
            auto pub = HexToBytes(record.signerPublicKeyHex);
            if (!nick || !text || !iv || !cipher || !sig || !pub) {
                if (error) *error = "Stored message decode failed";
                return false;
            }
            StoredSignedPrivateMessage msg{};
            msg.payload.messageId = record.messageId;
            msg.payload.sessionId = record.sessionId;
            msg.payload.sequenceNumber = record.sequenceNumber;
            msg.payload.fromNodeId = record.fromNodeId;
            msg.payload.fromNickname = *nick;
            msg.payload.toNodeId = record.toNodeId;
            msg.payload.text = *text;
            msg.payload.iv = *iv;
            msg.payload.ciphertext = *cipher;
            msg.payload.signature = *sig;
            msg.signerPublicKeyBlob = *pub;
            outMessages.push_back(std::move(msg));
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

bool ConversationStore::HasMessageId(const std::string& rootDir,
                                     const NodeId& localNodeId,
                                     const NodeId& peerNodeId,
                                     MessageId messageId,
                                     CryptoSigner& signer,
                                     bool* exists,
                                     std::string* error) {
    if (exists) *exists = false;
    std::vector<StoredConversationMessage> messages;
    if (!LoadConversation(rootDir, localNodeId, peerNodeId, signer, messages, error)) return false;
    for (const auto& msg : messages) {
        if (msg.messageId == messageId) {
            if (exists) *exists = true;
            break;
        }
    }
    return true;
}

bool ConversationStore::UpdateMessageState(const std::string& rootDir,
                                   const NodeId& localNodeId,
                                   const NodeId& peerNodeId,
                                   MessageId messageId,
                                   StoredMessageState newState,
                                   CryptoSigner& signer,
                                   const ByteVector& localPublicKeyBlob,
                                   std::string* error) {
    try {
        fs::path dir = fs::path(rootDir) / localNodeId;
        fs::path convoPath = dir / (peerNodeId + ".json");
        if (!fs::exists(convoPath)) return true;

        auto states = LoadStateOverrides(ConversationStatePath(dir, peerNodeId));
        states[messageId] = newState;
        return SaveStateOverrides(ConversationStatePath(dir, peerNodeId), states, error);
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

bool ConversationStore::CheckConversation(const std::string& rootDir,
                                  const NodeId& localNodeId,
                                  const NodeId& peerNodeId,
                                  CryptoSigner& signer,
                                  std::string* error) {
    try {
        fs::path dir = fs::path(rootDir) / localNodeId;
        fs::path convoPath = dir / (peerNodeId + ".json");
        fs::path manifestPath = dir / (peerNodeId + ".manifest.json");
        if (!fs::exists(convoPath)) return true;
        if (!fs::exists(manifestPath)) {
            if (error) *error = "Manifest missing";
            return false;
        }
        return VerifyConversationFileInternal(convoPath, manifestPath, signer, error);
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

bool ConversationStore::RepairConversation(const std::string& rootDir,
                                   const NodeId& localNodeId,
                                   const NodeId& peerNodeId,
                                   CryptoSigner& signer,
                                   const ByteVector& localPublicKeyBlob,
                                   std::string* error) {
    try {
        fs::path dir = fs::path(rootDir) / localNodeId;
        fs::path convoPath = dir / (peerNodeId + ".json");
        fs::path manifestPath = dir / (peerNodeId + ".manifest.json");
        if (!fs::exists(convoPath)) return true;

        std::vector<StoredRecord> records;
        bool hadCorruption = false;
        std::string loadError;
        if (!LoadValidConversationPrefix(convoPath, signer, records, &hadCorruption, &loadError)) {
            if (error) *error = loadError;
            return false;
        }
        if (!RewriteConversationAndManifest(convoPath, manifestPath, records, peerNodeId, signer, localPublicKeyBlob, error)) {
            return false;
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

} // namespace p2p
