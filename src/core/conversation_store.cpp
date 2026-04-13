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

namespace p2p {
namespace fs = std::filesystem;

namespace {

struct StoredRecord {
    std::uint64_t version = 1;
    std::string direction;
    std::uint64_t messageId = 0;
    std::uint64_t sessionId = 0;
    std::string fromNodeId;
    std::string fromNicknameHex;
    std::string toNodeId;
    std::string textHex;
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
    utils::WriteString(out, r.fromNodeId);
    utils::WriteString(out, r.fromNicknameHex);
    utils::WriteString(out, r.toNodeId);
    utils::WriteString(out, r.textHex);
    utils::WriteString(out, r.signatureHex);
    utils::WriteString(out, r.signerPublicKeyHex);
    utils::WriteString(out, r.storedAtUtc);
    utils::WriteString(out, r.state);
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
    oss << "\"from_node_id\":\"" << JsonEscape(r.fromNodeId) << "\",";
    oss << "\"from_nickname_hex\":\"" << r.fromNicknameHex << "\",";
    oss << "\"to_node_id\":\"" << JsonEscape(r.toNodeId) << "\",";
    oss << "\"text_hex\":\"" << r.textHex << "\",";
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
    const std::string marker = "\"" + key + "\":\"";
    auto pos = line.find(marker);
    if (pos == std::string::npos) return std::nullopt;
    pos += marker.size();
    auto end = line.find('"', pos);
    if (end == std::string::npos) return std::nullopt;
    return line.substr(pos, end - pos);
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
    StoredRecord r{};
    auto version = ExtractJsonUint64(line, "version");
    auto direction = ExtractJsonString(line, "direction");
    auto messageId = ExtractJsonUint64(line, "message_id");
    auto sessionId = ExtractJsonUint64(line, "session_id");
    auto fromNodeId = ExtractJsonString(line, "from_node_id");
    auto fromNickHex = ExtractJsonString(line, "from_nickname_hex");
    auto toNodeId = ExtractJsonString(line, "to_node_id");
    auto textHex = ExtractJsonString(line, "text_hex");
    auto signatureHex = ExtractJsonString(line, "signature_hex");
    auto signerPubHex = ExtractJsonString(line, "signer_public_key_hex");
    auto storedAt = ExtractJsonString(line, "stored_at_utc");
    auto state = ExtractJsonString(line, "state");
    auto prevHash = ExtractJsonString(line, "prev_hash_hex");
    auto recordHash = ExtractJsonString(line, "record_hash_hex");
    if (!version || !direction || !messageId || !sessionId || !fromNodeId || !fromNickHex || !toNodeId || !textHex ||
        !signatureHex || !signerPubHex || !storedAt || !prevHash || !recordHash) {
        return std::nullopt;
    }
    r.version = *version;
    r.direction = *direction;
    r.messageId = *messageId;
    r.sessionId = *sessionId;
    r.fromNodeId = *fromNodeId;
    r.fromNicknameHex = *fromNickHex;
    r.toNodeId = *toNodeId;
    r.textHex = *textHex;
    r.signatureHex = *signatureHex;
    r.signerPublicKeyHex = *signerPubHex;
    r.storedAtUtc = *storedAt;
    r.state = state.value_or("created");
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
    std::ifstream in(convoPath);
    if (!in) {
        if (error) *error = "Failed to open conversation file";
        return false;
    }

    std::vector<StoredRecord> records;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto record = ParseRecordJson(line);
        if (!record) {
            if (error) *error = "Conversation JSON parse failed";
            return false;
        }
        records.push_back(*record);
    }

    std::string prevHash;
    for (const auto& r : records) {
        if (r.prevHashHex != prevHash) {
            if (error) *error = "Hash chain mismatch";
            return false;
        }
        const auto recomputed = BytesToHex(Sha256(BuildStoredRecordHashData(r)));
        if (recomputed != r.recordHashHex) {
            if (error) *error = "Stored record hash mismatch";
            return false;
        }

        PrivateMessagePayload payload{};
        auto nick = HexToString(r.fromNicknameHex);
        auto text = HexToString(r.textHex);
        auto sig = HexToBytes(r.signatureHex);
        auto pub = HexToBytes(r.signerPublicKeyHex);
        if (!nick || !text || !sig || !pub) {
            if (error) *error = "Stored message decode failed";
            return false;
        }
        payload.messageId = r.messageId;
        payload.sessionId = r.sessionId;
        payload.fromNodeId = r.fromNodeId;
        payload.fromNickname = *nick;
        payload.toNodeId = r.toNodeId;
        payload.text = *text;
        payload.signature = *sig;

        ByteVector signData;
        utils::WriteUint64(signData, payload.messageId);
        utils::WriteUint64(signData, payload.sessionId);
        utils::WriteString(signData, payload.fromNodeId);
        utils::WriteString(signData, payload.fromNickname);
        utils::WriteString(signData, payload.toNodeId);
        utils::WriteString(signData, payload.text);

        if (!signer.Verify(signData, payload.signature, *pub)) {
            if (error) *error = "Stored message signature invalid";
            return false;
        }
        prevHash = r.recordHashHex;
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
    if (manifest->latestRecordHashHex != prevHash) {
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

        std::string prevHash;
        std::uint64_t nextCount = 1;

        if (fs::exists(convoPath) || fs::exists(manifestPath)) {
            if (!fs::exists(convoPath) || !fs::exists(manifestPath)) {
                if (error) *error = "Conversation file or manifest missing";
                return false;
            }
            if (!VerifyConversationFileInternal(convoPath, manifestPath, signer, error)) {
                return false;
            }

            std::string lastLine;
            if (ReadLastNonEmptyLine(convoPath, lastLine)) {
                auto lastRecord = ParseRecordJson(lastLine);
                if (!lastRecord) {
                    if (error) *error = "Failed to parse last record";
                    return false;
                }
                prevHash = lastRecord->recordHashHex;
            }

            std::string manifestText;
            if (!ReadWholeFile(manifestPath, manifestText)) {
                if (error) *error = "Failed to read manifest";
                return false;
            }
            auto manifest = ParseManifestJson(manifestText);
            if (!manifest) {
                if (error) *error = "Failed to parse manifest";
                return false;
            }
            nextCount = manifest->messageCount + 1;
        }

        StoredRecord record{};
        record.direction = (direction == StoredMessageDirection::Outgoing) ? "out" : "in";
        record.messageId = payload.messageId;
        record.sessionId = payload.sessionId;
        record.fromNodeId = payload.fromNodeId;
        record.fromNicknameHex = StringToHex(payload.fromNickname);
        record.toNodeId = payload.toNodeId;
        record.textHex = StringToHex(payload.text);
        record.signatureHex = BytesToHex(payload.signature);
        record.signerPublicKeyHex = BytesToHex(signerPublicKeyBlob);
        record.storedAtUtc = CurrentUtcIso8601();
        record.state = StoredMessageStateToString(state);
        record.prevHashHex = prevHash;
        record.recordHashHex = BytesToHex(Sha256(BuildStoredRecordHashData(record)));

        {
            std::ofstream out(convoPath, std::ios::binary | std::ios::app);
            if (!out) {
                if (error) *error = "Failed to open conversation file for append";
                return false;
            }
            out << SerializeRecordJson(record) << "\n";
        }

        ManifestRecord manifest{};
        manifest.peerNodeId = peerNodeId;
        manifest.messageCount = nextCount;
        manifest.latestRecordHashHex = record.recordHashHex;
        manifest.updatedAtUtc = record.storedAtUtc;
        manifest.localPublicKeyHex = BytesToHex(localPublicKeyBlob);

        ByteVector manifestSig;
        if (!signer.Sign(BuildManifestSignedData(manifest), manifestSig)) {
            if (error) *error = "Failed to sign manifest";
            return false;
        }
        manifest.signatureHex = BytesToHex(manifestSig);

        {
            std::ofstream out(manifestPath, std::ios::binary | std::ios::trunc);
            if (!out) {
                if (error) *error = "Failed to write manifest";
                return false;
            }
            out << SerializeManifestJson(manifest);
        }

        return true;
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
        if (!fs::exists(manifestPath)) {
            if (error) *error = "Manifest missing";
            return false;
        }
        if (!VerifyConversationFileInternal(convoPath, manifestPath, signer, error)) return false;

        std::ifstream in(convoPath);
        if (!in) {
            if (error) *error = "Failed to open conversation file";
            return false;
        }

        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            auto record = ParseRecordJson(line);
            if (!record) {
                if (error) *error = "Conversation JSON parse failed";
                return false;
            }
            auto nick = HexToString(record->fromNicknameHex);
            auto text = HexToString(record->textHex);
            if (!nick || !text) {
                if (error) *error = "Stored message decode failed";
                return false;
            }

            StoredConversationMessage msg{};
            msg.direction = (record->direction == "out") ? StoredMessageDirection::Outgoing : StoredMessageDirection::Incoming;
            msg.messageId = record->messageId;
            msg.sessionId = record->sessionId;
            msg.fromNodeId = record->fromNodeId;
            msg.fromNickname = *nick;
            msg.toNodeId = record->toNodeId;
            msg.text = *text;
            msg.storedAtUtc = record->storedAtUtc;
            msg.state = StoredMessageStateFromString(record->state);
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
        std::error_code ec;
        if (fs::exists(convoPath)) fs::remove(convoPath, ec);
        if (ec) { if (error) *error = "Failed to remove conversation file"; return false; }
        if (fs::exists(manifestPath)) fs::remove(manifestPath, ec);
        if (ec) { if (error) *error = "Failed to remove manifest file"; return false; }
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
        fs::path manifestPath = dir / (peerNodeId + ".manifest.json");
        if (!fs::exists(convoPath)) return true;
        if (!fs::exists(manifestPath)) {
            if (error) *error = "Manifest missing";
            return false;
        }
        if (!VerifyConversationFileInternal(convoPath, manifestPath, signer, error)) return false;

        std::ifstream in(convoPath);
        if (!in) {
            if (error) *error = "Failed to open conversation file";
            return false;
        }
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            auto record = ParseRecordJson(line);
            if (!record) {
                if (error) *error = "Conversation JSON parse failed";
                return false;
            }
            if (record->direction != "out" || record->messageId <= afterMessageId) continue;
            auto nick = HexToString(record->fromNicknameHex);
            auto text = HexToString(record->textHex);
            auto sig = HexToBytes(record->signatureHex);
            auto pub = HexToBytes(record->signerPublicKeyHex);
            if (!nick || !text || !sig || !pub) {
                if (error) *error = "Stored message decode failed";
                return false;
            }
            StoredSignedPrivateMessage msg{};
            msg.payload.messageId = record->messageId;
            msg.payload.sessionId = record->sessionId;
            msg.payload.fromNodeId = record->fromNodeId;
            msg.payload.fromNickname = *nick;
            msg.payload.toNodeId = record->toNodeId;
            msg.payload.text = *text;
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
        fs::path manifestPath = dir / (peerNodeId + ".manifest.json");
        if (!fs::exists(convoPath)) return true;
        if (!fs::exists(manifestPath)) {
            if (error) *error = "Manifest missing";
            return false;
        }
        if (!VerifyConversationFileInternal(convoPath, manifestPath, signer, error)) return false;

        std::ifstream in(convoPath);
        if (!in) {
            if (error) *error = "Failed to open conversation file";
            return false;
        }

        std::vector<StoredRecord> records;
        std::string line;
        bool found = false;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            auto record = ParseRecordJson(line);
            if (!record) {
                if (error) *error = "Conversation JSON parse failed";
                return false;
            }
            if (record->messageId == messageId) {
                record->state = StoredMessageStateToString(newState);
                found = true;
            }
            records.push_back(std::move(*record));
        }
        if (!found) return true;

        std::string prevHash;
        for (auto& record : records) {
            record.prevHashHex = prevHash;
            record.recordHashHex = BytesToHex(Sha256(BuildStoredRecordHashData(record)));
            prevHash = record.recordHashHex;
        }

        {
            std::ofstream out(convoPath, std::ios::binary | std::ios::trunc);
            if (!out) {
                if (error) *error = "Failed to rewrite conversation file";
                return false;
            }
            for (const auto& record : records) out << SerializeRecordJson(record) << "\n";
        }

        ManifestRecord manifest{};
        manifest.peerNodeId = peerNodeId;
        manifest.messageCount = records.size();
        manifest.latestRecordHashHex = prevHash;
        manifest.updatedAtUtc = CurrentUtcIso8601();
        manifest.localPublicKeyHex = BytesToHex(localPublicKeyBlob);

        ByteVector manifestSig;
        if (!signer.Sign(BuildManifestSignedData(manifest), manifestSig)) {
            if (error) *error = "Failed to sign manifest";
            return false;
        }
        manifest.signatureHex = BytesToHex(manifestSig);

        {
            std::ofstream out(manifestPath, std::ios::binary | std::ios::trunc);
            if (!out) {
                if (error) *error = "Failed to write manifest";
                return false;
            }
            out << SerializeManifestJson(manifest);
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

} // namespace p2p
