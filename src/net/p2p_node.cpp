#include "net/p2p_node.h"

#include "core/utils.h"
#include "net/packet_protocol.h"
#include "net/peer_connection.h"
#include "crypto/key_lifecycle.h"
#include "crypto/secure_key_store.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <array>
#include <cctype>
#include <ctime>
#include <iostream>

namespace p2p {

P2PNode::P2PNode(std::string nickname, std::uint16_t listenPort) {
    local_.nickname = std::move(nickname);
    local_.listenPort = listenPort;
    if (!LoadOrCreateLocalIdentity()) {
        local_.nodeId = utils::GenerateNodeId();
    }

    KnownNode self{};
    self.nodeId = local_.nodeId;
    self.nickname = local_.nickname;
    self.ip = "127.0.0.1";
    self.port = local_.listenPort;
    self.observedUdpPort = local_.listenPort;
    self.lastSeen = std::chrono::steady_clock::now();
    knownNodes_.Upsert(self);
    LoadContacts();
    LoadOverlayState();
    std::string reputationError;
    if (!peerReputation_.Load(local_.nodeId, &reputationError) && !reputationError.empty()) {
        utils::LogWarn("Failed to load peer reputation store: " + reputationError);
    }
}

P2PNode::~P2PNode() { Stop(); }



namespace fs = std::filesystem;
namespace {
std::string BytesToHexLocal(const p2p::ByteVector& bytes) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto b : bytes) {
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

bool HexNibble(char c, std::uint8_t& out) {
    if (c >= '0' && c <= '9') { out = static_cast<std::uint8_t>(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { out = static_cast<std::uint8_t>(10 + c - 'a'); return true; }
    if (c >= 'A' && c <= 'F') { out = static_cast<std::uint8_t>(10 + c - 'A'); return true; }
    return false;
}

std::string TrimCopy(std::string value) {
    auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

MessageId GenerateMessageIdForNode(const NodeId& nodeId) {
    static std::atomic<std::uint64_t> counter{1};
    const auto now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    const auto nodeHash = static_cast<std::uint64_t>(std::hash<std::string>{}(nodeId));
    return (now << 16) ^ (counter.fetch_add(1, std::memory_order_relaxed) & 0xFFFFull) ^ (nodeHash & 0xFFFFull);
}

bool HexToBytesLocal(const std::string& hex, p2p::ByteVector& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        std::uint8_t hi = 0, lo = 0;
        if (!HexNibble(hex[i], hi) || !HexNibble(hex[i + 1], lo)) return false;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return true;
}

std::string RelayMsgPath(const fs::path& root, const p2p::NodeId& targetNodeId, p2p::MessageId messageId) {
    return (root / (std::string("msg_") + targetNodeId + "_" + std::to_string(messageId) + ".spool")).string();
}

std::string RelayAckPath(const fs::path& root, const p2p::NodeId& targetNodeId, p2p::MessageId messageId) {
    return (root / (std::string("ack_") + targetNodeId + "_" + std::to_string(messageId) + ".spool")).string();
}
std::vector<p2p::ContactEntry> SortedContactsForDisplay(const std::unordered_map<p2p::NodeId, p2p::ContactEntry>& contacts) {
    std::vector<p2p::ContactEntry> out;
    for (const auto& [_, c] : contacts) out.push_back(c);
    std::sort(out.begin(), out.end(), [](const p2p::ContactEntry& a, const p2p::ContactEntry& b) {
        return a.nickname == b.nickname ? a.nodeId < b.nodeId : a.nickname < b.nickname;
    });
    return out;
}

std::vector<std::string> SplitPipe(const std::string& line) {
    std::vector<std::string> parts;
    std::stringstream ss(line);
    std::string item;
    while (std::getline(ss, item, '|')) parts.push_back(item);
    return parts;
}

std::string JoinRole(const p2p::GroupRole role) {
    return p2p::ToString(role);
}

constexpr std::size_t kInlineFileTransferLimit = 256 * 1024;
constexpr std::size_t kFileChunkBytes = 12 * 1024;

std::string ControlMessageKindToString(p2p::P2PNode::ControlMessageKind kind) {
    using K = p2p::P2PNode::ControlMessageKind;
    switch (kind) {
        case K::GroupSync: return "groupsync";
        case K::DeviceLink: return "device-link";
        case K::DeviceRevoke: return "device-revoke";
        case K::DeviceSync: return "device-sync";
        case K::FileMeta: return "filemeta";
        case K::FileOffer: return "fileoffer";
        case K::FileAccept: return "fileaccept";
        case K::FileReject: return "filereject";
        case K::FileChunk: return "filechunk";
        case K::GroupMessage: return "groupmsg";
        default: return "unknown";
    }
}
std::string ToString(p2p::P2PNode::FileTransferState state) {
    using S = p2p::P2PNode::FileTransferState;
    switch (state) {
        case S::Offered: return "offered";
        case S::Accepted: return "accepted";
        case S::Transferring: return "transferring";
        case S::Completed: return "completed";
        case S::Rejected: return "rejected";
        case S::Failed: return "failed";
        default: return "unknown";
    }
}

std::string ToString(p2p::P2PNode::ControlFlowState state) {
    using S = p2p::P2PNode::ControlFlowState;
    switch (state) {
        case S::Idle: return "idle";
        case S::Received: return "received";
        case S::Parsed: return "parsed";
        case S::Validated: return "validated";
        case S::Applied: return "applied";
        case S::Rejected: return "rejected";
        case S::Failed: return "failed";
        default: return "unknown";
    }
}


std::int64_t NowUnix() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}
}

bool P2PNode::LoadOrCreateLocalIdentity() {
    try {
        fs::create_directories("profile");
        const fs::path identityPath = fs::path("profile") / (local_.nickname + ".identity.json");

        if (fs::exists(identityPath)) {
            std::ifstream in(identityPath, std::ios::binary);
            std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            const std::string marker = "\"node_id\":\"";
            auto pos = text.find(marker);
            if (pos != std::string::npos) {
                pos += marker.size();
                auto end = text.find('"', pos);
                if (end != std::string::npos) {
                    local_.nodeId = text.substr(pos, end - pos);
                    return !local_.nodeId.empty();
                }
            }
        }

        local_.nodeId = utils::GenerateNodeId();
        std::ofstream out(identityPath, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out << "{\n  \"nickname\": \"" << local_.nickname << "\",\n  \"node_id\":\"" << local_.nodeId << "\"\n}\n";
        return true;
    } catch (...) {
        return false;
    }
}

void P2PNode::RestorePrivateSessionsFromHistory() {
    std::vector<StoredConversationMessage> latestMessages;
    std::string error;
    if (!ConversationStore::EnumerateLatestSessions(historyRootDir_, local_.nodeId, signer_, latestMessages, &error)) {
        utils::LogError("Failed to restore private sessions from history: " + error);
        return;
    }

    std::size_t restored = 0;
    for (const auto& msg : latestMessages) {
        const NodeId peerNodeId = (msg.fromNodeId == local_.nodeId) ? msg.toNodeId : msg.fromNodeId;
        const std::string peerNickname = (msg.fromNodeId == local_.nodeId) ? peerNodeId : msg.fromNickname;
        if (peerNodeId.empty()) continue;
        EnsureSessionForPeer(peerNodeId, peerNickname, msg.sessionId);
        ++restored;
    }

    if (restored > 0) {
        utils::LogSystem("Restored " + std::to_string(restored) + " private session(s) from local history");
    }
}




bool P2PNode::SaveContacts() const {
    std::lock_guard<std::mutex> lock(contactsMutex_);
    std::string error;
    if (!ContactStore::Save(contactsRootDir_, local_.nodeId, contacts_, &error)) {
        if (!error.empty()) utils::LogError("Failed to save contacts: " + error);
        return false;
    }
    return true;
}

void P2PNode::LoadContacts() {
    std::unordered_map<NodeId, ContactEntry> loaded;
    std::string error;
    if (!ContactStore::Load(contactsRootDir_, local_.nodeId, loaded, &error)) {
        if (!error.empty()) utils::LogError("Failed to load contacts: " + error);
        return;
    }
    std::lock_guard<std::mutex> lock(contactsMutex_);
    contacts_ = std::move(loaded);
}

std::optional<ContactEntry> P2PNode::FindContact(const NodeId& peerNodeId) const {
    std::lock_guard<std::mutex> lock(contactsMutex_);
    auto it = contacts_.find(peerNodeId);
    if (it == contacts_.end()) return std::nullopt;
    return it->second;
}

std::string P2PNode::ResolveDisplayName(const NodeId& peerNodeId, const std::string& fallback) const {
    {
        std::lock_guard<std::mutex> lock(contactsMutex_);
        auto it = contacts_.find(peerNodeId);
        if (it != contacts_.end() && !it->second.nickname.empty()) return it->second.nickname;
    }
    if (!fallback.empty()) return fallback;
    if (auto node = knownNodes_.FindByNodeId(peerNodeId)) {
        if (!node->nickname.empty()) return node->nickname;
    }
    return peerNodeId;
}

void P2PNode::UpsertContactHintsFromKnownNode(const KnownNode& node) {
    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(contactsMutex_);
        auto it = contacts_.find(node.nodeId);
        if (it == contacts_.end()) return;
        auto& c = it->second;
        if (c.nickname.empty() && !node.nickname.empty()) { c.nickname = node.nickname; changed = true; }
        if (c.lastKnownIp != node.ip) { c.lastKnownIp = node.ip; changed = true; }
        if (c.lastKnownPort != node.port) { c.lastKnownPort = node.port; changed = true; }
    }
    if (changed) SaveContacts();
}

bool P2PNode::AddOrUpdateContact(const NodeId& peerNodeId, const std::string& nickname) {
    if (peerNodeId.empty() || peerNodeId == local_.nodeId) return false;
    ContactEntry entry{};
    std::string resolvedNickname = nickname;
    if (resolvedNickname.empty()) {
        if (auto node = knownNodes_.FindByNodeId(peerNodeId)) resolvedNickname = node->nickname;
        if (resolvedNickname.empty()) resolvedNickname = peerNodeId;
    }
    {
        std::lock_guard<std::mutex> lock(contactsMutex_);
        auto& c = contacts_[peerNodeId];
        c.nodeId = peerNodeId;
        if (!resolvedNickname.empty()) c.nickname = resolvedNickname;
        c.trusted = true;
        c.blocked = false;
        if (c.addedAtUnix == 0) c.addedAtUnix = NowUnix();
        if (auto node = knownNodes_.FindByNodeId(peerNodeId)) {
            if (c.nickname.empty()) c.nickname = node->nickname;
            c.lastKnownIp = node->ip;
            c.lastKnownPort = node->port;
        }
        {
            std::lock_guard<std::mutex> pk(publicKeysMutex_);
            auto it = publicKeys_.find(peerNodeId);
            if (it != publicKeys_.end()) {
                c.publicKeyBlob = it->second;
                c.fingerprint = ComputeFingerprint(c.publicKeyBlob);
            }
        }
        entry = c;
    }
    if (SaveContacts()) {
        utils::LogSystem("Contact saved: " + (entry.nickname.empty() ? peerNodeId : entry.nickname) + " (" + peerNodeId + ")");
        return true;
    }
    return false;
}

bool P2PNode::RemoveContact(const NodeId& peerNodeId) {
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(contactsMutex_);
        removed = contacts_.erase(peerNodeId) > 0;
    }
    if (!removed) return false;
    SaveContacts();
    utils::LogSystem("Contact removed: " + peerNodeId);
    return true;
}

bool P2PNode::RenameContact(const NodeId& peerNodeId, const std::string& newNickname) {
    if (newNickname.empty()) return false;
    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(contactsMutex_);
        auto it = contacts_.find(peerNodeId);
        if (it == contacts_.end()) return false;
        it->second.nickname = newNickname;
        changed = true;
    }
    if (!changed) return false;
    SaveContacts();
    utils::LogSystem("Contact renamed: " + peerNodeId + " -> " + newNickname);
    return true;
}

bool P2PNode::AddContactFromInviteCode(const std::string& inviteCode) {
    ContactEntry entry{};
    std::string error;
    if (!ContactStore::ParseInviteCode(inviteCode, entry, &error)) {
        if (!error.empty()) utils::LogError(error);
        return false;
    }
    if (entry.nodeId == local_.nodeId) {
        utils::LogError("Cannot add yourself from invite code");
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(contactsMutex_);
        auto& c = contacts_[entry.nodeId];
        if (c.nodeId.empty()) c = entry;
        else {
            if (!entry.nickname.empty()) c.nickname = entry.nickname;
            if (!entry.publicKeyBlob.empty()) {
                c.publicKeyBlob = entry.publicKeyBlob;
                c.fingerprint = ComputeFingerprint(c.publicKeyBlob);
            }
            c.trusted = true;
            c.blocked = false;
            if (c.addedAtUnix == 0) c.addedAtUnix = entry.addedAtUnix;
        }
    }
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        publicKeys_[entry.nodeId] = entry.publicKeyBlob;
    }
    if (!SaveContacts()) return false;
    utils::LogSystem("Invite imported: " + entry.nickname + " (" + entry.nodeId + ")");
    return true;
}

std::string P2PNode::BuildLocalInviteCode() const {
    return ContactStore::BuildInviteCode(local_, localPublicKeyBlob_);
}

void P2PNode::PrintContacts() const {
    std::vector<ContactEntry> contacts;
    {
        std::lock_guard<std::mutex> lock(contactsMutex_);
        contacts = SortedContactsForDisplay(contacts_);
    }
    std::cout << "=== Contacts ===\n";
    int idx = 1;
    for (const auto& c : contacts) {
        auto peer = peerManager_.FindByNodeId(c.nodeId);
        std::cout << "[" << idx++ << "] " << (c.nickname.empty() ? c.nodeId : c.nickname)
                  << " id=" << c.nodeId;
        if (peer) std::cout << " online";
        else if (auto node = knownNodes_.FindByNodeId(c.nodeId)) {
            auto secs = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - node->lastSeen).count();
            std::cout << " last seen " << secs << "s ago";
        }
        std::cout << (c.trusted ? " trusted" : " untrusted");
        if (!c.fingerprint.empty()) std::cout << " fp=" << c.fingerprint;
        std::cout << '\n';
    }
    if (contacts.empty()) std::cout << "(empty)\n";
}

void P2PNode::PrintFingerprint() const {
    std::cout << "=== Your Identity ===\n";
    std::cout << "NodeID: " << local_.nodeId << "\n";
    std::cout << "Fingerprint: " << ComputeFingerprint(localPublicKeyBlob_) << "\n";
}


void P2PNode::PrintKeyStatus() const {
    KeyLifecycleStatus status{};
    if (!KeyLifecycleManager::GetStatus(local_.nodeId, const_cast<CryptoSigner&>(signer_), status)) {
        utils::LogError("Failed to read key lifecycle status");
        return;
    }
    std::cout << "=== Key Lifecycle Status ===\n";
    std::cout << "NodeID:               " << status.nodeId << "\n";
    std::cout << "Container:            " << std::string(status.containerName.begin(), status.containerName.end()) << "\n";
    std::cout << "Container present:    " << (status.containerExists ? "yes" : "no") << "\n";
    std::cout << "Signing fingerprint:  " << (status.signFingerprint.empty() ? "(unavailable)" : status.signFingerprint) << "\n";
    std::cout << "Encrypt fingerprint:  " << (status.encryptFingerprint.empty() ? "(unavailable)" : status.encryptFingerprint) << "\n";
    SecureKeyMetadata secureMeta{};
    std::string secureError;
    if (SecureKeyStore::LoadMetadata(local_.nodeId, secureMeta, &secureError)) {
        std::cout << "Secure metadata:      sealed (DPAPI) v" << secureMeta.protocolVersion
                  << (secureMeta.revoked ? " revoked" : " active") << "\n";
    } else {
        std::cout << "Secure metadata:      missing\n";
    }
}

bool P2PNode::BackupLocalKeys(const std::string& backupDir) {
    std::string outPath;
    std::string error;
    if (!KeyLifecycleManager::BackupPublicMaterial(local_.nodeId, local_.nickname, signer_, backupDir, &outPath, &error)) {
        if (!error.empty()) utils::LogError("Key backup failed: " + error);
        return false;
    }
    utils::LogSystem("Saved key backup manifest to " + outPath);
    return true;
}

bool P2PNode::RotateLocalKeys() {
    const std::string oldFingerprint = localPublicKeyBlob_.empty() ? std::string() : ComputeFingerprint(localPublicKeyBlob_);
    std::string backupPath;
    std::string backupError;
    KeyLifecycleManager::BackupPublicMaterial(local_.nodeId, local_.nickname, signer_, "profile/key_backups", &backupPath, &backupError);

    std::string error;
    if (!KeyLifecycleManager::RotateKeyContainer(local_.nodeId, signer_, &error)) {
        if (!error.empty()) utils::LogError("Key rotation failed: " + error);
        return false;
    }
    if (!signer_.ExportPublicKey(localPublicKeyBlob_) || !signer_.ExportEncryptPublicKey(localEncryptPublicKeyBlob_)) {
        utils::LogError("Key rotation failed: could not refresh public blobs");
        return false;
    }
    const std::string newFingerprint = ComputeFingerprint(localPublicKeyBlob_);
    SecureKeyMetadata secureMeta{};
    secureMeta.nodeId = local_.nodeId;
    secureMeta.containerName = signer_.GetContainerName();
    secureMeta.signFingerprint = newFingerprint;
    secureMeta.encryptFingerprint = ComputeFingerprint(localEncryptPublicKeyBlob_);
    secureMeta.protocolVersion = kProtocolVersion;
    secureMeta.updatedAtUnix = NowUnix();
    secureMeta.revoked = false;
    std::string secureStoreError;
    if (!SecureKeyStore::SaveMetadata(secureMeta, &secureStoreError) && !secureStoreError.empty()) {
        utils::LogWarn("Failed to update secure key metadata after rotation: " + secureStoreError);
    }
    utils::LogWarn("Local identity keys rotated. Old fingerprint: " + oldFingerprint + " | New fingerprint: " + newFingerprint);
    if (!backupPath.empty()) utils::LogSystem("Previous public material saved to " + backupPath);
    return true;
}

bool P2PNode::RevokeLocalKeys() {
    std::string backupPath;
    std::string backupError;
    KeyLifecycleManager::BackupPublicMaterial(local_.nodeId, local_.nickname, signer_, "profile/key_backups", &backupPath, &backupError);

    std::string error;
    if (!KeyLifecycleManager::RevokeKeyContainer(local_.nodeId, signer_, &error)) {
        if (!error.empty()) utils::LogError("Key revoke failed: " + error);
        return false;
    }
    localPublicKeyBlob_.clear();
    localEncryptPublicKeyBlob_.clear();
    SecureKeyMetadata secureMeta{};
    secureMeta.nodeId = local_.nodeId;
    secureMeta.containerName = signer_.GetContainerName();
    secureMeta.protocolVersion = kProtocolVersion;
    secureMeta.updatedAtUnix = NowUnix();
    secureMeta.revoked = true;
    std::string secureStoreError;
    if (!SecureKeyStore::SaveMetadata(secureMeta, &secureStoreError) && !secureStoreError.empty()) {
        utils::LogWarn("Failed to update secure key metadata after revoke: " + secureStoreError);
    }
    utils::LogWarn("Local key container revoked. Restart the messenger before sending messages again.");
    if (!backupPath.empty()) utils::LogSystem("Revoked key manifest saved to " + backupPath);
    return true;
}

bool P2PNode::TrustContactByIndex(int index) {
    ContactEntry contact{};
    {
        std::lock_guard<std::mutex> lock(contactsMutex_);
        auto ordered = SortedContactsForDisplay(contacts_);
        if (index <= 0 || index > static_cast<int>(ordered.size())) return false;
        contact = ordered[static_cast<std::size_t>(index - 1)];
        auto it = contacts_.find(contact.nodeId);
        if (it != contacts_.end()) {
            it->second.trusted = true;
            if (it->second.fingerprint.empty() && !it->second.publicKeyBlob.empty()) {
                it->second.fingerprint = ComputeFingerprint(it->second.publicKeyBlob);
            }
        }
    }
    if (!SaveContacts()) return false;
    {
        std::lock_guard<std::mutex> repLock(reputationMutex_);
        peerReputation_.NoteTrustedContact(contact.nodeId);
        std::string repError; peerReputation_.Save(local_.nodeId, &repError);
    }
    utils::LogSystem("Contact marked trusted: " + (contact.nickname.empty() ? contact.nodeId : contact.nickname));
    return true;
}

bool P2PNode::UntrustContactByIndex(int index) {
    ContactEntry contact{};
    {
        std::lock_guard<std::mutex> lock(contactsMutex_);
        auto ordered = SortedContactsForDisplay(contacts_);
        if (index <= 0 || index > static_cast<int>(ordered.size())) return false;
        contact = ordered[static_cast<std::size_t>(index - 1)];
        auto it = contacts_.find(contact.nodeId);
        if (it != contacts_.end()) it->second.trusted = false;
    }
    if (!SaveContacts()) return false;
    utils::LogSystem("Contact marked untrusted: " + (contact.nickname.empty() ? contact.nodeId : contact.nickname));
    return true;
}

bool P2PNode::InitWinSock() {
    if (winsockInitialized_) return true;
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return false;
    winsockInitialized_ = true;
    return true;
}

void P2PNode::CleanupWinSock() {
    if (winsockInitialized_) {
        WSACleanup();
        winsockInitialized_ = false;
    }
}

bool P2PNode::Start() {
    if (!InitWinSock()) return false;

    std::wstring cont = CryptoSigner::MakeContainerNameForNodeId(local_.nodeId);
    if (!signer_.Initialize(cont)) {
        utils::LogError("Crypto signer init failed");
        return false;
    }

    if (!signer_.ExportPublicKey(localPublicKeyBlob_)) {
        utils::LogError("Failed to export local public key");
        return false;
    }
    if (!signer_.ExportEncryptPublicKey(localEncryptPublicKeyBlob_)) {
        utils::LogError("Failed to export local encryption public key");
        return false;
    }

    SecureKeyMetadata previousSecureMeta{};
    std::string secureLoadError;
    if (SecureKeyStore::LoadMetadata(local_.nodeId, previousSecureMeta, &secureLoadError)) {
        if (previousSecureMeta.revoked) {
            utils::LogWarn("Secure key metadata shows the previous local key container was revoked before this start");
        }
    }

    SecureKeyMetadata secureMeta{};
    secureMeta.nodeId = local_.nodeId;
    secureMeta.containerName = signer_.GetContainerName();
    secureMeta.signFingerprint = ComputeFingerprint(localPublicKeyBlob_);
    secureMeta.encryptFingerprint = ComputeFingerprint(localEncryptPublicKeyBlob_);
    secureMeta.protocolVersion = kProtocolVersion;
    secureMeta.updatedAtUnix = NowUnix();
    secureMeta.revoked = false;
    std::string secureStoreError;
    if (!SecureKeyStore::SaveMetadata(secureMeta, &secureStoreError) && !secureStoreError.empty()) {
        utils::LogWarn("Failed to update secure key metadata: " + secureStoreError);
    }

    std::vector<std::string> historyProblems;
    if (!ConversationStore::VerifyAllForLocalNode(historyRootDir_, local_.nodeId, signer_, &historyProblems)) {
        for (const auto& problem : historyProblems) {
            utils::LogError("History integrity problem: " + problem);
        }
    }

    RestorePrivateSessionsFromHistory();
    ResumePendingFlows();
    LoadRelaySpoolFromDisk();
    LoadMessageJournalFromDisk();
    LoadBootstrapNodes();

    listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket_ == INVALID_SOCKET) return false;

    int opt = 1;
    setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(local_.listenPort);

    if (bind(listenSocket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) return false;
    if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) return false;

    udpSocket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSocket_ == INVALID_SOCKET) return false;
    setsockopt(udpSocket_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
    if (bind(udpSocket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) return false;

    running_ = true;
    acceptThread_ = std::thread(&P2PNode::AcceptLoop, this);
    discoveryThread_ = std::thread(&P2PNode::DiscoveryLoop, this);
    udpThread_ = std::thread(&P2PNode::UdpRecvLoop, this);

    utils::LogSystem("Node started");
    PrintInfo();
    return true;
}

void P2PNode::Stop() {
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false)) return;

    if (listenSocket_ != INVALID_SOCKET) {
        shutdown(listenSocket_, SD_BOTH);
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
    }
    if (udpSocket_ != INVALID_SOCKET) {
        closesocket(udpSocket_);
        udpSocket_ = INVALID_SOCKET;
    }

    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        for (auto& [_, peer] : pendingPeers_) peer->RequestClose();
        for (auto& [_, peer] : pendingPeers_) peer->FinalizeClose();
        pendingPeers_.clear();
    }

    auto peers = peerManager_.GetAllPeers();
    for (auto& p : peers) p->RequestClose();
    for (auto& p : peers) p->FinalizeClose();

    if (acceptThread_.joinable()) acceptThread_.join();
    if (discoveryThread_.joinable()) discoveryThread_.join();
    if (udpThread_.joinable()) udpThread_.join();

    SaveMessageJournalToDisk();
    { std::lock_guard<std::mutex> repLock(reputationMutex_); std::string repError; peerReputation_.Save(local_.nodeId, &repError); }

    signer_.Cleanup();
    CleanupWinSock();
}

bool P2PNode::ConnectToPeer(const std::string& ip, std::uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        closesocket(s);
        return false;
    }

    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return false;
    }

    auto peer = std::make_shared<PeerConnection>(this, s, ip, port, false);
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingPeers_[s] = peer;
    }
    peer->Start();
    SendHello(peer);
    utils::LogSystem("Connected to " + ip + ":" + std::to_string(port));
    return true;
}

void P2PNode::AcceptLoop() {
    while (running_) {
        sockaddr_in addr{};
        int len = sizeof(addr);
        SOCKET client = accept(listenSocket_, reinterpret_cast<sockaddr*>(&addr), &len);
        if (client == INVALID_SOCKET) break;

        auto ip = utils::SocketAddressToIp(addr);
        auto port = ntohs(addr.sin_port);

        auto peer = std::make_shared<PeerConnection>(this, client, ip, port, true);
        {
            std::lock_guard<std::mutex> lock(pendingMutex_);
            pendingPeers_[client] = peer;
        }
        peer->Start();
        utils::LogSystem("Incoming connection: " + ip + ":" + std::to_string(port));
    }
}

void P2PNode::DiscoveryLoop() {
    using namespace std::chrono_literals;
    while (running_) {
        std::this_thread::sleep_for(2s);
        if (!running_) break;
        BroadcastPeerListToAll();
        RunHeartbeatChecks();
        CleanupExpiredRelayQueues();
        SendUdpProbeToKnownNodes();
        TryAutoConnectKnownNodes();
        TryConnectBootstrapNodes();
        RetryRelayQueues();
        ReplayJournalEntries();
        TickProtocolFlows();
        TickFileTransfers();
    }
}

void P2PNode::SendHello(const std::shared_ptr<PeerConnection>& peer) {
    HelloPayload hello{};
    hello.nodeId = local_.nodeId;
    hello.nickname = local_.nickname;
    hello.listenPort = local_.listenPort;
    hello.observedIpForRemote.clear();
    hello.observedPortForRemote = 0;
    signer_.ExportPublicKey(hello.publicKeyBlob);

    auto body = protocol::SerializeHello(hello);
    auto packet = protocol::MakePacket(PacketType::Hello, utils::GeneratePacketId(), body);
    peer->EnqueuePacket(std::move(packet));
}

void P2PNode::SendHelloAck(const std::shared_ptr<PeerConnection>& peer) {
    HelloPayload hello{};
    hello.nodeId = local_.nodeId;
    hello.nickname = local_.nickname;
    hello.listenPort = local_.listenPort;
    hello.observedIpForRemote = peer->GetRemoteIp();
    hello.observedPortForRemote = peer->GetRemotePort();
    signer_.ExportPublicKey(hello.publicKeyBlob);

    auto body = protocol::SerializeHello(hello);
    auto packet = protocol::MakePacket(PacketType::HelloAck, utils::GeneratePacketId(), body);
    peer->EnqueuePacket(std::move(packet));
}

void P2PNode::SendPeerList(const std::shared_ptr<PeerConnection>& peer) {
    auto nodes = knownNodes_.GetAllExcept(local_.nodeId);
    auto body = protocol::SerializePeerList(nodes);
    auto packet = protocol::MakePacket(PacketType::PeerList, utils::GeneratePacketId(), body);
    peer->EnqueuePacket(std::move(packet));
}

void P2PNode::BroadcastPeerListToAll() {
    for (auto& p : peerManager_.GetAllPeers()) SendPeerList(p);
}

void P2PNode::SendPing(const std::shared_ptr<PeerConnection>& peer) {
    if (!peer || !peer->IsAlive()) return;
    auto packet = protocol::MakePacket(PacketType::Ping, utils::GeneratePacketId(), {});
    peer->EnqueuePacket(std::move(packet));
}

void P2PNode::SendPong(const std::shared_ptr<PeerConnection>& peer) {
    auto packet = protocol::MakePacket(PacketType::Pong, utils::GeneratePacketId(), {});
    peer->EnqueuePacket(std::move(packet));
}

void P2PNode::RunHeartbeatChecks() {
    auto now = std::chrono::steady_clock::now();
    for (const auto& peer : peerManager_.GetAllPeers()) {
        if (!peer || !peer->IsAlive() || !peer->IsActive()) continue;
        if (peer->IsHeartbeatTimedOut(now, heartbeatTimeout_)) {
            const auto name = peer->GetRemoteNickname().empty() ? peer->GetRemoteNodeId() : peer->GetRemoteNickname();
            utils::LogSystem("Heartbeat timeout for peer: " + name);
            SafeClosePeer(peer);
            continue;
        }
        if (peer->ShouldSendPing(now, heartbeatInterval_)) {
            SendPing(peer);
        }
    }
}

void P2PNode::CleanupExpiredRelayQueues() {
    const auto now = std::chrono::system_clock::now();
    bool mutated = false;
    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        for (auto it = relayQueuesByTarget_.begin(); it != relayQueuesByTarget_.end();) {
            auto& q = it->second;
            const auto before = q.size();
            q.erase(std::remove_if(q.begin(), q.end(), [&](const QueuedRelayMessage& msg) {
                return now - msg.queuedAt > relayMessageTtl_;
            }), q.end());
            mutated = mutated || (q.size() != before);
            if (q.empty()) it = relayQueuesByTarget_.erase(it); else ++it;
        }
        for (auto it = relayAckQueuesByTarget_.begin(); it != relayAckQueuesByTarget_.end();) {
            auto& q = it->second;
            const auto before = q.size();
            q.erase(std::remove_if(q.begin(), q.end(), [&](const QueuedRelayAck& msg) {
                return now - msg.queuedAt > relayAckTtl_;
            }), q.end());
            mutated = mutated || (q.size() != before);
            if (q.empty()) it = relayAckQueuesByTarget_.erase(it); else ++it;
        }
    }
    if (mutated) {
        SaveRelaySpoolToDisk();
        utils::LogSystem("Expired relay queue entries were cleaned up");
    }
}

bool P2PNode::CheckIncomingRateLimit(const std::shared_ptr<PeerConnection>& peer, PacketType type) {
    if (!peer) return true;

    const bool isMessageHeavy = (
        type == PacketType::ChatMessage ||
        type == PacketType::PrivateMessage ||
        type == PacketType::RelayPrivateMessage ||
        type == PacketType::HistorySyncResponse);

    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(rateLimitMutex_);
    auto& state = rateLimitBySocket_[peer->GetSocket()];
    const auto elapsed = std::chrono::duration<double>(now - state.lastRefill).count();
    state.lastRefill = now;

    state.generalTokens = std::min(generalBurst_, state.generalTokens + elapsed * generalRatePerSecond_);
    state.messageTokens = std::min(messageBurst_, state.messageTokens + elapsed * messageRatePerSecond_);

    if (state.generalTokens < 1.0 || (isMessageHeavy && state.messageTokens < 1.0)) {
        ++state.violations;
        if (state.violations == 1 || state.violations % 5 == 0) {
            const auto remote = peer->GetRemoteNickname().empty() ? peer->GetRemoteNodeId() : peer->GetRemoteNickname();
            utils::LogError("Rate limit exceeded for peer: " + remote);
            if (!peer->GetRemoteNodeId().empty()) {
                std::lock_guard<std::mutex> repLock(reputationMutex_);
                peerReputation_.NoteRateLimitViolation(peer->GetRemoteNodeId());
                std::string repError; peerReputation_.Save(local_.nodeId, &repError);
            }
        }
        if (state.violations >= maxRateViolations_) {
            utils::LogError("Closing peer due to repeated rate-limit violations");
            SafeClosePeer(peer);
        }
        return false;
    }

    state.generalTokens -= 1.0;
    if (isMessageHeavy) state.messageTokens -= 1.0;
    if (state.violations > 0) --state.violations;
    return true;
}

void P2PNode::OnPacket(const std::shared_ptr<PeerConnection>& peer, PacketType type, PacketId packetId, const ByteVector& payload) {
    if (peer) {
        peer->MarkReceivedActivity();
        if (!CheckIncomingRateLimit(peer, type)) return;
        const auto remoteId = peer->GetRemoteNodeId();
        if (!remoteId.empty()) {
            if (auto known = knownNodes_.FindByNodeId(remoteId)) {
                known->lastSeen = std::chrono::steady_clock::now();
                knownNodes_.Upsert(*known);
            }
        }
    }
    switch (type) {
        case PacketType::Hello: HandleHello(peer, payload); break;
        case PacketType::HelloAck: HandleHelloAck(peer, payload); break;
        case PacketType::ChatMessage: HandleChat(peer, packetId, payload); break;
        case PacketType::PeerList: HandlePeerList(payload); break;
        case PacketType::Ping: SendPong(peer); break;
        case PacketType::Pong: break;
        case PacketType::InviteRequest: HandleInviteRequest(peer, packetId, payload); break;
        case PacketType::InviteAccept: HandleInviteAccept(peer, packetId, payload); break;
        case PacketType::InviteReject: HandleInviteReject(peer, packetId, payload); break;
        case PacketType::PrivateMessage: HandlePrivateMessage(peer, packetId, payload); break;
        case PacketType::MessageAck: HandleMessageAck(peer, packetId, payload); break;
        case PacketType::ConnectRequest: HandleConnectRequest(peer, packetId, payload); break;
        case PacketType::UdpPunchRequest: HandleUdpPunchRequest(peer, packetId, payload); break;
        case PacketType::RelayPrivateMessage: HandleRelayPrivateMessage(peer, packetId, payload); break;
        case PacketType::RelayMessageAck: HandleRelayMessageAck(peer, packetId, payload); break;
        case PacketType::HistorySyncRequest: HandleHistorySyncRequest(peer, packetId, payload); break;
        case PacketType::HistorySyncResponse: HandleHistorySyncResponse(peer, packetId, payload); break;
        default: break;
    }
}

void P2PNode::HandleHello(const std::shared_ptr<PeerConnection>& peer, const ByteVector& payload) {
    HelloPayload hello{};
    if (!protocol::DeserializeHello(payload, hello)) { if (peer && !peer->GetRemoteNodeId().empty()) { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteInvalidPacket(peer->GetRemoteNodeId()); std::string repError; peerReputation_.Save(local_.nodeId, &repError); } SafeClosePeer(peer); return; }
    if (!FinalizePeerAfterHandshake(peer, hello)) return;
    SendHelloAck(peer);
    SendPeerList(peer);
}

void P2PNode::HandleHelloAck(const std::shared_ptr<PeerConnection>& peer, const ByteVector& payload) {
    HelloPayload hello{};
    if (!protocol::DeserializeHello(payload, hello)) { if (peer && !peer->GetRemoteNodeId().empty()) { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteInvalidPacket(peer->GetRemoteNodeId()); std::string repError; peerReputation_.Save(local_.nodeId, &repError); } SafeClosePeer(peer); return; }
    if (!FinalizePeerAfterHandshake(peer, hello)) return;
    SendPeerList(peer);
}

bool P2PNode::FinalizePeerAfterHandshake(const std::shared_ptr<PeerConnection>& peer, const HelloPayload& hello) {
    if (!peer) return false;
    if (hello.nodeId == local_.nodeId) { SafeClosePeer(peer); return false; }

    peer->SetRemoteIdentity(hello.nodeId, hello.nickname, hello.listenPort);

    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        publicKeys_[hello.nodeId] = hello.publicKeyBlob;
    }
    {
        std::lock_guard<std::mutex> lock(contactsMutex_);
        auto it = contacts_.find(hello.nodeId);
        if (it != contacts_.end() && !hello.publicKeyBlob.empty()) {
            it->second.publicKeyBlob = hello.publicKeyBlob;
            it->second.fingerprint = ComputeFingerprint(hello.publicKeyBlob);
        }
    }
    SaveContacts();

    if (!hello.observedIpForRemote.empty() && hello.observedPortForRemote != 0) {
        std::lock_guard<std::mutex> lock(observedEndpointMutex_);
        localObservedIp_ = hello.observedIpForRemote;
        localObservedPort_ = hello.observedPortForRemote;
    }

    {
        std::lock_guard<std::mutex> repLock(reputationMutex_);
        if (peerReputation_.ShouldBlock(hello.nodeId)) {
            utils::LogWarn("Blocking handshake from low-reputation peer: " + hello.nodeId);
            return false;
        }
    }

    KnownNode known{};
    if (auto existingKnown = knownNodes_.FindByNodeId(hello.nodeId)) known = *existingKnown;
    known.nodeId = hello.nodeId;
    known.nickname = hello.nickname;
    known.ip = peer->GetRemoteIp();
    known.port = hello.listenPort;
    known.observedPort = peer->GetRemotePort();
    known.lastSeen = std::chrono::steady_clock::now();
    const bool wasKnown = knownNodes_.Exists(hello.nodeId);
    knownNodes_.Upsert(known);
    UpsertContactHintsFromKnownNode(known);
    ResetReconnectState(hello.nodeId);

    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingPeers_.erase(peer->GetSocket());
    }

    auto existing = peerManager_.FindByNodeId(hello.nodeId);
    if (existing) {
        const bool keepIncoming = PreferIncomingFor(hello.nodeId);
        const bool newIsPreferred = (peer->IsIncoming() == keepIncoming);
        if (newIsPreferred) {
            peerManager_.RemoveBySocket(existing->GetSocket());
            SafeClosePeer(existing);
        } else {
            SafeClosePeer(peer);
            return false;
        }
    }

    if (!peer->TrySetActive()) { SafeClosePeer(peer); return false; }
    if (!peerManager_.AddPeer(peer)) { SafeClosePeer(peer); return false; }
    {
        std::lock_guard<std::mutex> repLock(reputationMutex_);
        peerReputation_.NoteGoodEvent(hello.nodeId, 4);
        std::string repError; peerReputation_.Save(local_.nodeId, &repError);
    }

    utils::LogSystem("Connected with " + hello.nickname);
    FlushRelayQueueForTarget(hello.nodeId);
    FlushRelayAckQueueForTarget(hello.nodeId);
    RequestHistorySync(hello.nodeId);
    bool shouldMirrorDevice = false;
    {
        std::lock_guard<std::mutex> lock(overlayMutex_);
        auto it = overlayState_.devices.find(hello.nodeId);
        shouldMirrorDevice = (it != overlayState_.devices.end() && it->second.approved && !it->second.revoked);
    }
    if (shouldMirrorDevice) {
        MirrorConversationToDevice(hello.nodeId, 8);
    }
    if (!wasKnown) BroadcastPeerListToAll();
    return true;
}

void P2PNode::HandleChat(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;
    ChatPayload chat{};
    if (!protocol::DeserializeChat(payload, chat)) return;
    utils::LogGlobal(chat.originNickname, chat.text);
    auto packet = protocol::MakePacket(PacketType::ChatMessage, packetId, payload);
    BroadcastRaw(packet, peer->GetRemoteNodeId());
}

void P2PNode::HandlePeerList(const ByteVector& payload) {
    std::vector<KnownNode> nodes;
    if (!protocol::DeserializePeerList(payload, nodes)) return;
    for (auto& node : nodes) {
        if (node.nodeId == local_.nodeId) continue;
        if (node.ip.empty() || (node.port == 0 && node.observedPort == 0)) continue;
        node.lastSeen = std::chrono::steady_clock::now();
        knownNodes_.Upsert(node);
        UpsertContactHintsFromKnownNode(node);
    }
}

ByteVector P2PNode::BuildInviteRequestSignedData(const InviteRequestPayload& p) const {
    ByteVector out;
    utils::WriteUint64(out, p.inviteId);
    utils::WriteString(out, p.fromNodeId);
    utils::WriteString(out, p.fromNickname);
    utils::WriteString(out, p.toNodeId);
    utils::WriteBytes(out, p.fromEncryptPublicKeyBlob);
    return out;
}

ByteVector P2PNode::BuildInviteAcceptSignedData(const InviteAcceptPayload& p) const {
    ByteVector out;
    utils::WriteUint64(out, p.inviteId);
    utils::WriteUint64(out, p.sessionId);
    utils::WriteString(out, p.fromNodeId);
    utils::WriteString(out, p.fromNickname);
    utils::WriteString(out, p.toNodeId);
    utils::WriteBytes(out, p.fromEncryptPublicKeyBlob);
    utils::WriteBytes(out, p.encryptedSessionKeyBlob);
    return out;
}

ByteVector P2PNode::BuildInviteRejectSignedData(const InviteRejectPayload& p) const {
    ByteVector out;
    utils::WriteUint64(out, p.inviteId);
    utils::WriteString(out, p.fromNodeId);
    utils::WriteString(out, p.fromNickname);
    utils::WriteString(out, p.toNodeId);
    utils::WriteString(out, p.reason);
    utils::WriteBytes(out, p.fromEncryptPublicKeyBlob);
    return out;
}

ByteVector P2PNode::BuildPrivateMessageSignedData(const PrivateMessagePayload& p) const {
    ByteVector out;
    utils::WriteUint64(out, p.messageId);
    utils::WriteUint64(out, p.sessionId);
    utils::WriteUint64(out, p.sequenceNumber);
    utils::WriteString(out, p.fromNodeId);
    utils::WriteString(out, p.fromNickname);
    utils::WriteString(out, p.toNodeId);
    utils::WriteBytes(out, p.iv);
    utils::WriteBytes(out, p.ciphertext);
    return out;
}

bool P2PNode::EncryptPrivateMessagePayload(PrivateMessagePayload& payload, const ByteVector& sessionKey) const {
    if (sessionKey.empty()) return false;
    if (!signer_.GenerateRandomBytes(16, payload.iv)) return false;
    ByteVector plain(payload.text.begin(), payload.text.end());
    return signer_.EncryptAes(sessionKey, payload.iv, plain, payload.ciphertext);
}

bool P2PNode::DecryptPrivateMessagePayload(PrivateMessagePayload& payload, const ByteVector& sessionKey) const {
    if (sessionKey.empty()) return false;
    ByteVector plain;
    if (!signer_.DecryptAes(sessionKey, payload.iv, payload.ciphertext, plain)) return false;
    payload.text.assign(plain.begin(), plain.end());
    return true;
}

ByteVector P2PNode::BuildMessageAckSignedData(const MessageAckPayload& p) const {
    ByteVector out;
    utils::WriteUint64(out, p.messageId);
    utils::WriteUint64(out, p.sessionId);
    utils::WriteString(out, p.fromNodeId);
    utils::WriteString(out, p.toNodeId);
    utils::WriteUint64(out, p.ackedRelayPacketId);
    return out;
}

ByteVector P2PNode::BuildConnectRequestSignedData(const ConnectRequestPayload& p) const {
    ByteVector out;
    utils::WriteString(out, p.requesterNodeId);
    utils::WriteString(out, p.requesterNickname);
    utils::WriteString(out, p.targetNodeId);
    utils::WriteString(out, p.requesterObservedIp);
    utils::WriteUint16(out, p.requesterAdvertisedPort);
    utils::WriteUint16(out, p.requesterObservedPort);
    return out;
}


ByteVector P2PNode::BuildUdpPunchRequestSignedData(const UdpPunchRequestPayload& p) const {
    ByteVector out;
    utils::WriteString(out, p.requesterNodeId);
    utils::WriteString(out, p.requesterNickname);
    utils::WriteString(out, p.targetNodeId);
    utils::WriteString(out, p.requesterObservedUdpIp);
    utils::WriteUint16(out, p.requesterAdvertisedTcpPort);
    utils::WriteUint16(out, p.requesterObservedUdpPort);
    return out;
}


ByteVector P2PNode::BuildHistorySyncRequestSignedData(const HistorySyncRequestPayload& p) const {
    ByteVector out;
    utils::WriteString(out, p.requesterNodeId);
    utils::WriteString(out, p.targetNodeId);
    utils::WriteUint64(out, p.afterMessageId);
    return out;
}

ByteVector P2PNode::BuildHistorySyncResponseSignedData(const HistorySyncResponsePayload& p) const {
    ByteVector out;
    utils::WriteString(out, p.responderNodeId);
    utils::WriteString(out, p.targetNodeId);
    utils::WriteBytes(out, p.messagesBlob);
    return out;
}

void P2PNode::SendInvite(const NodeId& targetNodeId) {
    InviteRequestPayload payload{};
    payload.inviteId = utils::GeneratePacketId();
    payload.fromNodeId = local_.nodeId;
    payload.fromNickname = local_.nickname;
    payload.toNodeId = targetNodeId;
    signer_.ExportPublicKey(payload.fromPublicKeyBlob);
    signer_.ExportEncryptPublicKey(payload.fromEncryptPublicKeyBlob);
    signer_.Sign(BuildInviteRequestSignedData(payload), payload.signature);

    PendingInvite inv{payload.inviteId, payload.fromNodeId, payload.fromNickname, payload.toNodeId};
    {
        std::lock_guard<std::mutex> lock(invitesMutex_);
        outgoingInvites_[payload.inviteId] = inv;
    }

    const PacketId packetId = utils::GeneratePacketId();
    router_.MarkSeen(packetId);
    auto body = protocol::SerializeInviteRequest(payload);
    auto packet = protocol::MakePacket(PacketType::InviteRequest, packetId, body);
    utils::LogSystem("Private invite sent");
    BroadcastRaw(packet);
}

void P2PNode::HandleInviteRequest(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;
    InviteRequestPayload p{};
    if (!protocol::DeserializeInviteRequest(payload, p)) { if (peer && !peer->GetRemoteNodeId().empty()) { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteInvalidPacket(peer->GetRemoteNodeId()); std::string repError; peerReputation_.Save(local_.nodeId, &repError); } return; }

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(p.fromNodeId);
        if (it != publicKeys_.end()) pub = it->second;
        else if (!p.fromPublicKeyBlob.empty()) {
            publicKeys_[p.fromNodeId] = p.fromPublicKeyBlob;
            pub = p.fromPublicKeyBlob;
        } else return;
        if (!p.fromEncryptPublicKeyBlob.empty()) publicEncryptKeys_[p.fromNodeId] = p.fromEncryptPublicKeyBlob;
    }
    if (!signer_.Verify(BuildInviteRequestSignedData(p), p.signature, pub)) {
        utils::LogError("Invite signature invalid");
        { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteSignatureFailure(p.fromNodeId); std::string repError; peerReputation_.Save(local_.nodeId, &repError); }
        return;
    }

    if (p.toNodeId == local_.nodeId) {
        PendingInvite inv{p.inviteId, p.fromNodeId, p.fromNickname, p.toNodeId};
        {
            std::lock_guard<std::mutex> lock(invitesMutex_);
            incomingInvites_[p.inviteId] = inv;
        }
        {
            std::lock_guard<std::mutex> lock(contactsMutex_);
            auto it = contacts_.find(p.fromNodeId);
            if (it != contacts_.end() && !p.fromPublicKeyBlob.empty()) {
                it->second.publicKeyBlob = p.fromPublicKeyBlob;
                it->second.fingerprint = ComputeFingerprint(p.fromPublicKeyBlob);
            }
        }
        utils::LogSystem(p.fromNickname + " invites you to private chat");
        return;
    }

    auto packet = protocol::MakePacket(PacketType::InviteRequest, packetId, payload);
    BroadcastRaw(packet, peer->GetRemoteNodeId());
}

void P2PNode::AcceptInvite(const NodeId& fromNodeId) {
    auto inviteOpt = FindIncomingInviteByFromNodeId(fromNodeId);
    if (!inviteOpt) { utils::LogError("No invite from this user"); return; }
    auto invite = *inviteOpt;
    SessionId sessionId = utils::GeneratePacketId();

    ByteVector remoteEncryptKey;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicEncryptKeys_.find(invite.fromNodeId);
        if (it == publicEncryptKeys_.end()) {
            utils::LogError("Missing inviter encryption public key");
            return;
        }
        remoteEncryptKey = it->second;
    }

    ByteVector sessionKey;
    if (!signer_.GenerateRandomBytes(32, sessionKey)) {
        utils::LogError("Failed to generate private session key");
        return;
    }

    InviteAcceptPayload payload{};
    payload.inviteId = invite.inviteId;
    payload.sessionId = sessionId;
    payload.fromNodeId = local_.nodeId;
    payload.fromNickname = local_.nickname;
    payload.toNodeId = invite.fromNodeId;
    signer_.ExportPublicKey(payload.fromPublicKeyBlob);
    signer_.ExportEncryptPublicKey(payload.fromEncryptPublicKeyBlob);
    if (!signer_.EncryptFor(sessionKey, remoteEncryptKey, payload.encryptedSessionKeyBlob)) {
        utils::LogError("Failed to encrypt private session key");
        return;
    }
    signer_.Sign(BuildInviteAcceptSignedData(payload), payload.signature);

    EnsureSessionForPeer(invite.fromNodeId, invite.fromNickname, sessionId);
    SetSessionKeyForPeer(invite.fromNodeId, sessionId, sessionKey);
    {
        std::lock_guard<std::mutex> lock(invitesMutex_);
        incomingInvites_.erase(invite.inviteId);
    }

    PacketId packetId = utils::GeneratePacketId();
    router_.MarkSeen(packetId);
    auto body = protocol::SerializeInviteAccept(payload);
    auto packet = protocol::MakePacket(PacketType::InviteAccept, packetId, body);
    utils::LogSystem("Private chat opened with " + invite.fromNickname + " (E2E ready)");
    PrintStoredConversation(invite.fromNodeId, invite.fromNickname);
    BroadcastRaw(packet);
}

void P2PNode::HandleInviteAccept(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;
    InviteAcceptPayload p{};
    if (!protocol::DeserializeInviteAccept(payload, p)) { if (peer && !peer->GetRemoteNodeId().empty()) { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteInvalidPacket(peer->GetRemoteNodeId()); std::string repError; peerReputation_.Save(local_.nodeId, &repError); } return; }

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(p.fromNodeId);
        if (it != publicKeys_.end()) pub = it->second;
        else if (!p.fromPublicKeyBlob.empty()) {
            publicKeys_[p.fromNodeId] = p.fromPublicKeyBlob;
            pub = p.fromPublicKeyBlob;
        } else return;
        if (!p.fromEncryptPublicKeyBlob.empty()) publicEncryptKeys_[p.fromNodeId] = p.fromEncryptPublicKeyBlob;
    }
    if (!signer_.Verify(BuildInviteAcceptSignedData(p), p.signature, pub)) {
        utils::LogError("Accept signature invalid");
        { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteSignatureFailure(p.fromNodeId); std::string repError; peerReputation_.Save(local_.nodeId, &repError); }
        return;
    }

    if (p.toNodeId == local_.nodeId) {
        {
            std::lock_guard<std::mutex> lock(invitesMutex_);
            outgoingInvites_.erase(p.inviteId);
        }
        {
            std::lock_guard<std::mutex> lock(contactsMutex_);
            auto it = contacts_.find(p.fromNodeId);
            if (it != contacts_.end() && !p.fromPublicKeyBlob.empty()) {
                it->second.publicKeyBlob = p.fromPublicKeyBlob;
                it->second.fingerprint = ComputeFingerprint(p.fromPublicKeyBlob);
            }
        }
        ByteVector sessionKey;
        if (!signer_.Decrypt(p.encryptedSessionKeyBlob, sessionKey)) {
            utils::LogError("Failed to decrypt private chat session key");
            return;
        }
        EnsureSessionForPeer(p.fromNodeId, p.fromNickname, p.sessionId);
        SetSessionKeyForPeer(p.fromNodeId, p.sessionId, sessionKey);
        utils::LogSystem("Private chat opened with " + p.fromNickname);
        PrintStoredConversation(p.fromNodeId, p.fromNickname);
        return;
    }

    auto packet = protocol::MakePacket(PacketType::InviteAccept, packetId, payload);
    BroadcastRaw(packet, peer->GetRemoteNodeId());
}

void P2PNode::BroadcastChat(const std::string& text) {
    ChatPayload payload{};
    payload.originNodeId = local_.nodeId;
    payload.originNickname = local_.nickname;
    payload.text = text;

    const PacketId packetId = utils::GeneratePacketId();
    router_.MarkSeen(packetId);

    auto body = protocol::SerializeChat(payload);
    auto packet = protocol::MakePacket(PacketType::ChatMessage, packetId, body);

    utils::LogGlobal(local_.nickname, text);
    BroadcastRaw(packet);
}

void P2PNode::RejectInvite(const NodeId& fromNodeId, const std::string& reason) {
    auto inviteOpt = FindIncomingInviteByFromNodeId(fromNodeId);
    if (!inviteOpt) { utils::LogError("No invite from this user"); return; }
    auto invite = *inviteOpt;

    InviteRejectPayload payload{};
    payload.inviteId = invite.inviteId;
    payload.fromNodeId = local_.nodeId;
    payload.fromNickname = local_.nickname;
    payload.toNodeId = invite.fromNodeId;
    payload.reason = reason;
    signer_.ExportPublicKey(payload.fromPublicKeyBlob);
    signer_.ExportEncryptPublicKey(payload.fromEncryptPublicKeyBlob);
    signer_.Sign(BuildInviteRejectSignedData(payload), payload.signature);

    {
        std::lock_guard<std::mutex> lock(invitesMutex_);
        incomingInvites_.erase(invite.inviteId);
    }

    PacketId packetId = utils::GeneratePacketId();
    router_.MarkSeen(packetId);
    auto body = protocol::SerializeInviteReject(payload);
    auto packet = protocol::MakePacket(PacketType::InviteReject, packetId, body);
    utils::LogSystem("Invite rejected");
    BroadcastRaw(packet);
}

void P2PNode::HandleInviteReject(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;
    InviteRejectPayload p{};
    if (!protocol::DeserializeInviteReject(payload, p)) { if (peer && !peer->GetRemoteNodeId().empty()) { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteInvalidPacket(peer->GetRemoteNodeId()); std::string repError; peerReputation_.Save(local_.nodeId, &repError); } return; }

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(p.fromNodeId);
        if (it != publicKeys_.end()) pub = it->second;
        else if (!p.fromPublicKeyBlob.empty()) {
            publicKeys_[p.fromNodeId] = p.fromPublicKeyBlob;
            pub = p.fromPublicKeyBlob;
        } else return;
        if (!p.fromEncryptPublicKeyBlob.empty()) publicEncryptKeys_[p.fromNodeId] = p.fromEncryptPublicKeyBlob;
    }
    if (!signer_.Verify(BuildInviteRejectSignedData(p), p.signature, pub)) {
        utils::LogError("Reject signature invalid");
        { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteSignatureFailure(p.fromNodeId); std::string repError; peerReputation_.Save(local_.nodeId, &repError); }
        return;
    }

    if (p.toNodeId == local_.nodeId) {
        {
            std::lock_guard<std::mutex> lock(invitesMutex_);
            outgoingInvites_.erase(p.inviteId);
        }
        utils::LogSystem(p.fromNickname + " rejected the invite");
        return;
    }

    auto packet = protocol::MakePacket(PacketType::InviteReject, packetId, payload);
    BroadcastRaw(packet, peer->GetRemoteNodeId());
}

void P2PNode::SendPrivateMessage(const NodeId& targetNodeId, const std::string& text) {
    auto sessionIdOpt = FindSessionByPeer(targetNodeId);
    if (!sessionIdOpt) { utils::LogError("No private session with this user"); return; }

    PrivateMessagePayload payload{};
    payload.messageId = GenerateMessageIdForNode(local_.nodeId);
    payload.sessionId = *sessionIdOpt;
    payload.sequenceNumber = GetNextOutgoingSequence(targetNodeId);
    payload.fromNodeId = local_.nodeId;
    payload.fromNickname = local_.nickname;
    payload.toNodeId = targetNodeId;
    payload.text = text;
    ByteVector sessionKey;
    if (!GetSessionKeyForPeer(targetNodeId, sessionKey)) {
        utils::LogError("No E2E session key for this private chat yet");
        return;
    }
    if (!EncryptPrivateMessagePayload(payload, sessionKey)) {
        utils::LogError("Failed to encrypt private message");
        return;
    }
    signer_.Sign(BuildPrivateMessageSignedData(payload), payload.signature);
    TrackPendingJournalMessage(payload);

    bool delivered = false;
    auto body = protocol::SerializePrivateMessage(payload);
    auto packet = protocol::MakePacket(PacketType::PrivateMessage, payload.messageId, body);
    if (auto directPeer = peerManager_.FindByNodeId(targetNodeId)) {
        router_.MarkSeen(payload.messageId);
        directPeer->EnqueuePacket(packet);
        delivered = true;
    } else {
        delivered = RelayPrivateMessageToNetwork(payload);
    }

    StoredMessageState state = StoredMessageState::Failed;
    if (delivered && peerManager_.FindByNodeId(targetNodeId)) state = StoredMessageState::Sent;
    else if (delivered) state = StoredMessageState::Relayed;
    AppendStoredPrivateMessage(payload, StoredMessageDirection::Outgoing, state, localPublicKeyBlob_);
    if (!delivered) {
        utils::LogError("Target peer is not connected and there is no relay path right now");
    } else if (!peerManager_.FindByNodeId(targetNodeId)) {
        utils::LogSystem("Private message sent through relay/offline queue");
    }
    if (text.rfind("[[", 0) != 0) utils::LogPrivate(local_.nickname, text);
}

void P2PNode::HandlePrivateMessage(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;

    PrivateMessagePayload p{};
    if (!protocol::DeserializePrivateMessage(payload, p)) { if (peer && !peer->GetRemoteNodeId().empty()) { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteInvalidPacket(peer->GetRemoteNodeId()); std::string repError; peerReputation_.Save(local_.nodeId, &repError); } return; }

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(p.fromNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }
    if (!signer_.Verify(BuildPrivateMessageSignedData(p), p.signature, pub)) {
        utils::LogError("Private message signature invalid");
        { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteSignatureFailure(p.fromNodeId); std::string repError; peerReputation_.Save(local_.nodeId, &repError); }
        return;
    }

    if (p.toNodeId != local_.nodeId) return;
    ByteVector sessionKey;
    if (!GetSessionKeyForPeer(p.fromNodeId, sessionKey)) {
        utils::LogError("Missing E2E session key for incoming private message");
        return;
    }
    if (!DecryptPrivateMessagePayload(p, sessionKey)) {
        utils::LogError("Failed to decrypt private message");
        return;
    }
    BufferOrDeliverIncomingPrivateMessage(p, pub, 0, true);
}

void P2PNode::HandleMessageAck(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;
    MessageAckPayload ack{};
    if (!protocol::DeserializeMessageAck(payload, ack)) { if (peer && !peer->GetRemoteNodeId().empty()) { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteInvalidPacket(peer->GetRemoteNodeId()); std::string repError; peerReputation_.Save(local_.nodeId, &repError); } return; }
    if (ack.toNodeId != local_.nodeId) return;

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(ack.fromNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }
    if (!signer_.Verify(BuildMessageAckSignedData(ack), ack.signature, pub)) {
        utils::LogError("Message ACK signature invalid");
        { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteSignatureFailure(ack.fromNodeId); std::string repError; peerReputation_.Save(local_.nodeId, &repError); }
        return;
    }

    {
        std::lock_guard<std::mutex> lock(ackMutex_);
        if (!seenMessageAcks_.insert(ack.messageId).second) return;
        deliveredOutgoingMessageIds_.insert(ack.messageId);
    }

    UpdateStoredMessageState(ack.fromNodeId, ack.messageId, StoredMessageState::Delivered);
    RemovePendingJournalMessage(ack.messageId);
    utils::LogSystem("Message delivered: id=" + std::to_string(ack.messageId));
}

bool P2PNode::RelayPrivateMessageToNetwork(const PrivateMessagePayload& payload) {
    auto peers = peerManager_.GetAllPeers();
    if (peers.empty()) return false;

    RelayPrivateMessagePayload relay{};
    relay.relayPacketId = utils::GeneratePacketId();
    relay.relayFromNodeId = local_.nodeId;
    relay.finalTargetNodeId = payload.toNodeId;
    relay.privateMessagePacket = protocol::SerializePrivateMessage(payload);

    QueueRelayMessage(relay);

    router_.MarkSeen(relay.relayPacketId);
    auto body = protocol::SerializeRelayPrivateMessage(relay);
    auto packet = protocol::MakePacket(PacketType::RelayPrivateMessage, relay.relayPacketId, body);

    if (auto directPeer = peerManager_.FindByNodeId(payload.toNodeId)) directPeer->EnqueuePacket(packet);
    else BroadcastRaw(packet);
    return true;
}

bool P2PNode::RelayMessageAckToNetwork(const MessageAckPayload& payload) {
    auto peers = peerManager_.GetAllPeers();
    if (peers.empty()) return false;

    RelayMessageAckPayload relay{};
    relay.relayPacketId = utils::GeneratePacketId();
    relay.relayFromNodeId = local_.nodeId;
    relay.finalTargetNodeId = payload.toNodeId;
    relay.ackPacket = protocol::SerializeMessageAck(payload);

    QueueRelayAck(relay);

    router_.MarkSeen(relay.relayPacketId);
    auto body = protocol::SerializeRelayMessageAck(relay);
    auto packet = protocol::MakePacket(PacketType::RelayMessageAck, relay.relayPacketId, body);

    if (auto directPeer = peerManager_.FindByNodeId(payload.toNodeId)) directPeer->EnqueuePacket(packet);
    else BroadcastRaw(packet);
    return true;
}

void P2PNode::QueueRelayMessage(const RelayPrivateMessagePayload& payload) {
    PrivateMessagePayload inner{};
    if (!protocol::DeserializePrivateMessage(payload.privateMessagePacket, inner)) return;

    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        auto& q = relayQueuesByTarget_[payload.finalTargetNodeId];
        for (const auto& existing : q) {
            if (existing.relayPacketId == payload.relayPacketId || existing.messageId == inner.messageId) return;
        }
        QueuedRelayMessage item{};
        item.relayPacketId = payload.relayPacketId;
        item.messageId = inner.messageId;
        item.relayFromNodeId = payload.relayFromNodeId;
        item.finalTargetNodeId = payload.finalTargetNodeId;
        item.privateMessagePacket = payload.privateMessagePacket;
        item.queuedAt = std::chrono::system_clock::now();
        item.nextAttemptAt = std::chrono::steady_clock::now();
        item.attemptCount = 0;
        q.push_back(std::move(item));
    }
    SaveRelaySpoolToDisk();
}

void P2PNode::QueueRelayAck(const RelayMessageAckPayload& payload) {
    MessageAckPayload inner{};
    if (!protocol::DeserializeMessageAck(payload.ackPacket, inner)) return;

    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        auto& q = relayAckQueuesByTarget_[payload.finalTargetNodeId];
        for (const auto& existing : q) {
            if (existing.relayPacketId == payload.relayPacketId || existing.messageId == inner.messageId) return;
        }
        QueuedRelayAck item{};
        item.relayPacketId = payload.relayPacketId;
        item.messageId = inner.messageId;
        item.relayFromNodeId = payload.relayFromNodeId;
        item.finalTargetNodeId = payload.finalTargetNodeId;
        item.ackPacket = payload.ackPacket;
        item.queuedAt = std::chrono::system_clock::now();
        item.nextAttemptAt = std::chrono::steady_clock::now();
        item.attemptCount = 0;
        q.push_back(std::move(item));
    }
    SaveRelaySpoolToDisk();
}

void P2PNode::FlushRelayQueueForTarget(const NodeId& targetNodeId) {
    std::deque<QueuedRelayMessage> pending;
    bool mutated = false;
    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        auto it = relayQueuesByTarget_.find(targetNodeId);
        if (it == relayQueuesByTarget_.end() || it->second.empty()) return;
        const auto now = std::chrono::steady_clock::now();
        for (auto& msg : it->second) {
            if (msg.nextAttemptAt > now) continue;
            pending.push_back(msg);
            ++msg.attemptCount;
            auto delaySeconds = std::min<std::uint32_t>(60u, 1u << std::min<std::uint32_t>(msg.attemptCount, 5u));
            msg.nextAttemptAt = now + std::chrono::seconds(delaySeconds);
            mutated = true;
        }
    }

    auto peer = peerManager_.FindByNodeId(targetNodeId);
    if (!peer || pending.empty()) {
        if (mutated) SaveRelaySpoolToDisk();
        return;
    }

    for (const auto& msg : pending) {
        RelayPrivateMessagePayload relay{};
        relay.relayPacketId = msg.relayPacketId;
        relay.relayFromNodeId = msg.relayFromNodeId;
        relay.finalTargetNodeId = msg.finalTargetNodeId;
        relay.privateMessagePacket = msg.privateMessagePacket;
        auto body = protocol::SerializeRelayPrivateMessage(relay);
        auto packet = protocol::MakePacket(PacketType::RelayPrivateMessage, relay.relayPacketId, body);
        peer->EnqueuePacket(packet);
    }

    if (mutated) SaveRelaySpoolToDisk();
    utils::LogSystem("Flushed queued relayed messages to " + targetNodeId);
}

void P2PNode::FlushRelayAckQueueForTarget(const NodeId& targetNodeId) {
    std::deque<QueuedRelayAck> pending;
    bool mutated = false;
    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        auto it = relayAckQueuesByTarget_.find(targetNodeId);
        if (it == relayAckQueuesByTarget_.end() || it->second.empty()) return;
        const auto now = std::chrono::steady_clock::now();
        for (auto& msg : it->second) {
            if (msg.nextAttemptAt > now) continue;
            pending.push_back(msg);
            ++msg.attemptCount;
            auto delaySeconds = std::min<std::uint32_t>(60u, 1u << std::min<std::uint32_t>(msg.attemptCount, 5u));
            msg.nextAttemptAt = now + std::chrono::seconds(delaySeconds);
            mutated = true;
        }
    }

    auto peer = peerManager_.FindByNodeId(targetNodeId);
    if (!peer || pending.empty()) {
        if (mutated) SaveRelaySpoolToDisk();
        return;
    }

    for (const auto& msg : pending) {
        RelayMessageAckPayload relay{};
        relay.relayPacketId = msg.relayPacketId;
        relay.relayFromNodeId = msg.relayFromNodeId;
        relay.finalTargetNodeId = msg.finalTargetNodeId;
        relay.ackPacket = msg.ackPacket;
        auto body = protocol::SerializeRelayMessageAck(relay);
        auto packet = protocol::MakePacket(PacketType::RelayMessageAck, relay.relayPacketId, body);
        peer->EnqueuePacket(packet);
    }

    if (mutated) SaveRelaySpoolToDisk();
    utils::LogSystem("Flushed queued relayed ACKs to " + targetNodeId);
}

void P2PNode::RemoveQueuedRelayMessageByMessageId(const NodeId& targetNodeId, MessageId messageId) {
    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        auto it = relayQueuesByTarget_.find(targetNodeId);
        if (it == relayQueuesByTarget_.end()) return;
        auto& q = it->second;
        q.erase(std::remove_if(q.begin(), q.end(), [&](const QueuedRelayMessage& m) { return m.messageId == messageId; }), q.end());
        if (q.empty()) relayQueuesByTarget_.erase(it);
    }
    SaveRelaySpoolToDisk();
}

void P2PNode::RemoveQueuedRelayAckByMessageId(const NodeId& targetNodeId, MessageId messageId) {
    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        auto it = relayAckQueuesByTarget_.find(targetNodeId);
        if (it == relayAckQueuesByTarget_.end()) return;
        auto& q = it->second;
        q.erase(std::remove_if(q.begin(), q.end(), [&](const QueuedRelayAck& m) { return m.messageId == messageId; }), q.end());
        if (q.empty()) relayAckQueuesByTarget_.erase(it);
    }
    SaveRelaySpoolToDisk();
}

void P2PNode::SendDeliveryAck(const PrivateMessagePayload& message, PacketId ackedRelayPacketId) {
    MessageAckPayload ack{};
    ack.messageId = message.messageId;
    ack.sessionId = message.sessionId;
    ack.fromNodeId = local_.nodeId;
    ack.toNodeId = message.fromNodeId;
    ack.ackedRelayPacketId = ackedRelayPacketId;
    signer_.Sign(BuildMessageAckSignedData(ack), ack.signature);

    auto body = protocol::SerializeMessageAck(ack);
    auto packet = protocol::MakePacket(PacketType::MessageAck, utils::GeneratePacketId(), body);
    if (auto directPeer = peerManager_.FindByNodeId(ack.toNodeId)) {
        directPeer->EnqueuePacket(packet);
    } else {
        RelayMessageAckToNetwork(ack);
    }
}

void P2PNode::HandleRelayPrivateMessage(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;

    RelayPrivateMessagePayload relay{};
    if (!protocol::DeserializeRelayPrivateMessage(payload, relay)) return;
    if (relay.finalTargetNodeId.empty() || relay.privateMessagePacket.empty()) return;

    QueueRelayMessage(relay);

    if (relay.finalTargetNodeId == local_.nodeId) {
        {
            std::lock_guard<std::mutex> lock(relayMutex_);
            if (!deliveredRelayPackets_.insert(relay.relayPacketId).second) return;
        }
        PrivateMessagePayload inner{};
        if (!protocol::DeserializePrivateMessage(relay.privateMessagePacket, inner)) return;

        ByteVector pub;
        {
            std::lock_guard<std::mutex> lock(publicKeysMutex_);
            auto it = publicKeys_.find(inner.fromNodeId);
            if (it == publicKeys_.end()) return;
            pub = it->second;
        }
        if (!signer_.Verify(BuildPrivateMessageSignedData(inner), inner.signature, pub)) {
            utils::LogError("Private message signature invalid");
            return;
        }
        if (inner.toNodeId != local_.nodeId) return;
        ByteVector sessionKey;
        if (!GetSessionKeyForPeer(inner.fromNodeId, sessionKey)) {
            utils::LogError("Missing E2E session key for incoming relayed private message");
            return;
        }
        if (!DecryptPrivateMessagePayload(inner, sessionKey)) {
            utils::LogError("Failed to decrypt relayed private message");
            return;
        }

        if (router_.MarkSeen(inner.messageId)) {
            BufferOrDeliverIncomingPrivateMessage(inner, pub, relay.relayPacketId, true);
        }
        return;
    }

    if (auto directPeer = peerManager_.FindByNodeId(relay.finalTargetNodeId)) {
        directPeer->EnqueuePacket(protocol::MakePacket(PacketType::RelayPrivateMessage, relay.relayPacketId, payload));
        return;
    }

    BroadcastRaw(protocol::MakePacket(PacketType::RelayPrivateMessage, relay.relayPacketId, payload), peer ? peer->GetRemoteNodeId() : "");
}

void P2PNode::HandleRelayMessageAck(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;

    RelayMessageAckPayload relay{};
    if (!protocol::DeserializeRelayMessageAck(payload, relay)) return;
    if (relay.finalTargetNodeId.empty() || relay.ackPacket.empty()) return;

    QueueRelayAck(relay);

    MessageAckPayload inner{};
    if (!protocol::DeserializeMessageAck(relay.ackPacket, inner)) return;
    RemoveQueuedRelayMessageByMessageId(inner.fromNodeId, inner.messageId);

    if (relay.finalTargetNodeId == local_.nodeId) {
        {
            std::lock_guard<std::mutex> lock(relayMutex_);
            if (!deliveredRelayAckPackets_.insert(relay.relayPacketId).second) return;
        }
        RemoveQueuedRelayAckByMessageId(local_.nodeId, inner.messageId);
        HandleMessageAck(peer, utils::GeneratePacketId(), relay.ackPacket);
        return;
    }

    if (auto directPeer = peerManager_.FindByNodeId(relay.finalTargetNodeId)) {
        directPeer->EnqueuePacket(protocol::MakePacket(PacketType::RelayMessageAck, relay.relayPacketId, payload));
        return;
    }

    BroadcastRaw(protocol::MakePacket(PacketType::RelayMessageAck, relay.relayPacketId, payload), peer ? peer->GetRemoteNodeId() : "");
}



void P2PNode::RequestHistorySync(const NodeId& peerNodeId) {
    if (peerNodeId.empty()) return;
    auto peer = peerManager_.FindByNodeId(peerNodeId);
    if (!peer) return;

    MessageId afterMessageId = 0;
    std::vector<StoredConversationMessage> messages;
    std::string error;
    if (ConversationStore::LoadConversation(historyRootDir_, local_.nodeId, peerNodeId, signer_, messages, &error)) {
        if (!messages.empty()) afterMessageId = messages.back().messageId;
    }

    HistorySyncRequestPayload req{};
    req.requesterNodeId = local_.nodeId;
    req.targetNodeId = peerNodeId;
    req.afterMessageId = afterMessageId;
    signer_.Sign(BuildHistorySyncRequestSignedData(req), req.signature);

    auto body = protocol::SerializeHistorySyncRequest(req);
    peer->EnqueuePacket(protocol::MakePacket(PacketType::HistorySyncRequest, utils::GeneratePacketId(), body));
}

void P2PNode::RetryRelayQueues() {
    std::vector<NodeId> targets;
    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        for (const auto& [target, _] : relayQueuesByTarget_) targets.push_back(target);
        for (const auto& [target, _] : relayAckQueuesByTarget_) targets.push_back(target);
    }
    std::sort(targets.begin(), targets.end());
    targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
    for (const auto& target : targets) {
        FlushRelayQueueForTarget(target);
        FlushRelayAckQueueForTarget(target);
    }
}

bool P2PNode::SaveRelaySpoolToDisk() const {
    try {
        fs::path dir = fs::path(relaySpoolRootDir_) / local_.nodeId;
        fs::create_directories(dir);
        for (const auto& entry : fs::directory_iterator(dir)) {
            if (entry.is_regular_file()) fs::remove(entry.path());
        }

        std::lock_guard<std::mutex> lock(relayMutex_);
        for (const auto& [target, q] : relayQueuesByTarget_) {
            for (const auto& msg : q) {
                std::ofstream out(RelayMsgPath(dir, target, msg.messageId), std::ios::binary | std::ios::trunc);
                if (!out) continue;
                out << "type=msg\n";
                out << "target=" << target << "\n";
                out << "relay_packet_id=" << msg.relayPacketId << "\n";
                out << "message_id=" << msg.messageId << "\n";
                out << "relay_from=" << msg.relayFromNodeId << "\n";
                out << "payload_hex=" << BytesToHexLocal(msg.privateMessagePacket) << "\n";
                out << "attempt_count=" << msg.attemptCount << "\n";
                out << "queued_at_unix=" << static_cast<long long>(std::chrono::system_clock::to_time_t(msg.queuedAt)) << "\n";
            }
        }
        for (const auto& [target, q] : relayAckQueuesByTarget_) {
            for (const auto& msg : q) {
                std::ofstream out(RelayAckPath(dir, target, msg.messageId), std::ios::binary | std::ios::trunc);
                if (!out) continue;
                out << "type=ack\n";
                out << "target=" << target << "\n";
                out << "relay_packet_id=" << msg.relayPacketId << "\n";
                out << "message_id=" << msg.messageId << "\n";
                out << "relay_from=" << msg.relayFromNodeId << "\n";
                out << "payload_hex=" << BytesToHexLocal(msg.ackPacket) << "\n";
                out << "attempt_count=" << msg.attemptCount << "\n";
                out << "queued_at_unix=" << static_cast<long long>(std::chrono::system_clock::to_time_t(msg.queuedAt)) << "\n";
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

void P2PNode::LoadRelaySpoolFromDisk() {
    try {
        fs::path dir = fs::path(relaySpoolRootDir_) / local_.nodeId;
        if (!fs::exists(dir)) return;

        std::lock_guard<std::mutex> lock(relayMutex_);
        relayQueuesByTarget_.clear();
        relayAckQueuesByTarget_.clear();
        for (const auto& entry : fs::directory_iterator(dir)) {
            if (!entry.is_regular_file()) continue;
            std::ifstream in(entry.path(), std::ios::binary);
            if (!in) continue;
            std::string line, type, target, relayFrom, payloadHex;
            PacketId relayPacketId = 0;
            MessageId messageId = 0;
            std::uint32_t attemptCount = 0;
            std::time_t queuedAtUnix = 0;
            while (std::getline(in, line)) {
                auto pos = line.find('=');
                if (pos == std::string::npos) continue;
                auto k = line.substr(0, pos);
                auto v = line.substr(pos + 1);
                if (k == "type") type = v;
                else if (k == "target") target = v;
                else if (k == "relay_packet_id") relayPacketId = static_cast<PacketId>(std::stoull(v));
                else if (k == "message_id") messageId = static_cast<MessageId>(std::stoull(v));
                else if (k == "relay_from") relayFrom = v;
                else if (k == "payload_hex") payloadHex = v;
                else if (k == "attempt_count") attemptCount = static_cast<std::uint32_t>(std::stoul(v));
                else if (k == "queued_at_unix") queuedAtUnix = static_cast<std::time_t>(std::stoll(v));
            }
            ByteVector payload;
            if (target.empty() || payloadHex.empty() || !HexToBytesLocal(payloadHex, payload)) continue;
            if (type == "msg") {
                QueuedRelayMessage item{};
                item.relayPacketId = relayPacketId;
                item.messageId = messageId;
                item.relayFromNodeId = relayFrom;
                item.finalTargetNodeId = target;
                item.privateMessagePacket = std::move(payload);
                item.queuedAt = queuedAtUnix != 0 ? std::chrono::system_clock::from_time_t(queuedAtUnix) : std::chrono::system_clock::now();
                item.attemptCount = attemptCount;
                item.nextAttemptAt = std::chrono::steady_clock::now();
                relayQueuesByTarget_[target].push_back(std::move(item));
            } else if (type == "ack") {
                QueuedRelayAck item{};
                item.relayPacketId = relayPacketId;
                item.messageId = messageId;
                item.relayFromNodeId = relayFrom;
                item.finalTargetNodeId = target;
                item.ackPacket = std::move(payload);
                item.queuedAt = queuedAtUnix != 0 ? std::chrono::system_clock::from_time_t(queuedAtUnix) : std::chrono::system_clock::now();
                item.attemptCount = attemptCount;
                item.nextAttemptAt = std::chrono::steady_clock::now();
                relayAckQueuesByTarget_[target].push_back(std::move(item));
            }
        }
    } catch (...) {
    }
}


bool P2PNode::SaveMessageJournalToDisk() const {
    try {
        fs::path path = fs::path(messageJournalRootDir_) / (local_.nodeId + ".journal");
        fs::create_directories(path.parent_path());
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        std::lock_guard<std::mutex> lock(journalMutex_);
        for (const auto& [messageId, entry] : pendingJournalMessages_) {
            out << "message_id=" << messageId
                << "\ttarget=" << entry.targetNodeId
                << "\tpayload_hex=" << BytesToHexLocal(entry.privateMessagePayload)
                << "\treplay_count=" << entry.replayCount
                << "\tcreated_at_unix=" << entry.createdAtUnix
                << "\tlast_attempt_unix=" << entry.lastAttemptUnix
                << "\tnext_attempt_unix=" << entry.nextAttemptUnix
                << "\n";
        }
        return true;
    } catch (...) {
        return false;
    }
}

void P2PNode::LoadMessageJournalFromDisk() {
    try {
        fs::path path = fs::path(messageJournalRootDir_) / (local_.nodeId + ".journal");
        std::ifstream in(path, std::ios::binary);
        if (!in) return;
        std::unordered_map<MessageId, PendingJournalMessage> loaded;
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            PendingJournalMessage entry{};
            std::stringstream ss(line);
            std::string field;
            while (std::getline(ss, field, '\t')) {
                auto pos = field.find('=');
                if (pos == std::string::npos) continue;
                auto key = field.substr(0, pos);
                auto value = field.substr(pos + 1);
                try {
                    if (key == "message_id") entry.messageId = static_cast<MessageId>(std::stoull(value));
                    else if (key == "target") entry.targetNodeId = value;
                    else if (key == "payload_hex") { if (!HexToBytesLocal(value, entry.privateMessagePayload)) entry.privateMessagePayload.clear(); }
                    else if (key == "replay_count") entry.replayCount = static_cast<std::uint32_t>(std::stoul(value));
                    else if (key == "created_at_unix") entry.createdAtUnix = static_cast<std::int64_t>(std::stoll(value));
                    else if (key == "last_attempt_unix") entry.lastAttemptUnix = static_cast<std::int64_t>(std::stoll(value));
                    else if (key == "next_attempt_unix") entry.nextAttemptUnix = static_cast<std::int64_t>(std::stoll(value));
                } catch (...) {}
            }
            if (entry.messageId == 0 || entry.targetNodeId.empty() || entry.privateMessagePayload.empty()) continue;
            loaded[entry.messageId] = std::move(entry);
        }
        {
            std::lock_guard<std::mutex> lock(journalMutex_);
            pendingJournalMessages_ = std::move(loaded);
        }
        if (!pendingJournalMessages_.empty()) {
            utils::LogWarn("Recovered " + std::to_string(pendingJournalMessages_.size()) + " journaled outgoing message(s) for replay");
        }
    } catch (...) {}
}

void P2PNode::TrackPendingJournalMessage(const PrivateMessagePayload& payload) {
    PendingJournalMessage entry{};
    entry.messageId = payload.messageId;
    entry.targetNodeId = payload.toNodeId;
    entry.privateMessagePayload = protocol::SerializePrivateMessage(payload);
    entry.createdAtUnix = NowUnix();
    {
        std::lock_guard<std::mutex> lock(journalMutex_);
        pendingJournalMessages_[entry.messageId] = std::move(entry);
    }
    SaveMessageJournalToDisk();
}

void P2PNode::RemovePendingJournalMessage(MessageId messageId) {
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(journalMutex_);
        removed = pendingJournalMessages_.erase(messageId) > 0;
    }
    if (removed) SaveMessageJournalToDisk();
}

void P2PNode::ReplayJournalEntries() {
    std::vector<PendingJournalMessage> candidates;
    const auto nowUnix = NowUnix();
    {
        std::lock_guard<std::mutex> lock(journalMutex_);
        for (const auto& kv : pendingJournalMessages_) {
            if (kv.second.nextAttemptUnix == 0 || kv.second.nextAttemptUnix <= nowUnix) {
                candidates.push_back(kv.second);
            }
        }
    }
    if (candidates.empty()) return;

    bool mutated = false;
    for (const auto& entry : candidates) {
        if (entry.messageId == 0 || entry.targetNodeId.empty() || entry.privateMessagePayload.empty()) continue;
        {
            std::lock_guard<std::mutex> ackLock(ackMutex_);
            if (deliveredOutgoingMessageIds_.count(entry.messageId) != 0) {
                RemovePendingJournalMessage(entry.messageId);
                continue;
            }
        }

        PrivateMessagePayload payload{};
        if (!protocol::DeserializePrivateMessage(entry.privateMessagePayload, payload)) {
            RemovePendingJournalMessage(entry.messageId);
            continue;
        }

        bool dispatched = false;
        if (auto directPeer = peerManager_.FindByNodeId(entry.targetNodeId)) {
            router_.MarkSeen(payload.messageId);
            directPeer->EnqueuePacket(protocol::MakePacket(PacketType::PrivateMessage, payload.messageId, entry.privateMessagePayload));
            dispatched = true;
        } else {
            dispatched = RelayPrivateMessageToNetwork(payload);
        }

        if (dispatched) {
            std::lock_guard<std::mutex> lock(journalMutex_);
            auto it = pendingJournalMessages_.find(entry.messageId);
            if (it != pendingJournalMessages_.end()) {
                it->second.replayCount += 1;
                it->second.lastAttemptUnix = nowUnix;
                it->second.nextAttemptUnix = nowUnix + 10;
                mutated = true;
            }
        }
    }
    if (mutated) SaveMessageJournalToDisk();
}

void P2PNode::HandleHistorySyncRequest(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;
    HistorySyncRequestPayload req{};
    if (!protocol::DeserializeHistorySyncRequest(payload, req)) return;
    if (req.targetNodeId != local_.nodeId) return;

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(req.requesterNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }
    if (!signer_.Verify(BuildHistorySyncRequestSignedData(req), req.signature, pub)) return;

    std::vector<StoredSignedPrivateMessage> signedMessages;
    std::string error;
    if (!ConversationStore::LoadSignedOutgoingMessagesAfter(historyRootDir_, local_.nodeId, req.requesterNodeId, req.afterMessageId, signer_, signedMessages, &error)) {
        return;
    }

    ByteVector blob;
    utils::WriteUint32(blob, static_cast<std::uint32_t>(signedMessages.size()));
    for (const auto& msg : signedMessages) {
        auto serialized = protocol::SerializePrivateMessage(msg.payload);
        utils::WriteBytes(blob, serialized);
    }

    HistorySyncResponsePayload resp{};
    resp.responderNodeId = local_.nodeId;
    resp.targetNodeId = req.requesterNodeId;
    resp.messagesBlob = std::move(blob);
    signer_.Sign(BuildHistorySyncResponseSignedData(resp), resp.signature);

    auto body = protocol::SerializeHistorySyncResponse(resp);
    if (peer) peer->EnqueuePacket(protocol::MakePacket(PacketType::HistorySyncResponse, utils::GeneratePacketId(), body));
}

void P2PNode::HandleHistorySyncResponse(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;
    HistorySyncResponsePayload resp{};
    if (!protocol::DeserializeHistorySyncResponse(payload, resp)) return;
    if (resp.targetNodeId != local_.nodeId) return;

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(resp.responderNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }
    if (!signer_.Verify(BuildHistorySyncResponseSignedData(resp), resp.signature, pub)) return;

    std::size_t offset = 0;
    std::uint32_t count = 0;
    if (!utils::ReadUint32(resp.messagesBlob, offset, count)) return;
    std::size_t imported = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        ByteVector itemBytes;
        if (!utils::ReadBytes(resp.messagesBlob, offset, itemBytes)) return;
        PrivateMessagePayload msg{};
        if (!protocol::DeserializePrivateMessage(itemBytes, msg)) continue;
        bool exists = false;
        std::string error;
        if (!ConversationStore::HasMessageId(historyRootDir_, local_.nodeId, resp.responderNodeId, msg.messageId, signer_, &exists, &error)) continue;
        if (exists) continue;
        if (!signer_.Verify(BuildPrivateMessageSignedData(msg), msg.signature, pub)) continue;
        ByteVector sessionKey;
        if (!GetSessionKeyForPeer(resp.responderNodeId, sessionKey)) continue;
        if (!DecryptPrivateMessagePayload(msg, sessionKey)) continue;
        if (msg.sequenceNumber > 0) {
            auto before = HasStoredMessageForPeer(resp.responderNodeId, msg.messageId);
            BufferOrDeliverIncomingPrivateMessage(msg, pub, 0, false);
            auto after = HasStoredMessageForPeer(resp.responderNodeId, msg.messageId);
            if (!before && after) ++imported;
        } else {
            EnsureSessionForPeer(resp.responderNodeId, peer ? peer->GetRemoteNickname() : std::string(), msg.sessionId);
            AppendStoredPrivateMessage(msg, StoredMessageDirection::Incoming, StoredMessageState::Delivered, pub);
            ++imported;
        }
    }
    if (imported > 0) {
        utils::LogSystem("History sync imported " + std::to_string(imported) + " message(s) from " + resp.responderNodeId);
    }
}

void P2PNode::HandleConnectRequest(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;

    ConnectRequestPayload p{};
    if (!protocol::DeserializeConnectRequest(payload, p)) { if (peer && !peer->GetRemoteNodeId().empty()) { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteInvalidPacket(peer->GetRemoteNodeId()); std::string repError; peerReputation_.Save(local_.nodeId, &repError); } return; }

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(p.requesterNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }

    if (!signer_.Verify(BuildConnectRequestSignedData(p), p.signature, pub)) {
        utils::LogError("Connect request signature invalid");
        { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteSignatureFailure(p.requesterNodeId); std::string repError; peerReputation_.Save(local_.nodeId, &repError); }
        return;
    }

    if (p.targetNodeId == local_.nodeId) {
        if (peerManager_.HasNode(p.requesterNodeId)) return;

        KnownNode requester{};
        requester.nodeId = p.requesterNodeId;
        requester.nickname = p.requesterNickname;
        requester.ip = p.requesterObservedIp;
        requester.port = p.requesterAdvertisedPort;
        requester.observedPort = p.requesterObservedPort;
        requester.lastSeen = std::chrono::steady_clock::now();
        knownNodes_.Upsert(requester);
        UpsertContactHintsFromKnownNode(requester);

        utils::LogSystem("Received reverse-connect request from " + p.requesterNickname);
        if (TryConnectToKnownNode(requester)) {
            utils::LogSystem("Reverse connect attempt launched to " + p.requesterNickname);
        } else {
            utils::LogError("Reverse connect attempt failed for " + p.requesterNickname);
        }
        return;
    }

    auto packet = protocol::MakePacket(PacketType::ConnectRequest, packetId, payload);
    BroadcastRaw(packet, peer ? peer->GetRemoteNodeId() : "");
}


void P2PNode::HandleUdpPunchRequest(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload) {
    if (!router_.MarkSeen(packetId)) return;

    UdpPunchRequestPayload p{};
    if (!protocol::DeserializeUdpPunchRequest(payload, p)) { if (peer && !peer->GetRemoteNodeId().empty()) { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteInvalidPacket(peer->GetRemoteNodeId()); std::string repError; peerReputation_.Save(local_.nodeId, &repError); } return; }

    ByteVector pub;
    {
        std::lock_guard<std::mutex> lock(publicKeysMutex_);
        auto it = publicKeys_.find(p.requesterNodeId);
        if (it == publicKeys_.end()) return;
        pub = it->second;
    }

    if (!signer_.Verify(BuildUdpPunchRequestSignedData(p), p.signature, pub)) {
        utils::LogError("UDP punch request signature invalid");
        { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteSignatureFailure(p.requesterNodeId); std::string repError; peerReputation_.Save(local_.nodeId, &repError); }
        return;
    }

    if (p.targetNodeId == local_.nodeId) {
        if (peerManager_.HasNode(p.requesterNodeId)) return;

        KnownNode requester{};
        if (auto existing = knownNodes_.FindByNodeId(p.requesterNodeId)) requester = *existing;
        requester.nodeId = p.requesterNodeId;
        requester.nickname = p.requesterNickname;
        if (!p.requesterObservedUdpIp.empty()) requester.ip = p.requesterObservedUdpIp;
        requester.port = p.requesterAdvertisedTcpPort;
        requester.observedUdpPort = p.requesterObservedUdpPort;
        requester.lastSeen = std::chrono::steady_clock::now();
        knownNodes_.Upsert(requester);
        UpsertContactHintsFromKnownNode(requester);

        utils::LogSystem("Received UDP hole-punch request from " + p.requesterNickname);
        SendUdpPunchBurst(requester, "target");
        TryConnectToKnownNode(requester);
        RequestReverseConnect(requester);
        return;
    }

    auto packet = protocol::MakePacket(PacketType::UdpPunchRequest, packetId, payload);
    BroadcastRaw(packet, peer ? peer->GetRemoteNodeId() : "");
}

std::uint64_t P2PNode::GetNextOutgoingSequence(const NodeId& peerNodeId) {
    std::lock_guard<std::mutex> lock(sequenceMutex_);
    auto it = nextOutgoingSequenceByPeer_.find(peerNodeId);
    if (it != nextOutgoingSequenceByPeer_.end()) {
        return it->second++;
    }

    std::vector<StoredConversationMessage> messages;
    std::string error;
    std::uint64_t maxSeq = 0;
    if (ConversationStore::LoadConversation(historyRootDir_, local_.nodeId, peerNodeId, signer_, messages, &error)) {
        for (const auto& msg : messages) {
            if (msg.direction == StoredMessageDirection::Outgoing) maxSeq = std::max(maxSeq, msg.sequenceNumber);
        }
    }
    auto& next = nextOutgoingSequenceByPeer_[peerNodeId];
    next = maxSeq + 1;
    return next++;
}

std::uint64_t P2PNode::GetExpectedIncomingSequence(const NodeId& peerNodeId) {
    std::lock_guard<std::mutex> lock(sequenceMutex_);
    auto it = expectedIncomingSequenceByPeer_.find(peerNodeId);
    if (it != expectedIncomingSequenceByPeer_.end()) return it->second;

    std::vector<StoredConversationMessage> messages;
    std::string error;
    std::uint64_t maxSeq = 0;
    if (ConversationStore::LoadConversation(historyRootDir_, local_.nodeId, peerNodeId, signer_, messages, &error)) {
        for (const auto& msg : messages) {
            if (msg.direction == StoredMessageDirection::Incoming) maxSeq = std::max(maxSeq, msg.sequenceNumber);
        }
    }
    auto& expected = expectedIncomingSequenceByPeer_[peerNodeId];
    expected = maxSeq + 1;
    if (expected == 0) expected = 1;
    return expected;
}

void P2PNode::DeliverOrderedIncomingPrivateMessage(const PrivateMessagePayload& payload, const ByteVector& signerPublicKeyBlob, PacketId ackedRelayPacketId, bool logMessage) {
    if (HasStoredMessageForPeer(payload.fromNodeId, payload.messageId)) {
        SendDeliveryAck(payload, ackedRelayPacketId);
        return;
    }
    EnsureSessionForPeer(payload.fromNodeId, payload.fromNickname, payload.sessionId);
    AppendStoredPrivateMessage(payload, StoredMessageDirection::Incoming, StoredMessageState::Delivered, signerPublicKeyBlob);
    ProcessOverlayPrivateMessage(payload);
    SendDeliveryAck(payload, ackedRelayPacketId);
    if (logMessage && payload.text.rfind("[[", 0) != 0) utils::LogPrivate(payload.fromNickname, payload.text);
}

void P2PNode::BufferOrDeliverIncomingPrivateMessage(const PrivateMessagePayload& payload, const ByteVector& signerPublicKeyBlob, PacketId ackedRelayPacketId, bool logMessage) {
    if (payload.sequenceNumber == 0) {
        DeliverOrderedIncomingPrivateMessage(payload, signerPublicKeyBlob, ackedRelayPacketId, logMessage);
        return;
    }

    std::vector<BufferedIncomingPrivateMessage> ready;
    {
        std::lock_guard<std::mutex> lock(sequenceMutex_);
        auto expectedIt = expectedIncomingSequenceByPeer_.find(payload.fromNodeId);
        if (expectedIt == expectedIncomingSequenceByPeer_.end()) {
            std::uint64_t maxSeq = 0;
            std::vector<StoredConversationMessage> messages;
            std::string error;
            if (ConversationStore::LoadConversation(historyRootDir_, local_.nodeId, payload.fromNodeId, signer_, messages, &error)) {
                for (const auto& msg : messages) {
                    if (msg.direction == StoredMessageDirection::Incoming) maxSeq = std::max(maxSeq, msg.sequenceNumber);
                }
            }
            expectedIt = expectedIncomingSequenceByPeer_.emplace(payload.fromNodeId, maxSeq + 1).first;
            if (expectedIt->second == 0) expectedIt->second = 1;
        }

        auto& expected = expectedIt->second;
        if (payload.sequenceNumber < expected) {
            // already delivered or stale retry
        } else if (payload.sequenceNumber > expected) {
            auto& buffer = reorderBufferByPeer_[payload.fromNodeId];
            buffer.try_emplace(payload.sequenceNumber, BufferedIncomingPrivateMessage{payload, signerPublicKeyBlob, ackedRelayPacketId, logMessage});
            return;
        } else {
            ready.push_back(BufferedIncomingPrivateMessage{payload, signerPublicKeyBlob, ackedRelayPacketId, logMessage});
            ++expected;
            auto bufIt = reorderBufferByPeer_.find(payload.fromNodeId);
            while (bufIt != reorderBufferByPeer_.end()) {
                auto nextIt = bufIt->second.find(expected);
                if (nextIt == bufIt->second.end()) break;
                ready.push_back(nextIt->second);
                bufIt->second.erase(nextIt);
                ++expected;
            }
            if (bufIt != reorderBufferByPeer_.end() && bufIt->second.empty()) reorderBufferByPeer_.erase(bufIt);
        }
    }

    if (ready.empty()) {
        SendDeliveryAck(payload, ackedRelayPacketId);
        return;
    }
    for (const auto& item : ready) {
        DeliverOrderedIncomingPrivateMessage(item.payload, item.signerPublicKeyBlob, item.ackedRelayPacketId, item.logMessage);
    }
}

void P2PNode::AppendStoredPrivateMessage(const PrivateMessagePayload& payload, StoredMessageDirection direction, StoredMessageState state, const ByteVector& signerPublicKeyBlob) {
    const NodeId peerNodeId = (direction == StoredMessageDirection::Outgoing) ? payload.toNodeId : payload.fromNodeId;
    std::string error;
    if (!ConversationStore::AppendPrivateMessage(historyRootDir_,
                                                 local_.nodeId,
                                                 peerNodeId,
                                                 payload,
                                                 direction,
                                                 state,
                                                 signerPublicKeyBlob,
                                                 signer_,
                                                 localPublicKeyBlob_,
                                                 &error)) {
        utils::LogError("Failed to store private message: " + error);
    }
}

bool P2PNode::HasStoredMessageForPeer(const NodeId& peerNodeId, MessageId messageId) const {
    bool exists = false;
    std::string error;
    if (!ConversationStore::HasMessageId(historyRootDir_, local_.nodeId, peerNodeId, messageId, const_cast<CryptoSigner&>(signer_), &exists, &error)) {
        if (!error.empty()) utils::LogError("Failed to check stored message id: " + error);
        return false;
    }
    return exists;
}

bool P2PNode::UpdateStoredMessageState(const NodeId& peerNodeId, MessageId messageId, StoredMessageState newState) {
    std::string error;
    if (!ConversationStore::UpdateMessageState(historyRootDir_, local_.nodeId, peerNodeId, messageId, newState, signer_, localPublicKeyBlob_, &error)) {
        if (!error.empty()) utils::LogError("Failed to update message state: " + error);
        return false;
    }
    return true;
}

void P2PNode::EnsureSessionForPeer(const NodeId& peerNodeId, const std::string& peerNickname, SessionId sessionId) {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    auto existing = sessionByPeer_.find(peerNodeId);
    if (existing != sessionByPeer_.end()) {
        auto sit = sessionsById_.find(existing->second);
        if (sit != sessionsById_.end()) {
            sit->second.active = true;
            if (!peerNickname.empty()) sit->second.peerNickname = peerNickname;
            return;
        }
    }
    sessionsById_[sessionId] = {sessionId, peerNodeId, peerNickname, {}, true};
    sessionByPeer_[peerNodeId] = sessionId;
}

bool P2PNode::SetSessionKeyForPeer(const NodeId& peerNodeId, SessionId sessionId, const ByteVector& sessionKey) {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    auto it = sessionByPeer_.find(peerNodeId);
    if (it != sessionByPeer_.end()) {
        auto sit = sessionsById_.find(it->second);
        if (sit != sessionsById_.end()) {
            sit->second.sessionKey = sessionKey;
            sit->second.sessionId = sessionId;
            return true;
        }
    }
    sessionsById_[sessionId] = {sessionId, peerNodeId, std::string(), sessionKey, true};
    sessionByPeer_[peerNodeId] = sessionId;
    return true;
}

bool P2PNode::GetSessionKeyForPeer(const NodeId& peerNodeId, ByteVector& sessionKeyOut) const {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    auto it = sessionByPeer_.find(peerNodeId);
    if (it == sessionByPeer_.end()) return false;
    auto sit = sessionsById_.find(it->second);
    if (sit == sessionsById_.end() || sit->second.sessionKey.empty()) return false;
    sessionKeyOut = sit->second.sessionKey;
    return true;
}

void P2PNode::PrintStoredConversation(const NodeId& peerNodeId, const std::string& peerNicknameHint) const {
    std::vector<StoredConversationMessage> messages;
    std::string error;
    if (!ConversationStore::LoadConversation(historyRootDir_, local_.nodeId, peerNodeId, const_cast<CryptoSigner&>(signer_), messages, &error)) {
        utils::LogError("Failed to load history: " + error);
        return;
    }
    const std::string caption = ResolveDisplayName(peerNodeId, peerNicknameHint.empty() ? peerNodeId : peerNicknameHint);
    utils::LogRaw("=== Private history with " + caption + " ===");
    if (messages.empty()) {
        utils::LogRaw("  (empty)");
        return;
    }
    for (const auto& msg : messages) {
        const std::string author = (msg.direction == StoredMessageDirection::Outgoing) ? local_.nickname : msg.fromNickname;
        std::string suffix;
        if (msg.direction == StoredMessageDirection::Outgoing) {
            switch (msg.state) {
                case StoredMessageState::Queued: suffix = " [queued]"; break;
                case StoredMessageState::Sent: suffix = " [sent]"; break;
                case StoredMessageState::Relayed: suffix = " [relayed]"; break;
                case StoredMessageState::Delivered: suffix = " [delivered]"; break;
                case StoredMessageState::Failed: suffix = " [failed]"; break;
                default: break;
            }
        }
        utils::LogRaw("[History | " + author + suffix + "] " + msg.text);
    }
}

void P2PNode::LoadBootstrapNodes() {
    std::ifstream in(bootstrapConfigPath_);
    if (!in) return;

    std::vector<BootstrapEndpoint> parsed;
    std::string line;
    while (std::getline(in, line)) {
        line = TrimCopy(line);
        if (line.empty() || line[0] == '#') continue;
        const auto pos = line.rfind(':');
        if (pos == std::string::npos) continue;
        const auto ip = TrimCopy(line.substr(0, pos));
        const auto portText = TrimCopy(line.substr(pos + 1));
        if (ip.empty() || portText.empty()) continue;
        try {
            const int portValue = std::stoi(portText);
            if (portValue <= 0 || portValue > 65535) continue;
            parsed.push_back({ip, static_cast<std::uint16_t>(portValue), {}});
        } catch (...) {
            continue;
        }
    }

    std::size_t count = parsed.size();
    {
        std::lock_guard<std::mutex> lock(bootstrapMutex_);
        bootstrapNodes_ = std::move(parsed);
    }

    if (count > 0) {
        utils::LogSystem("Loaded " + std::to_string(count) + " bootstrap node(s) from " + bootstrapConfigPath_);
    }
}

void P2PNode::TryConnectBootstrapNodes() {
    std::vector<BootstrapEndpoint> snapshot;
    {
        std::lock_guard<std::mutex> lock(bootstrapMutex_);
        snapshot = bootstrapNodes_;
    }
    if (snapshot.empty()) return;

    auto peers = peerManager_.Snapshot();
    const auto now = std::chrono::steady_clock::now();
    bool changed = false;

    for (std::size_t i = 0; i < snapshot.size(); ++i) {
        bool alreadyConnected = false;
        for (const auto& peer : peers) {
            if (peer.remoteIp == snapshot[i].ip && (peer.remotePort == snapshot[i].port || peer.remotePort == 0)) {
                alreadyConnected = true;
                break;
            }
        }
        if (alreadyConnected) continue;
        if (snapshot[i].lastAttempt != std::chrono::steady_clock::time_point{} &&
            std::chrono::duration_cast<std::chrono::seconds>(now - snapshot[i].lastAttempt).count() < 5) {
            continue;
        }
        snapshot[i].lastAttempt = now;
        changed = true;
        if (ConnectToPeer(snapshot[i].ip, snapshot[i].port)) {
            utils::LogSystem("Bootstrap connect attempt: " + snapshot[i].ip + ":" + std::to_string(snapshot[i].port));
        }
    }

    if (changed) {
        std::lock_guard<std::mutex> lock(bootstrapMutex_);
        bootstrapNodes_ = std::move(snapshot);
    }
}

bool P2PNode::OpenPrivateChat(const NodeId& peerNodeId, const std::string& peerNickname) {
    if (peerNodeId.empty() || peerNodeId == local_.nodeId) {
        utils::LogError("Invalid private chat target");
        return false;
    }

    if (!FindSessionByPeer(peerNodeId).has_value()) {
        std::string error;
        auto restoredSessionId = ConversationStore::GetLatestSessionId(historyRootDir_, local_.nodeId, peerNodeId, signer_, &error);
        if (!restoredSessionId.has_value() && !error.empty()) {
            utils::LogError("Failed to restore history session: " + error);
            return false;
        }
        if (restoredSessionId.has_value()) {
            EnsureSessionForPeer(peerNodeId, peerNickname, *restoredSessionId);
            utils::LogSystem("Restored previous private session with " + (peerNickname.empty() ? peerNodeId : peerNickname));
        }
    }

    PrintStoredConversation(peerNodeId, peerNickname);
    return true;
}

bool P2PNode::IsPeerConnected(const NodeId& peerNodeId) const {
    if (peerNodeId.empty()) return false;
    return peerManager_.HasNode(peerNodeId);
}

bool P2PNode::DeleteConversationHistory(const NodeId& peerNodeId) {
    if (peerNodeId.empty() || peerNodeId == local_.nodeId) {
        utils::LogError("Invalid chat target for delete");
        return false;
    }

    std::string error;
    if (!ConversationStore::DeleteConversation(historyRootDir_, local_.nodeId, peerNodeId, &error)) {
        utils::LogError("Failed to delete history: " + error);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        auto it = sessionByPeer_.find(peerNodeId);
        if (it != sessionByPeer_.end()) {
            sessionsById_.erase(it->second);
            sessionByPeer_.erase(it);
        }
    }

    utils::LogSystem("Local chat history deleted for peer " + peerNodeId);
    return true;
}

bool P2PNode::CheckConversationHistory(const NodeId& peerNodeId) {
    if (peerNodeId.empty() || peerNodeId == local_.nodeId) {
        utils::LogError("Invalid chat target for check");
        return false;
    }
    std::string error;
    if (!ConversationStore::CheckConversation(historyRootDir_, local_.nodeId, peerNodeId, signer_, &error)) {
        utils::LogError("History check failed: " + error);
        return false;
    }
    utils::LogSystem("History OK for peer " + peerNodeId);
    return true;
}

bool P2PNode::RepairConversationHistory(const NodeId& peerNodeId) {
    if (peerNodeId.empty() || peerNodeId == local_.nodeId) {
        utils::LogError("Invalid chat target for repair");
        return false;
    }
    std::string error;
    if (!ConversationStore::RepairConversation(historyRootDir_, local_.nodeId, peerNodeId, signer_, localPublicKeyBlob_, &error)) {
        utils::LogError("History repair failed: " + error);
        return false;
    }
    utils::LogSystem("History repaired for peer " + peerNodeId);
    return true;
}

void P2PNode::PrintKnownNodes() const {
    auto users = GetDisplayUsers();
    utils::LogRaw("=== Users ===");
    if (users.empty()) utils::LogRaw("  (none)");
    for (const auto& u : users) {
        std::string status = u.online ? "online" : ("last seen " + std::to_string(u.lastSeenSecondsAgo) + "s ago");
        int repScore = 0; bool repBlocked = false;
        { std::lock_guard<std::mutex> repLock(reputationMutex_); if (auto rec = peerReputation_.Find(u.nodeId)) { repScore = rec->score; repBlocked = rec->blocked; } }
        utils::LogRaw("[" + std::to_string(u.index) + "] " + u.nickname + " " + status + " rep=" + std::to_string(repScore) + (repBlocked ? " blocked" : "") + " id=" + u.nodeId);
    }
}

void P2PNode::PrintPeerReputation() const {
    utils::LogRaw("=== Peer Reputation ===");
    std::vector<PeerReputationRecord> records;
    {
        std::lock_guard<std::mutex> repLock(reputationMutex_);
        records = peerReputation_.GetAllSorted();
    }
    if (records.empty()) {
        utils::LogRaw("  (empty)");
        return;
    }
    for (const auto& rec : records) {
        utils::LogRaw("  " + rec.nodeId + " score=" + std::to_string(rec.score) +
                      " good=" + std::to_string(rec.goodEvents) +
                      " ratelimit=" + std::to_string(rec.rateLimitViolations) +
                      " invalid=" + std::to_string(rec.invalidPackets) +
                      " sigfail=" + std::to_string(rec.signatureFailures) +
                      (rec.blocked ? " blocked" : ""));
    }
}

void P2PNode::PrintInvites() const {
    utils::LogRaw("=== Invites ===");
    auto invites = GetDisplayInvites();
    if (invites.empty()) {
        utils::LogRaw("  (none)");
        return;
    }
    for (const auto& inv : invites) {
        utils::LogRaw("[" + std::to_string(inv.index) + "] from " + inv.fromNickname + " id=" + inv.fromNodeId);
    }
}

void P2PNode::PrintSessions() const {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    utils::LogRaw("=== Sessions ===");
    if (sessionsById_.empty()) utils::LogRaw("  (none)");
    for (const auto& [id, s] : sessionsById_) utils::LogRaw("  [" + std::to_string(id) + "] " + ResolveDisplayName(s.peerNodeId, s.peerNickname) + " id=" + s.peerNodeId + (s.active ? " active" : " offline"));
}

void P2PNode::PrintInfo() const {
    utils::LogRaw("========================================");
    utils::LogRaw("You: " + local_.nickname);
    utils::LogRaw("ID:  " + local_.nodeId);
    utils::LogRaw("Port: " + std::to_string(local_.listenPort));
    {
        std::lock_guard<std::mutex> lock(observedEndpointMutex_);
        if (!localObservedIp_.empty() && localObservedPort_ != 0) {
            utils::LogRaw("Observed TCP endpoint: " + localObservedIp_ + ":" + std::to_string(localObservedPort_));
        }
        if (!localObservedUdpIp_.empty() && localObservedUdpPort_ != 0) {
            utils::LogRaw("Observed UDP endpoint: " + localObservedUdpIp_ + ":" + std::to_string(localObservedUdpPort_));
        }
    }
    {
        std::lock_guard<std::mutex> lock(bootstrapMutex_);
        utils::LogRaw("Bootstrap nodes: " + std::to_string(bootstrapNodes_.size()));
    }
    {
        std::lock_guard<std::mutex> lock(contactsMutex_);
        utils::LogRaw("Contacts: " + std::to_string(contacts_.size()));
    }
    {
        std::lock_guard<std::mutex> lock(overlayMutex_);
        utils::LogRaw("Linked devices: " + std::to_string(overlayState_.devices.size()));
        utils::LogRaw("Groups: " + std::to_string(overlayState_.groups.size()));
    }
    {
        std::lock_guard<std::mutex> lock(relayMutex_);
        std::size_t totalQueued = 0;
        for (const auto& [_, q] : relayQueuesByTarget_) totalQueued += q.size();
        std::size_t totalQueuedAcks = 0;
        for (const auto& [_, q] : relayAckQueuesByTarget_) totalQueuedAcks += q.size();
        utils::LogRaw("Queued relay messages: " + std::to_string(totalQueued));
        utils::LogRaw("Queued relay ACKs: " + std::to_string(totalQueuedAcks));
    }
    utils::LogRaw("========================================");
}

bool P2PNode::SaveOverlayState() const {
    std::lock_guard<std::mutex> lock(overlayMutex_);
    std::string error;
    if (!p2p::SaveOverlayState(overlayRootDir_, local_.nodeId, overlayState_, &error)) {
        if (!error.empty()) utils::LogError("Failed to save overlay state: " + error);
        return false;
    }
    return true;
}

void P2PNode::LoadOverlayState() {
    OverlayState loaded;
    std::string error;
    if (!p2p::LoadOverlayState(overlayRootDir_, local_.nodeId, loaded, &error)) {
        if (!error.empty()) utils::LogError("Failed to load overlay state: " + error);
        return;
    }
    std::lock_guard<std::mutex> lock(overlayMutex_);
    overlayState_ = std::move(loaded);
}

std::vector<ContactEntry> P2PNode::GetSortedContacts() const {
    std::lock_guard<std::mutex> lock(contactsMutex_);
    return SortedContactsForDisplay(contacts_);
}

std::vector<DeviceEntry> P2PNode::GetSortedDevices() const {
    std::vector<DeviceEntry> out;
    std::lock_guard<std::mutex> lock(overlayMutex_);
    for (const auto& [_, d] : overlayState_.devices) out.push_back(d);
    std::sort(out.begin(), out.end(), [](const DeviceEntry& a, const DeviceEntry& b) {
        return a.nickname == b.nickname ? a.nodeId < b.nodeId : a.nickname < b.nickname;
    });
    return out;
}

std::vector<GroupEntry> P2PNode::GetSortedGroups() const {
    std::vector<GroupEntry> out;
    std::lock_guard<std::mutex> lock(overlayMutex_);
    for (const auto& [_, g] : overlayState_.groups) out.push_back(g);
    std::sort(out.begin(), out.end(), [](const GroupEntry& a, const GroupEntry& b) {
        return a.name == b.name ? a.groupId < b.groupId : a.name < b.name;
    });
    return out;
}

void P2PNode::PrintDevices() const {
    utils::LogRaw("=== Devices ===");
    auto devices = GetSortedDevices();
    if (devices.empty()) { utils::LogRaw("  (none)"); return; }
    int i = 1;
    for (const auto& d : devices) {
        std::string flags;
        if (d.approved) flags += " approved";
        if (d.revoked) flags += " revoked";
        utils::LogRaw("[" + std::to_string(i++) + "] " + (d.nickname.empty() ? d.nodeId : d.nickname) +
                      " id=" + d.nodeId + " label=" + d.label + flags);
    }
}

void P2PNode::PrintGroups() const {
    utils::LogRaw("=== Groups ===");
    auto groups = GetSortedGroups();
    if (groups.empty()) { utils::LogRaw("  (none)"); return; }
    int i = 1;
    for (const auto& g : groups) {
        utils::LogRaw("[" + std::to_string(i++) + "] " + g.name + " id=" + g.groupId +
                      " owner=" + g.ownerNodeId + " version=" + std::to_string(g.version) +
                      " members=" + std::to_string(g.members.size()));
        for (const auto& m : g.members) {
            utils::LogRaw("    - " + (m.nickname.empty() ? m.nodeId : m.nickname) + " (" + ToString(m.role) + ")");
        }
    }
}

bool P2PNode::LinkDeviceByContactIndex(int index, const std::string& label) {
    auto contacts = GetSortedContacts();
    if (index <= 0 || static_cast<std::size_t>(index) > contacts.size()) return false;
    const auto& c = contacts[static_cast<std::size_t>(index - 1)];
    if (!c.trusted || c.blocked) {
        utils::LogError("Device link requires trusted non-blocked contact");
        return false;
    }
    auto sessionIdOpt = FindSessionByPeer(c.nodeId);
    ByteVector sessionKey;
    if (!sessionIdOpt || !GetSessionKeyForPeer(c.nodeId, sessionKey)) {
        utils::LogError("No active E2E private session with this user");
        return false;
    }
    DeviceEntry d{};
    d.nodeId = c.nodeId; d.nickname = c.nickname; d.label = label.empty() ? c.nickname : label; d.fingerprint = c.fingerprint;
    d.approved = true; d.revoked = false; d.linkedAtUnix = NowUnix();
    SendPrivateMessage(d.nodeId, "[[DEVICE-LINK]]|" + local_.nodeId + "|" + local_.nickname + "|" + d.label + "|" + d.fingerprint);
    {
        std::lock_guard<std::mutex> lock(overlayMutex_);
        overlayState_.devices[d.nodeId] = d;
    }
    SaveOverlayState();
    MirrorConversationToDevice(d.nodeId, 16);
    utils::LogSystem("Linked device: " + d.label);
    return true;
}

bool P2PNode::RevokeDeviceByIndex(int index) {
    auto devices = GetSortedDevices();
    if (index <= 0 || static_cast<std::size_t>(index) > devices.size()) return false;
    const auto nodeId = devices[static_cast<std::size_t>(index - 1)].nodeId;
    auto sessionIdOpt = FindSessionByPeer(nodeId);
    ByteVector sessionKey;
    if (!sessionIdOpt || !GetSessionKeyForPeer(nodeId, sessionKey)) {
        utils::LogError("No active E2E private session with this device");
        return false;
    }
    SendPrivateMessage(nodeId, "[[DEVICE-REVOKE]]|" + local_.nodeId);
    {
        std::lock_guard<std::mutex> lock(overlayMutex_);
        auto it = overlayState_.devices.find(nodeId);
        if (it == overlayState_.devices.end()) return false;
        it->second.revoked = true;
        it->second.approved = false;
        it->second.revokedAtUnix = NowUnix();
    }
    SaveOverlayState();
    utils::LogSystem("Revoked device: " + nodeId);
    return true;
}

bool P2PNode::CreateGroup(const std::string& name) {
    if (name.empty()) return false;
    GroupEntry g{};
    g.groupId = utils::GenerateNodeId();
    g.name = name;
    g.ownerNodeId = local_.nodeId;
    g.version = 1;
    g.members.push_back(GroupMemberEntry{local_.nodeId, local_.nickname, GroupRole::Owner});
    g.events.push_back(GroupEventEntry{1, "group_created", local_.nodeId, local_.nodeId, name, NowUnix()});
    {
        std::lock_guard<std::mutex> lock(overlayMutex_);
        overlayState_.groups[g.groupId] = g;
    }
    SaveOverlayState();
    utils::LogSystem("Group created: " + name);
    return true;
}

std::string P2PNode::BuildGroupSyncText(const GroupEntry& group) const {
    std::ostringstream oss;
    oss << "[[GROUPSYNC]]|" << group.groupId << '|' << group.name << '|' << group.ownerNodeId << '|' << group.version;
    for (const auto& m : group.members) {
        oss << '|' << m.nodeId << ',' << m.nickname << ',' << ToString(m.role);
    }
    return oss.str();
}

void P2PNode::SendGroupSnapshotToMember(const GroupEntry& group, const GroupMemberEntry& member) {
    if (member.nodeId == local_.nodeId) return;
    SendPrivateMessage(member.nodeId, BuildGroupSyncText(group));
}

bool P2PNode::SyncGroupByIndex(int groupIndex) {
    auto groups = GetSortedGroups();
    if (groupIndex <= 0 || static_cast<std::size_t>(groupIndex) > groups.size()) return false;
    auto group = groups[static_cast<std::size_t>(groupIndex - 1)];
    for (const auto& m : group.members) SendGroupSnapshotToMember(group, m);
    utils::LogSystem("Group snapshot synced: " + group.name);
    return true;
}

bool P2PNode::AddGroupMember(int groupIndex, int contactIndex) {
    auto groups = GetSortedGroups();
    auto contacts = GetSortedContacts();
    if (groupIndex <= 0 || static_cast<std::size_t>(groupIndex) > groups.size()) return false;
    if (contactIndex <= 0 || static_cast<std::size_t>(contactIndex) > contacts.size()) return false;
    const auto contact = contacts[static_cast<std::size_t>(contactIndex - 1)];
    if (!contact.trusted || contact.blocked) { utils::LogError("Group membership requires trusted contact"); return false; }
    GroupEntry updated;
    {
        std::lock_guard<std::mutex> lock(overlayMutex_);
        auto it = overlayState_.groups.find(groups[static_cast<std::size_t>(groupIndex - 1)].groupId);
        if (it == overlayState_.groups.end()) return false;
        if (it->second.ownerNodeId != local_.nodeId) { utils::LogError("Only local owner can change membership in this alpha build"); return false; }
        for (const auto& m : it->second.members) if (m.nodeId == contact.nodeId) return false;
        it->second.version += 1;
        it->second.members.push_back(GroupMemberEntry{contact.nodeId, contact.nickname, GroupRole::Member});
        it->second.events.push_back(GroupEventEntry{it->second.version, "member_added", local_.nodeId, contact.nodeId, contact.nickname, NowUnix()});
        updated = it->second;
    }
    SaveOverlayState();
    for (const auto& m : updated.members) SendGroupSnapshotToMember(updated, m);
    utils::LogSystem("Group member added: " + contact.nickname);
    return true;
}

bool P2PNode::RemoveGroupMember(int groupIndex, int contactIndex) {
    auto groups = GetSortedGroups();
    auto contacts = GetSortedContacts();
    if (groupIndex <= 0 || static_cast<std::size_t>(groupIndex) > groups.size()) return false;
    if (contactIndex <= 0 || static_cast<std::size_t>(contactIndex) > contacts.size()) return false;
    const auto contact = contacts[static_cast<std::size_t>(contactIndex - 1)];
    GroupEntry updated;
    {
        std::lock_guard<std::mutex> lock(overlayMutex_);
        auto it = overlayState_.groups.find(groups[static_cast<std::size_t>(groupIndex - 1)].groupId);
        if (it == overlayState_.groups.end()) return false;
        if (it->second.ownerNodeId != local_.nodeId) { utils::LogError("Only local owner can remove members in this alpha build"); return false; }
        auto& members = it->second.members;
        auto rem = std::remove_if(members.begin(), members.end(), [&](const GroupMemberEntry& m){ return m.nodeId == contact.nodeId; });
        if (rem == members.end()) return false;
        members.erase(rem, members.end());
        it->second.version += 1;
        it->second.events.push_back(GroupEventEntry{it->second.version, "member_removed", local_.nodeId, contact.nodeId, contact.nickname, NowUnix()});
        updated = it->second;
    }
    SaveOverlayState();
    for (const auto& m : updated.members) SendGroupSnapshotToMember(updated, m);
    SendPrivateMessage(contact.nodeId, BuildGroupSyncText(updated));
    utils::LogSystem("Group member removed: " + contact.nickname);
    return true;
}

bool P2PNode::ChangeGroupRole(int groupIndex, int contactIndex, const std::string& roleText) {
    auto roleOpt = ParseGroupRole(roleText);
    if (!roleOpt) return false;
    auto groups = GetSortedGroups();
    auto contacts = GetSortedContacts();
    if (groupIndex <= 0 || static_cast<std::size_t>(groupIndex) > groups.size()) return false;
    if (contactIndex <= 0 || static_cast<std::size_t>(contactIndex) > contacts.size()) return false;
    const auto contact = contacts[static_cast<std::size_t>(contactIndex - 1)];
    GroupEntry updated;
    {
        std::lock_guard<std::mutex> lock(overlayMutex_);
        auto it = overlayState_.groups.find(groups[static_cast<std::size_t>(groupIndex - 1)].groupId);
        if (it == overlayState_.groups.end()) return false;
        if (it->second.ownerNodeId != local_.nodeId) { utils::LogError("Only owner can change roles"); return false; }
        bool found = false;
        for (auto& m : it->second.members) {
            if (m.nodeId == contact.nodeId) { m.role = *roleOpt; found = true; break; }
        }
        if (!found) return false;
        it->second.version += 1;
        it->second.events.push_back(GroupEventEntry{it->second.version, "role_changed", local_.nodeId, contact.nodeId, roleText, NowUnix()});
        updated = it->second;
    }
    SaveOverlayState();
    for (const auto& m : updated.members) SendGroupSnapshotToMember(updated, m);
    return true;
}

bool P2PNode::SendGroupMessageByIndex(int groupIndex, const std::string& text) {
    auto groups = GetSortedGroups();
    if (groupIndex <= 0 || static_cast<std::size_t>(groupIndex) > groups.size()) return false;
    const auto& g = groups[static_cast<std::size_t>(groupIndex - 1)];
    for (const auto& m : g.members) {
        if (m.nodeId == local_.nodeId) continue;
        SendPrivateMessage(m.nodeId, "[[GROUPMSG]]|" + g.groupId + "|" + g.name + "|" + local_.nickname + "|" + text);
    }
    utils::LogSystem("Group message fan-out sent to " + std::to_string(g.members.size() > 0 ? g.members.size()-1 : 0) + " recipient(s)");
    return true;
}

bool P2PNode::SendFileOfferToPeer(const NodeId& targetNodeId, const std::string& displayName, const std::filesystem::path& srcPath, const std::string& groupId, const std::string& groupName) {
    auto contactOpt = FindContact(targetNodeId);
    if (!contactOpt || !contactOpt->trusted || contactOpt->blocked) {
        utils::LogError("File send requires trusted non-blocked contact");
        return false;
    }
    auto sessionIdOpt = FindSessionByPeer(targetNodeId);
    ByteVector sessionKey;
    if (!sessionIdOpt || !GetSessionKeyForPeer(targetNodeId, sessionKey)) {
        utils::LogError("No E2E session key for this private chat yet");
        return false;
    }
    std::error_code ec;
    if (!fs::exists(srcPath, ec) || !fs::is_regular_file(srcPath, ec)) {
        utils::LogError("Attachment source file not found");
        return false;
    }
    const auto size = static_cast<std::uint64_t>(fs::file_size(srcPath, ec));
    if (ec) {
        utils::LogError("Failed to read attachment size");
        return false;
    }
    if (size == 0) {
        utils::LogError("Empty files are not supported");
        return false;
    }
    if (size > kInlineFileTransferLimit) {
        utils::LogError("File is too large for current alpha transfer layer (limit 256 KB)");
        return false;
    }
    std::ifstream in(srcPath, std::ios::binary);
    if (!in) {
        utils::LogError("Failed to open attachment source file");
        return false;
    }
    ByteVector bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (bytes.size() != size) {
        utils::LogError("Failed to read full attachment payload");
        return false;
    }
    OutgoingFileTransfer transfer{};
    transfer.transferId = utils::GenerateNodeId();
    transfer.targetNodeId = targetNodeId;
    transfer.targetNickname = displayName;
    transfer.fileName = srcPath.filename().string();
    transfer.fileSize = size;
    transfer.groupId = groupId;
    transfer.groupName = groupName;
    transfer.bytes = std::move(bytes);
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        outgoingFileTransfers_[transfer.transferId] = transfer;
        FileTransferStatus st{};
        st.transferId = transfer.transferId;
        st.peerNodeId = targetNodeId;
        st.peerNickname = displayName;
        st.fileName = transfer.fileName;
        st.fileSize = transfer.fileSize;
        st.state = FileTransferState::Offered;
        st.incoming = false;
        st.groupName = groupName;
        st.updatedAtUnix = NowUnix();
        st.deadlineUnix = st.updatedAtUnix + transferTimeoutSeconds_;
        st.resumable = true;
        fileTransferStatuses_[st.transferId] = st;
    }
    SendPrivateMessage(targetNodeId,
        "[[FILEOFFER]]|" + transfer.transferId + "|" + transfer.fileName + "|" + std::to_string(transfer.fileSize) + "|" + transfer.groupId + "|" + transfer.groupName);
    if (groupId.empty()) {
        utils::LogSystem("File offer sent to " + displayName + ": " + transfer.fileName + " (use /downloads on receiver)");
    } else {
        utils::LogSystem("Group file offer sent to " + displayName + " for group " + groupName + ": " + transfer.fileName);
    }
    return true;
}

bool P2PNode::SendAttachmentByContactIndex(int contactIndex, const std::string& pathText) {
    auto contacts = GetSortedContacts();
    if (contactIndex <= 0 || static_cast<std::size_t>(contactIndex) > contacts.size()) return false;
    const auto& contact = contacts[static_cast<std::size_t>(contactIndex - 1)];
    return SendFileOfferToPeer(contact.nodeId, contact.nickname.empty() ? contact.nodeId : contact.nickname, fs::path(pathText));
}

bool P2PNode::SendGroupAttachmentByIndex(int groupIndex, const std::string& pathText) {
    auto groups = GetSortedGroups();
    if (groupIndex <= 0 || static_cast<std::size_t>(groupIndex) > groups.size()) return false;
    const auto& g = groups[static_cast<std::size_t>(groupIndex - 1)];
    bool any = false;
    for (const auto& m : g.members) {
        if (m.nodeId == local_.nodeId) continue;
        if (SendFileOfferToPeer(m.nodeId, m.nickname.empty() ? m.nodeId : m.nickname, fs::path(pathText), g.groupId, g.name)) {
            any = true;
        }
    }
    return any;
}

void P2PNode::PrintPendingFiles() const {
    utils::LogRaw("=== Pending Files ===");
    std::vector<IncomingFileOffer> items;
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        for (const auto& [_, offer] : pendingIncomingFileOffers_) items.push_back(offer);
    }
    std::sort(items.begin(), items.end(), [](const IncomingFileOffer& a, const IncomingFileOffer& b) {
        if (a.senderNickname != b.senderNickname) return a.senderNickname < b.senderNickname;
        if (a.fileName != b.fileName) return a.fileName < b.fileName;
        return a.transferId < b.transferId;
    });
    if (items.empty()) { utils::LogRaw("  (none)"); return; }
    int i = 1;
    for (const auto& offer : items) {
        std::string extra;
        if (!offer.groupName.empty()) extra = " group=" + offer.groupName;
        if (offer.accepted) extra += " accepted";
        utils::LogRaw("[" + std::to_string(i++) + "] from=" + (offer.senderNickname.empty() ? offer.senderNodeId : offer.senderNickname) +
                      " file=" + offer.fileName + " size=" + std::to_string(offer.fileSize) + extra);
    }
}

bool P2PNode::RetryFileTransfer(const std::string& transferId) {
    OutgoingFileTransfer outgoing{};
    IncomingFileOffer incoming{};
    bool haveOutgoing = false;
    bool haveIncoming = false;
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        auto it = outgoingFileTransfers_.find(transferId);
        if (it != outgoingFileTransfers_.end()) { outgoing = it->second; haveOutgoing = true; }
        auto in = pendingIncomingFileOffers_.find(transferId);
        if (in != pendingIncomingFileOffers_.end()) { incoming = in->second; haveIncoming = true; }
    }
    if (haveOutgoing) {
        SendPrivateMessage(outgoing.targetNodeId, "[[FILEOFFER]]|" + outgoing.transferId + "|" + outgoing.fileName + "|" + std::to_string(outgoing.fileSize) + "|" + outgoing.groupId + "|" + outgoing.groupName); return true;
    }
    if (haveIncoming && incoming.accepted) {
        SendPrivateMessage(incoming.senderNodeId, "[[FILEACCEPT]]|" + incoming.transferId); return true;
    }
    return false;
}

void P2PNode::TickFileTransfers() {
    std::vector<std::string> timedOut;
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        for (auto& [id, st] : fileTransferStatuses_) {
            if (st.state == FileTransferState::Completed || st.state == FileTransferState::Rejected || st.state == FileTransferState::Failed) continue;
            if (st.deadlineUnix == 0) st.deadlineUnix = NowUnix() + transferTimeoutSeconds_;
            if (NowUnix() < st.deadlineUnix) continue;
            if (st.retryCount >= st.maxRetries) {
                st.state = FileTransferState::Failed;
                st.updatedAtUnix = NowUnix();
                st.deadlineUnix = 0;
                utils::LogError("File transfer failed by timeout: " + st.transferId);
                continue;
            }
            ++st.retryCount;
            st.deadlineUnix = NowUnix() + transferTimeoutSeconds_;
            st.updatedAtUnix = NowUnix();
            timedOut.push_back(id);
        }
    }
    for (const auto& id : timedOut) {
        if (RetryFileTransfer(id)) utils::LogSystem("Retried file transfer: " + id);
    }
}

void P2PNode::PrintFileTransfers() const {
    utils::LogRaw("=== File Transfers ===");
    std::vector<FileTransferStatus> items;
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        for (const auto& [_, st] : fileTransferStatuses_) items.push_back(st);
    }
    std::sort(items.begin(), items.end(), [](const FileTransferStatus& a, const FileTransferStatus& b) {
        if (a.updatedAtUnix != b.updatedAtUnix) return a.updatedAtUnix > b.updatedAtUnix;
        return a.transferId < b.transferId;
    });
    if (items.empty()) { utils::LogRaw("  (none)"); return; }
    for (const auto& st : items) {
        std::string line = "[" + st.transferId + "] " + (st.incoming ? "in" : "out") +
            " peer=" + (st.peerNickname.empty() ? st.peerNodeId : st.peerNickname) +
            " file=" + st.fileName +
            " size=" + std::to_string(st.fileSize) +
            " state=" + ToString(st.state);
        if (st.totalChunks > 0) {
            line += " chunks=" + std::to_string(st.currentChunk) + "/" + std::to_string(st.totalChunks);
        }
        if (!st.groupName.empty()) line += " group=" + st.groupName;
        utils::LogRaw(line);
    }
}

void P2PNode::PrintControlStates() const {
    utils::LogRaw("=== Control States ===");
    std::vector<std::pair<std::string, ControlStateEntry>> items;
    {
        std::lock_guard<std::mutex> lock(controlStateMutex_);
        for (const auto& kv : controlStates_) items.push_back(kv);
    }
    std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    if (items.empty()) { utils::LogRaw("  (none)"); return; }
    for (const auto& [k, st] : items) {
        utils::LogRaw(k + " => " + ToString(st.state) + " retries=" + std::to_string(st.retryCount) + " deadline=" + std::to_string(st.deadlineUnix));
    }
}

bool P2PNode::AcceptPendingFileByIndex(int index) {
    if (index <= 0) return false;
    std::vector<IncomingFileOffer> items;
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        for (const auto& [_, offer] : pendingIncomingFileOffers_) items.push_back(offer);
    }
    std::sort(items.begin(), items.end(), [](const IncomingFileOffer& a, const IncomingFileOffer& b) {
        if (a.senderNickname != b.senderNickname) return a.senderNickname < b.senderNickname;
        if (a.fileName != b.fileName) return a.fileName < b.fileName;
        return a.transferId < b.transferId;
    });
    if (static_cast<std::size_t>(index) > items.size()) return false;
    const auto picked = items[static_cast<std::size_t>(index - 1)];
    auto sessionIdOpt = FindSessionByPeer(picked.senderNodeId);
    ByteVector sessionKey;
    if (!sessionIdOpt || !GetSessionKeyForPeer(picked.senderNodeId, sessionKey)) {
        utils::LogError("No E2E session key for this private chat yet");
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        auto it = pendingIncomingFileOffers_.find(picked.transferId);
        if (it == pendingIncomingFileOffers_.end()) return false;
        it->second.accepted = true;
        auto st = fileTransferStatuses_.find(picked.transferId);
        if (st != fileTransferStatuses_.end()) {
            st->second.state = FileTransferState::Accepted;
            st->second.updatedAtUnix = NowUnix();
            st->second.deadlineUnix = st->second.updatedAtUnix + transferTimeoutSeconds_;
            st->second.peerAccepted = true;
        }
    }
    SendPrivateMessage(picked.senderNodeId, "[[FILEACCEPT]]|" + picked.transferId);
    utils::LogSystem("Accepted file download: " + picked.fileName);
    return true;
}

bool P2PNode::RejectPendingFileByIndex(int index) {
    if (index <= 0) return false;
    std::vector<IncomingFileOffer> items;
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        for (const auto& [_, offer] : pendingIncomingFileOffers_) items.push_back(offer);
    }
    std::sort(items.begin(), items.end(), [](const IncomingFileOffer& a, const IncomingFileOffer& b) {
        if (a.senderNickname != b.senderNickname) return a.senderNickname < b.senderNickname;
        if (a.fileName != b.fileName) return a.fileName < b.fileName;
        return a.transferId < b.transferId;
    });
    if (static_cast<std::size_t>(index) > items.size()) return false;
    const auto picked = items[static_cast<std::size_t>(index - 1)];
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        pendingIncomingFileOffers_.erase(picked.transferId);
        incomingFileTransfers_.erase(picked.transferId);
        auto st = fileTransferStatuses_.find(picked.transferId);
        if (st != fileTransferStatuses_.end()) {
            st->second.state = FileTransferState::Rejected;
            st->second.updatedAtUnix = NowUnix();
                st->second.deadlineUnix = st->second.updatedAtUnix + transferTimeoutSeconds_;
        }
    }
    SendPrivateMessage(picked.senderNodeId, "[[FILEREJECT]]|" + picked.transferId);
    utils::LogSystem("Rejected file: " + picked.fileName);
    return true;
}

bool P2PNode::MirrorConversationToDevice(const NodeId& deviceNodeId, std::size_t maxMessages) {
    if (deviceNodeId.empty() || maxMessages == 0) return false;
    auto contacts = GetSortedContacts();
    std::size_t mirrored = 0;
    for (const auto& c : contacts) {
        if (c.nodeId == deviceNodeId || c.nodeId == local_.nodeId) continue;
        std::vector<StoredConversationMessage> messages;
        std::string error;
        if (!ConversationStore::LoadConversation(historyRootDir_, local_.nodeId, c.nodeId, signer_, messages, &error)) {
            continue;
        }
        if (messages.size() > maxMessages) {
            messages.erase(messages.begin(), messages.end() - static_cast<std::ptrdiff_t>(maxMessages));
        }
        for (const auto& m : messages) {
            std::string sender = m.fromNickname.empty() ? m.fromNodeId : m.fromNickname;
            std::string body = "[[DEVSYNC]]|" + c.nodeId + "|" + sender + "|" + m.text;
            SendPrivateMessage(deviceNodeId, body);
            ++mirrored;
        }
    }
    if (mirrored > 0) {
        utils::LogSystem("Mirrored " + std::to_string(mirrored) + " message(s) to linked device " + deviceNodeId);
    }
    return true;
}

bool P2PNode::SyncDeviceByIndex(int index) {
    auto devices = GetSortedDevices();
    if (index <= 0 || static_cast<std::size_t>(index) > devices.size()) return false;
    const auto& d = devices[static_cast<std::size_t>(index - 1)];
    if (!d.approved || d.revoked) {
        utils::LogError("Device is not active for sync");
        return false;
    }
    auto sessionIdOpt = FindSessionByPeer(d.nodeId);
    ByteVector sessionKey;
    if (!sessionIdOpt || !GetSessionKeyForPeer(d.nodeId, sessionKey)) {
        utils::LogError("No E2E session key for linked device");
        return false;
    }
    return MirrorConversationToDevice(d.nodeId, 16);
}

bool P2PNode::ApplyDeviceSyncText(const NodeId& senderNodeId, const std::string& text) {
    auto parts = SplitPipe(text);
    if (parts.size() < 4 || parts[0] != "[[DEVSYNC]]") return false;
    utils::LogSystem("Synced from device " + senderNodeId + " peer=" + parts[1] + " msg=" + parts[3]);
    return true;
}

bool P2PNode::ApplyFileOfferText(const NodeId& senderNodeId, const std::string& senderNickname, const std::string& text) {
    auto parts = SplitPipe(text);
    if (parts.size() < 4 || parts[0] != "[[FILEOFFER]]") return false;
    IncomingFileOffer offer{};
    offer.transferId = parts[1];
    offer.senderNodeId = senderNodeId;
    offer.senderNickname = senderNickname;
    offer.fileName = parts[2];
    try { offer.fileSize = static_cast<std::uint64_t>(std::stoull(parts[3])); } catch (...) { return false; }
    if (parts.size() > 4) offer.groupId = parts[4];
    if (parts.size() > 5) offer.groupName = parts[5];
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        pendingIncomingFileOffers_[offer.transferId] = offer;
        incomingFileTransfers_.erase(offer.transferId);
        FileTransferStatus st{};
        st.transferId = offer.transferId;
        st.peerNodeId = senderNodeId;
        st.peerNickname = senderNickname;
        st.fileName = offer.fileName;
        st.fileSize = offer.fileSize;
        st.state = FileTransferState::Offered;
        st.incoming = true;
        st.groupName = offer.groupName;
        st.updatedAtUnix = NowUnix();
        st.deadlineUnix = st.updatedAtUnix + transferTimeoutSeconds_;
        st.resumable = true;
        fileTransferStatuses_[st.transferId] = st;
    }
    std::string msg = "Incoming file offer from " + (senderNickname.empty() ? senderNodeId : senderNickname) + ": " + offer.fileName +
                      " (" + std::to_string(offer.fileSize) + " bytes)";
    if (!offer.groupName.empty()) msg += " in group " + offer.groupName;
    msg += ". Use /downloads and /download <n> or /rejectfile <n>.";
    utils::LogSystem(msg);
    return true;
}

bool P2PNode::ApplyFileAcceptText(const NodeId& senderNodeId, const std::string& text) {
    auto parts = SplitPipe(text);
    if (parts.size() < 2 || parts[0] != "[[FILEACCEPT]]") return false;
    OutgoingFileTransfer transfer{};
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        auto it = outgoingFileTransfers_.find(parts[1]);
        if (it == outgoingFileTransfers_.end()) return true;
        transfer = it->second;
    }
    if (transfer.targetNodeId != senderNodeId) return true;
    const std::size_t totalChunks = (transfer.bytes.size() + kFileChunkBytes - 1) / kFileChunkBytes;
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        auto st = fileTransferStatuses_.find(transfer.transferId);
        if (st != fileTransferStatuses_.end()) {
            st->second.state = FileTransferState::Transferring;
            st->second.totalChunks = totalChunks;
            st->second.currentChunk = 0;
            st->second.updatedAtUnix = NowUnix();
        }
    }
    for (std::size_t i = 0; i < totalChunks; ++i) {
        const std::size_t off = i * kFileChunkBytes;
        const std::size_t len = std::min(kFileChunkBytes, transfer.bytes.size() - off);
        ByteVector chunk(transfer.bytes.begin() + static_cast<std::ptrdiff_t>(off), transfer.bytes.begin() + static_cast<std::ptrdiff_t>(off + len));
        SendPrivateMessage(senderNodeId, "[[FILECHUNK]]|" + transfer.transferId + "|" + std::to_string(i + 1) + "|" + std::to_string(totalChunks) +
            "|" + transfer.fileName + "|" + BytesToHexLocal(chunk));
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        auto st = fileTransferStatuses_.find(transfer.transferId);
        if (st != fileTransferStatuses_.end()) {
            st->second.currentChunk = i + 1;
            st->second.updatedAtUnix = NowUnix();
        }
    }
    { std::lock_guard<std::mutex> lock(fileTransfersMutex_); outgoingFileTransfers_.erase(transfer.transferId); auto st=fileTransferStatuses_.find(transfer.transferId); if (st!=fileTransferStatuses_.end()) { st->second.state = FileTransferState::Completed; st->second.updatedAtUnix = NowUnix(); } }
    utils::LogSystem("File data sent: " + transfer.fileName + " to " + (transfer.targetNickname.empty() ? senderNodeId : transfer.targetNickname));
    return true;
}

bool P2PNode::ApplyFileRejectText(const NodeId& senderNodeId, const std::string& text) {
    auto parts = SplitPipe(text);
    if (parts.size() < 2 || parts[0] != "[[FILEREJECT]]") return false;
    std::string fileName;
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        auto it = outgoingFileTransfers_.find(parts[1]);
        if (it != outgoingFileTransfers_.end()) {
            fileName = it->second.fileName;
            outgoingFileTransfers_.erase(it);
        }
        auto st = fileTransferStatuses_.find(parts[1]);
        if (st != fileTransferStatuses_.end()) {
            st->second.state = FileTransferState::Rejected;
            st->second.updatedAtUnix = NowUnix();
        }
    }
    if (!fileName.empty()) utils::LogSystem("File rejected by " + senderNodeId + ": " + fileName);
    return true;
}

bool P2PNode::ApplyFileChunkText(const NodeId& senderNodeId, const std::string& text) {
    auto parts = SplitPipe(text);
    if (parts.size() < 6 || parts[0] != "[[FILECHUNK]]") return false;
    const auto transferId = parts[1];
    std::size_t seq = 0, total = 0;
    try {
        seq = static_cast<std::size_t>(std::stoull(parts[2]));
        total = static_cast<std::size_t>(std::stoull(parts[3]));
    } catch (...) { return false; }
    if (seq == 0 || total == 0 || seq > total) return false;
    ByteVector chunk;
    if (!HexToBytesLocal(parts[5], chunk)) return false;

    IncomingFileOffer offer;
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        auto itOffer = pendingIncomingFileOffers_.find(transferId);
        if (itOffer == pendingIncomingFileOffers_.end() || !itOffer->second.accepted) return true;
        offer = itOffer->second;
        auto& transfer = incomingFileTransfers_[transferId];
        if (transfer.offer.transferId.empty()) transfer.offer = offer;
        if (transfer.totalChunks == 0) {
            transfer.totalChunks = total;
            transfer.chunks.resize(total);
            transfer.received.assign(total, false);
            transfer.receivedCount = 0;
            auto st = fileTransferStatuses_.find(transferId);
            if (st != fileTransferStatuses_.end()) {
                st->second.state = FileTransferState::Transferring;
                st->second.totalChunks = total;
                st->second.currentChunk = 0;
                st->second.updatedAtUnix = NowUnix();
            }
        }
        if (transfer.totalChunks != total) return true;
        const std::size_t idx = seq - 1;
        if (!transfer.received[idx]) {
            transfer.chunks[idx] = std::move(chunk);
            transfer.received[idx] = true;
            transfer.receivedCount += 1;
            auto st = fileTransferStatuses_.find(transferId);
            if (st != fileTransferStatuses_.end()) {
                st->second.currentChunk = transfer.receivedCount;
                st->second.updatedAtUnix = NowUnix();
            }
        }
        if (transfer.receivedCount != transfer.totalChunks) return true;
        ByteVector assembled;
        assembled.reserve(static_cast<std::size_t>(offer.fileSize));
        for (const auto& c : transfer.chunks) assembled.insert(assembled.end(), c.begin(), c.end());
        fs::path dir = fs::path("downloads") / local_.nodeId / (offer.groupName.empty() ? senderNodeId : offer.groupName);
        std::error_code ec;
        fs::create_directories(dir, ec);
        fs::path dst = dir / parts[4];
        if (fs::exists(dst)) {
            for (int n = 1; n < 1000; ++n) {
                fs::path cand = dir / (dst.stem().string() + "_" + std::to_string(n) + dst.extension().string());
                if (!fs::exists(cand)) { dst = cand; break; }
            }
        }
        std::ofstream out(dst, std::ios::binary | std::ios::trunc);
        if (!out) {
            utils::LogError("Failed to write downloaded file: " + dst.string());
            return true;
        }
        out.write(reinterpret_cast<const char*>(assembled.data()), static_cast<std::streamsize>(assembled.size()));
        out.close();
        pendingIncomingFileOffers_.erase(transferId);
        incomingFileTransfers_.erase(transferId);
        auto st = fileTransferStatuses_.find(transferId);
        if (st != fileTransferStatuses_.end()) {
            st->second.state = FileTransferState::Completed;
            st->second.updatedAtUnix = NowUnix();
        }
        utils::LogSystem("File saved: " + dst.string());
    }
    return true;
}

bool P2PNode::ApplyGroupSyncText(const NodeId& senderNodeId, const std::string& text) {

    auto parts = SplitPipe(text);
    if (parts.size() < 5 || parts[0] != "[[GROUPSYNC]]") return false;
    GroupEntry incoming{};
    incoming.groupId = parts[1]; incoming.name = parts[2]; incoming.ownerNodeId = parts[3]; incoming.version = 0;
    try { incoming.version = std::stoull(parts[4]); } catch (...) { return false; }
    if (incoming.ownerNodeId != senderNodeId) {
        utils::LogError("Rejected group sync: sender is not owner");
        return true;
    }
    for (std::size_t i = 5; i < parts.size(); ++i) {
        std::stringstream ss(parts[i]);
        std::string a,b,c;
        if (!std::getline(ss,a,',')) continue; if (!std::getline(ss,b,',')) continue; if (!std::getline(ss,c,',')) continue;
        incoming.members.push_back(GroupMemberEntry{a,b,ParseGroupRole(c).value_or(GroupRole::Member)});
    }
    bool containsLocal = false;
    for (const auto& m : incoming.members) if (m.nodeId == local_.nodeId) { containsLocal = true; break; }
    {
        std::lock_guard<std::mutex> lock(overlayMutex_);
        auto it = overlayState_.groups.find(incoming.groupId);
        if (it != overlayState_.groups.end() && it->second.version > incoming.version) {
            utils::LogSystem("Ignored stale group snapshot for " + incoming.name);
            return true;
        }
        if (!containsLocal) { overlayState_.groups.erase(incoming.groupId); }
        auto& target = overlayState_.groups[incoming.groupId];
        target.groupId = incoming.groupId; target.name = incoming.name; target.ownerNodeId = incoming.ownerNodeId; target.version = incoming.version; target.members = incoming.members;
        target.events.push_back(GroupEventEntry{incoming.version, "snapshot_applied", senderNodeId, local_.nodeId, incoming.name, NowUnix()});
    }
    SaveOverlayState();
    utils::LogSystem("Applied group sync: " + incoming.name);
    return true;
}

bool P2PNode::ApplyDeviceLinkText(const NodeId& senderNodeId, const std::string& text) {
    auto parts = SplitPipe(text);
    if (parts.empty()) return false;
    if (parts[0] == "[[DEVICE-LINK]]" && parts.size() >= 5) {
        DeviceEntry d{}; d.nodeId = senderNodeId; d.nickname = parts[2]; d.label = parts[3]; d.fingerprint = parts[4]; d.approved = true; d.linkedAtUnix = NowUnix();
        { std::lock_guard<std::mutex> lock(overlayMutex_); overlayState_.devices[d.nodeId] = d; }
        SaveOverlayState();
        utils::LogSystem("Linked remote device: " + d.label);
        return true;
    }
    if (parts[0] == "[[DEVICE-REVOKE]]" && parts.size() >= 2) {
        {
            std::lock_guard<std::mutex> lock(overlayMutex_);
            auto it = overlayState_.devices.find(senderNodeId);
            if (it != overlayState_.devices.end()) {
                it->second.revoked = true; it->second.approved = false; it->second.revokedAtUnix = NowUnix();
            }
        }
        SaveOverlayState();
        utils::LogSystem("Remote device revoked: " + senderNodeId);
        return true;
    }
    return false;
}

bool P2PNode::ApplyFileMetaText(const NodeId& senderNodeId, const std::string& text) {
    auto parts = SplitPipe(text);
    if (parts.size() < 6 || parts[0] != "[[FILEMETA]]") return false;
    utils::LogSystem("Incoming attachment metadata from " + senderNodeId + ": " + parts[3] + " size=" + parts[4]);
    return true;
}

P2PNode::ControlEnvelope P2PNode::ParseControlEnvelope(const PrivateMessagePayload& payload) const {
    ControlEnvelope envelope{};
    envelope.raw = payload.text;
    envelope.senderNodeId = payload.fromNodeId;
    envelope.senderNickname = payload.fromNickname;
    if (payload.text.rfind("[[", 0) != 0) return envelope;
    envelope.parts = SplitPipe(payload.text);
    if (envelope.parts.empty()) return envelope;
    const auto& tag = envelope.parts[0];
    if (tag == "[[GROUPSYNC]]") envelope.kind = ControlMessageKind::GroupSync;
    else if (tag == "[[DEVICE-LINK]]") envelope.kind = ControlMessageKind::DeviceLink;
    else if (tag == "[[DEVICE-REVOKE]]") envelope.kind = ControlMessageKind::DeviceRevoke;
    else if (tag == "[[DEVSYNC]]") envelope.kind = ControlMessageKind::DeviceSync;
    else if (tag == "[[FILEMETA]]") envelope.kind = ControlMessageKind::FileMeta;
    else if (tag == "[[FILEOFFER]]") envelope.kind = ControlMessageKind::FileOffer;
    else if (tag == "[[FILEACCEPT]]") envelope.kind = ControlMessageKind::FileAccept;
    else if (tag == "[[FILEREJECT]]") envelope.kind = ControlMessageKind::FileReject;
    else if (tag == "[[FILECHUNK]]") envelope.kind = ControlMessageKind::FileChunk;
    else if (tag == "[[GROUPMSG]]") envelope.kind = ControlMessageKind::GroupMessage;
    return envelope;
}

std::string P2PNode::MakeControlStateKey(const ControlEnvelope& envelope) const {
    std::string token;
    if (envelope.parts.size() > 1) token = envelope.parts[1];
    if (token.empty()) token = envelope.senderNodeId;
    return ControlMessageKindToString(envelope.kind) + ":" + envelope.senderNodeId + ":" + token;
}

bool P2PNode::ValidateControlStateTransition(ControlFlowState oldState, ControlFlowState newState) const {
    using S = ControlFlowState;
    if (oldState == S::Idle) return true;
    if (oldState == newState) return true;
    switch (oldState) {
        case S::Received: return newState == S::Parsed || newState == S::Rejected || newState == S::Failed;
        case S::Parsed: return newState == S::Validated || newState == S::Applied || newState == S::Rejected || newState == S::Failed;
        case S::Validated: return newState == S::Applied || newState == S::Rejected || newState == S::Failed;
        case S::Applied: return false;
        case S::Rejected: return false;
        case S::Failed: return newState == S::Received || newState == S::Parsed;
        default: return true;
    }
}

void P2PNode::UpdateControlState(const std::string& key, ControlFlowState state) {
    std::lock_guard<std::mutex> lock(controlStateMutex_);
    auto& entry = controlStates_[key];
    if (!ValidateControlStateTransition(entry.state, state)) {
        utils::LogError("Rejected invalid control-state transition for " + key + ": " + ToString(entry.state) + " -> " + ToString(state));
        return;
    }
    entry.state = state;
    entry.updatedAtUnix = NowUnix();
    if (entry.deadlineUnix == 0 && (state == ControlFlowState::Received || state == ControlFlowState::Parsed || state == ControlFlowState::Validated)) {
        entry.deadlineUnix = entry.updatedAtUnix + controlTimeoutSeconds_;
    }
    if (state == ControlFlowState::Applied || state == ControlFlowState::Rejected) entry.deadlineUnix = 0;
}

P2PNode::ProtocolFlowResult P2PNode::RetryTimedOutControl(const std::string& key) {
    std::lock_guard<std::mutex> lock(controlStateMutex_);
    auto it = controlStates_.find(key);
    if (it == controlStates_.end()) return ProtocolFlowResult::None;
    auto& e = it->second;
    if (e.deadlineUnix == 0 || e.updatedAtUnix == 0 || NowUnix() < e.deadlineUnix) return ProtocolFlowResult::None;
    if (e.retryCount >= e.maxRetries) {
        e.state = ControlFlowState::Failed;
        e.updatedAtUnix = NowUnix();
        e.deadlineUnix = 0;
        return ProtocolFlowResult::TimedOut;
    }
    ++e.retryCount;
    e.state = ControlFlowState::Received;
    e.updatedAtUnix = NowUnix();
    e.deadlineUnix = e.updatedAtUnix + controlTimeoutSeconds_;
    return ProtocolFlowResult::Retried;
}

void P2PNode::TickProtocolFlows() {
    std::vector<std::string> keys;
    {
        std::lock_guard<std::mutex> lock(controlStateMutex_);
        for (const auto& kv : controlStates_) keys.push_back(kv.first);
    }
    for (const auto& key : keys) {
        auto result = RetryTimedOutControl(key);
        if (result == ProtocolFlowResult::Retried) utils::LogSystem("Control flow retry scheduled: " + key);
        else if (result == ProtocolFlowResult::TimedOut) utils::LogError("Control flow timed out: " + key);
    }
}

void P2PNode::ResumePendingFlows() {
    {
        std::lock_guard<std::mutex> lock(fileTransfersMutex_);
        for (auto& [id, st] : fileTransferStatuses_) {
            if (st.state == FileTransferState::Offered || st.state == FileTransferState::Accepted || st.state == FileTransferState::Transferring) {
                st.resumable = true;
                st.deadlineUnix = NowUnix() + transferTimeoutSeconds_;
            }
        }
    }
    utils::LogSystem("Resumed pending protocol flows from in-memory state");
}

bool P2PNode::DispatchControlMessage(const ControlEnvelope& envelope) {
    if (envelope.kind == ControlMessageKind::Unknown) return false;
    const auto key = MakeControlStateKey(envelope);
    {
        std::lock_guard<std::mutex> lock(controlStateMutex_);
        auto& e = controlStates_[key];
        e.kind = envelope.kind;
        e.senderNodeId = envelope.senderNodeId;
        e.token = envelope.parts.size() > 1 ? envelope.parts[1] : envelope.senderNodeId;
        e.updatedAtUnix = NowUnix();
        e.deadlineUnix = e.updatedAtUnix + controlTimeoutSeconds_;
    }
    UpdateControlState(key, ControlFlowState::Received);
    bool handled = false;
    switch (envelope.kind) {
        case ControlMessageKind::GroupSync:
            UpdateControlState(key, ControlFlowState::Parsed);
            handled = ApplyGroupSyncText(envelope.senderNodeId, envelope.raw);
            break;
        case ControlMessageKind::DeviceLink:
        case ControlMessageKind::DeviceRevoke:
            UpdateControlState(key, ControlFlowState::Parsed);
            handled = ApplyDeviceLinkText(envelope.senderNodeId, envelope.raw);
            break;
        case ControlMessageKind::DeviceSync:
            UpdateControlState(key, ControlFlowState::Parsed);
            handled = ApplyDeviceSyncText(envelope.senderNodeId, envelope.raw);
            break;
        case ControlMessageKind::FileMeta:
            UpdateControlState(key, ControlFlowState::Parsed);
            handled = ApplyFileMetaText(envelope.senderNodeId, envelope.raw);
            break;
        case ControlMessageKind::FileOffer:
            UpdateControlState(key, ControlFlowState::Parsed);
            handled = ApplyFileOfferText(envelope.senderNodeId, envelope.senderNickname, envelope.raw);
            break;
        case ControlMessageKind::FileAccept:
            UpdateControlState(key, ControlFlowState::Parsed);
            handled = ApplyFileAcceptText(envelope.senderNodeId, envelope.raw);
            break;
        case ControlMessageKind::FileReject:
            UpdateControlState(key, ControlFlowState::Parsed);
            handled = ApplyFileRejectText(envelope.senderNodeId, envelope.raw);
            break;
        case ControlMessageKind::FileChunk:
            UpdateControlState(key, ControlFlowState::Parsed);
            handled = ApplyFileChunkText(envelope.senderNodeId, envelope.raw);
            break;
        case ControlMessageKind::GroupMessage: {
            UpdateControlState(key, ControlFlowState::Parsed);
            auto parts = envelope.parts.empty() ? SplitPipe(envelope.raw) : envelope.parts;
            if (parts.size() >= 5) {
                utils::LogSystem("[Group " + parts[2] + "] " + parts[3] + ": " + parts[4]);
                handled = true;
            }
            break;
        }
        default:
            break;
    }
    UpdateControlState(key, handled ? ControlFlowState::Applied : ControlFlowState::Rejected);
    return handled;
}

void P2PNode::ProcessOverlayPrivateMessage(const PrivateMessagePayload& payload) {
    const auto envelope = ParseControlEnvelope(payload);
    if (envelope.kind == ControlMessageKind::Unknown) return;
    if (!DispatchControlMessage(envelope)) {
        utils::LogError("Failed to dispatch control message: " + envelope.raw);
    }
}

std::vector<DisplayInvite> P2PNode::GetDisplayInvites() const {
    std::vector<DisplayInvite> result;
    {
        std::lock_guard<std::mutex> lock(invitesMutex_);
        for (const auto& [_, inv] : incomingInvites_) {
            result.push_back(DisplayInvite{0, inv.inviteId, inv.fromNodeId, inv.fromNickname});
        }
    }
    std::sort(result.begin(), result.end(), [](const DisplayInvite& a, const DisplayInvite& b) {
        if (a.fromNickname != b.fromNickname) return a.fromNickname < b.fromNickname;
        return a.fromNodeId < b.fromNodeId;
    });
    int i = 1;
    for (auto& inv : result) inv.index = i++;
    return result;
}

std::vector<DisplayUser> P2PNode::GetDisplayUsers() const {
    auto nodes = knownNodes_.GetAllExcept(local_.nodeId);
    std::unordered_set<NodeId> online;
    for (const auto& p : peerManager_.Snapshot()) online.insert(p.remoteNodeId);

    std::unordered_map<NodeId, DisplayUser> merged;
    const auto now = std::chrono::steady_clock::now();
    for (const auto& n : nodes) {
        std::uint64_t lastSeenSecondsAgo = 0;
        if (now > n.lastSeen) {
            lastSeenSecondsAgo = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(now - n.lastSeen).count());
        }
        merged[n.nodeId] = {0, n.nodeId, ResolveDisplayName(n.nodeId, n.nickname), online.contains(n.nodeId), lastSeenSecondsAgo};
    }
    {
        std::lock_guard<std::mutex> lock(contactsMutex_);
        for (const auto& [id, c] : contacts_) {
            if (id == local_.nodeId) continue;
            auto it = merged.find(id);
            if (it == merged.end()) {
                merged[id] = {0, id, (c.nickname.empty() ? id : c.nickname), online.contains(id), 0};
            } else if (!c.nickname.empty()) {
                it->second.nickname = c.nickname;
            }
        }
    }
    std::vector<DisplayUser> result;
    result.reserve(merged.size());
    for (auto& [_, u] : merged) result.push_back(u);
    std::sort(result.begin(), result.end(), [](const DisplayUser& a, const DisplayUser& b) {
        if (a.online != b.online) return a.online > b.online;
        return a.nickname == b.nickname ? a.nodeId < b.nodeId : a.nickname < b.nickname;
    });
    int i = 1;
    for (auto& u : result) u.index = i++;
    return result;
}

void P2PNode::BroadcastRaw(const ByteVector& packet, const NodeId& excludeNodeId) {
    auto peers = peerManager_.GetAllPeers();
    for (auto& p : peers) {
        if (!excludeNodeId.empty() && p->GetRemoteNodeId() == excludeNodeId) continue;
        p->EnqueuePacket(packet);
    }
}

void P2PNode::OnPeerDisconnected(SOCKET socket) {
    {
        std::lock_guard<std::mutex> lock(rateLimitMutex_);
        rateLimitBySocket_.erase(socket);
    }
    if (socket == INVALID_SOCKET) return;

    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        auto it = pendingPeers_.find(socket);
        if (it != pendingPeers_.end()) {
            auto p = it->second;
            pendingPeers_.erase(it);
            if (p) p->RequestClose();
            return;
        }
    }

    auto p = peerManager_.FindBySocket(socket);
    if (p) {
        const NodeId remoteNodeId = p->GetRemoteNodeId();
        const std::string remoteNickname = p->GetRemoteNickname();
        peerManager_.RemoveBySocket(socket);
        p->RequestClose();

        if (!remoteNodeId.empty()) {
            if (auto known = knownNodes_.FindByNodeId(remoteNodeId)) {
                known->lastSeen = std::chrono::steady_clock::now();
                knownNodes_.Upsert(*known);
            }
            NoteReconnectFailure(remoteNodeId);
            { std::lock_guard<std::mutex> repLock(reputationMutex_); peerReputation_.NoteDisconnect(remoteNodeId); std::string repError; peerReputation_.Save(local_.nodeId, &repError); }
            std::lock_guard<std::mutex> lock(sessionsMutex_);
            auto it = sessionByPeer_.find(remoteNodeId);
            if (it != sessionByPeer_.end()) {
                auto sit = sessionsById_.find(it->second);
                if (sit != sessionsById_.end()) {
                    sit->second.active = false;
                }
            }
            utils::LogSystem("Peer disconnected: " + (remoteNickname.empty() ? remoteNodeId : remoteNickname) + ". Active private chat with this peer was closed.");
        }
    }
}

bool P2PNode::ShouldAttemptAutoConnect(const KnownNode& node) {
    if (node.nodeId.empty() || node.ip.empty() || node.port == 0) return false;
    if (node.nodeId == local_.nodeId) return false;
    if (peerManager_.HasNode(node.nodeId)) return false;
    {
        std::lock_guard<std::mutex> repLock(reputationMutex_);
        if (peerReputation_.ShouldBlock(node.nodeId)) return false;
    }

    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(reconnectMutex_);
        auto it = reconnectStates_.find(node.nodeId);
        if (it != reconnectStates_.end() && it->second.nextAttempt != std::chrono::steady_clock::time_point{} && now < it->second.nextAttempt) {
            return false;
        }
    }
    std::lock_guard<std::mutex> lock(connectAttemptsMutex_);
    auto it = lastConnectAttempt_.find(node.nodeId);
    if (it != lastConnectAttempt_.end()) {
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
        if (diff < 2) return false;
    }
    return true;
}

void P2PNode::MarkConnectAttempt(const NodeId& nodeId) {
    std::lock_guard<std::mutex> lock(connectAttemptsMutex_);
    lastConnectAttempt_[nodeId] = std::chrono::steady_clock::now();
}

void P2PNode::NoteReconnectFailure(const NodeId& nodeId) {
    if (nodeId.empty()) return;
    std::lock_guard<std::mutex> lock(reconnectMutex_);
    auto& state = reconnectStates_[nodeId];
    state.failureCount = std::min<std::uint32_t>(state.failureCount + 1, 8u);
    const auto delaySeconds = std::min<std::uint32_t>(60u, 1u << std::min<std::uint32_t>(state.failureCount - 1, 5u));
    state.nextAttempt = std::chrono::steady_clock::now() + std::chrono::seconds(delaySeconds);
}

void P2PNode::ResetReconnectState(const NodeId& nodeId) {
    if (nodeId.empty()) return;
    std::lock_guard<std::mutex> lock(reconnectMutex_);
    reconnectStates_.erase(nodeId);
}

bool P2PNode::TryConnectToKnownNode(const KnownNode& node) {
    if (node.ip.empty()) return false;

    std::vector<std::uint16_t> ports;
    if (node.port != 0) ports.push_back(node.port);
    if (node.observedPort != 0 && node.observedPort != node.port) ports.push_back(node.observedPort);

    bool connected = false;
    MarkConnectAttempt(node.nodeId);
    for (auto port : ports) {
        if (ConnectToPeer(node.ip, port)) {
            connected = true;
            break;
        }
    }
    if (!connected) {
        NoteReconnectFailure(node.nodeId);
    }
    return connected;
}

void P2PNode::RequestReverseConnect(const KnownNode& target) {
    ConnectRequestPayload payload{};
    payload.requesterNodeId = local_.nodeId;
    payload.requesterNickname = local_.nickname;
    payload.targetNodeId = target.nodeId;
    payload.requesterAdvertisedPort = local_.listenPort;
    {
        std::lock_guard<std::mutex> lock(observedEndpointMutex_);
        payload.requesterObservedIp = localObservedIp_;
        payload.requesterObservedPort = localObservedPort_;
    }
    if (payload.requesterObservedIp.empty()) return;

    signer_.Sign(BuildConnectRequestSignedData(payload), payload.signature);

    const PacketId packetId = utils::GeneratePacketId();
    router_.MarkSeen(packetId);
    auto body = protocol::SerializeConnectRequest(payload);
    auto packet = protocol::MakePacket(PacketType::ConnectRequest, packetId, body);
    BroadcastRaw(packet);
    utils::LogSystem("Asked network to relay reverse-connect request to " + target.nickname);
}

void P2PNode::RequestUdpHolePunch(const KnownNode& target) {
    UdpPunchRequestPayload payload{};
    payload.requesterNodeId = local_.nodeId;
    payload.requesterNickname = local_.nickname;
    payload.targetNodeId = target.nodeId;
    payload.requesterAdvertisedTcpPort = local_.listenPort;
    {
        std::lock_guard<std::mutex> lock(observedEndpointMutex_);
        payload.requesterObservedUdpIp = localObservedUdpIp_;
        payload.requesterObservedUdpPort = localObservedUdpPort_;
    }

    if (payload.requesterObservedUdpIp.empty() || payload.requesterObservedUdpPort == 0) {
        utils::LogError("UDP hole punching skipped: no observed UDP endpoint yet");
        return;
    }

    signer_.Sign(BuildUdpPunchRequestSignedData(payload), payload.signature);

    SendUdpPunchBurst(target, "requester");

    const PacketId packetId = utils::GeneratePacketId();
    router_.MarkSeen(packetId);
    auto body = protocol::SerializeUdpPunchRequest(payload);
    auto packet = protocol::MakePacket(PacketType::UdpPunchRequest, packetId, body);
    BroadcastRaw(packet);
    utils::LogSystem("Asked network to coordinate UDP hole punch to " + target.nickname);
}

void P2PNode::SendUdpProbeToEndpoint(const std::string& ip, std::uint16_t port) {
    if (udpSocket_ == INVALID_SOCKET || ip.empty() || port == 0) return;

    ByteVector data;
    utils::WriteUint32(data, 0x55445031u);
    utils::WriteUint16(data, 1);
    utils::WriteString(data, local_.nodeId);
    utils::WriteString(data, local_.nickname);
    utils::WriteUint16(data, local_.listenPort);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) return;

    sendto(udpSocket_, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
}

void P2PNode::SendUdpProbeToKnownNodes() {
    for (const auto& peer : peerManager_.GetAllPeers()) {
        SendUdpProbeToEndpoint(peer->GetRemoteIp(), peer->GetAdvertisedListenPort());
        SendUdpProbeToEndpoint(peer->GetRemoteIp(), peer->GetRemotePort());
    }

    auto nodes = knownNodes_.GetAllExcept(local_.nodeId);
    for (const auto& node : nodes) {
        SendUdpProbeToEndpoint(node.ip, node.port);
        if (node.observedUdpPort != 0 && node.observedUdpPort != node.port) SendUdpProbeToEndpoint(node.ip, node.observedUdpPort);
        else if (node.observedPort != 0 && node.observedPort != node.port) SendUdpProbeToEndpoint(node.ip, node.observedPort);
    }
}

void P2PNode::SendUdpPunchBurst(const KnownNode& node, const std::string& reason) {
    if (udpSocket_ == INVALID_SOCKET || node.ip.empty()) return;

    std::vector<std::uint16_t> ports;
    if (node.observedUdpPort != 0) ports.push_back(node.observedUdpPort);
    if (node.port != 0 && node.port != node.observedUdpPort) ports.push_back(node.port);
    if (node.observedPort != 0 && node.observedPort != node.port && node.observedPort != node.observedUdpPort) ports.push_back(node.observedPort);

    ByteVector data;
    utils::WriteUint32(data, 0x55445031u);
    utils::WriteUint16(data, 3);
    utils::WriteString(data, local_.nodeId);
    utils::WriteString(data, local_.nickname);
    utils::WriteUint16(data, local_.listenPort);

    for (int burst = 0; burst < 6; ++burst) {
        for (auto port : ports) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            if (inet_pton(AF_INET, node.ip.c_str(), &addr.sin_addr) != 1) continue;
            sendto(udpSocket_, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }
    if (!ports.empty()) utils::LogSystem("UDP punch burst sent to " + node.nickname + " (" + reason + ")");
}

void P2PNode::UdpRecvLoop() {
    while (running_) {
        std::array<std::uint8_t, 2048> buffer{};
        sockaddr_in from{};
        int fromLen = sizeof(from);
        int recvd = recvfrom(udpSocket_, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0, reinterpret_cast<sockaddr*>(&from), &fromLen);
        if (recvd <= 0) break;
        ByteVector data(buffer.begin(), buffer.begin() + recvd);
        HandleUdpDatagram(utils::SocketAddressToIp(from), ntohs(from.sin_port), data);
    }
}

void P2PNode::HandleUdpDatagram(const std::string& ip, std::uint16_t port, const ByteVector& data) {
    std::size_t offset = 0;
    std::uint32_t magic = 0;
    std::uint16_t kind = 0;
    std::string nodeId;
    std::string nickname;
    std::uint16_t advertisedTcpPort = 0;

    if (!utils::ReadUint32(data, offset, magic) || magic != 0x55445031u) return;
    if (!utils::ReadUint16(data, offset, kind)) return;
    if (!utils::ReadString(data, offset, nodeId)) return;
    if (!utils::ReadString(data, offset, nickname)) return;
    if (!utils::ReadUint16(data, offset, advertisedTcpPort)) return;

    if (nodeId == local_.nodeId) return;

    KnownNode node{};
    if (auto existing = knownNodes_.FindByNodeId(nodeId)) node = *existing;
    node.nodeId = nodeId;
    if (!nickname.empty()) node.nickname = nickname;
    node.ip = ip;
    if (advertisedTcpPort != 0) node.port = advertisedTcpPort;
    node.observedUdpPort = port;
    node.lastSeen = std::chrono::steady_clock::now();
    knownNodes_.Upsert(node);
    UpsertContactHintsFromKnownNode(node);

    if (kind == 1) {
        ByteVector ack;
        utils::WriteUint32(ack, 0x55445031u);
        utils::WriteUint16(ack, 2);
        utils::WriteString(ack, local_.nodeId);
        utils::WriteString(ack, local_.nickname);
        utils::WriteUint16(ack, local_.listenPort);
        utils::WriteString(ack, ip);
        utils::WriteUint16(ack, port);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) == 1) {
            sendto(udpSocket_, reinterpret_cast<const char*>(ack.data()), static_cast<int>(ack.size()), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        }
        return;
    }

    if (kind == 2) {
        std::string observedIp;
        std::uint16_t observedPort = 0;
        if (!utils::ReadString(data, offset, observedIp)) return;
        if (!utils::ReadUint16(data, offset, observedPort)) return;
        std::lock_guard<std::mutex> lock(observedEndpointMutex_);
        localObservedUdpIp_ = observedIp;
        localObservedUdpPort_ = observedPort;
        return;
    }

    if (kind == 3) {
        utils::LogSystem("UDP punch packet received from " + nickname + " at " + ip + ":" + std::to_string(port));
        if (!peerManager_.HasNode(nodeId)) {
            TryConnectToKnownNode(node);
            RequestReverseConnect(node);
        }
    }
}

void P2PNode::TryAutoConnectKnownNodes() {
    auto nodes = knownNodes_.GetAllExcept(local_.nodeId);
    for (const auto& n : nodes) {
        if (!ShouldAttemptAutoConnect(n)) continue;
        MarkConnectAttempt(n.nodeId);
        if (!TryConnectToKnownNode(n)) {
            RequestReverseConnect(n);
            RequestUdpHolePunch(n);
        }
    }
}

bool P2PNode::PreferIncomingFor(const NodeId& remoteNodeId) const {
    return local_.nodeId > remoteNodeId;
}

void P2PNode::SafeClosePeer(const std::shared_ptr<PeerConnection>& peer) {
    if (peer) peer->RequestClose();
}

std::optional<PendingInvite> P2PNode::FindIncomingInviteByFromNodeId(const NodeId& fromNodeId) const {
    std::lock_guard<std::mutex> lock(invitesMutex_);
    for (const auto& [_, inv] : incomingInvites_) if (inv.fromNodeId == fromNodeId) return inv;
    return std::nullopt;
}

std::optional<SessionId> P2PNode::FindSessionByPeer(const NodeId& peerNodeId) const {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    auto it = sessionByPeer_.find(peerNodeId);
    if (it == sessionByPeer_.end()) return std::nullopt;
    return it->second;
}

} // namespace p2p
