#pragma once
#include "core/contact_store.h"
#include "core/conversation_store.h"
#include "core/fingerprint_utils.h"
#include "core/overlay_state.h"
#include "core/peer_reputation.h"
#include "core/types.h"
#include "core/version.h"
#include "crypto/crypto_signer.h"
#include "crypto/key_lifecycle.h"
#include "crypto/secure_key_store.h"
#include "net/known_nodes.h"
#include "net/peer_manager.h"
#include "net/router.h"
#include "net/stun_turn_client.h"

#include <filesystem>
#include <deque>
#include <fstream>
#include <map>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace p2p {

class PeerConnection;

class P2PNode {
public:

enum class ControlMessageKind {
    Unknown = 0,
    GroupSync,
    DeviceLink,
    DeviceRevoke,
    DeviceSync,
    FileMeta,
    FileOffer,
    FileAccept,
    FileReject,
    FileChunk,
    GroupMessage
};

enum class ControlFlowState {
    Idle = 0,
    Received,
    Parsed,
    Validated,
    Applied,
    Rejected,
    Failed
};

enum class FileTransferState {
    Offered = 0,
    Accepted,
    Transferring,
    Completed,
    Rejected,
    Failed
};

enum class ProtocolFlowResult {
    None = 0,
    Retried,
    TimedOut,
    Resumed
};

struct ControlEnvelope {
    ControlMessageKind kind = ControlMessageKind::Unknown;
    std::vector<std::string> parts;
    std::string raw;
    NodeId senderNodeId;
    std::string senderNickname;
};

    P2PNode(std::string nickname, std::uint16_t listenPort);
    ~P2PNode();

    bool Start();
    void Stop();

    bool ConnectToPeer(const std::string& ip, std::uint16_t port);

    void BroadcastChat(const std::string& text);
    bool PublishPost(const std::string& title, const std::string& body);
    void PrintPosts(std::size_t limit = 20) const;
    void SendInvite(const NodeId& targetNodeId);
    void AcceptInvite(const NodeId& fromNodeId);
    void RejectInvite(const NodeId& fromNodeId, const std::string& reason = "rejected");
    void SendPrivateMessage(const NodeId& targetNodeId, const std::string& text);
    bool OpenPrivateChat(const NodeId& peerNodeId, const std::string& peerNickname = "");
    bool DeleteConversationHistory(const NodeId& peerNodeId);
    bool CheckConversationHistory(const NodeId& peerNodeId);
    bool RepairConversationHistory(const NodeId& peerNodeId);
    bool IsPeerConnected(const NodeId& peerNodeId) const;
    bool ExportConversationHistoryByContactIndex(int index, const std::string& path) const;
    bool SearchConversationHistoryByContactIndex(int index, const std::string& term) const;

    bool AddOrUpdateContact(const NodeId& peerNodeId, const std::string& nickname = "");
    bool RemoveContact(const NodeId& peerNodeId);
    bool RenameContact(const NodeId& peerNodeId, const std::string& newNickname);
    bool AddContactFromInviteCode(const std::string& inviteCode);
    std::string BuildLocalInviteCode() const;
    void PrintContacts() const;
    void PrintFingerprint() const;
    void PrintKeyStatus() const;
    bool BackupLocalKeys(const std::string& backupDir = "profile/key_backups");
    bool RotateLocalKeys();
    bool RevokeLocalKeys();
    bool TrustContactByIndex(int index);
    bool UntrustContactByIndex(int index);
    bool BlockContactByIndex(int index);
    bool UnblockContactByIndex(int index);
    bool VerifyContactKeyByIndex(int index);
    bool UnverifyContactKeyByIndex(int index);
    bool PrintSafetyNumberByIndex(int index) const;

    void PrintKnownNodes() const;
    void PrintPeerReputation() const;
    void PrintInvites() const;
    void PrintSessions() const;
    void PrintInfo() const;
    void PrintStats() const;
    void PrintNatStatus() const;
    void PrintDevices() const;
    void PrintGroups() const;
    bool LinkDeviceByContactIndex(int index, const std::string& label = "");
    bool RevokeDeviceByIndex(int index);
    bool CreateGroup(const std::string& name);
    bool AddGroupMember(int groupIndex, int contactIndex);
    bool RemoveGroupMember(int groupIndex, int contactIndex);
    bool ChangeGroupRole(int groupIndex, int contactIndex, const std::string& roleText);
    bool SyncGroupByIndex(int groupIndex);
    bool SendGroupMessageByIndex(int groupIndex, const std::string& text);
    bool SendAttachmentByContactIndex(int contactIndex, const std::string& path);
    bool SendGroupAttachmentByIndex(int groupIndex, const std::string& path);
    void PrintPendingFiles() const;
    void PrintFileTransfers() const;
    void PrintControlStates() const;
    bool AcceptPendingFileByIndex(int index);
    bool RejectPendingFileByIndex(int index);
    bool CancelFileTransferByIndex(int index);
    bool SyncDeviceByIndex(int index);
    std::vector<DisplayUser> GetDisplayUsers() const;
    std::vector<DisplayInvite> GetDisplayInvites() const;

    void OnPacket(const std::shared_ptr<PeerConnection>& peer, PacketType type, PacketId packetId, const ByteVector& payload);
    void OnPeerDisconnected(SOCKET socket);

private:
    bool InitWinSock();
    void CleanupWinSock();

    void AcceptLoop();
    void DiscoveryLoop();
    void UdpRecvLoop();

    void SendHello(const std::shared_ptr<PeerConnection>& peer);
    void SendHelloAck(const std::shared_ptr<PeerConnection>& peer);
    void SendPeerList(const std::shared_ptr<PeerConnection>& peer);
    void BroadcastPeerListToAll();
    void SendPing(const std::shared_ptr<PeerConnection>& peer);
    void SendPong(const std::shared_ptr<PeerConnection>& peer);
    void RunHeartbeatChecks();
    void CleanupExpiredRelayQueues();
    void CleanupPendingHandshakes();
    bool CheckIncomingRateLimit(const std::shared_ptr<PeerConnection>& peer, PacketType type);

    void HandleHello(const std::shared_ptr<PeerConnection>& peer, const ByteVector& payload);
    void HandleHelloAck(const std::shared_ptr<PeerConnection>& peer, const ByteVector& payload);
    void HandleChat(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
    void HandlePost(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
    void HandlePostSyncRequest(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
    void HandlePostSyncResponse(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
    void HandlePeerList(const ByteVector& payload);
    void HandleInviteRequest(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
    void HandleInviteAccept(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
    void HandleInviteReject(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
    void HandlePrivateMessage(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
    void HandleMessageAck(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
    void HandleConnectRequest(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
    void HandleUdpPunchRequest(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
    void HandleRelayPrivateMessage(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
    void HandleRelayMessageAck(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
    void HandleHistorySyncRequest(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
    void HandleHistorySyncResponse(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);

    bool FinalizePeerAfterHandshake(const std::shared_ptr<PeerConnection>& peer, const HelloPayload& hello);
    void BroadcastRaw(const ByteVector& packet, const NodeId& excludeNodeId = "");
    void TryAutoConnectKnownNodes();
    bool ShouldAttemptAutoConnect(const KnownNode& node);
    void MarkConnectAttempt(const NodeId& nodeId);
    void NoteReconnectFailure(const NodeId& nodeId);
    void ResetReconnectState(const NodeId& nodeId);
    bool PreferIncomingFor(const NodeId& remoteNodeId) const;
    void SafeClosePeer(const std::shared_ptr<PeerConnection>& peer);

    std::optional<PendingInvite> FindIncomingInviteByFromNodeId(const NodeId& fromNodeId) const;
    std::optional<SessionId> FindSessionByPeer(const NodeId& peerNodeId) const;

    bool SaveContacts() const;
    void LoadContacts();
    std::optional<ContactEntry> FindContact(const NodeId& peerNodeId) const;
    std::string ResolveDisplayName(const NodeId& peerNodeId, const std::string& fallback = "") const;
    void UpsertContactHintsFromKnownNode(const KnownNode& node);
    bool IsBlockedNode(const NodeId& peerNodeId) const;
    std::string ComputeSafetyNumberForKey(const ByteVector& keyBlob) const;

    ByteVector BuildInviteRequestSignedData(const InviteRequestPayload& p) const;
    ByteVector BuildInviteAcceptSignedData(const InviteAcceptPayload& p) const;
    ByteVector BuildInviteRejectSignedData(const InviteRejectPayload& p) const;
    ByteVector BuildPrivateMessageSignedData(const PrivateMessagePayload& p) const;
    bool EncryptPrivateMessagePayload(PrivateMessagePayload& payload, const ByteVector& sessionKey) const;
    bool DecryptPrivateMessagePayload(PrivateMessagePayload& payload, const ByteVector& sessionKey) const;
    ByteVector BuildMessageAckSignedData(const MessageAckPayload& p) const;
    ByteVector BuildConnectRequestSignedData(const ConnectRequestPayload& p) const;
    ByteVector BuildUdpPunchRequestSignedData(const UdpPunchRequestPayload& p) const;
    ByteVector BuildHistorySyncRequestSignedData(const HistorySyncRequestPayload& p) const;
    ByteVector BuildHistorySyncResponseSignedData(const HistorySyncResponsePayload& p) const;
    ByteVector BuildPostSignedData(const PostPayload& p) const;
    ByteVector BuildPostSyncRequestSignedData(const PostSyncRequestPayload& p) const;
    ByteVector BuildPostSyncResponseSignedData(const PostSyncResponsePayload& p) const;
void RoutePublishedPost(const PostPayload& payload, PacketId packetId, const NodeId& excludeNodeId = "");
std::vector<std::shared_ptr<PeerConnection>> SelectRelayPeers(std::size_t maxPeers, const NodeId& excludeNodeId = "") const;
void RepropagatePostWithDelay(PostPayload payload, PacketId packetId, const NodeId& excludeNodeId = "");
    void RequestReverseConnect(const KnownNode& target);
    void RequestUdpHolePunch(const KnownNode& target);
    bool TryConnectToKnownNode(const KnownNode& node);
    void SendUdpProbeToKnownNodes();
    void TickNatTraversalServices();
    void LoadNatTraversalConfig();
    bool SendStunTurnDatagram(const std::string& ip, std::uint16_t port, const std::vector<std::uint8_t>& data);
    void SendUdpProbeToEndpoint(const std::string& ip, std::uint16_t port);
    void SendUdpPunchBurst(const KnownNode& node, const std::string& reason);
    void HandleUdpDatagram(const std::string& ip, std::uint16_t port, const ByteVector& data);
    void AppendStoredPrivateMessage(const PrivateMessagePayload& payload, StoredMessageDirection direction, StoredMessageState state, const ByteVector& signerPublicKeyBlob);
    bool HasStoredMessageForPeer(const NodeId& peerNodeId, MessageId messageId) const;
    bool UpdateStoredMessageState(const NodeId& peerNodeId, MessageId messageId, StoredMessageState newState);
    std::uint64_t GetNextOutgoingSequence(const NodeId& peerNodeId);
    std::uint64_t GetExpectedIncomingSequence(const NodeId& peerNodeId);
    void DeliverOrderedIncomingPrivateMessage(const PrivateMessagePayload& payload, const ByteVector& signerPublicKeyBlob, PacketId ackedRelayPacketId, bool logMessage);
    void BufferOrDeliverIncomingPrivateMessage(const PrivateMessagePayload& payload, const ByteVector& signerPublicKeyBlob, PacketId ackedRelayPacketId, bool logMessage);
    bool RelayPrivateMessageToNetwork(const PrivateMessagePayload& payload);
    bool RelayMessageAckToNetwork(const MessageAckPayload& payload);
    void QueueRelayMessage(const RelayPrivateMessagePayload& payload);
    void QueueRelayAck(const RelayMessageAckPayload& payload);
    void FlushRelayQueueForTarget(const NodeId& targetNodeId);
    void FlushRelayAckQueueForTarget(const NodeId& targetNodeId);
    void RemoveQueuedRelayMessageByMessageId(const NodeId& targetNodeId, MessageId messageId);
    void RemoveQueuedRelayAckByMessageId(const NodeId& targetNodeId, MessageId messageId);
    void SendDeliveryAck(const PrivateMessagePayload& message, PacketId ackedRelayPacketId);
    void EnsureSessionForPeer(const NodeId& peerNodeId, const std::string& peerNickname, SessionId sessionId);
    bool SetSessionKeyForPeer(const NodeId& peerNodeId, SessionId sessionId, const ByteVector& sessionKey);
    bool GetSessionKeyForPeer(const NodeId& peerNodeId, ByteVector& sessionKeyOut) const;
    void RequestHistorySync(const NodeId& peerNodeId);
    void RetryRelayQueues();
    bool SaveMessageJournalToDisk() const;
    bool SaveReplayCacheToDisk() const;
    void FlushReplayCacheIfDirty() const;
    void LoadMessageJournalFromDisk();
    void LoadReplayCacheFromDisk();
    void ReplayJournalEntries();
    void TrackPendingJournalMessage(const PrivateMessagePayload& payload);
    void RemovePendingJournalMessage(MessageId messageId);
    bool SaveRelaySpoolToDisk() const;
    void LoadRelaySpoolFromDisk();
    void LoadBootstrapNodes();
    void TryConnectBootstrapNodes();
    void PrintStoredConversation(const NodeId& peerNodeId, const std::string& peerNicknameHint = "") const;
    bool LoadOrCreateLocalIdentity();
    void RestorePrivateSessionsFromHistory();
    bool SaveOverlayState() const;
    void LoadOverlayState();
    void ProcessOverlayPrivateMessage(const PrivateMessagePayload& payload);
    void SendGroupSnapshotToMember(const GroupEntry& group, const GroupMemberEntry& member);
    std::vector<ContactEntry> GetSortedContacts() const;
    std::vector<DeviceEntry> GetSortedDevices() const;
    std::vector<GroupEntry> GetSortedGroups() const;
    std::string BuildGroupSyncText(const GroupEntry& group) const;
    bool ApplyGroupSyncText(const NodeId& senderNodeId, const std::string& text);
    bool ApplyDeviceLinkText(const NodeId& senderNodeId, const std::string& text);
    bool ApplyFileMetaText(const NodeId& senderNodeId, const std::string& text);
    bool SendFileOfferToPeer(const NodeId& targetNodeId, const std::string& displayName, const std::filesystem::path& srcPath, const std::string& groupId = "", const std::string& groupName = "");
    bool ApplyFileOfferText(const NodeId& senderNodeId, const std::string& senderNickname, const std::string& text);
    bool ApplyFileAcceptText(const NodeId& senderNodeId, const std::string& text);
    bool ApplyFileRejectText(const NodeId& senderNodeId, const std::string& text);
    bool ApplyFileChunkText(const NodeId& senderNodeId, const std::string& text);
    bool MarkRecentIncomingMessage(MessageId messageId);
    bool MarkRecentControlReplay(const std::string& replayKey);
    std::uint64_t GetLocalCapabilityFlags() const;
    bool IsCompatibleHello(const HelloPayload& hello, std::string* reason = nullptr) const;
    bool SendFileChunksStream(const std::string& transferId, std::size_t startChunk);
    ControlEnvelope ParseControlEnvelope(const PrivateMessagePayload& payload) const;
    bool DispatchControlMessage(const ControlEnvelope& envelope);
    void UpdateControlState(const std::string& key, ControlFlowState state);
    bool ValidateControlStateTransition(ControlFlowState oldState, ControlFlowState newState) const;
    std::string MakeControlStateKey(const ControlEnvelope& envelope) const;
    void TickProtocolFlows();
    ProtocolFlowResult RetryTimedOutControl(const std::string& key);
    void TickFileTransfers();
    bool RetryFileTransfer(const std::string& transferId);
    void ResumePendingFlows();
    bool MirrorConversationToDevice(const NodeId& deviceNodeId, std::size_t maxMessages = 16);
    bool ApplyDeviceSyncText(const NodeId& senderNodeId, const std::string& text);
    void LoadPostsFromDisk();
    bool SavePostToDisk(const PostPayload& payload, bool signatureVerified);
    void RequestPostSync(const NodeId& peerNodeId);

private:

    struct RuntimeMetrics {
        std::uint64_t rateLimitHits = 0;
        std::uint64_t handshakeRejects = 0;
        std::uint64_t handshakeFloodRejects = 0;
        std::uint64_t handshakeCooldownBlocks = 0;
        std::uint64_t replayDrops = 0;
        std::uint64_t relayQueueDrops = 0;
        std::uint64_t fileTransferCancels = 0;
        std::uint64_t fileTransferCompletions = 0;
        std::uint64_t fileTransferRetries = 0;
        std::uint64_t fileTransferFailures = 0;
        std::uint64_t historySearches = 0;
        std::uint64_t historyExports = 0;
        std::uint64_t stunQueries = 0;
        std::uint64_t stunSuccesses = 0;
        std::uint64_t turnAllocations = 0;
        std::uint64_t turnRefreshes = 0;
        std::uint64_t relayQueuePressureEvents = 0;
        std::uint64_t relayRetryBudgetDrops = 0;
        std::uint64_t crashRecoveryRestarts = 0;
        std::uint64_t crashRecoveryTransferResumes = 0;
    };

    struct ControlStateEntry {
        ControlFlowState state = ControlFlowState::Idle;
        std::int64_t updatedAtUnix = 0;
        std::int64_t deadlineUnix = 0;
        std::uint32_t retryCount = 0;
        std::uint32_t maxRetries = 3;
        ControlMessageKind kind = ControlMessageKind::Unknown;
        std::string senderNodeId;
        std::string token;
    };

    struct FileTransferStatus {
        std::string transferId;
        NodeId peerNodeId;
        std::string peerNickname;
        std::string fileName;
        std::uint64_t fileSize = 0;
        FileTransferState state = FileTransferState::Offered;
        std::size_t currentChunk = 0;
        std::size_t totalChunks = 0;
        bool incoming = false;
        bool resumable = false;
        bool peerAccepted = false;
        std::uint32_t retryCount = 0;
        std::uint32_t maxRetries = 3;
        std::int64_t deadlineUnix = 0;
        std::string sourcePath;
        std::string groupName;
        std::string fileChecksum;
        std::uint64_t bytesTransferred = 0;
        std::int64_t updatedAtUnix = 0;
    };

    struct OutgoingFileTransfer {
        std::string transferId;
        NodeId targetNodeId;
        std::string targetNickname;
        std::string fileName;
        std::uint64_t fileSize = 0;
        std::string groupId;
        std::string groupName;
        std::string sourcePath;
        std::size_t totalChunks = 0;
        std::size_t nextChunkIndex = 0;
        std::string fileChecksum;
        bool streamInProgress = false;
    };

    struct IncomingFileOffer {
        std::string transferId;
        NodeId senderNodeId;
        std::string senderNickname;
        std::string fileName;
        std::uint64_t fileSize = 0;
        std::string groupId;
        std::string groupName;
        std::size_t totalChunks = 0;
        std::string fileChecksum;
        bool accepted = false;
    };

    struct IncomingFileTransfer {
        IncomingFileOffer offer;
        std::size_t totalChunks = 0;
        std::size_t nextExpectedChunk = 1;
        std::uint64_t receivedBytes = 0;
        std::string tempPath;
        std::string rollingChecksum;
    };

    struct PublicPostRecord {
        std::string postId;
        NodeId authorNodeId;
        std::string authorNickname;
        std::uint64_t createdAtUnix = 0;
        std::string title;
        std::string body;
        ByteVector authorPublicKeyBlob;
        ByteVector signature;
        bool signatureVerified = false;
    };

    LocalNodeInfo local_;
    SOCKET listenSocket_ = INVALID_SOCKET;
    SOCKET udpSocket_ = INVALID_SOCKET;
    std::atomic<bool> running_{false};
    bool winsockInitialized_ = false;

    std::thread acceptThread_;
    std::thread discoveryThread_;
    std::thread udpThread_;

    PeerManager peerManager_;
    Router router_;
    KnownNodeTable knownNodes_;
    CryptoSigner signer_;

    mutable std::mutex publicKeysMutex_;
    std::unordered_map<NodeId, ByteVector> publicKeys_;
    std::unordered_map<NodeId, ByteVector> publicEncryptKeys_;
    ByteVector localPublicKeyBlob_;
    ByteVector localEncryptPublicKeyBlob_;
    std::string historyRootDir_ = "history";
    std::string messageJournalRootDir_ = "message_journal";
    std::string relaySpoolRootDir_ = "relay_spool";
    std::string bootstrapConfigPath_ = "bootstrap_nodes.txt";

    mutable std::mutex observedEndpointMutex_;
    std::string localObservedIp_;
    std::uint16_t localObservedPort_ = 0;
    std::string localObservedUdpIp_;
    std::uint16_t localObservedUdpPort_ = 0;
    std::string relayedIp_;
    std::uint16_t relayedPort_ = 0;

    mutable std::mutex natMutex_;
    std::vector<nat::ServerEndpoint> stunServers_;
    std::vector<nat::ServerEndpoint> turnServers_;
    std::size_t nextStunServerIndex_ = 0;
    std::size_t nextTurnServerIndex_ = 0;
    std::int64_t lastStunQueryUnix_ = 0;
    std::int64_t lastTurnAttemptUnix_ = 0;
    std::int64_t lastTurnRefreshUnix_ = 0;
    std::unique_ptr<nat::StunTurnClient> natClient_;

    mutable std::mutex pendingMutex_;
    std::unordered_map<SOCKET, std::shared_ptr<PeerConnection>> pendingPeers_;

    mutable std::mutex connectAttemptsMutex_;

    struct ReconnectState {
        std::uint32_t failureCount = 0;
        std::chrono::steady_clock::time_point nextAttempt{};
    };

    mutable std::mutex reconnectMutex_;
    std::unordered_map<NodeId, ReconnectState> reconnectStates_;
    std::unordered_map<NodeId, std::chrono::steady_clock::time_point> lastConnectAttempt_;
    mutable std::mutex bootstrapMutex_;
    std::vector<BootstrapEndpoint> bootstrapNodes_;

    mutable std::mutex postsMutex_;
    std::vector<PublicPostRecord> postsFeed_;
    std::unordered_set<std::string> knownPostIds_;
    std::string postsRootDir_ = "posts";
    mutable std::mutex postPublishRateMutex_;
    std::deque<std::int64_t> localPostPublishTimes_;

    mutable std::mutex invitesMutex_;
    std::unordered_map<InviteId, PendingInvite> incomingInvites_;
    std::unordered_map<InviteId, PendingInvite> outgoingInvites_;

    mutable std::mutex sessionsMutex_;
    std::unordered_map<SessionId, PrivateSession> sessionsById_;
    std::unordered_map<NodeId, SessionId> sessionByPeer_;

    mutable std::mutex relayMutex_;
    std::unordered_map<NodeId, std::deque<QueuedRelayMessage>> relayQueuesByTarget_;
    std::unordered_map<NodeId, std::deque<QueuedRelayAck>> relayAckQueuesByTarget_;
    std::unordered_set<PacketId> deliveredRelayPackets_;
    std::unordered_set<PacketId> deliveredRelayAckPackets_;

    struct BufferedIncomingPrivateMessage {
        PrivateMessagePayload payload;
        ByteVector signerPublicKeyBlob;
        PacketId ackedRelayPacketId = 0;
        bool logMessage = false;
    };

    mutable std::mutex sequenceMutex_;
    std::unordered_map<NodeId, std::uint64_t> nextOutgoingSequenceByPeer_;
    std::unordered_map<NodeId, std::uint64_t> expectedIncomingSequenceByPeer_;
    std::unordered_map<NodeId, std::map<std::uint64_t, BufferedIncomingPrivateMessage>> reorderBufferByPeer_;

    mutable std::mutex ackMutex_;
    std::unordered_set<MessageId> seenMessageAcks_;
    std::unordered_set<MessageId> deliveredOutgoingMessageIds_;

    mutable std::mutex replayMutex_;
    std::string replayCacheRootDir_ = "profile/replay_cache";
    std::unordered_set<MessageId> recentIncomingMessageIds_;
    std::deque<MessageId> recentIncomingMessageOrder_;
    std::unordered_set<std::string> recentControlReplayKeys_;
    std::deque<std::string> recentControlReplayOrder_;
    mutable bool replayCacheDirty_ = false;
    mutable std::int64_t replayCacheLastFlushUnix_ = 0;

    struct PendingJournalMessage {
        MessageId messageId = 0;
        NodeId targetNodeId;
        ByteVector privateMessagePayload;
        std::uint32_t replayCount = 0;
        std::int64_t createdAtUnix = 0;
        std::int64_t lastAttemptUnix = 0;
        std::int64_t nextAttemptUnix = 0;
    };

    mutable std::mutex journalMutex_;
    std::unordered_map<MessageId, PendingJournalMessage> pendingJournalMessages_;

    struct RateLimiterState {
        double generalTokens = 80.0;
        double messageTokens = 24.0;
        std::chrono::steady_clock::time_point lastRefill = std::chrono::steady_clock::now();
        std::uint32_t violations = 0;
    };

    mutable std::mutex rateLimitMutex_;
    std::unordered_map<SOCKET, RateLimiterState> rateLimitBySocket_;

    mutable std::mutex metricsMutex_;
    mutable RuntimeMetrics metrics_;

    mutable std::mutex handshakeGuardMutex_;
    std::unordered_map<std::string, std::deque<std::int64_t>> incomingHandshakeAttemptsByIp_;
    std::unordered_map<NodeId, std::int64_t> blockedHandshakeUntilByNodeId_;

    mutable std::mutex reputationMutex_;
    PeerReputationStore peerReputation_;

    std::string contactsRootDir_ = "contacts";
    mutable std::mutex contactsMutex_;
    std::unordered_map<NodeId, ContactEntry> contacts_;

    mutable std::mutex fileTransfersMutex_;
    std::unordered_map<std::string, OutgoingFileTransfer> outgoingFileTransfers_;
    std::unordered_map<std::string, IncomingFileOffer> pendingIncomingFileOffers_;
    std::unordered_map<std::string, IncomingFileTransfer> incomingFileTransfers_;
    std::unordered_map<std::string, FileTransferStatus> fileTransferStatuses_;

    std::string overlayRootDir_ = "overlay";
    mutable std::mutex overlayMutex_;
    OverlayState overlayState_;

    mutable std::mutex controlStateMutex_;
    std::unordered_map<std::string, ControlStateEntry> controlStates_;

    const std::string sessionRootDir_ = "sessions";

    const std::chrono::seconds heartbeatInterval_{5};
    const std::chrono::seconds heartbeatTimeout_{45};
    const std::chrono::hours relayMessageTtl_{24};
    const std::chrono::hours relayAckTtl_{6};
    const double generalRatePerSecond_{16.0};
    const double generalBurst_{80.0};
    const double messageRatePerSecond_{6.0};
    const double messageBurst_{24.0};
    const std::uint32_t maxRateViolations_{20};
    const std::int64_t controlTimeoutSeconds_{20};
    const std::int64_t transferTimeoutSeconds_{45};
    const std::size_t maxRecentIncomingMessageIds_{8192};
    const std::size_t maxRecentControlReplayKeys_{8192};
    const std::size_t maxPendingHandshakes_{32};
    const std::size_t maxHandshakeAttemptsPerIpWindow_{8};
    const std::int64_t handshakeWindowSeconds_{10};
    const std::int64_t handshakeTimeoutSeconds_{8};
    const std::int64_t blockedHandshakeCooldownSeconds_{20};
    const std::size_t maxRelayQueuePerTarget_{256};
    const std::size_t maxParallelIncomingTransfers_{3};
    const std::size_t maxOutgoingFileTransfers_{16};
    const std::size_t maxPendingIncomingFileOffers_{64};
    const std::size_t maxPostTitleBytes_{256};
    const std::size_t maxPostBodyBytes_{64 * 1024};
    const std::size_t maxPostSyncPostsPerResponse_{512};
    const std::size_t maxPostSyncBlobBytes_{2 * 1024 * 1024};
    const std::size_t maxPostPublishesPerMinute_{20};
    const std::int64_t stunRefreshSeconds_{45};
    const std::int64_t turnRetrySeconds_{90};
    const std::int64_t turnRefreshSeconds_{300};
    const std::size_t relayRetryBudgetPerTarget_{64};
};

} // namespace p2p
