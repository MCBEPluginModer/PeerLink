#pragma once
#include "core/contact_store.h"
#include "core/conversation_store.h"
#include "core/fingerprint_utils.h"
#include "core/types.h"
#include "crypto/crypto_signer.h"
#include "net/known_nodes.h"
#include "net/peer_manager.h"
#include "net/router.h"

#include <map>

namespace p2p {

class PeerConnection;

class P2PNode {
public:
    P2PNode(std::string nickname, std::uint16_t listenPort);
    ~P2PNode();

    bool Start();
    void Stop();

    bool ConnectToPeer(const std::string& ip, std::uint16_t port);

    void BroadcastChat(const std::string& text);
    void SendInvite(const NodeId& targetNodeId);
    void AcceptInvite(const NodeId& fromNodeId);
    void RejectInvite(const NodeId& fromNodeId, const std::string& reason = "rejected");
    void SendPrivateMessage(const NodeId& targetNodeId, const std::string& text);
    bool OpenPrivateChat(const NodeId& peerNodeId, const std::string& peerNickname = "");
    bool DeleteConversationHistory(const NodeId& peerNodeId);
    bool IsPeerConnected(const NodeId& peerNodeId) const;

    bool AddOrUpdateContact(const NodeId& peerNodeId, const std::string& nickname = "");
    bool RemoveContact(const NodeId& peerNodeId);
    bool RenameContact(const NodeId& peerNodeId, const std::string& newNickname);
    bool AddContactFromInviteCode(const std::string& inviteCode);
    std::string BuildLocalInviteCode() const;
    void PrintContacts() const;
    void PrintFingerprint() const;
    bool TrustContactByIndex(int index);
    bool UntrustContactByIndex(int index);
    bool BlockContactByIndex(int index);
    bool UnblockContactByIndex(int index);
    bool RePinContactByIndex(int index);
    bool DistrustMismatchByIndex(int index);
    bool ApproveIdentityMigrationByIndex(int index);
    bool ResetSessionByIndex(int index);
    bool RekeySessionByIndex(int index);

    void PrintKnownNodes() const;
    void PrintInvites() const;
    void PrintSessions() const;
    void PrintInfo() const;
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
    bool CheckIncomingRateLimit(const std::shared_ptr<PeerConnection>& peer, PacketType type);

    void HandleHello(const std::shared_ptr<PeerConnection>& peer, const ByteVector& payload);
    void HandleHelloAck(const std::shared_ptr<PeerConnection>& peer, const ByteVector& payload);
    void HandleChat(const std::shared_ptr<PeerConnection>& peer, PacketId packetId, const ByteVector& payload);
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
    bool CanInteractWithContact(const NodeId& peerNodeId, bool requireTrusted, std::string* error = nullptr) const;
    bool GetVerificationPublicKeyForPeer(const NodeId& peerNodeId, const ByteVector& advertisedPublicKey, const ByteVector* advertisedEncryptPublicKey, ByteVector& out, std::string* error = nullptr);
    bool StoreVerifiedPeerIdentity(const NodeId& peerNodeId, const std::string& nickname, const ByteVector& verifiedPublicKey, const ByteVector& verifiedEncryptPublicKey, bool createIfMissing, bool trustNewContact, std::string* error = nullptr);

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
    void RequestReverseConnect(const KnownNode& target);
    void RequestUdpHolePunch(const KnownNode& target);
    bool TryConnectToKnownNode(const KnownNode& node);
    void SendUdpProbeToKnownNodes();
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
    void SetSessionState(const NodeId& peerNodeId, SessionId sessionId, PrivateSessionState state, const std::string& error = "");
    std::string DescribeSessionState(const PrivateSession& session) const;
    void MarkContactKeyMismatch(const NodeId& peerNodeId, const ByteVector& advertisedPublicKey, const ByteVector* advertisedEncryptPublicKey = nullptr, const std::string& nicknameHint = "");
    bool ClearContactKeyMismatch(const NodeId& peerNodeId, bool adoptPendingKey, bool trustAfterAdopt, bool markMigration, std::string* error = nullptr);
    bool ResetSessionForPeer(const NodeId& peerNodeId, const std::string& reason, PrivateSessionState newState = PrivateSessionState::Closed);
    void DropInvitesForPeer(const NodeId& peerNodeId);
    void EnsureSessionForPeer(const NodeId& peerNodeId, const std::string& peerNickname, SessionId sessionId);
    bool SetSessionKeyForPeer(const NodeId& peerNodeId, SessionId sessionId, const ByteVector& sessionKey);
    bool GetSessionKeyForPeer(const NodeId& peerNodeId, ByteVector& sessionKeyOut) const;
    void RequestHistorySync(const NodeId& peerNodeId);
    void RetryRelayQueues();
    bool SaveRelaySpoolToDisk() const;
    void LoadRelaySpoolFromDisk();
    void LoadBootstrapNodes();
    void TryConnectBootstrapNodes();
    void PrintStoredConversation(const NodeId& peerNodeId, const std::string& peerNicknameHint = "") const;
    bool LoadOrCreateLocalIdentity();
    void RestorePrivateSessionsFromHistory();

private:
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
    std::string relaySpoolRootDir_ = "relay_spool";
    std::string bootstrapConfigPath_ = "bootstrap_nodes.txt";

    mutable std::mutex observedEndpointMutex_;
    std::string localObservedIp_;
    std::uint16_t localObservedPort_ = 0;
    std::string localObservedUdpIp_;
    std::uint16_t localObservedUdpPort_ = 0;

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

    struct RateLimiterState {
        double generalTokens = 80.0;
        double messageTokens = 24.0;
        std::chrono::steady_clock::time_point lastRefill = std::chrono::steady_clock::now();
        std::uint32_t violations = 0;
    };

    mutable std::mutex rateLimitMutex_;
    std::unordered_map<SOCKET, RateLimiterState> rateLimitBySocket_;

    std::string contactsRootDir_ = "contacts";
    mutable std::mutex contactsMutex_;
    std::unordered_map<NodeId, ContactEntry> contacts_;

    const std::string sessionRootDir_ = "sessions";

    const std::chrono::seconds heartbeatInterval_{5};
    const std::chrono::seconds heartbeatTimeout_{30};
    const std::chrono::hours relayMessageTtl_{24};
    const std::chrono::hours relayAckTtl_{6};
    const double generalRatePerSecond_{16.0};
    const double generalBurst_{80.0};
    const double messageRatePerSecond_{6.0};
    const double messageBurst_{24.0};
    const std::uint32_t maxRateViolations_{20};
};

} // namespace p2p
