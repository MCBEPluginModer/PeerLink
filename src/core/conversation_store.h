#pragma once

#include "core/types.h"

#include <string>
#include <vector>

namespace p2p {

class CryptoSigner;

enum class StoredMessageDirection {
    Incoming,
    Outgoing
};

enum class StoredMessageState {
    Created,
    Queued,
    Sent,
    Relayed,
    Delivered,
    Failed
};

struct StoredConversationMessage {
    StoredMessageDirection direction = StoredMessageDirection::Incoming;
    std::uint64_t messageId = 0;
    std::uint64_t sessionId = 0;
    std::uint64_t sequenceNumber = 0;
    NodeId fromNodeId;
    std::string fromNickname;
    NodeId toNodeId;
    std::string text;
    ByteVector iv;
    ByteVector ciphertext;
    std::string storedAtUtc;
    StoredMessageState state = StoredMessageState::Created;
};


struct StoredSignedPrivateMessage {
    PrivateMessagePayload payload;
    ByteVector signerPublicKeyBlob;
};

class ConversationStore {
public:
    static bool AppendPrivateMessage(const std::string& rootDir,
                                     const NodeId& localNodeId,
                                     const NodeId& peerNodeId,
                                     const PrivateMessagePayload& payload,
                                     StoredMessageDirection direction,
                                     StoredMessageState state,
                                     const ByteVector& signerPublicKeyBlob,
                                     CryptoSigner& signer,
                                     const ByteVector& localPublicKeyBlob,
                                     std::string* error = nullptr);

    static bool VerifyAllForLocalNode(const std::string& rootDir,
                                      const NodeId& localNodeId,
                                      CryptoSigner& signer,
                                      std::vector<std::string>* problems = nullptr);

    static bool LoadConversation(const std::string& rootDir,
                                 const NodeId& localNodeId,
                                 const NodeId& peerNodeId,
                                 CryptoSigner& signer,
                                 std::vector<StoredConversationMessage>& outMessages,
                                 std::string* error = nullptr);

    static std::optional<SessionId> GetLatestSessionId(const std::string& rootDir,
                                                       const NodeId& localNodeId,
                                                       const NodeId& peerNodeId,
                                                       CryptoSigner& signer,
                                                       std::string* error = nullptr);

    static bool EnumerateLatestSessions(const std::string& rootDir,
                                        const NodeId& localNodeId,
                                        CryptoSigner& signer,
                                        std::vector<StoredConversationMessage>& outLatestMessages,
                                        std::string* error = nullptr);

    static bool DeleteConversation(const std::string& rootDir,
                                   const NodeId& localNodeId,
                                   const NodeId& peerNodeId,
                                   std::string* error = nullptr);

    static bool LoadSignedOutgoingMessagesAfter(const std::string& rootDir,
                                                const NodeId& localNodeId,
                                                const NodeId& peerNodeId,
                                                MessageId afterMessageId,
                                                CryptoSigner& signer,
                                                std::vector<StoredSignedPrivateMessage>& outMessages,
                                                std::string* error = nullptr);

    static bool HasMessageId(const std::string& rootDir,
                             const NodeId& localNodeId,
                             const NodeId& peerNodeId,
                             MessageId messageId,
                             CryptoSigner& signer,
                             bool* exists,
                             std::string* error = nullptr);

    static bool UpdateMessageState(const std::string& rootDir,
                                   const NodeId& localNodeId,
                                   const NodeId& peerNodeId,
                                   MessageId messageId,
                                   StoredMessageState newState,
                                   CryptoSigner& signer,
                                   const ByteVector& localPublicKeyBlob,
                                   std::string* error = nullptr);

    static bool CheckConversation(const std::string& rootDir,
                                  const NodeId& localNodeId,
                                  const NodeId& peerNodeId,
                                  CryptoSigner& signer,
                                  std::string* error = nullptr);

    static bool RepairConversation(const std::string& rootDir,
                                   const NodeId& localNodeId,
                                   const NodeId& peerNodeId,
                                   CryptoSigner& signer,
                                   const ByteVector& localPublicKeyBlob,
                                   std::string* error = nullptr);
};

} // namespace p2p
