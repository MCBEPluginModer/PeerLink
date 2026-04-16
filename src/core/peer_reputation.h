#pragma once

#include "core/types.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace p2p {

struct PeerReputationRecord {
    NodeId nodeId;
    int score = 0;
    std::uint32_t goodEvents = 0;
    std::uint32_t rateLimitViolations = 0;
    std::uint32_t invalidPackets = 0;
    std::uint32_t signatureFailures = 0;
    std::uint32_t disconnects = 0;
    std::uint32_t manualTrustBoosts = 0;
    bool blocked = false;
    std::int64_t updatedAtUnix = 0;
};

class PeerReputationStore {
public:
    bool Load(const std::string& localNodeId, std::string* error);
    bool Save(const std::string& localNodeId, std::string* error) const;

    void NoteGoodEvent(const NodeId& nodeId, int delta = 2);
    void NoteRateLimitViolation(const NodeId& nodeId, int delta = -12);
    void NoteInvalidPacket(const NodeId& nodeId, int delta = -10);
    void NoteSignatureFailure(const NodeId& nodeId, int delta = -20);
    void NoteDisconnect(const NodeId& nodeId, int delta = -2);
    void NoteTrustedContact(const NodeId& nodeId, int delta = 8);

    const PeerReputationRecord* Find(const NodeId& nodeId) const;
    bool ShouldBlock(const NodeId& nodeId) const;
    std::vector<PeerReputationRecord> GetAllSorted() const;

private:
    PeerReputationRecord& Touch(const NodeId& nodeId);
    void ClampAndFlag(PeerReputationRecord& rec);

private:
    std::unordered_map<NodeId, PeerReputationRecord> records_;
};

} // namespace p2p
