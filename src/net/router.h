#pragma once

#include "core/types.h"

namespace p2p {

class Router {
public:
    bool MarkSeen(PacketId packetId);

private:
    std::mutex mutex_;
    std::unordered_set<PacketId> seen_;
    std::deque<PacketId> order_;
    static constexpr std::size_t kMaxSeen = 4096;
};

} // namespace p2p