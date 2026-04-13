#include "net/router.h"

namespace p2p {

bool Router::MarkSeen(PacketId packetId) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (seen_.contains(packetId)) {
        return false;
    }

    seen_.insert(packetId);
    order_.push_back(packetId);

    if (order_.size() > kMaxSeen) {
        auto old = order_.front();
        order_.pop_front();
        seen_.erase(old);
    }

    return true;
}

} // namespace p2p