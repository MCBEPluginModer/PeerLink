#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace p2p {

class SafeBuffer {
public:
    SafeBuffer() = default;
    explicit SafeBuffer(std::size_t size) : data_(size) {}

    std::size_t Size() const noexcept { return data_.size(); }
    bool Empty() const noexcept { return data_.empty(); }

    std::uint8_t* Data() noexcept { return data_.data(); }
    const std::uint8_t* Data() const noexcept { return data_.data(); }

    void Resize(std::size_t size) { data_.resize(size); }
    void Clear() noexcept { data_.clear(); }

    std::uint8_t& At(std::size_t index) {
        if (index >= data_.size()) {
            throw std::out_of_range("SafeBuffer::At out of range");
        }
        return data_[index];
    }

    const std::uint8_t& At(std::size_t index) const {
        if (index >= data_.size()) {
            throw std::out_of_range("SafeBuffer::At out of range");
        }
        return data_[index];
    }

private:
    std::vector<std::uint8_t> data_;
};

} // namespace p2p
