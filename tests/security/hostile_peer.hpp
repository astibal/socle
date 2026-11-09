#pragma once

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <random>
#include <vector>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace socle::test::hostile {

struct CorpusConfig {
    std::uint32_t seed = 0x53454355U;
    std::size_t random_frames = 512;
    std::size_t max_random_size = 4096;
};

inline std::vector<std::vector<std::byte>> frame_corpus(const CorpusConfig& config = {}) {
    std::vector<std::vector<std::byte>> result{
        {},
        {std::byte{0}},
        {std::byte{'S'}},
        {std::byte{'S'}, std::byte{'C'}},
        {std::byte{'S'}, std::byte{'C'}, std::byte{0}},
        {std::byte{'S'}, std::byte{'C'}, std::byte{0xff}},
    };
    if(config.max_random_size == 0) return result;
    std::mt19937 generator(config.seed);
    std::uniform_int_distribution<std::size_t> size_distribution(1, config.max_random_size);
    std::uniform_int_distribution<unsigned> byte_distribution(0, 255);
    result.reserve(result.size() + config.random_frames);
    for(std::size_t iteration = 0; iteration < config.random_frames; ++iteration) {
        std::vector<std::byte> frame(size_distribution(generator));
        for(auto& byte: frame)
            byte = std::byte{static_cast<unsigned char>(byte_distribution(generator))};
        // Never accidentally generate a valid SC protocol frame. The caller
        // can therefore use a successful operation as an availability oracle.
        frame[0] = std::byte{static_cast<unsigned char>(iteration & 1U ? 'X' : 0)};
        result.emplace_back(std::move(frame));
    }
    return result;
}

enum class DrainResult { Reply, NoReply, PeerClosed, Error };

inline DrainResult send_and_drain(int fd, const std::vector<std::byte>& frame,
                                  std::chrono::milliseconds timeout =
                                      std::chrono::milliseconds(100)) {
    const std::byte empty{0};
    const void* data = frame.empty() ? static_cast<const void*>(&empty) : frame.data();
    const std::size_t size = frame.empty() ? 1 : frame.size();
    ssize_t sent;
    do { sent = ::send(fd, data, size, MSG_NOSIGNAL); } while(sent < 0 && errno == EINTR);
    if(sent != static_cast<ssize_t>(size)) return DrainResult::Error;

    pollfd descriptor{fd, POLLIN, 0};
    int ready;
    do { ready = ::poll(&descriptor, 1, static_cast<int>(timeout.count())); }
    while(ready < 0 && errno == EINTR);
    if(ready == 0) return DrainResult::NoReply;
    if(ready < 0) return DrainResult::Error;
    if((descriptor.revents & POLLIN) == 0) return DrainResult::PeerClosed;

    std::array<std::byte, 128U * 1024U> response{};
    ssize_t received;
    do { received = ::recv(fd, response.data(), response.size(), 0); }
    while(received < 0 && errno == EINTR);
    if(received > 0) return DrainResult::Reply;
    return received == 0 ? DrainResult::PeerClosed : DrainResult::Error;
}

inline std::size_t open_fd_count() {
    std::error_code error;
    std::size_t count = 0;
    for(std::filesystem::directory_iterator it("/proc/self/fd", error), end;
        !error && it != end; it.increment(error)) {
        ++count;
    }
    return error ? 0 : count;
}

} // namespace socle::test::hostile
