#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "hostcx.hpp"
#include "baseproxy.hpp"
#include "tcpcom.hpp"
#include "udpcom.hpp"

namespace {

class CountingTCPCom : public TCPCom {
public:
    baseCom* replicate() override { return new CountingTCPCom(); }
    ssize_t write(int, const void*, size_t size, int) override {
        ++write_calls;
        last_write_size = size;
        return 0;
    }

    int write_calls = 0;
    std::size_t last_write_size = 0;
};

class ChunkedTCPCom : public TCPCom {
public:
    explicit ChunkedTCPCom(std::vector<std::uint8_t> input = {},
                           std::size_t chunk_size = 16 * 1024,
                           std::size_t successful_writes = SIZE_MAX)
        : input_(std::move(input)), chunk_size_(chunk_size),
          successful_writes_(successful_writes) {}

    baseCom* replicate() override { return new ChunkedTCPCom(); }

    ssize_t read(int, void* destination, size_t size, int) override {
        if(read_offset_ == input_.size()) {
            errno = EAGAIN;
            return -1;
        }
        auto const count = std::min({size, chunk_size_, input_.size() - read_offset_});
        std::copy_n(input_.data() + read_offset_, count,
                    static_cast<std::uint8_t*>(destination));
        read_offset_ += count;
        ++read_calls;
        return static_cast<ssize_t>(count);
    }

    ssize_t write(int, const void* source, size_t size, int) override {
        if(size == 0) return 0;
        if(write_calls >= successful_writes_) {
            errno = EAGAIN;
            return -1;
        }
        auto const count = std::min(size, chunk_size_);
        auto const* bytes = static_cast<std::uint8_t const*>(source);
        output.insert(output.end(), bytes, bytes + count);
        ++write_calls;
        return static_cast<ssize_t>(count);
    }

    std::vector<std::uint8_t> output;
    std::size_t read_calls = 0;
    std::size_t write_calls = 0;

private:
    std::vector<std::uint8_t> input_;
    std::size_t chunk_size_;
    std::size_t successful_writes_;
    std::size_t read_offset_ = 0;
};

class PostWriteTrackingHostCX : public baseHostCX {
public:
    PostWriteTrackingHostCX(baseCom* transport, bool incremental)
        : baseHostCX(transport, -1), incremental_(incremental) {}

    std::size_t post_write_calls = 0;

protected:
    void post_write() override { ++post_write_calls; }
    bool write_needs_incremental_flush() override { return incremental_; }

private:
    bool incremental_;
};

class ScopedIoBatch {
public:
    explicit ScopedIoBatch(std::size_t value)
        : previous_(baseHostCX::params_t::io_batch.exchange(value)) {}
    ~ScopedIoBatch() { baseHostCX::params_t::io_batch = previous_; }
private:
    std::size_t previous_;
};

class RawAcceptCountingProxy : public baseProxy {
public:
    explicit RawAcceptCountingProxy(baseCom* transport) : baseProxy(transport) {
        new_raw(true);
    }

    std::size_t left_callbacks = 0;

protected:
    void on_left_new_raw(int) override { ++left_callbacks; }
};

class SocketPair {
public:
    SocketPair() {
        if(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd_.data()) != 0) {
            fd_ = {-1, -1};
        }
    }

    ~SocketPair() {
        for(auto fd: fd_) {
            if(fd >= 0) ::close(fd);
        }
    }

    int release_first() {
        auto const fd = fd_[0];
        fd_[0] = -1;
        return fd;
    }

    int second() const { return fd_[1]; }
    bool valid() const { return fd_[0] >= 0 && fd_[1] >= 0; }

private:
    std::array<int, 2> fd_ {-1, -1};
};

std::vector<std::uint8_t> pattern(std::size_t size) {
    std::vector<std::uint8_t> value(size);
    for(std::size_t i = 0; i < value.size(); ++i) {
        value[i] = static_cast<std::uint8_t>(i % 251);
    }
    return value;
}

std::size_t send_available(int fd, std::vector<std::uint8_t> const& data) {
    std::size_t sent = 0;
    while(sent < data.size()) {
        auto const result = ::send(fd, data.data() + sent, data.size() - sent,
                                   MSG_NOSIGNAL);
        if(result > 0) {
            sent += static_cast<std::size_t>(result);
            continue;
        }
        if(result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        return sent;
    }
    return sent;
}

TEST(TransferDrain, ReadConsumesMultipleSocketChunksPerDispatch) {
    SocketPair sockets;
    ASSERT_TRUE(sockets.valid());

    auto const payload = pattern(128 * 1024);
    auto const sent = send_available(sockets.second(), payload);
    ASSERT_GT(sent, baseHostCX::params_t::buffsize.load()) << "send errno=" << errno;

    baseHostCX connection(new TCPCom(), sockets.release_first());
    connection.opening(false);

    auto const received = connection.read();
    ASSERT_EQ(received, static_cast<int>(sent));
    ASSERT_EQ(connection.readbuf()->size(), sent);
    EXPECT_TRUE(std::equal(payload.begin(), payload.begin() + sent,
                           connection.readbuf()->data()));
}

TEST(TransferDrain, WriteConsumesMultipleTlsSizedChunksPerDispatch) {
    SocketPair sockets;
    ASSERT_TRUE(sockets.valid());

    auto const payload = pattern(128 * 1024);
    baseHostCX connection(new TCPCom(), sockets.release_first());
    connection.opening(false);
    connection.writebuf()->append(payload.data(), payload.size());

    auto const written = connection.write();
    ASSERT_EQ(written, static_cast<int>(payload.size())) << "write errno=" << errno;
    EXPECT_TRUE(connection.writebuf()->empty());

    std::vector<std::uint8_t> received(payload.size());
    std::size_t received_size = 0;
    while(received_size < received.size()) {
        auto const result = ::recv(sockets.second(), received.data() + received_size,
                                   received.size() - received_size, 0);
        if(result > 0) {
            received_size += static_cast<std::size_t>(result);
            continue;
        }
        if(result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        break;
    }

    ASSERT_EQ(received_size, payload.size());
    EXPECT_EQ(received, payload);
}

TEST(TransferDrain, EmptyWriteStillTicksTransportStateMachine) {
    auto* transport = new CountingTCPCom();
    baseHostCX connection(transport, -1);
    connection.opening(false);

    EXPECT_EQ(connection.write(), 0);
    EXPECT_EQ(transport->write_calls, 1);
    EXPECT_EQ(transport->last_write_size, 0U);
}

TEST(TransferDrain, ReadStopsAtFairnessBudget) {
    constexpr std::size_t batch = 64 * 1024;
    ScopedIoBatch batch_guard(batch);
    auto const payload = pattern(batch * 2);
    auto* transport = new ChunkedTCPCom(payload);
    baseHostCX connection(transport, -1);
    connection.opening(false);

    EXPECT_EQ(connection.read(), static_cast<int>(batch));
    EXPECT_EQ(connection.readbuf()->size(), batch);
    EXPECT_GT(transport->read_calls, 1U);
}

TEST(TransferDrain, ReadLimitSurvivesMultiplePartialReads) {
    constexpr std::size_t limit = 20 * 1024;
    constexpr std::size_t chunk = 8 * 1024;
    ScopedIoBatch batch_guard(64 * 1024);
    auto const payload = pattern(32 * 1024);
    auto* transport = new ChunkedTCPCom(payload, chunk);
    baseHostCX connection(transport, -1);
    connection.opening(false);
    connection.read_limit(limit);

    EXPECT_EQ(connection.read(), static_cast<int>(limit));
    EXPECT_EQ(connection.readbuf()->size(), limit);
    EXPECT_GT(transport->read_calls, 1U);
    EXPECT_TRUE(std::equal(payload.begin(), payload.begin() + limit,
                           connection.readbuf()->data()));
}

TEST(TransferDrain, WriteStopsAtFairnessBudget) {
    constexpr std::size_t batch = 64 * 1024;
    ScopedIoBatch batch_guard(batch);
    auto const payload = pattern(batch * 2);
    auto* transport = new ChunkedTCPCom();
    baseHostCX connection(transport, -1);
    connection.opening(false);
    connection.writebuf()->append(payload.data(), payload.size());

    EXPECT_EQ(connection.write(), static_cast<int>(batch));
    EXPECT_EQ(connection.writebuf()->size(), batch);
    EXPECT_EQ(transport->write_calls, batch / (16 * 1024));
    ASSERT_EQ(transport->output.size(), batch);
    EXPECT_TRUE(std::equal(payload.begin(), payload.begin() + batch,
                           transport->output.begin()));
}

TEST(TransferDrain, CompactsWriteBufferOncePerBatch) {
    constexpr std::size_t batch = 64 * 1024;
    ScopedIoBatch batch_guard(batch);
    auto const payload = pattern(batch * 2);
    auto* transport = new ChunkedTCPCom();
    PostWriteTrackingHostCX connection(transport, false);
    connection.opening(false);
    connection.writebuf()->append(payload.data(), payload.size());

    EXPECT_EQ(connection.write(), static_cast<int>(batch));
    EXPECT_EQ(connection.post_write_calls, 1U);
    EXPECT_EQ(connection.writebuf()->size(), batch);
    ASSERT_EQ(transport->output.size(), batch);
    EXPECT_TRUE(std::equal(payload.begin(), payload.begin() + batch,
                           transport->output.begin()));
    EXPECT_TRUE(std::equal(payload.begin() + batch, payload.end(),
                           connection.writebuf()->data()));
}

TEST(TransferDrain, PreservesIncrementalPostWriteSemantics) {
    constexpr std::size_t batch = 64 * 1024;
    ScopedIoBatch batch_guard(batch);
    auto const payload = pattern(batch);
    auto* transport = new ChunkedTCPCom();
    PostWriteTrackingHostCX connection(transport, true);
    connection.opening(false);
    connection.writebuf()->append(payload.data(), payload.size());

    EXPECT_EQ(connection.write(), static_cast<int>(batch));
    EXPECT_EQ(connection.post_write_calls, batch / (16 * 1024));
    EXPECT_TRUE(connection.writebuf()->empty());
    EXPECT_EQ(transport->output, payload);
}

TEST(TransferDrain, ReturnsProgressWhenDrainEndsInWouldBlock) {
    constexpr std::size_t chunk = 16 * 1024;
    auto const payload = pattern(chunk * 4);
    auto* transport = new ChunkedTCPCom({}, chunk, 1);
    baseHostCX connection(transport, -1);
    connection.opening(false);
    connection.writebuf()->append(payload.data(), payload.size());

    EXPECT_EQ(connection.write(), static_cast<int>(chunk));
    EXPECT_EQ(connection.writebuf()->size(), payload.size() - chunk);
    EXPECT_EQ(transport->output.size(), chunk);
    EXPECT_TRUE(std::equal(payload.begin() + chunk, payload.end(),
                           connection.writebuf()->data()));
}

TEST(AcceptDrain, DatagramListenerGetsOneCallbackPerReadinessEvent) {
    auto const listener_fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_GE(listener_fd, 0);

    RawAcceptCountingProxy proxy(new UDPCom());
    baseHostCX listener(new UDPCom(), listener_fd);

    EXPECT_EQ(proxy.handle_sockets_accept_batch('l', proxy.com(), &listener), 1U);
    EXPECT_EQ(proxy.left_callbacks, 1U);
}

} // namespace
