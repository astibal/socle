#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <sys/socket.h>
#include <thread>
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

class WriteEventPendingTCPCom : public CountingTCPCom {
public:
    bool write_event_pending() const override { return true; }
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

struct LifecycleState {
    std::size_t cleanup_calls = 0;
    std::size_t shutdown_calls = 0;
    std::size_t close_calls = 0;
    int shutdown_fd = 0;
    int close_fd = 0;
};

class LifecycleTCPCom : public TCPCom {
public:
    explicit LifecycleTCPCom(LifecycleState* state,
                             std::vector<std::uint8_t> input = {},
                             bool eof_after_input = false,
                             std::size_t chunk_size = 16 * 1024,
                             std::size_t successful_writes = SIZE_MAX,
                             bool consumes_fd = false)
        : state_(state), input_(std::move(input)),
          eof_after_input_(eof_after_input), chunk_size_(chunk_size),
          successful_writes_(successful_writes), consumes_fd_(consumes_fd) {}

    baseCom* replicate() override { return new LifecycleTCPCom(state_); }

    ssize_t read(int, void* destination, size_t size, int) override {
        if(read_offset_ < input_.size()) {
            auto const count = std::min({size, chunk_size_, input_.size() - read_offset_});
            std::copy_n(input_.data() + read_offset_, count,
                        static_cast<std::uint8_t*>(destination));
            read_offset_ += count;
            return static_cast<ssize_t>(count);
        }
        if(eof_after_input_) return 0;
        errno = EAGAIN;
        return -1;
    }

    ssize_t write(int, const void* source, size_t size, int) override {
        if(size == 0) return 0;
        if(write_calls_ >= successful_writes_) {
            errno = EPIPE;
            return -1;
        }
        auto const count = std::min(size, chunk_size_);
        auto const* bytes = static_cast<std::uint8_t const*>(source);
        output.insert(output.end(), bytes, bytes + count);
        ++write_calls_;
        return static_cast<ssize_t>(count);
    }

    void cleanup() override { ++state_->cleanup_calls; }
    void shutdown(int fd) override {
        ++state_->shutdown_calls;
        state_->shutdown_fd = fd;
    }
    void close(int fd) override {
        ++state_->close_calls;
        state_->close_fd = fd;
    }
    bool shutdown_consumes_fd() const override { return consumes_fd_; }
    bool com_status() override { return ready_; }
    void ready(bool value) { ready_ = value; }

    std::vector<std::uint8_t> output;

private:
    LifecycleState* state_;
    std::vector<std::uint8_t> input_;
    bool eof_after_input_;
    std::size_t chunk_size_;
    std::size_t successful_writes_;
    bool consumes_fd_;
    bool ready_ = true;
    std::size_t read_offset_ = 0;
    std::size_t write_calls_ = 0;
};

class CrossDirectionTCPCom : public LifecycleTCPCom {
public:
    explicit CrossDirectionTCPCom(LifecycleState* state)
        : LifecycleTCPCom(state) {}

    bool readable(int) override { return false; }
    bool writable(int) override { return false; }

    ssize_t read(int fd, void* destination, size_t size, int flags) override {
        ++read_calls;
        return LifecycleTCPCom::read(fd, destination, size, flags);
    }
    ssize_t write(int fd, const void* source, size_t size, int flags) override {
        ++write_calls;
        return LifecycleTCPCom::write(fd, source, size, flags);
    }

    std::size_t read_calls = 0;
    std::size_t write_calls = 0;
};

class AcceptOnceTCPCom : public LifecycleTCPCom {
public:
    AcceptOnceTCPCom(LifecycleState* state, int accepted_fd)
        : LifecycleTCPCom(state), state_(state), accepted_fd_(accepted_fd) {}

    baseCom* replicate() override { return new LifecycleTCPCom(state_); }
    int accept(int, sockaddr*, socklen_t*) override {
        if(accepted_fd_ < 0) {
            errno = EAGAIN;
            return -1;
        }
        auto const result = accepted_fd_;
        accepted_fd_ = -1;
        return result;
    }

private:
    LifecycleState* state_;
    int accepted_fd_;
};

class ReconnectingTCPCom : public LifecycleTCPCom {
public:
    explicit ReconnectingTCPCom(LifecycleState* state)
        : LifecycleTCPCom(state), state_(state) {}

    baseCom* replicate() override { return new ReconnectingTCPCom(state_); }
    int connect(const char*, const char*) override { return next_fd_++; }

private:
    LifecycleState* state_;
    int next_fd_ = 101;
};

class ConnectResultTCPCom : public LifecycleTCPCom {
public:
    ConnectResultTCPCom(LifecycleState* state, int result)
        : LifecycleTCPCom(state), state_(state), result_(result) {}

    baseCom* replicate() override { return new ConnectResultTCPCom(state_, result_); }
    int connect(const char*, const char*) override { return result_; }

private:
    LifecycleState* state_;
    int result_;
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

class RecordingProxy : public baseProxy {
public:
    explicit RecordingProxy(baseCom* transport) : baseProxy(transport) {}

    std::size_t left_errors = 0;
    std::size_t right_errors = 0;
    std::size_t left_messages = 0;
    std::size_t right_messages = 0;
    std::size_t left_pc_errors = 0;
    std::size_t right_pc_errors = 0;

    void on_left_error(baseHostCX*) override { ++left_errors; }
    void on_right_error(baseHostCX*) override { ++right_errors; }
    void on_left_message(baseHostCX*) override { ++left_messages; }
    void on_right_message(baseHostCX*) override { ++right_messages; }
    void on_left_pc_error(baseHostCX*) override { ++left_pc_errors; }
    void on_right_pc_error(baseHostCX*) override { ++right_pc_errors; }

    void restore_left(baseHostCX* cx) { baseProxy::on_left_pc_restore(cx); }
    void restore_right(baseHostCX* cx) { baseProxy::on_right_pc_restore(cx); }
    void adopt_left(std::unique_ptr<baseHostCX> cx) { baseProxy::on_left_new(std::move(cx)); }
    void adopt_right(std::unique_ptr<baseHostCX> cx) { baseProxy::on_right_new(std::move(cx)); }
};

class ConnectFactoryProxy : public RecordingProxy {
public:
    explicit ConnectFactoryProxy(baseCom* transport) : RecordingProxy(transport) {}

    LifecycleState* next_state = nullptr;
    int next_result = -1;

    baseHostCX* new_cx(const char* host, const char* port) override {
        return new baseHostCX(new ConnectResultTCPCom(next_state, next_result), host, port);
    }
};

class ThrowingAcceptProxy : public baseProxy {
public:
    ThrowingAcceptProxy(baseCom* transport, LifecycleState* child_state)
        : baseProxy(transport), child_state_(child_state) {}

    baseHostCX* new_cx(int descriptor) override {
        return new baseHostCX(new LifecycleTCPCom(child_state_), descriptor);
    }

    void on_left_new(std::unique_ptr<baseHostCX>) override {
        throw std::runtime_error("handoff failed");
    }

private:
    LifecycleState* child_state_;
};

class MessageHostCX : public baseHostCX {
public:
    using baseHostCX::baseHostCX;
    bool new_message() const override { return has_message; }
    bool has_message = true;
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

TEST(TransferLifecycle, PreservesReadProgressWhenPeerThenCloses) {
    auto const payload = pattern(32 * 1024);
    LifecycleState state;
    baseHostCX connection(new LifecycleTCPCom(&state, payload, true), -1);
    connection.opening(false);

    EXPECT_EQ(connection.read(), static_cast<int>(payload.size()));
    EXPECT_EQ(connection.readbuf()->size(), payload.size());
    EXPECT_FALSE(connection.error());
    EXPECT_TRUE(connection.read_eof());
    EXPECT_TRUE(std::equal(payload.begin(), payload.end(),
                           connection.readbuf()->data()));
}

TEST(TransferLifecycle, PreservesWrittenPrefixAndMarksFatalTailError) {
    constexpr std::size_t chunk = 16 * 1024;
    auto const payload = pattern(chunk * 3);
    LifecycleState state;
    auto* transport = new LifecycleTCPCom(&state, {}, false, chunk, 1);
    baseHostCX connection(transport, -1);
    connection.opening(false);
    connection.writebuf()->append(payload.data(), payload.size());

    EXPECT_EQ(connection.write(), static_cast<int>(chunk));
    EXPECT_TRUE(connection.error());
    EXPECT_EQ(connection.writebuf()->size(), payload.size() - chunk);
    EXPECT_EQ(transport->output.size(), chunk);
    EXPECT_TRUE(std::equal(payload.begin() + chunk, payload.end(),
                           connection.writebuf()->data()));
}

TEST(TransferLifecycle, CloseAfterWriteDefersRegularDescriptorCloseExactlyOnce) {
    auto const payload = pattern(1024);
    LifecycleState state;
    {
        auto* transport = new LifecycleTCPCom(&state);
        baseHostCX connection(transport, 101);
        connection.opening(false);
        connection.close_after_write(true);
        connection.writebuf()->append(payload.data(), payload.size());

        EXPECT_EQ(connection.write(), static_cast<int>(payload.size()));
        EXPECT_EQ(connection.socket(), 0);
        EXPECT_EQ(connection.closed_socket(), 101);
        EXPECT_EQ(state.shutdown_calls, 1U);
        EXPECT_EQ(state.shutdown_fd, 101);
        EXPECT_EQ(state.close_calls, 0U);
    }
    EXPECT_EQ(state.cleanup_calls, 1U);
    EXPECT_EQ(state.close_calls, 1U);
    EXPECT_EQ(state.close_fd, 101);
}

TEST(TransferLifecycle, ConsumedDescriptorIsNotClosedAgain) {
    auto const payload = pattern(1024);
    LifecycleState state;
    {
        auto* transport = new LifecycleTCPCom(&state, {}, false,
                                               16 * 1024, SIZE_MAX, true);
        baseHostCX connection(transport, 102);
        connection.opening(false);
        connection.close_after_write(true);
        connection.writebuf()->append(payload.data(), payload.size());

        EXPECT_EQ(connection.write(), static_cast<int>(payload.size()));
        EXPECT_EQ(connection.socket(), 0);
        EXPECT_EQ(connection.closed_socket(), 0);
        EXPECT_EQ(state.shutdown_calls, 1U);
        EXPECT_EQ(state.shutdown_fd, 102);
    }
    EXPECT_EQ(state.cleanup_calls, 1U);
    EXPECT_EQ(state.close_calls, 0U);
}

TEST(TransferLifecycle, ForcedReadEagainAppliesOnce) {
    auto const payload = pattern(1024);
    LifecycleState state;
    baseHostCX connection(new LifecycleTCPCom(&state, payload), -1);
    connection.opening(false);
    connection.read_force_eagain();

    EXPECT_EQ(connection.read(), -1);
    EXPECT_TRUE(connection.readbuf()->empty());
    EXPECT_EQ(connection.read(), static_cast<int>(payload.size()));
    EXPECT_EQ(connection.readbuf()->size(), payload.size());
}

TEST(TransferLifecycle, PeerReadWaitReleasesOnlyAfterPeerIsReady) {
    auto const payload = pattern(1024);
    LifecycleState left_state;
    LifecycleState right_state;
    auto* left_transport = new LifecycleTCPCom(&left_state, payload);
    auto* right_transport = new LifecycleTCPCom(&right_state);
    left_transport->ready(true);
    right_transport->ready(false);
    baseHostCX left(left_transport, -1);
    baseHostCX right(right_transport, -1);
    left.opening(false);
    right.opening(false);
    left.peer(&right);
    right.peer(&left);
    left.read_waiting_for_peercom(true);

    EXPECT_EQ(left.read(), -1);
    EXPECT_TRUE(left.readbuf()->empty());
    EXPECT_FALSE(left.error());

    right_transport->ready(true);
    EXPECT_EQ(left.read(), static_cast<int>(payload.size()));
    EXPECT_EQ(left.readbuf()->size(), payload.size());
    EXPECT_FALSE(left.error());
}

TEST(TransferLifecycle, MissingPeerDuringWriteWaitIsFatal) {
    LifecycleState state;
    baseHostCX connection(new LifecycleTCPCom(&state), -1);
    connection.opening(false);
    connection.write_waiting_for_peercom(true);

    EXPECT_EQ(connection.write(), 0);
    EXPECT_TRUE(connection.error());
}

TEST(TransferLifecycle, FanoutPreservesSourceUntilFinalFastlaneDestination) {
    auto const payload = pattern(32 * 1024);
    LifecycleState first_state;
    LifecycleState final_state;
    baseHostCX first(new LifecycleTCPCom(&first_state), -1);
    baseHostCX final(new LifecycleTCPCom(&final_state), -2);
    first.meter_write_bytes = baseHostCX::params_t::fast_copy_start + 1;
    final.meter_write_bytes = baseHostCX::params_t::fast_copy_start + 1;

    buffer source(payload.size());
    source.append(payload.data(), payload.size());

    first.to_write(source, false);
    EXPECT_EQ(first.writebuf()->size(), payload.size());
    EXPECT_EQ(source.size(), payload.size());

    final.to_write(source, true);
    EXPECT_EQ(final.writebuf()->size(), payload.size());
    EXPECT_TRUE(source.empty());
    EXPECT_TRUE(std::equal(payload.begin(), payload.end(), first.writebuf()->data()));
    EXPECT_TRUE(std::equal(payload.begin(), payload.end(), final.writebuf()->data()));
}

TEST(ProxyLifecycle, PartialWriteThenFatalErrorStopsWithoutBottleneckRetry) {
    constexpr std::size_t chunk = 16 * 1024;
    auto const payload = pattern(chunk * 3);
    LifecycleState master_state;
    LifecycleState connection_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));
    auto* transport = new LifecycleTCPCom(&connection_state, {}, false, chunk, 1);
    baseHostCX connection(transport, -1);
    connection.opening(false);
    connection.writebuf()->append(payload.data(), payload.size());

    EXPECT_FALSE(proxy.handle_cx_write_once('l', proxy.com(), &connection));
    EXPECT_EQ(proxy.left_errors, 1U);
    EXPECT_FALSE(proxy.state().write_left_bottleneck());
    EXPECT_EQ(connection.socket(), 0);
    EXPECT_EQ(connection.writebuf()->size(), payload.size() - chunk);
}

TEST(ProxyLifecycle, DispatchesMessageBeforePeerWaitCanPauseIt) {
    LifecycleState master_state;
    LifecycleState connection_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));
    MessageHostCX connection(new LifecycleTCPCom(&connection_state), -1);
    connection.opening(false);
    connection.read_waiting_for_peercom(true);

    EXPECT_FALSE(proxy.handle_cx_events('l', &connection));
    EXPECT_EQ(proxy.left_messages, 1U);
    EXPECT_FALSE(connection.error());
}

TEST(ProxyLifecycle, DispatchesMessagesFromNormalAndPermanentSides) {
    LifecycleState master_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));
    std::array<LifecycleState, 4> states{};
    std::array<std::unique_ptr<MessageHostCX>, 4> contexts;
    constexpr std::array<unsigned char, 4> sides {'l', 'r', 'x', 'y'};

    for(std::size_t i = 0; i < contexts.size(); ++i) {
        contexts[i] = std::make_unique<MessageHostCX>(
            new LifecycleTCPCom(&states[i]), -20 - static_cast<int>(i));
        contexts[i]->opening(false);
        EXPECT_FALSE(proxy.handle_cx_events(sides[i], contexts[i].get()));
    }

    EXPECT_EQ(proxy.left_messages, 2U);
    EXPECT_EQ(proxy.right_messages, 2U);
}

TEST(ProxyLifecycle, SuccessfulReadWriteAndWriteErrorsRouteEverySide) {
    LifecycleState master_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));
    constexpr std::array<unsigned char, 4> sides {'l', 'r', 'x', 'y'};
    auto const payload = pattern(64);

    for(std::size_t i = 0; i < sides.size(); ++i) {
        LifecycleState state;
        baseHostCX connection(new LifecycleTCPCom(&state, payload),
                              -30 - static_cast<int>(i));
        connection.opening(false);
        EXPECT_TRUE(proxy.handle_cx_read(sides[i], &connection));
        EXPECT_EQ(connection.readbuf()->size(), payload.size());
    }
    EXPECT_EQ(proxy.stats().last_read, static_cast<int>(payload.size() * sides.size()));

    for(std::size_t i = 0; i < sides.size(); ++i) {
        LifecycleState state;
        auto* transport = new LifecycleTCPCom(&state);
        baseHostCX connection(transport, -40 - static_cast<int>(i));
        connection.opening(false);
        connection.writebuf()->append(payload.data(), payload.size());
        EXPECT_TRUE(proxy.handle_cx_write(sides[i], &connection));
        EXPECT_EQ(transport->output, payload);
    }
    EXPECT_EQ(proxy.stats().last_write, static_cast<int>(payload.size() * sides.size()));
    EXPECT_EQ(proxy.stats().mtr_down.total(), payload.size() * 2);
    EXPECT_EQ(proxy.stats().mtr_up.total(), payload.size() * 2);

    for(std::size_t i = 0; i < sides.size(); ++i) {
        LifecycleState state;
        baseHostCX connection(
            new LifecycleTCPCom(&state, {}, false, payload.size(), 0),
            -50 - static_cast<int>(i));
        connection.opening(false);
        connection.writebuf()->append(payload.data(), payload.size());
        EXPECT_FALSE(proxy.handle_cx_write(sides[i], &connection));
        EXPECT_EQ(state.shutdown_calls, 1U);
    }
    EXPECT_EQ(proxy.left_errors, 1U);
    EXPECT_EQ(proxy.right_errors, 1U);
    EXPECT_EQ(proxy.left_pc_errors, 1U);
    EXPECT_EQ(proxy.right_pc_errors, 1U);
}

TEST(ProxyLifecycle, CrossDirectionRetriesAreConsumedOnlyByMatchingEvents) {
    LifecycleState master_state;
    LifecycleState connection_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));
    auto* transport = new CrossDirectionTCPCom(&connection_state);
    baseHostCX connection(transport, -45);
    connection.opening(false);

    transport->forced_read_on_write(true);
    EXPECT_TRUE(proxy.handle_cx_read('l', &connection));
    EXPECT_EQ(transport->read_calls, 0U);
    EXPECT_TRUE(transport->forced_read_on_write());

    EXPECT_TRUE(proxy.handle_cx_read('l', &connection, true));
    EXPECT_EQ(transport->read_calls, 1U);
    EXPECT_FALSE(transport->forced_read_on_write());

    auto const payload = pattern(16);
    connection.writebuf()->append(payload.data(), payload.size());
    transport->forced_write_on_read(true);
    EXPECT_TRUE(proxy.handle_cx_write('l', &connection));
    EXPECT_EQ(transport->write_calls, 0U);
    EXPECT_TRUE(transport->forced_write_on_read());

    EXPECT_TRUE(proxy.handle_cx_write('l', &connection, true));
    EXPECT_EQ(transport->write_calls, 1U);
    EXPECT_FALSE(transport->forced_write_on_read());
}

TEST(ProxyLifecycle, RoutesErrorsBySideAndShutsEachContextDown) {
    LifecycleState master_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));

    for (const unsigned char side : {'l', 'r', 'x', 'y'}) {
        LifecycleState connection_state;
        baseHostCX connection(new LifecycleTCPCom(&connection_state), -1);
        connection.opening(false);
        connection.error(true);

        EXPECT_FALSE(proxy.handle_cx_events(side, &connection));
        EXPECT_EQ(connection.socket(), 0);
        EXPECT_EQ(connection_state.shutdown_calls, 1U);
    }

    EXPECT_EQ(proxy.left_errors, 1U);
    EXPECT_EQ(proxy.right_errors, 1U);
    EXPECT_EQ(proxy.left_pc_errors, 1U);
    EXPECT_EQ(proxy.right_pc_errors, 1U);
}

TEST(ProxyLifecycle, SideMonitoringCoversNormalAndBoundContexts) {
    LifecycleState master_state;
    LifecycleState normal_state;
    LifecycleState bound_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));
    auto* normal = new baseHostCX(new LifecycleTCPCom(&normal_state), -1);
    auto* bound = new baseHostCX(new LifecycleTCPCom(&bound_state), -2);
    normal->opening(false);
    bound->opening(false);
    proxy.ladd(normal);
    proxy.lbadd(bound);

    EXPECT_EQ(proxy.change_side_monitoring('l', true, false, 1, 0), 2U);
    EXPECT_TRUE(normal->read_waiting_for_peercom());
    EXPECT_TRUE(bound->read_waiting_for_peercom());
    EXPECT_EQ(proxy.change_side_monitoring('l', true, false, -1, 0), 2U);
    EXPECT_FALSE(normal->read_waiting_for_peercom());
    EXPECT_FALSE(bound->read_waiting_for_peercom());
    EXPECT_EQ(proxy.change_side_monitoring('?', true, true, 1, 1), 0U);
}

TEST(ProxyLifecycle, ReadBackpressurePreservesPendingFullDuplexWrite) {
    int sockets[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);

    LifecycleState master_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));
    auto* blocked_transport = new CountingTCPCom();
    auto* reverse_transport = new CountingTCPCom();
    blocked_transport->master(proxy.com());
    reverse_transport->master(proxy.com());
    auto* blocked = new baseHostCX(blocked_transport, sockets[0]);
    auto* reverse = new baseHostCX(reverse_transport, sockets[1]);
    blocked->opening(false);
    reverse->opening(false);
    proxy.ladd(blocked);
    proxy.radd(reverse);

    auto const payload = pattern(1024);
    blocked->writebuf()->append(payload.data(), payload.size());
    reverse->writebuf()->append(payload.data(), payload.size());
    reverse->com()->set_write_monitor(reverse->socket());

    ASSERT_TRUE(proxy.handle_cx_write_once('l', proxy.com(), blocked));
    EXPECT_TRUE(proxy.state().write_left_bottleneck());
    EXPECT_TRUE(reverse->read_waiting_for_peercom());
    ASSERT_NE(proxy.poller(), nullptr);
    EXPECT_GT(proxy.poller()->wait(0), 0);
    EXPECT_TRUE(proxy.poller()->in_write_set(sockets[1]));

    EXPECT_EQ(proxy.change_side_monitoring('r', true, false, -1, 0), 1U);
    EXPECT_GT(proxy.poller()->wait(0), 0);
    EXPECT_TRUE(proxy.poller()->in_write_set(sockets[1]));
    EXPECT_FALSE(reverse->read_waiting_for_peercom());
}

TEST(ProxyLifecycle, ReadBackpressureDoesNotAddWriteInterestToListener) {
    int sockets[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);

    LifecycleState master_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));
    auto* listener_transport = new CountingTCPCom();
    listener_transport->master(proxy.com());
    auto* listener = new baseHostCX(listener_transport, sockets[0]);
    ASSERT_TRUE(listener->opening());
    proxy.lbadd(listener);

    EXPECT_EQ(proxy.change_side_monitoring('l', false, false, 1, 0), 1U);
    ASSERT_NE(proxy.poller(), nullptr);
    EXPECT_EQ(proxy.poller()->wait(0), 0);
    EXPECT_TRUE(listener->read_waiting_for_peercom());

    ::close(sockets[1]);
}

TEST(ProxyLifecycle, ReadEofKeepsWriteHalfAvailableForDelayedResponse) {
    int sockets[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);

    LifecycleState master_state;
    LifecycleState connection_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));
    auto* transport = new LifecycleTCPCom(&connection_state, {}, true);
    transport->master(proxy.com());
    baseHostCX connection(transport, sockets[0]);
    connection.opening(false);
    proxy.com()->set_monitor(sockets[0]);

    EXPECT_TRUE(proxy.handle_cx_read('l', &connection));
    EXPECT_TRUE(connection.read_eof());
    EXPECT_FALSE(connection.error());
    EXPECT_EQ(connection.socket(), sockets[0]);
    EXPECT_EQ(connection_state.shutdown_calls, 0U);
    EXPECT_EQ(proxy.left_errors, 1U);

    auto const response = pattern(4096);
    connection.to_write(std::string(reinterpret_cast<char const*>(response.data()),
                                    response.size()));
    EXPECT_EQ(connection.write(), static_cast<int>(response.size()));
    EXPECT_EQ(transport->output, response);
    EXPECT_EQ(connection_state.shutdown_calls, 0U);
    ASSERT_NE(proxy.poller(), nullptr);
    EXPECT_EQ(proxy.poller()->wait(0), 0)
        << "drained write-only half must not retain a writable-event spin";

    connection.remove_socket();
    ::close(sockets[0]);
    ::close(sockets[1]);
}

TEST(ProxyLifecycle, PollDispatchDeliversQueuedOutputAfterReadHalfClose) {
    int sockets[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);

    LifecycleState master_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));
    auto* transport = new TCPCom();
    transport->master(proxy.com());
    auto* connection = new baseHostCX(transport, sockets[0]);
    connection->opening(false);
    proxy.ladd(connection);

    ASSERT_EQ(::shutdown(sockets[1], SHUT_WR), 0);
    connection->read_eof(true);
    std::string const response = "delayed-response";
    connection->to_write(response);

    ASSERT_NE(proxy.poller(), nullptr);
    ASSERT_GT(proxy.poller()->wait(1000), 0);
    proxy.run_poll();

    std::array<char, 64> received{};
    ASSERT_EQ(::recv(sockets[1], received.data(), received.size(), 0),
              static_cast<ssize_t>(response.size()));
    EXPECT_EQ(std::string_view(received.data(), response.size()), response);
    EXPECT_EQ(proxy.poller()->wait(0), 0)
        << "delivered half-closed output must leave no readiness spin";

    ::close(sockets[1]);
}

TEST(TransferLifecycle, ReconnectResetsReadEofAndClosesRetiredDescriptor) {
    LifecycleState state;
    baseHostCX connection(new ReconnectingTCPCom(&state), "127.0.0.1", "1");

    ASSERT_EQ(connection.connect(), 101);
    connection.read_eof(true);
    connection.shutdown();
    EXPECT_EQ(state.shutdown_calls, 1U);
    EXPECT_EQ(state.close_calls, 0U);

    ASSERT_EQ(connection.connect(), 102);
    EXPECT_FALSE(connection.read_eof());
    EXPECT_EQ(state.close_calls, 1U);
    EXPECT_EQ(state.close_fd, 101);
}

TEST(TransferLifecycle, ReadRescanPreservesProtocolWriteEvent) {
    int sockets[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);

    LifecycleState master_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));
    auto* transport = new WriteEventPendingTCPCom();
    transport->master(proxy.com());
    baseHostCX connection(transport, sockets[0]);
    baseHostCX congested_peer(new CountingTCPCom(), -1);
    connection.opening(false);
    congested_peer.opening(false);
    connection.peer(&congested_peer);
    congested_peer.peer(&connection);
    proxy.com()->set_monitor(sockets[0]);

    std::vector<std::uint8_t> queued(baseHostCX::params_t::write_full + 1, 0x5a);
    congested_peer.writebuf()->append(queued.data(), queued.size());

    EXPECT_EQ(connection.read(), -1);
    ASSERT_NE(proxy.poller(), nullptr);
    EXPECT_TRUE(proxy.poller()->rescan_set_out.find(sockets[0]));
    EXPECT_FALSE(proxy.poller()->rescan_set_in.find(sockets[0]));

    ::close(sockets[1]);
}

TEST(AcceptDrain, DatagramListenerGetsOneCallbackPerReadinessEvent) {
    auto const listener_fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_GE(listener_fd, 0);

    RawAcceptCountingProxy proxy(new UDPCom());
    baseHostCX listener(new UDPCom(), listener_fd);

    EXPECT_EQ(proxy.handle_sockets_accept_batch('l', proxy.com(), &listener), 1U);
    EXPECT_EQ(proxy.left_callbacks, 1U);
}

TEST(ProxyLifecycle, ExceptionDuringAcceptedContextHandoffClosesExactlyOnce) {
    SocketPair pair;
    ASSERT_TRUE(pair.valid());
    auto const accepted_fd = pair.release_first();

    LifecycleState master_state;
    LifecycleState listener_state;
    LifecycleState child_state;
    ThrowingAcceptProxy proxy(new AcceptOnceTCPCom(&master_state, accepted_fd),
                              &child_state);
    baseHostCX listener(new LifecycleTCPCom(&listener_state), -1);

    EXPECT_THROW(proxy.handle_sockets_accept('l', proxy.com(), &listener),
                 std::runtime_error);
    EXPECT_EQ(child_state.cleanup_calls, 1U);
    EXPECT_EQ(child_state.close_calls, 1U);
    EXPECT_EQ(child_state.close_fd, accepted_fd);

    // LifecycleTCPCom records close operations without calling the syscall.
    ::close(accepted_fd);
}

TEST(ProxyLifecycle, RegistersOwnsAndShutsDownEveryContextClass) {
    LifecycleState master_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));
    std::array<LifecycleState, 8> states{};
    std::array<int, 8> peers{};

    auto make_connection = [&](std::size_t index) {
        int pair[2] {-1, -1};
        EXPECT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair), 0);
        peers[index] = pair[1];
        auto* transport = new LifecycleTCPCom(&states[index]);
        transport->master(proxy.com());
        auto* connection = new baseHostCX(transport, pair[0]);
        connection->opening(false);
        return connection;
    };

    proxy.ladd(make_connection(0));
    proxy.radd(make_connection(1));
    proxy.lbadd(make_connection(2));
    proxy.rbadd(make_connection(3));
    proxy.lpcadd(make_connection(4));
    proxy.rpcadd(make_connection(5));
    proxy.ldaadd(make_connection(6));
    proxy.rdaadd(make_connection(7));

    EXPECT_EQ(proxy.lsize(), 4);
    EXPECT_EQ(proxy.rsize(), 4);
    auto description = proxy.to_string(iDIA);
    EXPECT_NE(description.find("a:"), std::string::npos);
    EXPECT_NE(description.find("l:"), std::string::npos);
    EXPECT_NE(description.find("x:"), std::string::npos);
    EXPECT_NE(description.find("r:"), std::string::npos);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_TRUE(proxy.run_timers());

    proxy.shutdown();
    EXPECT_EQ(proxy.lsize(), 0);
    EXPECT_EQ(proxy.rsize(), 0);
    for (auto const& state : states) EXPECT_EQ(state.shutdown_calls, 1U);
    for (auto fd : peers) ::close(fd);
}

TEST(ProxyLifecycle, DefaultOwnershipAndPermanentRestoreCallbacksRemainUsable) {
    LifecycleState master_state;
    LifecycleState left_state;
    LifecycleState right_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));
    auto left = std::make_unique<baseHostCX>(new LifecycleTCPCom(&left_state), -101);
    auto right = std::make_unique<baseHostCX>(new LifecycleTCPCom(&right_state), -102);
    auto* left_raw = left.get();
    auto* right_raw = right.get();
    left_raw->opening(true);
    right_raw->opening(true);

    proxy.adopt_left(std::move(left));
    proxy.adopt_right(std::move(right));
    EXPECT_EQ(proxy.lsize(), 1);
    EXPECT_EQ(proxy.rsize(), 1);
    proxy.restore_left(left_raw);
    proxy.restore_right(right_raw);
    EXPECT_FALSE(left_raw->opening());
    EXPECT_FALSE(right_raw->opening());
}

TEST(ProxyLifecycle, FailedPermanentConnectReleasesBothSideContexts) {
    LifecycleState master_state;
    LifecycleState left_state;
    LifecycleState right_state;
    ConnectFactoryProxy proxy(new LifecycleTCPCom(&master_state));

    proxy.next_state = &left_state;
    proxy.next_result = -1;
    EXPECT_EQ(proxy.connect("192.0.2.1", "443", 'L'), -1);
    EXPECT_EQ(left_state.cleanup_calls, 1U);
    EXPECT_TRUE(proxy.lpc().empty());

    proxy.next_state = &right_state;
    proxy.next_result = 0;
    EXPECT_EQ(proxy.connect("198.51.100.2", "443", 'R'), 0);
    EXPECT_EQ(right_state.cleanup_calls, 1U);
    EXPECT_TRUE(proxy.rpc().empty());
}

TEST(ProxyLifecycle, OpeningAndIdleTimeoutsRouteEverySideAndCloseContexts) {
    auto const old_open = baseHostCX::params_t::open_timeout.exchange(0);
    auto const old_idle = baseHostCX::params_t::idle_delay.exchange(0);
    struct restore_parameters {
        std::size_t open;
        std::size_t idle;
        ~restore_parameters() {
            baseHostCX::params_t::open_timeout = open;
            baseHostCX::params_t::idle_delay = idle;
        }
    } restore {old_open, old_idle};

    LifecycleState master_state;
    RecordingProxy proxy(new LifecycleTCPCom(&master_state));
    std::array<LifecycleState, 8> states{};
    std::array<std::unique_ptr<baseHostCX>, 8> contexts;
    for (std::size_t i = 0; i < contexts.size(); ++i) {
        contexts[i] = std::make_unique<baseHostCX>(new LifecycleTCPCom(&states[i]),
                                                   -200 - static_cast<int>(i));
        contexts[i]->opening(i < 4);
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));

    constexpr std::array<unsigned char, 4> sides {'l', 'r', 'x', 'y'};
    for (std::size_t i = 0; i < sides.size(); ++i)
        EXPECT_FALSE(proxy.handle_cx_events(sides[i], contexts[i].get()));
    for (std::size_t i = 0; i < sides.size(); ++i)
        EXPECT_FALSE(proxy.handle_cx_events(sides[i], contexts[i + 4].get()));

    EXPECT_EQ(proxy.left_errors, 2U);
    EXPECT_EQ(proxy.right_errors, 2U);
    EXPECT_EQ(proxy.left_pc_errors, 2U);
    EXPECT_EQ(proxy.right_pc_errors, 2U);
    for (auto const& state : states) EXPECT_EQ(state.shutdown_calls, 1U);
}

TEST(TransferLifecycle, HostFormattingRawWritesAndReconnectGuardsCoverDetachedStates) {
    LifecycleState left_state;
    LifecycleState right_state;
    baseHostCX left(new LifecycleTCPCom(&left_state), "192.0.2.1", "1234");
    baseHostCX right(new LifecycleTCPCom(&right_state), "198.51.100.2", "443");
    left.peer(&right);
    right.peer(&left);
    left.meter_read_count = 2;
    left.meter_read_bytes = 20;
    left.meter_write_count = 3;
    left.meter_write_bytes = 30;
    EXPECT_NE(left.to_string(iDIA).find("rx_cnt=2"), std::string::npos);

    auto const old_socket_names = baseHostCX::socket_in_name;
    baseHostCX::socket_in_name = true;
    EXPECT_NE(left.full_name('l').find("to"), std::string::npos);
    EXPECT_NE(right.full_name('r').find("to"), std::string::npos);
    left.peer(nullptr);
    EXPECT_EQ(left.full_name('l').find("to"), std::string::npos);
    baseHostCX::socket_in_name = old_socket_names;

    unsigned char payload[] {'r', 'a', 'w'};
    left.to_write(payload, sizeof(payload));
    EXPECT_EQ(left.writebuf()->size(), sizeof(payload));
    EXPECT_FALSE(left.reconnect());
    left.permanent(true);
    left.host("");
    left.port("");
    EXPECT_FALSE(left.reconnect());
}

} // namespace
