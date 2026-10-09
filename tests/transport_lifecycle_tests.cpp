#include <gtest/gtest.h>

#include <udpcom.hpp>
#include <tcpcom.hpp>
#include <uxcom.hpp>
#include <socketinfo.hpp>
#include <epoll.hpp>
#include <traflog/filewriter.hpp>
#include <mpdisplay.hpp>

#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace {

uint64_t virtual_key(int fd) {
    return static_cast<uint32_t>(fd);
}

class DatagramPoolScope {
public:
    DatagramPoolScope() : pool(UDPCom::datagram_com_static()) {
        clear();
    }
    ~DatagramPoolScope() { clear(); }

    void clear() {
        auto lock = std::scoped_lock(pool->lock);
        pool->datagrams_received.clear();
        pool->flow_to_virtual.clear();
        pool->in_virt_set.clear();
    }

    std::shared_ptr<DatagramCom> pool;
};

class IPv4TCPCom : public TCPCom {
public:
    void use_ipv4_listener() { bind_sock_family = AF_INET; }
};

class StubUDPCom : public UDPCom {
public:
    ssize_t recv(int fd, void* destination, size_t size, int flags) override {
        last_fd = fd;
        last_flags = flags;
        const auto copied = std::min(size, receive_data.size());
        std::memcpy(destination, receive_data.data(), copied);
        return static_cast<ssize_t>(copied);
    }

    int last_fd = 0;
    int last_flags = 0;
    std::string receive_data = "socket-data";
};

class NoopEpollHandler : public epoll_handler {
public:
    void handle_event(baseCom*) override { ++calls; }
    std::size_t calls = 0;
};

std::shared_ptr<Datagram> add_datagram(DatagramPoolScope& scope, int fd) {
    auto datagram = std::make_shared<Datagram>();
    scope.pool->datagrams_received[virtual_key(fd)] = datagram;
    return datagram;
}

void set_ipv4(sockaddr_storage& storage, const char* address, uint16_t port) {
    auto* ipv4 = reinterpret_cast<sockaddr_in*>(&storage);
    ipv4->sin_family = AF_INET;
    ipv4->sin_port = htons(port);
    ASSERT_EQ(inet_pton(AF_INET, address, &ipv4->sin_addr), 1);
}

} // namespace

TEST(EpollLifecycle, PeerHalfCloseIsReadableButNotSocketError) {
    int pair[2] {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair), 0);

    epoll poller;
    ASSERT_GE(poller.init(), 0);
    ASSERT_TRUE(poller.add(pair[0], EPOLLIN));
    ASSERT_EQ(::shutdown(pair[1], SHUT_WR), 0)
        << "fd=" << pair[1] << " errno=" << errno << " (" << std::strerror(errno) << ")";

    ASSERT_GT(poller.wait(1000), 0);
    EXPECT_TRUE(poller.in_set.find(pair[0]));
    EXPECT_TRUE(poller.hup_set.find(pair[0]));
    EXPECT_FALSE(poller.err_set.find(pair[0]));

    ::close(pair[0]);
    ::close(pair[1]);
}

TEST(EpollLifecycle, SocketErrorRemainsDistinctFromPeerShutdown) {
    epoll poller;
    constexpr int descriptor = 123;
    poller.events[0].data.fd = descriptor;
    poller.events[0].events = EPOLLERR | EPOLLHUP;

    ASSERT_EQ(poller.process_epoll_events(1), 1);
    EXPECT_TRUE(poller.err_set.find(descriptor));
    EXPECT_TRUE(poller.hup_set.find(descriptor));
    EXPECT_TRUE(poller.in_set.find(descriptor));
}

TEST(TCPComLifecycle, ConnectAcceptTransferPeekAndShutdown) {
    struct BlockingScope {
        bool previous = baseCom::GLOBAL_IO_BLOCKING();
        BlockingScope() { baseCom::GLOBAL_IO_BLOCKING() = true; }
        ~BlockingScope() { baseCom::GLOBAL_IO_BLOCKING() = previous; }
    } blocking;

    IPv4TCPCom listener;
    listener.use_ipv4_listener();
    const int listener_fd = listener.bind(static_cast<unsigned short>(0));
    ASSERT_GE(listener_fd, 0);

    sockaddr_in bound{};
    socklen_t bound_size = sizeof(bound);
    ASSERT_EQ(getsockname(listener_fd, reinterpret_cast<sockaddr*>(&bound), &bound_size), 0);
    const auto port = std::to_string(ntohs(bound.sin_port));

    TCPCom client;
    const int client_fd = client.connect("127.0.0.1", port.c_str());
    ASSERT_GE(client_fd, 0);
    EXPECT_EQ(client.socket(), client_fd);
    EXPECT_TRUE(client.is_connected(client_fd));
    EXPECT_TRUE(client.com_status());

    sockaddr_storage peer{};
    socklen_t peer_size = sizeof(peer);
    const int accepted = listener.accept(listener_fd, reinterpret_cast<sockaddr*>(&peer), &peer_size);
    ASSERT_GE(accepted, 0);
    EXPECT_NE(fcntl(accepted, F_GETFL, 0) & O_NONBLOCK, 0);
    EXPECT_NE(fcntl(accepted, F_GETFD, 0) & FD_CLOEXEC, 0);

    std::string remote_host;
    std::string remote_port;
    EXPECT_TRUE(listener.resolve_socket_src(accepted, &remote_host, &remote_port));
    EXPECT_EQ(remote_host, "127.0.0.1");
    EXPECT_FALSE(remote_port.empty());
    EXPECT_TRUE(listener.resolve_socket_dst(accepted, &remote_host, &remote_port));
    EXPECT_EQ(remote_host, "127.0.0.1");
    EXPECT_EQ(remote_port, port);

    ASSERT_EQ(listener.unblock(listener_fd), 0);
    errno = 0;
    EXPECT_EQ(listener.accept(listener_fd, nullptr, nullptr), -1);
    EXPECT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);

    ASSERT_EQ(client.write(client_fd, "hello", 5, MSG_NOSIGNAL), 5);
    std::array<char, 16> data{};
    ASSERT_EQ(listener.read(accepted, data.data(), data.size(), 0), 5);
    EXPECT_EQ(std::string_view(data.data(), 5), "hello");

    ASSERT_EQ(listener.write(accepted, "reply", 5, MSG_NOSIGNAL), 5);
    data.fill(0);
    ASSERT_EQ(client.peek(client_fd, data.data(), data.size(), 0), 5);
    EXPECT_EQ(std::string_view(data.data(), 5), "reply");
    data.fill(0);
    ASSERT_EQ(client.read(client_fd, data.data(), data.size(), 0), 5);
    EXPECT_EQ(std::string_view(data.data(), 5), "reply");

    listener.shutdown(accepted);
    EXPECT_EQ(client.read(client_fd, data.data(), data.size(), 0), 0);

    ::close(accepted);
    ::close(client_fd);
    ::close(listener_fd);
}

TEST(TCPComLifecycle, NonblockingWriteMapsBackpressureToZero) {
    int pair[2] {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair), 0);
    int send_buffer = 4096;
    ASSERT_EQ(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)), 0);

    TCPCom com;
    std::array<char, 4096> payload{};
    ssize_t result = 1;
    for (int i = 0; i < 1024 && result > 0; ++i)
        result = com.write(pair[0], payload.data(), payload.size(), MSG_NOSIGNAL);
    EXPECT_EQ(result, 0);

    ::close(pair[0]);
    ::close(pair[1]);
}

TEST(TCPComLifecycle, RejectsUnresolvablePeerAndUnixBind) {
    TCPCom com;
    EXPECT_EQ(com.connect("invalid..hostname", "443"), -2);
    EXPECT_EQ(com.bind("/tmp/not-supported.sock"), -1);
}

TEST(UDPComLifecycle, PeekPreservesPacketAndShortReadDiscardsItsTail) {
    DatagramPoolScope scope;
    UDPCom com;
    com.init(nullptr);
    constexpr int fd = -1001;
    auto datagram = add_datagram(scope, fd);
    unsigned char first[] = "abcdef";
    unsigned char second[] = "XYZ";
    ASSERT_EQ(datagram->enqueue(first, 6), 6U);
    ASSERT_EQ(datagram->enqueue(second, 3), 3U);
    scope.pool->in_virt_set.insert(fd);

    std::array<char, 8> output{};
    EXPECT_EQ(com.read_from_pool(fd, output.data(), 3, MSG_PEEK), 3);
    EXPECT_EQ(std::string_view(output.data(), 3), "abc");
    EXPECT_EQ(datagram->queue_bytes_l(), 9U);

    output.fill(0);
    EXPECT_EQ(com.read_from_pool(fd, output.data(), 3, 0), 3);
    EXPECT_EQ(std::string_view(output.data(), 3), "abc");
    EXPECT_EQ(datagram->queue_bytes_l(), 3U);
    EXPECT_TRUE(scope.pool->in_virt_set.find(fd));

    output.fill(0);
    EXPECT_EQ(com.read_from_pool(fd, output.data(), output.size(), 0), 3);
    EXPECT_EQ(std::string_view(output.data(), 3), "XYZ");
    EXPECT_TRUE(datagram->empty_l());
    EXPECT_FALSE(scope.pool->in_virt_set.find(fd));
}

TEST(UDPComLifecycle, HostReadDoesNotCoalesceQueuedDatagrams) {
    DatagramPoolScope scope;
    constexpr int fd = -1014;
    auto datagram = add_datagram(scope, fd);
    unsigned char first[] = "first";
    unsigned char second[] = "second";
    ASSERT_EQ(datagram->enqueue(first, 5), 5U);
    ASSERT_EQ(datagram->enqueue(second, 6), 6U);
    scope.pool->in_virt_set.insert(fd);

    baseHostCX connection(new UDPCom(), fd);
    EXPECT_EQ(connection.read(), 5);
    EXPECT_EQ(connection.meter_read_count, 1U);
    EXPECT_EQ(connection.meter_read_bytes, 5U);
    EXPECT_EQ(connection.readbuf()->size(), 5U);
    EXPECT_EQ(std::string_view(
                  reinterpret_cast<char const*>(connection.readbuf()->data()), 5),
              "first");
    EXPECT_EQ(datagram->queue_bytes_l(), 6U);
    EXPECT_TRUE(scope.pool->in_virt_set.find(fd));
}

TEST(UDPComLifecycle, EmbryonicReadDrainsPoolBeforeRealSocket) {
    DatagramPoolScope scope;
    UDPCom com;
    com.init(nullptr);
    constexpr int fd = -1002;
    auto datagram = add_datagram(scope, fd);
    unsigned char packet[] = "packet";
    ASSERT_EQ(datagram->enqueue(packet, 6), 6U);
    scope.pool->in_virt_set.insert(fd);
    com.embryonics(virtual_key(fd), false);

    std::array<char, 16> output{};
    EXPECT_EQ(com.read(123, output.data(), output.size(), 0), 6);
    EXPECT_EQ(std::string_view(output.data(), 6), "packet");
    EXPECT_TRUE(com.embryonics().pool_depleted);
    EXPECT_FALSE(scope.pool->in_virt_set.find(fd));
}

TEST(UDPComLifecycle, DescriptorValidityDistinguishesLiveVirtualTokensFromErrors) {
    DatagramPoolScope scope;
    UDPCom com;
    com.init(nullptr);
    constexpr int fd = -1010;

    EXPECT_FALSE(com.descriptor_valid(fd));
    EXPECT_FALSE(com.descriptor_valid(-1));
    EXPECT_FALSE(com.descriptor_valid(0));
    auto datagram = add_datagram(scope, fd);
    datagram->owner_token = com.owner_token();
    EXPECT_TRUE(com.descriptor_valid(fd));
    scope.clear();
    EXPECT_FALSE(com.descriptor_valid(fd));
}

TEST(UDPComLifecycle, ForeignWorkerPreservesSharedVirtualReadiness) {
    DatagramPoolScope scope;
    constexpr int fd = -1012;
    add_datagram(scope, fd);
    scope.pool->in_virt_set.insert(fd);

    auto* com = new UDPCom();
    com->poller.init_if_null();
    baseProxy worker(com);

    auto result = worker.run_poll_socket(
        fd, scope.pool->in_virt_set, baseProxy::socket_set_type::VIRTSET);

    EXPECT_EQ(result.null_count, 0U);
    EXPECT_TRUE(scope.pool->in_virt_set.find(fd));
}

TEST(UDPComLifecycle, OwningWorkerLeavesVirtualReadinessToTransport) {
    DatagramPoolScope scope;
    constexpr int fd = -1015;
    add_datagram(scope, fd);
    scope.pool->in_virt_set.insert(fd);

    NoopEpollHandler handler;
    auto* com = new UDPCom();
    com->poller.init_if_null();
    com->poller.set_handler(fd, &handler);
    baseProxy worker(com);

    auto result = worker.run_poll_socket(
        fd, scope.pool->in_virt_set, baseProxy::socket_set_type::VIRTSET);

    EXPECT_EQ(result.generic_count, 1U);
    EXPECT_EQ(handler.calls, 1U);
    EXPECT_TRUE(scope.pool->in_virt_set.find(fd));
}

TEST(UDPComLifecycle, OrphanedVirtualReadinessIsRemoved) {
    DatagramPoolScope scope;
    constexpr int fd = -1013;
    scope.pool->in_virt_set.insert(fd);

    auto* com = new UDPCom();
    com->poller.init_if_null();
    baseProxy worker(com);

    auto result = worker.run_poll_socket(
        fd, scope.pool->in_virt_set, baseProxy::socket_set_type::VIRTSET);

    EXPECT_EQ(result.null_count, 1U);
    EXPECT_FALSE(scope.pool->in_virt_set.find(fd));
}

TEST(UDPComLifecycle, ReusePreservesEntryAndFlowMappingExactlyOnce) {
    DatagramPoolScope scope;
    UDPCom com;
    com.init(nullptr);
    constexpr int fd = -1003;
    auto datagram = add_datagram(scope, fd);
    datagram->reuse = true;
    datagram->owner_token = com.owner_token();
    datagram->flow_key = "flow-key";
    scope.pool->flow_to_virtual[datagram->flow_key] = virtual_key(fd);

    EXPECT_EQ(com.remove_datagram_entry(fd), 0);
    EXPECT_NE(scope.pool->datagrams_received.find(virtual_key(fd)),
              scope.pool->datagrams_received.end());
    EXPECT_EQ(scope.pool->flow_to_virtual.at("flow-key"), virtual_key(fd));
    EXPECT_FALSE(datagram->reuse);

    EXPECT_EQ(com.remove_datagram_entry(fd), 1);
    EXPECT_EQ(scope.pool->datagrams_received.find(virtual_key(fd)),
              scope.pool->datagrams_received.end());
    EXPECT_EQ(scope.pool->flow_to_virtual.find("flow-key"), scope.pool->flow_to_virtual.end());
}

TEST(UDPComLifecycle, StaleOwnerCannotWriteOrRemoveReplacementFlow) {
    DatagramPoolScope scope;
    UDPCom com;
    com.init(nullptr);
    constexpr int fd = -1004;
    auto datagram = add_datagram(scope, fd);
    datagram->owner_token = com.owner_token() + 1;

    errno = 0;
    EXPECT_EQ(com.write_to_pool(fd, "x", 1, 0), -1);
    EXPECT_EQ(errno, ESTALE);
    EXPECT_EQ(com.remove_datagram_entry(fd), 0);
    EXPECT_NE(scope.pool->datagrams_received.find(virtual_key(fd)),
              scope.pool->datagrams_received.end());
}

TEST(UDPComLifecycle, ResolvesVirtualEndpointsAndTranslation) {
    DatagramPoolScope scope;
    UDPCom com;
    com.init(nullptr);
    constexpr int fd = -1005;
    auto datagram = add_datagram(scope, fd);
    set_ipv4(datagram->src, "192.0.2.10", 12345);
    set_ipv4(datagram->dst, "198.51.100.20", 53);
    datagram->socket_left = 77;

    std::string host;
    std::string port;
    EXPECT_TRUE(com.resolve_socket(true, fd, &host, &port, nullptr));
    EXPECT_EQ(host, "192.0.2.10");
    EXPECT_EQ(port, "12345");
    EXPECT_TRUE(com.resolve_socket(false, fd, &host, &port, nullptr));
    EXPECT_EQ(host, "198.51.100.20");
    EXPECT_EQ(port, "53");
    EXPECT_TRUE(com.resolve_nonlocal_socket(fd));
    EXPECT_EQ(com.nonlocal_dst_host(), "198.51.100.20");
    EXPECT_EQ(com.nonlocal_dst_port(), 53);
    EXPECT_EQ(com.translate_socket(fd), 77);
    EXPECT_TRUE(com.in_writeset(fd));
    EXPECT_FALSE(com.in_exset(fd));
}

TEST(UDPComLifecycle, QueueCapacityAndCopiesAreIndependent) {
    Datagram original;
    for (unsigned char value = 1; value <= 5; ++value)
        ASSERT_EQ(original.enqueue(&value, 1), 1U);
    unsigned char overflow = 6;
    EXPECT_EQ(original.enqueue(&overflow, 1), 0U);
    EXPECT_EQ(original.queue_bytes_l(), 5U);

    Datagram copied = original;
    original.rx_queue[0].clear();
    EXPECT_EQ(original.queue_bytes_l(), 4U);
    EXPECT_EQ(copied.queue_bytes_l(), 5U);
    EXPECT_EQ(copied.rx_queue[0][0], 1);
}

TEST(UDPComLifecycle, EmptyPoolFallsThroughToAssociatedSocket) {
    DatagramPoolScope scope;
    StubUDPCom com;
    com.init(nullptr);
    constexpr int fd = -1006;
    auto datagram = add_datagram(scope, fd);
    datagram->socket_left = 91;

    std::array<char, 32> output{};
    EXPECT_EQ(com.read_from_pool(fd, output.data(), output.size(), MSG_DONTWAIT), 11);
    EXPECT_EQ(std::string_view(output.data(), 11), "socket-data");
    EXPECT_EQ(com.last_fd, 91);
    EXPECT_EQ(com.last_flags, MSG_DONTWAIT);
    EXPECT_EQ(com.read_from_pool(-9999, output.data(), output.size(), 0), 0);
}

TEST(UDPComLifecycle, AssociatedSocketCarriesReplyWithCallerFlags) {
    DatagramPoolScope scope;
    UDPCom com;
    com.init(nullptr);
    constexpr int fd = -1007;
    auto datagram = add_datagram(scope, fd);
    datagram->owner_token = com.owner_token();

    int pair[2] {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, pair), 0);
    datagram->socket_left = pair[0];
    ASSERT_EQ(com.write_to_pool(fd, "reply", 5, MSG_DONTWAIT | MSG_NOSIGNAL), 5);

    std::array<char, 16> output{};
    ASSERT_EQ(::recv(pair[1], output.data(), output.size(), 0), 5);
    EXPECT_EQ(std::string_view(output.data(), 5), "reply");
    datagram->socket_left.reset();
    ::close(pair[0]);
    ::close(pair[1]);
}

TEST(UDPComLifecycle, PoolReplyBuildsTemporaryLoopbackSocket) {
    DatagramPoolScope scope;
    UDPCom com;
    com.init(nullptr);
    constexpr int fd = -1011;
    auto datagram = add_datagram(scope, fd);
    datagram->owner_token = com.owner_token();

    int receiver = ::socket(AF_INET, SOCK_DGRAM, 0);
    int source_probe = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(receiver, 0);
    ASSERT_GE(source_probe, 0);
    sockaddr_in loopback{};
    loopback.sin_family = AF_INET;
    loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(receiver, reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback)), 0);
    ASSERT_EQ(::bind(source_probe, reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback)), 0);

    socklen_t size = sizeof(sockaddr_storage);
    ASSERT_EQ(getsockname(receiver, reinterpret_cast<sockaddr*>(&datagram->src), &size), 0);
    size = sizeof(sockaddr_storage);
    ASSERT_EQ(getsockname(source_probe, reinterpret_cast<sockaddr*>(&datagram->dst), &size), 0);
    ::close(source_probe);

    ASSERT_EQ(com.write_to_pool(fd, "reply", 5, MSG_NOSIGNAL), 5);
    std::array<char, 16> output{};
    ASSERT_EQ(::recv(receiver, output.data(), output.size(), 0), 5);
    EXPECT_EQ(std::string_view(output.data(), 5), "reply");
    ::close(receiver);
}

TEST(UDPComLifecycle, SharedConnectionCacheClosesOnlyAfterLastOwner) {
    int pair[2] {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair), 0);
    UDPCom first;
    UDPCom last;
    constexpr auto key = "shared-udp-connection";
    {
        auto lock = std::scoped_lock(UDPCom::ConnectionsCache::lock);
        UDPCom::ConnectionsCache::cache.clear();
        UDPCom::ConnectionsCache::cache[key] = {pair[0], 2};
    }
    first.connections.my_key = key;
    last.connections.my_key = key;

    first.shutdown(pair[0]);
    EXPECT_NE(fcntl(pair[0], F_GETFD), -1);
    EXPECT_EQ(UDPCom::ConnectionsCache::cache.at(key).second, 1);

    last.shutdown(pair[0]);
    EXPECT_EQ(UDPCom::ConnectionsCache::cache.count(key), 0U);
    errno = 0;
    EXPECT_EQ(fcntl(pair[0], F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
    ::close(pair[1]);
}

TEST(UDPComLifecycle, ConnectsLoopbackAndDescribesRealSocket) {
    int receiver = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(receiver, 0);
    sockaddr_in loopback{};
    loopback.sin_family = AF_INET;
    loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(receiver, reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback)), 0);
    socklen_t size = sizeof(loopback);
    ASSERT_EQ(getsockname(receiver, reinterpret_cast<sockaddr*>(&loopback), &size), 0);

    UDPCom com;
    com.l3_proto(AF_INET);
    const auto port = std::to_string(ntohs(loopback.sin_port));
    const int fd = com.connect("127.0.0.1", port.c_str());
    ASSERT_GT(fd, 0);
    EXPECT_TRUE(com.is_connected(fd));
    EXPECT_TRUE(com.in_writeset(fd));
    EXPECT_FALSE(com.in_exset(fd));
    EXPECT_EQ(com.shortname(), "udp");
    EXPECT_EQ(com.to_string(iINF), "UDPCom");
    EXPECT_TRUE(com.connections.gen_cache_key(fd).has_value());
    std::unique_ptr<baseCom> copy(com.replicate());
    EXPECT_EQ(copy->c_type(), "UDPCom");

    com.shutdown(fd);
    ::close(receiver);
}

TEST(UDPComLifecycle, VirtualShutdownRemovesOwnedFlowAndReadiness) {
    DatagramPoolScope scope;
    UDPCom com;
    com.init(nullptr);
    constexpr int fd = -1008;
    auto datagram = add_datagram(scope, fd);
    datagram->owner_token = com.owner_token();
    datagram->flow_key = "shutdown-flow";
    scope.pool->flow_to_virtual[datagram->flow_key] = virtual_key(fd);
    scope.pool->in_virt_set.insert(fd);

    EXPECT_TRUE(com.shutdown_consumes_fd());
    com.shutdown(fd);
    EXPECT_EQ(scope.pool->datagrams_received.find(virtual_key(fd)),
              scope.pool->datagrams_received.end());
    EXPECT_EQ(scope.pool->flow_to_virtual.find("shutdown-flow"), scope.pool->flow_to_virtual.end());
    EXPECT_FALSE(scope.pool->in_virt_set.find(fd));
}

TEST(UDPComLifecycle, ConnectionCacheKeyRequiresSpoofedSource) {
    UDPCom com;
    EXPECT_FALSE(com.connections.gen_cache_key("198.51.100.1", "53").has_value());
    com.nonlocal_src(true);
    com.nonlocal_src_host() = "192.0.2.1";
    com.nonlocal_src_port() = 12345;
    EXPECT_EQ(com.connections.gen_cache_key("198.51.100.1", "53"),
              std::optional<std::string>("192.0.2.1:12345-198.51.100.1:53"));
}

TEST(UDPComLifecycle, ExplicitRelaySocketDoesNotRequireTransparentPrivilege) {
    int relay = ::socket(AF_INET, SOCK_DGRAM, 0);
    int client = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(relay, 0);
    ASSERT_GE(client, 0);

    int reuse = 1;
    ASSERT_EQ(setsockopt(relay, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)), 0);
    sockaddr_in loopback{};
    loopback.sin_family = AF_INET;
    loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(relay, reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback)), 0);
    ASSERT_EQ(::bind(client, reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback)), 0);

    sockaddr_storage relay_address{};
    sockaddr_storage client_address{};
    socklen_t address_size = sizeof(sockaddr_storage);
    ASSERT_EQ(getsockname(relay, reinterpret_cast<sockaddr*>(&relay_address), &address_size), 0);
    address_size = sizeof(sockaddr_storage);
    ASSERT_EQ(getsockname(client, reinterpret_cast<sockaddr*>(&client_address), &address_size), 0);

    SocketInfo endpoints;
    endpoints.src = AddressInfo(&client_address);
    endpoints.dst = AddressInfo(&relay_address);
    const int reply = endpoints.create_socket_left(SOCK_DGRAM, false);
    ASSERT_GE(reply, 0);
    ASSERT_EQ(::send(reply, "ok", 2, MSG_NOSIGNAL), 2);

    std::array<char, 8> received{};
    ASSERT_EQ(::recv(client, received.data(), received.size(), 0), 2);
    EXPECT_EQ(std::string_view(received.data(), 2), "ok");

    ::close(reply);
    ::close(client);
    ::close(relay);
}

TEST(UxComLifecycle, BindConnectTransferAndRejectDuplicatePath) {
    struct BlockingScope {
        bool previous = baseCom::GLOBAL_IO_BLOCKING();
        BlockingScope() { baseCom::GLOBAL_IO_BLOCKING() = true; }
        ~BlockingScope() { baseCom::GLOBAL_IO_BLOCKING() = previous; }
    } blocking;

    const auto path = std::filesystem::temp_directory_path()
                      / ("socle-uxcom-" + std::to_string(::getpid()) + ".sock");
    std::filesystem::remove(path);

    UxCom listener;
    EXPECT_EQ(listener.bind(static_cast<unsigned short>(1234)), -1);
    const int listener_fd = listener.bind(path.c_str());
    ASSERT_GE(listener_fd, 0);

    UxCom duplicate;
    EXPECT_EQ(duplicate.bind(path.c_str()), -130);

    UxCom client;
    const int client_fd = client.connect(path.c_str(), "ignored");
    ASSERT_GT(client_fd, 0);
    EXPECT_EQ(client.shortname(), "ux");
    EXPECT_EQ(client.to_string(iINF), "UxCom");

    sockaddr_storage peer{};
    socklen_t peer_size = sizeof(peer);
    const int accepted = listener.accept(
        listener_fd, reinterpret_cast<sockaddr*>(&peer), &peer_size);
    ASSERT_GE(accepted, 0);

    ASSERT_EQ(client.write(client_fd, "unix", 4, MSG_NOSIGNAL), 4);
    std::array<char, 8> data{};
    ASSERT_EQ(listener.read(accepted, data.data(), data.size(), 0), 4);
    EXPECT_EQ(std::string_view(data.data(), 4), "unix");

    std::unique_ptr<baseCom> copy(client.replicate());
    ASSERT_NE(dynamic_cast<UxCom*>(copy.get()), nullptr);

    ::close(accepted);
    ::close(client_fd);
    ::close(listener_fd);
    std::filesystem::remove(path);
}

TEST(FileWriterLifecycle, RejectsBadTargetsAndPersistsStringsAndBuffers) {
    const auto directory = std::filesystem::temp_directory_path()
                           / ("socle-filewriter-" + std::to_string(::getpid()));
    const auto output = directory / "capture.bin";
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);

    socle::fileWriter writer;
    EXPECT_FALSE(writer.open(""));
    EXPECT_FALSE(writer.flush("unused"));
    EXPECT_EQ(writer.write("unused", std::string("before-open")), 0U);
    buffer empty;
    EXPECT_EQ(writer.write("unused", empty), 0U);
    EXPECT_FALSE(writer.open((directory / "missing" / "file").string()));

    ASSERT_TRUE(writer.open(output.string()));
    EXPECT_TRUE(writer.open((directory / "ignored").string()));
    EXPECT_EQ(writer.filename(), output.string());
    EXPECT_EQ(writer.write(output.string(), std::string("header:")), 7U);
    buffer payload;
    payload.append("data", 4);
    EXPECT_EQ(writer.write(output.string(), payload), 4U);
    EXPECT_EQ(writer.write(output.string(), empty), 0U);
    EXPECT_TRUE(writer.flush(output.string()));
    EXPECT_TRUE(writer.close(output.string()));
    EXPECT_FALSE(writer.opened());
    EXPECT_TRUE(writer.close(output.string()));

    std::ifstream input(output, std::ios::binary);
    std::string contents((std::istreambuf_iterator<char>(input)), {});
    EXPECT_EQ(contents, "header:data");
    EXPECT_EQ(std::filesystem::status(output).permissions()
              & std::filesystem::perms::owner_all,
              std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
    std::filesystem::remove_all(directory);
}

TEST(MpDisplay, FormatsBinaryCsvSplitAndLongStrings) {
    unsigned char raw[] {0x41, 0x00, 0x25, 0x5c, 0x7e};
    const auto dump = mp::hex_dump(raw, sizeof(raw), 2, '>');
    EXPECT_NE(dump.find("41 00 25 5C 7E"), mp::string::npos);
    EXPECT_NE(dump.find("A...~"), mp::string::npos);

    buffer data;
    data.append(raw, sizeof(raw));
    EXPECT_EQ(mp::hex_dump(&data, 0, 0), mp::hex_dump(data, 0, 0));
    mp::vector<mp::string> csv_values;
    csv_values.push_back(mp::string("one"));
    csv_values.push_back(mp::string("two"));
    csv_values.push_back(mp::string("three"));
    EXPECT_EQ(mp::string_csv(csv_values, ';'), "one;two;three");
    mp::vector<mp::string> empty_values;
    EXPECT_EQ(mp::string_csv(empty_values, ';'), "");

    const auto fields = mp::string_split(mp::string("a::c"), ':');
    ASSERT_EQ(fields.size(), 3U);
    EXPECT_EQ(fields[1], "");

    const std::string long_value(900, 'x');
    const auto formatted = mp::string_format("[%s]", long_value.c_str());
    EXPECT_EQ(formatted.size(), long_value.size() + 2);
    EXPECT_EQ(formatted.front(), '[');
    EXPECT_EQ(formatted.back(), ']');
}
