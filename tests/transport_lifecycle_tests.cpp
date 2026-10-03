#include <gtest/gtest.h>

#include <udpcom.hpp>
#include <tcpcom.hpp>
#include <socketinfo.hpp>

#include <array>
#include <cstring>

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
    EXPECT_EQ(com.translate_socket(fd), 77);
    EXPECT_TRUE(com.in_writeset(fd));
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
