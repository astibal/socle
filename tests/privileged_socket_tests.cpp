#include <gtest/gtest.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

#include <netinet/in.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <unistd.h>

#include <privileged_socket.hpp>
#include "security/hostile_peer.hpp"

namespace {

class PrivilegedSocketTest : public ::testing::Test {
protected:
    void TearDown() override {
        socle::privsep::clear_client();
    }
};

TEST_F(PrivilegedSocketTest, DirectFacadePreservesSyscallSemantics) {
    int sockets[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(sockets), 0);
    const int requested = 8192;
    EXPECT_EQ(socle::setsockopt(sockets[0], SOL_SOCKET, SO_RCVBUF, &requested, sizeof(requested)), 0);

    int actual = 0;
    socklen_t actual_size = sizeof(actual);
    ASSERT_EQ(::getsockopt(sockets[0], SOL_SOCKET, SO_RCVBUF, &actual, &actual_size), 0);
    EXPECT_GE(actual, requested);
    ::close(sockets[0]);
    ::close(sockets[1]);
}

TEST_F(PrivilegedSocketTest, RejectsTruncatedDataFrame) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    socle::privsep::SeqPacketChannel receiver(channels[1]);
    ::close(channels[1]);

    std::vector<std::byte> oversized(128U * 1024U);
    ASSERT_EQ(::send(channels[0], oversized.data(), oversized.size(), MSG_NOSIGNAL),
              static_cast<ssize_t>(oversized.size()));
    ::close(channels[0]);

    socle::privsep::Message message;
    errno = 0;
    EXPECT_EQ(receiver.receive(message), -1);
    EXPECT_EQ(errno, EMSGSIZE);
    EXPECT_TRUE(message.data.empty());
    EXPECT_EQ(message.fd, -1);
}

TEST_F(PrivilegedSocketTest, RejectsTruncatedDescriptorFrame) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    socle::privsep::SeqPacketChannel receiver(channels[1]);
    ::close(channels[1]);

    int descriptors[3] = {-1, -1, -1};
    for(int& descriptor : descriptors) {
        descriptor = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        ASSERT_GE(descriptor, 0);
    }
    std::byte payload{std::byte{'X'}};
    iovec iov{&payload, sizeof(payload)};
    std::array<std::byte, CMSG_SPACE(sizeof(descriptors))> control{};
    msghdr outbound{};
    outbound.msg_iov = &iov;
    outbound.msg_iovlen = 1;
    outbound.msg_control = control.data();
    outbound.msg_controllen = control.size();
    auto* cmsg = CMSG_FIRSTHDR(&outbound);
    ASSERT_NE(cmsg, nullptr);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(descriptors));
    std::memcpy(CMSG_DATA(cmsg), descriptors, sizeof(descriptors));
    ASSERT_EQ(::sendmsg(channels[0], &outbound, MSG_NOSIGNAL), 1);
    ::close(channels[0]);
    for(const int descriptor : descriptors) ::close(descriptor);

    socle::privsep::Message message;
    errno = 0;
    EXPECT_EQ(receiver.receive(message), -1);
    EXPECT_EQ(errno, EMSGSIZE);
    EXPECT_TRUE(message.data.empty());
    EXPECT_EQ(message.fd, -1);
}

TEST_F(PrivilegedSocketTest, HelperSurvivesTruncatedDatagramAndServesNextRequest) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    socle::privsep::Server server(channels[1]);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });

    std::vector<std::byte> oversized(128U * 1024U, std::byte{'X'});
    ASSERT_EQ(::send(channels[0], oversized.data(), oversized.size(), MSG_NOSIGNAL),
              static_cast<ssize_t>(oversized.size()));
    {
        socle::privsep::Client client(channels[0], std::chrono::seconds(1));
        ::close(channels[0]);
        ::close(channels[1]);
        EXPECT_EQ(client.ping(), 0);
    }
    helper.join();
    const auto stats = server.stats();
    EXPECT_EQ(stats.ping, 1U);
    EXPECT_EQ(stats.protocol_errors, 1U);
    EXPECT_EQ(stats.transport_errors, 0U);
}

TEST_F(PrivilegedSocketTest, HostileFrameCorpusPreservesAvailabilityAndDescriptors) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    socle::privsep::Server server(channels[1]);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });
    const auto descriptors_before = socle::test::hostile::open_fd_count();

    const auto corpus = socle::test::hostile::frame_corpus(
        {0x50524956U, 512, 4096});
    for(const auto& frame: corpus) {
        ASSERT_EQ(socle::test::hostile::send_and_drain(channels[0], frame),
                  socle::test::hostile::DrainResult::Reply);
    }

    {
        socle::privsep::Client client(channels[0], std::chrono::seconds(1));
        ::close(channels[0]);
        ::close(channels[1]);
        EXPECT_EQ(client.ping(), 0);
    }
    helper.join();
    const auto descriptors_after = socle::test::hostile::open_fd_count();
    if(descriptors_before != 0 && descriptors_after != 0) {
        EXPECT_EQ(descriptors_after, descriptors_before - 2U);
    }
}

TEST_F(PrivilegedSocketTest, PassesDescriptorAndAppliesSocketOption) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    socle::privsep::Server server(channels[1]);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });

    auto client = std::make_shared<socle::privsep::Client>(channels[0], std::chrono::seconds(1));
    ::close(channels[0]);
    ::close(channels[1]);
    ASSERT_EQ(client->ping(), 0);
    socle::privsep::install_client(client);

    int targets[2] = {-1, -1};
    EXPECT_EQ(socle::privsep::make_channel_pair(targets), 0);
    const int requested = 8192;
    EXPECT_EQ(socle::setsockopt(targets[0], SOL_SOCKET, SO_RCVBUF,
                             &requested, sizeof(requested)), 0);

    int actual = 0;
    socklen_t actual_size = sizeof(actual);
    EXPECT_EQ(::getsockopt(targets[0], SOL_SOCKET, SO_RCVBUF, &actual, &actual_size), 0);
    EXPECT_GE(actual, requested);

    ::close(targets[0]);
    ::close(targets[1]);
    socle::privsep::clear_client();
    client.reset();
    helper.join();

    const auto stats = server.stats();
    EXPECT_EQ(stats.ping, 1U);
    EXPECT_EQ(stats.setsockopt, 1U);
    EXPECT_EQ(stats.errors, 0U);
    EXPECT_GE(stats.drains, 1U);
    EXPECT_GE(stats.max_ops_per_drain, 1U);
}

TEST_F(PrivilegedSocketTest, ReturnsRemoteErrno) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    socle::privsep::Server server(channels[1]);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });

    auto client = std::make_shared<socle::privsep::Client>(channels[0], std::chrono::seconds(1));
    ::close(channels[0]);
    ::close(channels[1]);
    socle::privsep::install_client(client);

    int targets[2] = {-1, -1};
    EXPECT_EQ(socle::privsep::make_channel_pair(targets), 0);
    const int invalid_value = 1;
    errno = 0;
    EXPECT_EQ(socle::setsockopt(targets[0], SOL_SOCKET, -1,
                             &invalid_value, sizeof(invalid_value)), -1);
    EXPECT_EQ(errno, ENOPROTOOPT);

    ::close(targets[0]);
    ::close(targets[1]);
    socle::privsep::clear_client();
    client.reset();
    helper.join();

    const auto stats = server.stats();
    EXPECT_EQ(stats.setsockopt, 1U);
    EXPECT_EQ(stats.errors, 1U);
    EXPECT_EQ(stats.operation_errors, 1U);
    EXPECT_EQ(stats.protocol_errors, 0U);
}

TEST_F(PrivilegedSocketTest, CreatesBindsAndListensThroughHelperAndExportsStats) {
    int channels[2] = {-1, -1};
    ASSERT_EQ(socle::privsep::make_channel_pair(channels), 0);
    socle::privsep::Server server(channels[1]);
    std::thread helper([&server] { EXPECT_EQ(server.run(), 0); });

    auto client = std::make_shared<socle::privsep::Client>(channels[0], std::chrono::seconds(1));
    ::close(channels[0]);
    ::close(channels[1]);
    socle::privsep::install_client(client);

    const int listener = socle::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    EXPECT_GE(listener, 0);
    if(listener >= 0) {
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        const std::string name = "sc-privsep-" + std::to_string(::getpid());
        std::memcpy(address.sun_path + 1, name.data(), name.size());
        const auto address_len = static_cast<socklen_t>(
            offsetof(sockaddr_un, sun_path) + 1 + name.size());
        EXPECT_EQ(socle::bind(listener, reinterpret_cast<sockaddr*>(&address), address_len), 0);
        EXPECT_EQ(socle::listen(listener, 4), 0);

        int accepting = 0;
        socklen_t accepting_size = sizeof(accepting);
        EXPECT_EQ(::getsockopt(listener, SOL_SOCKET, SO_ACCEPTCONN,
                               &accepting, &accepting_size), 0);
        EXPECT_EQ(accepting, 1);
        ::close(listener);
    }

    socle::privsep::Stats remote_stats;
    EXPECT_EQ(socle::privileged_stats(remote_stats), 0);
    EXPECT_EQ(remote_stats.socket, 1U);
    EXPECT_EQ(remote_stats.bind, 1U);
    EXPECT_EQ(remote_stats.listen, 1U);
    EXPECT_EQ(remote_stats.stats, 1U);
    EXPECT_EQ(remote_stats.errors, 0U);

    socle::privsep::clear_client();
    client.reset();
    helper.join();
}

TEST_F(PrivilegedSocketTest, ForkedStandaloneHelperServesFacadeAndStopsCleanly) {
    ASSERT_EQ(socle::privsep::start_local_helper(), 0);

    const int socket = socle::socket(AF_UNIX, SOCK_SEQPACKET, 0);
    EXPECT_GE(socket, 0);
    if(socket >= 0) {
        EXPECT_EQ(::fcntl(socket, F_GETFD, 0) & FD_CLOEXEC, 0);
        ::close(socket);
    }

    socle::privsep::Stats stats;
    EXPECT_EQ(socle::privileged_stats(stats), 0);
    EXPECT_EQ(stats.ping, 1U);
    EXPECT_EQ(stats.socket, 1U);
    EXPECT_EQ(stats.stats, 1U);
    EXPECT_EQ(stats.errors, 0U);

    EXPECT_EQ(socle::privsep::stop_local_helper(), 0);
}

TEST_F(PrivilegedSocketTest, StopAcceptsHelperAutoReapedByDaemonSigchldPolicy) {
    struct sigaction ignored{};
    struct sigaction previous{};
    ignored.sa_handler = SIG_IGN;
    sigemptyset(&ignored.sa_mask);
    ASSERT_EQ(::sigaction(SIGCHLD, &ignored, &previous), 0);

    ASSERT_EQ(socle::privsep::start_local_helper(), 0);
    EXPECT_EQ(socle::privsep::stop_local_helper(), 0);

    ASSERT_EQ(::sigaction(SIGCHLD, &previous, nullptr), 0);
}

} // namespace
