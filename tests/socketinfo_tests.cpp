#include <gtest/gtest.h>

#include <fcntl.h>

#include <socketinfo.hpp>

TEST(SocketInfoTest, PacksAndUnpacksIpv4AndIpv6) {
    AddressInfo ipv4(AF_INET, "192.0.2.10", 443);
    ASSERT_TRUE(ipv4);
    EXPECT_EQ(ipv4.as_v4()->sin_family, AF_INET);
    EXPECT_EQ(ntohs(ipv4.as_v4()->sin_port), 443);
    ipv4.str_host.clear();
    ipv4.port = 0;
    ipv4.unpack();
    EXPECT_EQ(ipv4.family, AF_INET);
    EXPECT_EQ(ipv4.str_host, "192.0.2.10");
    EXPECT_EQ(ipv4.port, 443);
    EXPECT_EQ(ipv4.family_str(), "ip4");

    AddressInfo ipv6(AF_INET6, "2001:db8::10", 8443);
    ASSERT_TRUE(ipv6);
    ipv6.str_host.clear();
    ipv6.port = 0;
    ipv6.unpack();
    EXPECT_EQ(ipv6.family, AF_INET6);
    EXPECT_EQ(ipv6.str_host, "2001:db8::10");
    EXPECT_EQ(ipv6.port, 8443);
    EXPECT_EQ(ipv6.family_str(), "ip6");
    EXPECT_EQ(SockOps::family_str(AF_UNIX), "p1");
}

TEST(SocketInfoTest, NormalizesIpv4MappedIpv6) {
    sockaddr_storage mapped{};
    auto* mapped6 = reinterpret_cast<sockaddr_in6*>(&mapped);
    mapped6->sin6_family = AF_INET6;
    mapped6->sin6_port = htons(5353);
    ASSERT_EQ(inet_pton(AF_INET6, "::ffff:198.51.100.7", &mapped6->sin6_addr), 1);

    std::string address;
    unsigned short port = 0;
    EXPECT_EQ(SockOps::ss_address_unpack(&mapped, &address, &port), AF_INET);
    EXPECT_EQ(address, "198.51.100.7");
    EXPECT_EQ(port, 5353);
    EXPECT_EQ(SockOps::ss_address_unpack(&mapped, nullptr, nullptr), AF_INET);

    sockaddr_storage normalized{};
    EXPECT_EQ(SockOps::ss_address_remap(&mapped, &normalized), AF_INET);
    EXPECT_EQ(normalized.ss_family, AF_INET);
    EXPECT_EQ(SockOps::ss_str(&normalized), "ip4/198.51.100.7:5353");
}

TEST(SocketInfoTest, SessionKeysAreStableDirectionalAndSigned) {
    SocketInfo info;
    info.src = AddressInfo(AF_INET, "192.0.2.1", 12345);
    info.dst = AddressInfo(AF_INET, "198.51.100.2", 443);

    auto const positive = info.create_session_key(false);
    auto const repeated = info.create_session_key(false);
    auto const negative = info.create_session_key(true);
    EXPECT_EQ(positive, repeated);
    EXPECT_EQ(positive & 0x80000000U, 0U);
    EXPECT_NE(negative & 0x80000000U, 0U);
    EXPECT_EQ(positive & 0x7fffffffU, negative & 0x7fffffffU);

    std::swap(info.src, info.dst);
    EXPECT_NE(info.create_session_key(false), positive);

    SocketInfo ipv6;
    ipv6.src = AddressInfo(AF_INET6, "2001:db8::1", 1000);
    ipv6.dst = AddressInfo(AF_INET6, "2001:db8::2", 2000);
    EXPECT_EQ(ipv6.create_session_key(false), ipv6.create_session_key(false));
    EXPECT_EQ(ipv6.create_session_key(false) & 0x80000000U, 0U);
    EXPECT_NE(ipv6.create_session_key(true) & 0x80000000U, 0U);
}

TEST(SocketInfoTest, SessionKeyRepacksMappedStorageUsingLogicalFamily) {
    SocketInfo info;
    info.src.family = AF_INET;
    info.src.str_host = "203.0.113.4";
    info.src.port = 32000;
    sockaddr_storage mapped{};
    auto* mapped6 = reinterpret_cast<sockaddr_in6*>(&mapped);
    mapped6->sin6_family = AF_INET6;
    mapped6->sin6_port = htons(info.src.port);
    ASSERT_EQ(inet_pton(AF_INET6, "::ffff:203.0.113.4", &mapped6->sin6_addr), 1);
    info.src.ss = mapped;
    info.dst = AddressInfo(AF_INET, "198.51.100.9", 53);

    SocketInfo canonical;
    canonical.src = AddressInfo(AF_INET, info.src.str_host, info.src.port);
    canonical.dst = info.dst;
    EXPECT_EQ(info.create_session_key(false), canonical.create_session_key(false));
}

TEST(SocketInfoTest, CreatesReusableNonblockingUdpSocket) {
    const int socket = SockOps::socket_create(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(socket, 0);
    const int flags = fcntl(socket, F_GETFL, 0);
    EXPECT_NE(flags & O_NONBLOCK, 0);
    ::close(socket);
}
