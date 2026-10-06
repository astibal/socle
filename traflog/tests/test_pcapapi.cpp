#include <gtest/gtest.h>

#include <socketinfo.hpp>
#include <tcpcom.hpp>
#include <traflog/pcapapi.hpp>
#include <traflog/pcaplog.hpp>

#include <cstring>
#include <filesystem>

using namespace socle::pcap;

namespace socle::pcap {
bool lock_fd(int fd);
bool unlock_fd(int fd);
}

namespace {

class CaptureProxy : public baseProxy {
public:
    CaptureProxy() : baseProxy(new TCPCom()) {}
    void attach(baseHostCX* left, baseHostCX* right) {
        left_sockets.push_back(left);
        right_sockets.push_back(right);
    }
};

class CountingPacketHook : public socle::pcapng::IP_Hook {
public:
    bool execute(connection_details const&, buffer const& packet) override {
        if (!packet.empty()) ++packets;
        return true;
    }
    std::size_t packets = 0;
};

} // namespace


// NOTE: it's not really practical to check generated PCAP content automatically packet by packet,
//       please check files in wireshark.

TEST(PcapTest, GreHeaderWithoutKeyKeepsLegacyWireFormat) {
    connection_details details {};
    details.ip_version = 4;
    buffer output;

    append_GRE_header(output, details);

    ASSERT_EQ(4U, gre_header_size(details));
    ASSERT_EQ(4U, output.size());
    auto const* bytes = static_cast<unsigned char const*>(output.data());
    EXPECT_EQ(0x00, bytes[0]); // No optional GRE fields.
    EXPECT_EQ(0x00, bytes[1]);
    EXPECT_EQ(0x08, bytes[2]); // Inner protocol: IPv4.
    EXPECT_EQ(0x00, bytes[3]);
}

TEST(PcapTest, GreHeaderWithKeyUsesRfc2890WireFormat) {
    connection_details details {};
    details.ip_version = 4;
    details.gre_key = 0x01020304U;
    buffer output;

    append_GRE_header(output, details);

    ASSERT_EQ(8U, gre_header_size(details));
    ASSERT_EQ(8U, output.size());
    auto const* bytes = static_cast<unsigned char const*>(output.data());
    EXPECT_EQ(0x20, bytes[0]); // RFC 2890 K bit.
    EXPECT_EQ(0x00, bytes[1]);
    EXPECT_EQ(0x08, bytes[2]); // Inner protocol: IPv4.
    EXPECT_EQ(0x00, bytes[3]);
    EXPECT_EQ(0x01, bytes[4]); // Key is serialized in network byte order.
    EXPECT_EQ(0x02, bytes[5]);
    EXPECT_EQ(0x03, bytes[6]);
    EXPECT_EQ(0x04, bytes[7]);
}

TEST(PcapTest, GreTunnelEncapsulationUsesOuterFamilyAndInnerDirection) {
    SocketInfo inner4;
    inner4.src.str_host = "192.0.2.10";
    inner4.dst.str_host = "198.51.100.20";
    inner4.src.port = 12345;
    inner4.dst.port = 53;
    ASSERT_TRUE(inner4.src.pack());
    ASSERT_TRUE(inner4.dst.pack());

    SocketInfo tunnel4;
    tunnel4.src.str_host = "203.0.113.1";
    tunnel4.dst.str_host = "203.0.113.2";
    ASSERT_TRUE(tunnel4.src.pack());
    ASSERT_TRUE(tunnel4.dst.pack());

    connection_details details4 {};
    details4.source = *inner4.src.ss;
    details4.destination = *inner4.dst.ss;
    details4.ip_version = 4;
    details4.next_proto = connection_details::UDP;
    details4.tun_proto = connection_details::GRE;
    details4.tun_ttl = 7;
    details4.tun_details = &tunnel4;

    buffer outbound4;
    append_IPv4_header(outbound4, details4, 0, 3);
    ASSERT_EQ(outbound4.size(), sizeof(iphdr) + sizeof(grehdr) + sizeof(iphdr));
    iphdr outer4 {};
    iphdr inner_header4 {};
    std::memcpy(&outer4, outbound4.data(), sizeof(outer4));
    std::memcpy(&inner_header4,
                static_cast<unsigned char const*>(outbound4.data())
                    + sizeof(outer4) + sizeof(grehdr),
                sizeof(inner_header4));
    EXPECT_EQ(outer4.protocol, IPPROTO_GRE);
    EXPECT_EQ(outer4.ttl, details4.tun_ttl);
    EXPECT_EQ(outer4.saddr, tunnel4.src.as_v4()->sin_addr.s_addr);
    EXPECT_EQ(outer4.daddr, tunnel4.dst.as_v4()->sin_addr.s_addr);
    EXPECT_EQ(inner_header4.protocol, connection_details::UDP);

    buffer inbound4;
    append_IPv4_header(inbound4, details4, 1, 3);
    std::memcpy(&outer4, inbound4.data(), sizeof(outer4));
    std::memcpy(&inner_header4,
                static_cast<unsigned char const*>(inbound4.data())
                    + sizeof(outer4) + sizeof(grehdr),
                sizeof(inner_header4));
    // The GRE exporter endpoints stay fixed; only the encapsulated flow reverses.
    EXPECT_EQ(outer4.saddr, tunnel4.src.as_v4()->sin_addr.s_addr);
    EXPECT_EQ(outer4.daddr, tunnel4.dst.as_v4()->sin_addr.s_addr);
    EXPECT_EQ(inner_header4.saddr, inner4.dst.as_v4()->sin_addr.s_addr);
    EXPECT_EQ(inner_header4.daddr, inner4.src.as_v4()->sin_addr.s_addr);

    SocketInfo inner6;
    inner6.src.str_host = "2001:db8::10";
    inner6.dst.str_host = "2001:db8::20";
    inner6.src.family = AF_INET6;
    inner6.dst.family = AF_INET6;
    inner6.src.port = 12345;
    inner6.dst.port = 53;
    ASSERT_TRUE(inner6.src.pack());
    ASSERT_TRUE(inner6.dst.pack());

    SocketInfo tunnel6;
    tunnel6.src.str_host = "2001:db8:1::1";
    tunnel6.dst.str_host = "2001:db8:1::2";
    tunnel6.src.family = AF_INET6;
    tunnel6.dst.family = AF_INET6;
    ASSERT_TRUE(tunnel6.src.pack());
    ASSERT_TRUE(tunnel6.dst.pack());

    connection_details details6 {};
    details6.source = *inner6.src.ss;
    details6.destination = *inner6.dst.ss;
    details6.ip_version = 6;
    details6.next_proto = connection_details::UDP;
    details6.tun_proto = connection_details::GRE;
    details6.tun_ttl = 9;
    details6.tun_details = &tunnel6;

    buffer outbound6;
    append_IPv6_header(outbound6, details6, 0, 5);
    ASSERT_EQ(outbound6.size(), sizeof(ip6_hdr) + sizeof(grehdr) + sizeof(ip6_hdr));
    ip6_hdr outer6 {};
    ip6_hdr inner_header6 {};
    std::memcpy(&outer6, outbound6.data(), sizeof(outer6));
    std::memcpy(&inner_header6,
                static_cast<unsigned char const*>(outbound6.data())
                    + sizeof(outer6) + sizeof(grehdr),
                sizeof(inner_header6));
    EXPECT_EQ(outer6.ip6_nxt, IPPROTO_GRE);
    EXPECT_EQ(outer6.ip6_hops, details6.tun_ttl);
    EXPECT_EQ(std::memcmp(&outer6.ip6_src, &tunnel6.src.as_v6()->sin6_addr,
                          sizeof(in6_addr)), 0);
    EXPECT_EQ(std::memcmp(&outer6.ip6_dst, &tunnel6.dst.as_v6()->sin6_addr,
                          sizeof(in6_addr)), 0);
    EXPECT_EQ(inner_header6.ip6_nxt, connection_details::UDP);

    buffer inbound6;
    append_IPv6_header(inbound6, details6, 1, 5);
    std::memcpy(&outer6, inbound6.data(), sizeof(outer6));
    std::memcpy(&inner_header6,
                static_cast<unsigned char const*>(inbound6.data())
                    + sizeof(outer6) + sizeof(grehdr),
                sizeof(inner_header6));
    EXPECT_EQ(std::memcmp(&outer6.ip6_src, &tunnel6.src.as_v6()->sin6_addr,
                          sizeof(in6_addr)), 0);
    EXPECT_EQ(std::memcmp(&outer6.ip6_dst, &tunnel6.dst.as_v6()->sin6_addr,
                          sizeof(in6_addr)), 0);
    EXPECT_EQ(std::memcmp(&inner_header6.ip6_src, &inner6.dst.as_v6()->sin6_addr,
                          sizeof(in6_addr)), 0);
    EXPECT_EQ(std::memcmp(&inner_header6.ip6_dst, &inner6.src.as_v6()->sin6_addr,
                          sizeof(in6_addr)), 0);

    details4.tun_details = &tunnel6;
    buffer inner4_outer6;
    append_IPv4_header(inner4_outer6, details4, 0, 1);
    ASSERT_EQ(inner4_outer6.size(), sizeof(ip6_hdr) + sizeof(grehdr) + sizeof(iphdr));

    details6.tun_details = &tunnel4;
    buffer inner6_outer4;
    append_IPv6_header(inner6_outer4, details6, 0, 1);
    ASSERT_EQ(inner6_outer4.size(), sizeof(iphdr) + sizeof(grehdr) + sizeof(ip6_hdr));
}

TEST(PcapTest, HeaderBuildersRejectUnsupportedProtocolsAndFamilies) {
    connection_details details {};
    iphdr header4 {};
    ip6_hdr header6 {};

    details.next_proto = 255;
    EXPECT_THROW(create_IPv4_header(header4, details, 0, 0), std::invalid_argument);
    EXPECT_THROW(create_IPv6_header(header6, details, 0, 0), std::invalid_argument);

    details.next_proto = connection_details::UDP;
    details.tun_proto = connection_details::GRE;
    details.ip_version = 255;
    EXPECT_THROW(create_IPv4_header(header4, details, 2, 0), std::invalid_argument);
    EXPECT_THROW(create_IPv6_header(header6, details, 2, 0), std::invalid_argument);

    details.ip_version = 4;
    details.tun_proto = connection_details::NONE;
    EXPECT_THROW(create_IPv4_header(header4, details, 2, 0), std::invalid_argument);
    EXPECT_THROW(create_IPv6_header(header6, details, 2, 0), std::invalid_argument);
}

TEST(PcapTest, FileHelpersReportLockAndWriteFailures) {
    auto* file = std::tmpfile();
    ASSERT_NE(file, nullptr);
    auto const fd = ::fileno(file);
    ASSERT_GE(fd, 0);

    EXPECT_TRUE(lock_fd(fd));
    EXPECT_TRUE(unlock_fd(fd));
    std::fclose(file);

    EXPECT_FALSE(lock_fd(-1));
    EXPECT_FALSE(unlock_fd(-1));
    save_payload(-1, "x", 1);
}

TEST(PcapTest, FrameBuildersRejectNegativeAndEmptyPayloads) {
    tcp_details tcp {};
    connection_details udp {};
    buffer output;

    EXPECT_EQ(append_TCP_frame(output, nullptr, -1, 0, 0, tcp),
              static_cast<size_t>(-1));
    EXPECT_EQ(append_UDP_frame(output, nullptr, -1, 0, udp),
              static_cast<size_t>(-1));

    socle::pcapng::pcapng_epb frame;
    EXPECT_EQ(frame.append_TCP(output, nullptr, -1, 0, 0, tcp),
              static_cast<size_t>(-1));
    EXPECT_EQ(frame.append_TCP(output, nullptr, 0, 0, 0, tcp),
              static_cast<size_t>(-1));
    EXPECT_EQ(frame.append_UDP(output, nullptr, -1, 0, udp),
              static_cast<size_t>(-1));
}


TEST(PcapTest, BasicHttp) {

    SocketInfo s;
    s.src.str_host = "1.1.1.1";
    s.dst.str_host = "8.8.8.8";
    s.src.port = 63333;
    s.dst.port = 80;
    s.dst.pack();
    s.src.pack();

    ASSERT_TRUE(s.src.ss.has_value());
    ASSERT_TRUE(s.dst.ss.has_value());

    tcp_details d{};
    d.seq_in =  11111L;
    d.seq_out = 22222L;
    d.source = s.src.ss.value();
    d.destination = s.dst.ss.value();

    auto* f = std::tmpfile();
    ASSERT_NE(f, nullptr);

    std::stringstream req;
    req << "GET /ipv4/tcp HTTP/1.0\r\n";
    req << "Host: smithproxy.org\r\n";
    req << "\r\n";

    auto request = req.str();

    std::stringstream resp;
    resp << "HTTP/1.0 500 Testing OK\r\n";\
    resp << "\r\n";

    auto response = resp.str();

    // buffer::use_pool = false;

    auto fd = fileno(f);
    save_PCAP_magic(fd);
    save_TCP_frame(fd, "", 0, 0, TCPFLAG_SYN, d);
    save_TCP_frame(fd, "", 0, 1, TCPFLAG_SYN | TCPFLAG_ACK, d);
    save_TCP_frame(fd, "", 0, 0, TCPFLAG_ACK, d);
    save_TCP_frame(fd, request.data(), request.size(), 0, 0, d);
    save_TCP_frame(fd, response.data(), response.size(), 1, 0, d);
    save_TCP_frame(fd, "", 0, 0, TCPFLAG_FIN | TCPFLAG_ACK, d);
    save_TCP_frame(fd, "", 0, 1, TCPFLAG_FIN | TCPFLAG_ACK, d);

    fclose(f);
}


TEST(PcapTest, BasicHttp_v6) {

    SocketInfo s;
    s.src.str_host = "fe80::7f65:f37c:5f6:965d";
    s.dst.str_host = "2001:67c:68::76";
    s.src.family = AF_INET6;
    s.dst.family = AF_INET6;
    s.src.port = 63333;
    s.dst.port = 80;
    s.dst.pack();
    s.src.pack();

    ASSERT_TRUE(s.src.ss.has_value());
    ASSERT_TRUE(s.dst.ss.has_value());

    tcp_details d{};
    d.seq_in =  11111L;
    d.seq_out = 22222L;
    d.source = s.src.ss.value();
    d.destination = s.dst.ss.value();
    d.ip_version = 6;

    auto* f = std::tmpfile();
    ASSERT_NE(f, nullptr);

    std::stringstream req;
    req << "GET /ipv6/tcp HTTP/1.0\r\n";
    req << "Host: smithproxy.org\r\n";
    req << "\r\n";

    auto request = req.str();

    std::stringstream resp;
    resp << "HTTP/1.0 200 Testing OK\r\n";\
    resp << "\r\n";

    auto response = resp.str();

    // buffer::use_pool = false;

    auto fd = fileno(f);
    save_PCAP_magic(fd);
    save_TCP_frame(fd, "", 0, 0, TCPFLAG_SYN, d);
    save_TCP_frame(fd, "", 0, 1, TCPFLAG_SYN | TCPFLAG_ACK, d);
    save_TCP_frame(fd, "", 0, 0, TCPFLAG_ACK, d);
    save_TCP_frame(fd, request.data(), request.size(), 0, 0, d);
    save_TCP_frame(fd, response.data(), response.size(), 1, 0, d);
    save_TCP_frame(fd, "", 0, 0, TCPFLAG_FIN | TCPFLAG_ACK, d);
    save_TCP_frame(fd, "", 0, 1, TCPFLAG_FIN | TCPFLAG_ACK, d);

    fclose(f);
}


TEST(PcapTest, BasicUDP) {

    SocketInfo s;
    s.src.str_host = "1.1.1.1";
    s.dst.str_host = "8.8.8.8";
    s.src.port = 63333;
    s.dst.port = 514;

    s.dst.pack();
    s.src.pack();

    ASSERT_TRUE(s.src.ss.has_value());
    ASSERT_TRUE(s.dst.ss.has_value());

    connection_details d{};
    d.next_proto = connection_details::UDP;
    d.source = s.src.ss.value();
    d.destination = s.dst.ss.value();

    auto* f = std::tmpfile();
    ASSERT_NE(f, nullptr);

    std::stringstream req;
    req << "/ipv4/udp";

    auto request = req.str();

    std::stringstream resp;
    resp << "OK";

    auto response = resp.str();

    // buffer::use_pool = false;

    auto fd = fileno(f);
    save_PCAP_magic(fd);
    save_UDP_frame(fd, request.data(), request.size(), 0, d);
    save_UDP_frame(fd, response.data(), response.size(), 1, d);

    fclose(f);
}


TEST(PcapTest, BasicUDP_v6) {

    SocketInfo s;
    s.src.str_host = "fe80::7f65:f37c:5f6:965d";
    s.dst.str_host = "2001:67c:68::76";
    s.src.family = AF_INET6;
    s.dst.family = AF_INET6;
    s.src.port = 63333;
    s.dst.port = 514;

    s.dst.pack();
    s.src.pack();

    ASSERT_TRUE(s.src.ss.has_value());
    ASSERT_TRUE(s.dst.ss.has_value());

    connection_details d{};
    d.next_proto = connection_details::UDP;
    d.source = s.src.ss.value();
    d.destination = s.dst.ss.value();
    d.ip_version = 6;

    auto* f = std::tmpfile();
    ASSERT_NE(f, nullptr);

    std::stringstream req;
    req << "/ipv6/udp";

    auto request = req.str();

    std::stringstream resp;
    resp << "OK";

    auto response = resp.str();

    // buffer::use_pool = false;

    auto fd = fileno(f);
    save_PCAP_magic(fd);
    save_UDP_frame(fd, request.data(), request.size(), 0, d);
    save_UDP_frame(fd, response.data(), response.size(), 1, d);

    fclose(f);
}

TEST(PcapLogTest, WritesTcpAndUdpFlowsThroughHighLevelLogger) {
    auto directory = std::filesystem::temp_directory_path()
                     / ("socle-pcaplog-" + std::to_string(::getpid()));
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);

    CaptureProxy proxy;
    proxy.attach(new baseHostCX(new TCPCom(), "127.0.0.1", "12345"),
                 new baseHostCX(new TCPCom(), "127.0.0.2", "443"));

    std::filesystem::path output;
    auto packets = std::make_shared<CountingPacketHook>();
    {
        socle::traflog::PcapLog capture(
            &proxy, directory.c_str(), "coverage-", "pcapng", true);
        capture.ip_packet_hook = packets;
        output = capture.FS.filename_full;
        ASSERT_FALSE(output.empty());
        buffer payload;
        payload.append("request", 7);
        capture.write(socle::side_t::LEFT, std::string("test frame"));
        capture.write(socle::side_t::LEFT, payload);
        capture.write(socle::side_t::RIGHT, payload);
        EXPECT_TRUE(capture.tcp_start_written);

        capture.details.next_proto = connection_details::UDP;
        capture.write(socle::side_t::LEFT, payload);
        EXPECT_GT(capture.stat_bytes_written, 0);
    }

    ASSERT_TRUE(std::filesystem::exists(output));
    // Three synthetic TCP handshake packets plus the two payload writes.
    EXPECT_GE(packets->packets, 5U);
    std::filesystem::remove_all(directory);
}

// UDP
// src: 192.168.254.100:56579
// dst: 8.8.8.8:53
// correct checksum: f685
// incorrect seen: dcf6
const unsigned char dns_req[] = {

        //LCC
        //0x00, 0x04, 0x00, 0x01, 0x00, 0x06, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x08, 0x00,

        // IP
        //0x45, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x40, 0x00, 0x80, 0x11, 0x2b, 0x72, 0xc0, 0xa8, 0xfe, 0x64,
        //                                                          < chksum >
        /*0x08, 0x08, 0x08, 0x08,*/

        // UDP
                              /*0xdd, 0x03, 0x00, 0x35, 0x00, 0x4a, 0x00, 0x00,*/
                                                                                0xd9, 0x9a, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x66, 0x69, 0x72, 0x65, 0x66, 0x6f, 0x78,
        0x08, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x08, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
        0x65, 0x73, 0x07, 0x6d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x02, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

TEST(PcapTest, L4_chksum) {
    const bool calculate_checksums = CONFIG::CALCULATE_CHECKSUMS;
    CONFIG::CALCULATE_CHECKSUMS = true;
    SocketInfo s;
    s.src.str_host = "192.168.254.100";
    s.dst.str_host = "8.8.8.8";

    s.src.family = AF_INET;
    s.dst.family = AF_INET;

    s.src.port = 56579;
    s.dst.port = 53;

    s.dst.pack();
    s.src.pack();

    tcp_details d;
    d.source = s.src.ss.value();
    d.destination = s.dst.ss.value();
    d.next_proto = connection_details::UDP;
    d.ip_version = 4;


    struct udphdr udp_header{};
    auto [ sport, dport ] = d.extract_ports();

    udp_header.source = sport;
    udp_header.dest = dport;
    udp_header.len = htons(sizeof(udp_header) + sizeof(dns_req));
    udp_header.check = htons(L4_chksum<udphdr>(d, 0, &udp_header, (const char*) dns_req, sizeof(dns_req)));

    std::cout << string_format("chksum: 0x%x\n", udp_header.check);
    CONFIG::CALCULATE_CHECKSUMS = calculate_checksums;
    ASSERT_TRUE(udp_header.check == ntohs(0xf685));
}
