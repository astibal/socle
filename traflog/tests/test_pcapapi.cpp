#include <gtest/gtest.h>

#include <socketinfo.hpp>
#include <traflog/pcapapi.hpp>

using namespace socle::pcap;


// NOTE: it's not really practical to check generated PCAP content automatically packet by packet,
//       please check files in wireshark.


TEST(PcapTest, BasicHttp) {

    SocketInfo s;
    s.str_src_host = "1.1.1.1";
    s.str_dst_host = "8.8.8.8";
    s.sport = 63333;
    s.dport = 80;
    s.pack_dst_ss();
    s.pack_src_ss();

    ASSERT_TRUE(s.src_ss.has_value());
    ASSERT_TRUE(s.dst_ss.has_value());

    tcp_details d{};
    d.seq_in =  11111L;
    d.seq_out = 22222L;
    d.source = s.src_ss.value();
    d.destination = s.dst_ss.value();

    auto f = fopen("/tmp/ipv4_tcp.pcap", "w");

    std::stringstream req;
    req << "GET /ipv4/tcp HTTP/1.0\r\n";
    req << "Host: smithproxy.org\r\n";
    req << "\r\n";

    auto request = req.str();

    std::stringstream resp;
    resp << "HTTP/1.0 500 Testing OK\r\n";\
    resp << "\r\n";

    auto response = resp.str();

    buffer::use_pool = false;

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
    s.str_src_host = "fe80::7f65:f37c:5f6:965d";
    s.str_dst_host = "2001:67c:68::76";
    s.src_family = AF_INET6;
    s.dst_family = AF_INET6;
    s.sport = 63333;
    s.dport = 80;
    s.pack_dst_ss();
    s.pack_src_ss();

    ASSERT_TRUE(s.src_ss.has_value());
    ASSERT_TRUE(s.dst_ss.has_value());

    tcp_details d{};
    d.seq_in =  11111L;
    d.seq_out = 22222L;
    d.source = s.src_ss.value();
    d.destination = s.dst_ss.value();
    d.ip_version = 6;

    auto f = fopen("/tmp/ipv6_tcp.pcap", "w");

    std::stringstream req;
    req << "GET /ipv6/tcp HTTP/1.0\r\n";
    req << "Host: smithproxy.org\r\n";
    req << "\r\n";

    auto request = req.str();

    std::stringstream resp;
    resp << "HTTP/1.0 200 Testing OK\r\n";\
    resp << "\r\n";

    auto response = resp.str();

    buffer::use_pool = false;

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
    s.str_src_host = "1.1.1.1";
    s.str_dst_host = "8.8.8.8";
    s.sport = 63333;
    s.dport = 514;

    s.pack_dst_ss();
    s.pack_src_ss();

    ASSERT_TRUE(s.src_ss.has_value());
    ASSERT_TRUE(s.dst_ss.has_value());

    connection_details d{};
    d.next_proto = connection_details::UDP;
    d.source = s.src_ss.value();
    d.destination = s.dst_ss.value();

    auto f = fopen("/tmp/ipv4_udp.pcap", "w");

    std::stringstream req;
    req << "/ipv4/udp";

    auto request = req.str();

    std::stringstream resp;
    resp << "OK";

    auto response = resp.str();

    buffer::use_pool = false;

    auto fd = fileno(f);
    save_PCAP_magic(fd);
    save_UDP_frame(fd, request.data(), request.size(), 0, d);
    save_UDP_frame(fd, response.data(), response.size(), 1, d);

    fclose(f);
}


TEST(PcapTest, BasicUDP_v6) {

    SocketInfo s;
    s.str_src_host = "fe80::7f65:f37c:5f6:965d";
    s.str_dst_host = "2001:67c:68::76";
    s.src_family = AF_INET6;
    s.dst_family = AF_INET6;
    s.sport = 63333;
    s.dport = 514;

    s.pack_dst_ss();
    s.pack_src_ss();

    ASSERT_TRUE(s.src_ss.has_value());
    ASSERT_TRUE(s.dst_ss.has_value());

    connection_details d{};
    d.next_proto = connection_details::UDP;
    d.source = s.src_ss.value();
    d.destination = s.dst_ss.value();
    d.ip_version = 6;

    auto f = fopen("/tmp/ipv6_udp.pcap", "w");

    std::stringstream req;
    req << "/ipv6/udp";

    auto request = req.str();

    std::stringstream resp;
    resp << "OK";

    auto response = resp.str();

    buffer::use_pool = false;

    auto fd = fileno(f);
    save_PCAP_magic(fd);
    save_UDP_frame(fd, request.data(), request.size(), 0, d);
    save_UDP_frame(fd, response.data(), response.size(), 1, d);

    fclose(f);
}