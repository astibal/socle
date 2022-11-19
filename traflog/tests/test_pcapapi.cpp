#include <gtest/gtest.h>

#include <socketinfo.hpp>
#include <traflog/pcapapi.hpp>

using namespace socle::pcap;


// NOTE: it's not really practical to check generated PCAP content automatically packet by packet,
//       please check files in wireshark.


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

    auto f = fopen("/tmp/ipv4_udp.pcap", "w");

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

    auto f = fopen("/tmp/ipv6_udp.pcap", "w");

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
    ASSERT_TRUE(udp_header.check == ntohs(0xf685));
}