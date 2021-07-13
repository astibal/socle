#include <gtest/gtest.h>

#include <socketinfo.hpp>
#include <traflog/pcapapi.hpp>

using namespace socle::pcapng;

TEST(NgTest, Empty) {
    auto f = fopen("/tmp/ng_empty.pcapng", "w");
    auto fd = fileno(f);
    save_NG_magic(fd);
    fclose(f);
}


TEST(NgTest, Empty_Ipb) {
    auto f = fopen("/tmp/ng_empty_ifb.pcapng", "w");
    auto fd = fileno(f);
    save_NG_magic(fd);

    pcapng_ifb hdr;
    save_NG_ifb(fd, hdr);
    fclose(f);
}


TEST(NgTest, BasicHttp) {

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
    d.seq_in = 11111L;
    d.seq_out = 22222L;
    d.source = s.src_ss.value();
    d.destination = s.dst_ss.value();

    auto f = fopen("/tmp/ng_ipv4_tcp.pcapng", "w");

    std::stringstream req;
    req << "GET /ng/ipv4/tcp HTTP/1.0\r\n";
    req << "Host: smithproxy.org\r\n";
    req << "\r\n";

    auto request = req.str();

    std::stringstream resp;
    resp << "HTTP/1.0 200 NG test OK\r\n";\
    resp << "\r\n";

    auto response = resp.str();

    auto fd = fileno(f);

    save_NG_magic(fd);

    pcapng_ifb hdr;
    save_NG_ifb(fd, hdr);



    // should be separate frames for each packet, but this works for a test
    pcapng_epb frameS;
    frameS.comment("commented frame");

    frameS.save_TCP(fd, "", 0, 0, TCPFLAG_SYN, d);

    pcapng_epb frame1;
    frame1.save_TCP(fd, "", 0, 1, TCPFLAG_SYN | TCPFLAG_ACK, d);

    pcapng_epb frame2;
    frame2.save_TCP(fd, "", 0, 0, TCPFLAG_ACK, d);

    pcapng_epb frame3;
    frame3.comment("request data");
    frame3.save_TCP(fd, request.data(), request.size(), 0, 0, d);

    pcapng_epb frame4;
    frame4.comment("response data");
    frame4.save_TCP(fd, response.data(), response.size(), 1, 0, d);

    pcapng_epb frame5;
    frame5.save_TCP(fd, "", 0, 0, TCPFLAG_FIN | TCPFLAG_ACK, d);

    pcapng_epb frameL;
    frameL.save_TCP(fd, "", 0, 1, TCPFLAG_FIN | TCPFLAG_ACK, d);

    fflush(f);

    fclose(f);


}

TEST(NgTest, BasicUDP) {

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

    auto f = fopen("/tmp/ng_ipv4_udp.pcapng", "w");

    std::stringstream req;
    req << "/ng/ipv4/udp";

    auto request = req.str();

    std::stringstream resp;
    resp << "NG OK";

    auto response = resp.str();

    auto fd = fileno(f);

    save_NG_magic(fd);

    pcapng_ifb hdr;
    save_NG_ifb(fd, hdr);

    pcapng_epb frame1;
    frame1.save_UDP(fd, (const char*) request.data(), request.size(), 0, d);

    pcapng_epb frame2;
    frame2.save_UDP(fd, (const char*) response.data(), response.size(), 1, d);

    fclose(f);
}

TEST(NgTest, BasicUDP_v6) {

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

    auto f = fopen("/tmp/ng_ipv6_udp.pcapng", "w");

    std::stringstream req;
    req << "/ng/ipv6/udp";

    auto request = req.str();

    std::stringstream resp;
    resp << "NG OK";

    auto response = resp.str();

    // buffer::use_pool = false;

    auto fd = fileno(f);

    save_NG_magic(fd);

    pcapng_ifb hdr;
    save_NG_ifb(fd, hdr);

    pcapng_epb frame1;
    frame1.save_UDP(fd, request.data(), request.size(), 0, d);

    pcapng_epb frame2;
    frame2.comment("yay!");
    frame2.save_UDP(fd, response.data(), response.size(), 1, d);

    fclose(f);
}