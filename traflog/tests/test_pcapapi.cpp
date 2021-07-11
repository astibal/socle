#include <gtest/gtest.h>

#include <socketinfo.hpp>
#include <traflog/pcapapi.hpp>

using namespace socle::pcap;

TEST(PcapTest, BasicHttp) {

    SocketInfo s;
    s.str_src_host = "1.1.1.1";
    s.str_dst_host = "8.8.8.8";
    s.sport = 11111;
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

    auto f = fopen("/tmp/a.pcap", "w");

    std::stringstream req;
    req << "GET / HTTP/1.0\r\n";
    req << "Host: smithproxy.org\r\n";
    req << "\r\n";

    auto request = req.str();

    std::stringstream resp;
    resp << "HTTP/1.0 500 Testing OK\r\n";\
    resp << "\r\n";

    auto response = resp.str();

    write_pcap_header(fileno(f));
    write_pcap_frame(fileno(f), "", 0, 0, TCPFLAG_SYN, d);
    write_pcap_frame(fileno(f), "", 0, 1, TCPFLAG_SYN | TCPFLAG_ACK, d);
    write_pcap_frame(fileno(f), "", 0, 0, TCPFLAG_ACK, d);
    write_pcap_frame(fileno(f), request.data(), request.size(), 0, 0, d);
    write_pcap_frame(fileno(f), response.data(), response.size(), 1, 0, d);
    write_pcap_frame(fileno(f), "", 0, 0, TCPFLAG_FIN | TCPFLAG_ACK, d);
    write_pcap_frame(fileno(f), "", 0, 1, TCPFLAG_FIN | TCPFLAG_ACK, d);
    fclose(f);
}
