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
    s.src.str_host = "1.1.1.1";
    s.dst.str_host = "8.8.8.8";
    s.src.port = 63333;
    s.dst.port = 80;
    s.dst.pack();
    s.src.pack();

    ASSERT_TRUE(s.src.ss.has_value());
    ASSERT_TRUE(s.dst.ss.has_value());

    tcp_details d{};
    d.seq_in = 11111L;
    d.seq_out = 22222L;
    d.source = s.src.ss.value();
    d.destination = s.dst.ss.value();

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


#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <vars.hpp>

struct DevInfo {
    int socket {-1};
    std::string devname;
};

std::optional<DevInfo> tun_alloc(std::string const& dev)
{
    if(dev.empty()) return std::nullopt;

    int fd;

    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
        return std::nullopt;
    }

    ifreq ifr {};
    memset(&ifr, 0, sizeof(ifr));

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    std::strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ);

    if (auto err = ioctl(fd, TUNSETIFF, (void *) &ifr); err < 0) {
        std::cerr << "cannot create: " << dev << " : " << string_error() << "\n";
        close(fd);
        return std::nullopt;
    }


    {
        auto ns = raw::var<int>(socket(AF_INET, SOCK_DGRAM, IPPROTO_IP), raw::deleter::close);
        if(ns.value < 0) return std::nullopt;

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ);
        ifr.ifr_flags = IFF_UP | IFF_POINTOPOINT | IFF_RUNNING | IFF_NOARP;
        if (auto err = ioctl(ns.value, SIOCSIFFLAGS, (void *) &ifr); err < 0) {
            std::cerr << "cannot set up: " << dev << " : " << string_error() << "\n";
            return std::nullopt;
        }
    }


    DevInfo r = { fd, ifr.ifr_name };
    return r;
}

TEST(PcapExperiments, Tun4) {

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

    d.tun_proto = IPPROTO_GRE;

    std::stringstream req;
    req << "/ng/ipv4/udp";

    auto request = req.str();

    std::stringstream resp;
    resp << "NG OK";

    auto response = resp.str();

    buffer a;
    append_IP_header(a, d, 0, request.size());
    append_UDP_header(a, d, 0, request.data(), request.size());
    a.append(request.data(), request.size());

    buffer b;
    append_IP_header(b, d, 1, response.size());
    append_UDP_header(b, d, 1, response.data(), response.size());
    b.append(response.data(), response.size());


    auto devinfo = tun_alloc("sxtun0");

    if(devinfo) {
        sleep(15);


        for (int i = 0; i < 20; ++i) {
            //::write(devinfo->socket, &sa, 2);
            while(::write(devinfo->socket, a.data(), a.size()) <= 0);

            //::write(devinfo->socket, &sb, 2);
            while(::write(devinfo->socket, b.data(), b.size()) <= 0);
        }

        sleep(15);
    }
}

int raw_socket() {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if(s < 0) return s;

    int one = 1;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0) {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        close(s);

        return -1;
    }

    return s;
}




TEST(PcapExperiments, Tun6) {
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

    d.tun_proto = IPPROTO_GRE;
    d.tun_ttl = 3;

    SocketInfo tun;
//    tun.src.str_host = "fe11::11";
//    tun.dst.str_host = "fe11::88";
//    tun.src.family = AF_INET6;
//    tun.dst.family = AF_INET6;

    tun.src.str_host = "172.30.1.1";
    tun.dst.str_host = "172.30.255.1";
    tun.src.family = AF_INET;
    tun.dst.family = AF_INET;


    d.tun_details = &tun;

    std::stringstream req;
    req << "/ng/ipv6/udp";

    auto request = req.str();

    std::stringstream resp;
    resp << "NG OK";

    auto response = resp.str();

    buffer a;
    append_IP_header(a, d, 0, request.size());
    append_UDP_header(a, d, 0, request.data(), request.size());
    a.append(request.data(), request.size());

    buffer b;
    append_IP_header(b, d, 1, response.size());

    append_UDP_header(b, d, 1, response.data(), response.size());
    b.append(response.data(), response.size());


    [&] {
        auto r = raw_socket();
        if(r) {
            sendto(r, a.data(), a.size(), 0, (sockaddr*) &d.tun_details->dst.ss.value(),
                   sizeof(sockaddr_storage));
            sendto(r, b.data(), b.size(), 0, (sockaddr*) &d.tun_details->dst.ss.value(),
                   sizeof(sockaddr_storage));

        } else {
            std::cerr << "no raw socket" << std::endl;
        }
    }();


    auto devinfo = tun_alloc("sxtun0");

    if(devinfo) {
        sleep(15);


        for (int i = 0; i < 20; ++i) {
            //::write(devinfo->socket, &sa, 2);
            while(::write(devinfo->socket, a.data(), a.size()) <= 0);

            //::write(devinfo->socket, &sb, 2);
            while(::write(devinfo->socket, b.data(), b.size()) <= 0);

        }

        sleep(15);
    }
}