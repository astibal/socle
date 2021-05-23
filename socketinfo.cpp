/*
    Socle - Socket Library Ecosystem
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    This library  is free  software;  you can redistribute  it and/or
    modify  it  under   the  terms of the  GNU Lesser  General Public
    License  as published by  the   Free Software Foundation;  either
    version 3.0 of the License, or (at your option) any later version.
    This library is  distributed  in the hope that  it will be useful,
    but WITHOUT ANY WARRANTY;  without  even  the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    See the GNU Lesser General Public License for more details.

    You  should have received a copy of the GNU Lesser General Public
    License along with this library.
*/

#include <fcntl.h>
#include <random>

#include <socketinfo.hpp>
#include <common/internet.hpp>


void SocketInfo::unpack_src_ss() {

    if(! src_ss.has_value()) throw socket_info_error("cannot obtain source details");

    src_family = inet_ss_address_unpack(& src_ss.value(), &str_src_host, &sport);
}


void SocketInfo::unpack_dst_ss() {

    if(! dst_ss.has_value()) throw socket_info_error("cannot obtain destination details");

    dst_family = inet_ss_address_unpack(& dst_ss.value(), &str_dst_host, &dport);
}


sockaddr_storage pack_ss(int family, const char* host, unsigned short port) {

    sockaddr_storage ss{};

    if(family == AF_INET6) {
        auto p_ip6_src = (sockaddr_in6 *) &ss;

        inet_pton(AF_INET6, host, &p_ip6_src->sin6_addr);
        ss.ss_family = AF_INET6;
        p_ip6_src->sin6_port = htons(port);
    }
    else {
        auto p_ip4_src = (sockaddr_in *) &ss;

        inet_pton(AF_INET, host, &p_ip4_src->sin_addr);
        ss.ss_family = AF_INET;
        p_ip4_src->sin_port = htons(port);
    }

    return ss;
}

void SocketInfo::pack_dst_ss () {
    dst_ss = std::make_optional(pack_ss(dst_family, str_dst_host.c_str(), dport));
}

void SocketInfo::pack_src_ss () {
    src_ss = std::make_optional(pack_ss(src_family, str_src_host.c_str(), sport));
}



uint32_t SocketInfo::create_session_key(bool shift) {


    if(! src_ss.has_value()) {
        pack_src_ss();
    }

    if(! dst_ss.has_value()) {
        pack_dst_ss();
    }

    switch (src_family) {
        case AF_INET6:
            return create_session_key6(&src_ss.value(), &dst_ss.value(), shift);
        default:
            return create_session_key4(&src_ss.value(), &dst_ss.value(), shift);
    }
}

uint32_t SocketInfo::create_session_key4(sockaddr_storage* from, sockaddr_storage* orig, bool shift) {

    uint32_t s = inet::to_sockaddr_in(from)->sin_addr.s_addr;
    uint32_t d = inet::to_sockaddr_in(orig)->sin_addr.s_addr;
    uint32_t sp = ntohs(inet::to_sockaddr_in(from)->sin_port);
    uint32_t sd = ntohs(inet::to_sockaddr_in(orig)->sin_port);

    std::seed_seq seed1{ s, d, sp, sd };
    std::mt19937 e(seed1);
    std::uniform_int_distribution<> dist;

    uint32_t mirand = dist(e);


    if(shift)
        mirand |= (1 << 31); //this will produce negative number, which should determine  if it's normal socket or not



    return mirand; // however we return it as the key, therefore cast to unsigned int
}

uint32_t SocketInfo::create_session_key6(sockaddr_storage* from, sockaddr_storage* orig, bool shift) {

    uint32_t s0 = ((uint32_t*)&inet::to_sockaddr_in6(from)->sin6_addr)[0];
    uint32_t s1 = ((uint32_t*)&inet::to_sockaddr_in6(from)->sin6_addr)[1];
    uint32_t s2 = ((uint32_t*)&inet::to_sockaddr_in6(from)->sin6_addr)[2];
    uint32_t s3 = ((uint32_t*)&inet::to_sockaddr_in6(from)->sin6_addr)[3];

    uint32_t d0 = ((uint32_t*)&inet::to_sockaddr_in6(orig)->sin6_addr)[0];
    uint32_t d1 = ((uint32_t*)&inet::to_sockaddr_in6(orig)->sin6_addr)[1];
    uint32_t d2 = ((uint32_t*)&inet::to_sockaddr_in6(orig)->sin6_addr)[2];
    uint32_t d3 = ((uint32_t*)&inet::to_sockaddr_in6(orig)->sin6_addr)[3];

    uint32_t sp = ntohs(inet::to_sockaddr_in6(from)->sin6_port);
    uint32_t dp = ntohs(inet::to_sockaddr_in6(orig)->sin6_port);

    std::seed_seq seed1{ s0, d0, s1, d1, s2, d2, s3, d3, sp, dp };
    std::mt19937 e(seed1);
    std::uniform_int_distribution<> dist;

    uint32_t mirand = dist(e);

    if(shift)
        mirand |= (1 << 31); //this will produce negative number, which should determine  if it's normal socket or not

    return mirand; // however we return it as the key, therefore cast to unsigned int
}


int SocketInfo::create_socket_left (int l4_proto) {

    auto socket_setup = [&]() -> int {
        int fd = socket(src_family, l4_proto, 0);

        if (fd < 0) {
            throw socket_info_error("socket call failed");

        }
        int n;

        if (n = 1; 0 != ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(int))) {
            throw socket_info_error(string_format("cannot set socket %d option SO_REUSEADDR\n", fd).c_str());
        }

        if (n = 1; 0 != ::setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &n, sizeof(int))) {
            throw socket_info_error(string_format("cannot set socket %d option IP_RECVORIGDSTADDR\n", fd).c_str());
        }

        if (n = 1; 0 != ::setsockopt(fd, SOL_IP, SO_BROADCAST, &n, sizeof(int))) {
            throw socket_info_error(string_format("cannot set socket %d option SO_BROADCAST\n", fd).c_str());
        }

        if(src_family == AF_INET) {
            if (n = 1; 0 != ::setsockopt(fd, SOL_IP, IP_TRANSPARENT, &n, sizeof(int))) {
                throw socket_info_error(string_format("cannot set socket %d option IP_TRANSPARENT\n", fd).c_str());
            }
        }
        else if (src_family == AF_INET6) {
            if (n = 1; 0 != ::setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &n, sizeof(int))) {
                throw socket_info_error(string_format("cannot set socket %d option IPV6_TRANSPARENT\n", fd).c_str());
            }
        }
        else {
            throw socket_info_error("cannot set transparency for unknown family");
        }

        if (int oldf = fcntl(fd, F_GETFL, 0) ; ! (oldf & O_NONBLOCK)) {
            if (fcntl(fd, F_SETFL, oldf | O_NONBLOCK) < 0) {
                throw socket_info_error(string_format("Error setting socket %d as non-blocking\n", fd).c_str());

                return -1;
            }
        }

        return fd;
    };

    int fd_left = socket_setup();

    pack_src_ss();
    pack_dst_ss();

    //_cons(inet_ss_str(& src_ss.value()).c_str());
    //_cons(inet_ss_str(& dst_ss.value()).c_str());

    auto plug_socket = [&](int fd, sockaddr* bind_ss, sockaddr* connect_ss) {

        // should be faster then std::string
        constexpr const char* bind_connect_race_hack_iface = "lo";
        constexpr size_t bcrhi_sz = 2;

        if(0 != ::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, bind_connect_race_hack_iface, bcrhi_sz)) {
            throw socket_info_error("cannot bind to device - bind-connect races may occur");
        }

        if(::bind(fd, bind_ss, sizeof(struct sockaddr_storage))) {
            throw socket_info_error(string_format("cannot bind port %d to %s:%d\n", fd, str_dst_host.c_str(), dport).c_str());
        }

        if (::connect(fd, connect_ss, sizeof(struct sockaddr_storage))) {
            throw socket_info_error(string_format("cannot connect port %d to %s:%d\n", fd, str_src_host.c_str(), sport).c_str());
        }

        if(0 != ::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "", 0)) {
            throw socket_info_error("cannot bind to 'any' device - socket inoperable");
        }
    };

    plug_socket(fd_left, (sockaddr *) &dst_ss.value(), (sockaddr *) &src_ss.value());

    return fd_left;
}

std::string SocketInfo::inet_family_str(int fa) {
    switch(fa) {
        case AF_INET:
            return std::string("ip4");
        case AF_INET6:
            return std::string("ip6");

        default:
            return string_format("p%d",fa);
    }
}


int SocketInfo::inet_ss_address_unpack(sockaddr_storage* ptr, std::string* dst, unsigned short* port) {

    constexpr size_t buf_sz = 64;

    char b[buf_sz]; memset(b,0,buf_sz);
    int family = ptr->ss_family;
    unsigned short val_port = 0;

    if(family == AF_INET6) {
        inet_ntop(ptr->ss_family,&(((struct sockaddr_in6*) ptr)->sin6_addr),b,buf_sz);
        val_port = ((struct sockaddr_in6*) ptr)->sin6_port;
    }
    else if(family == AF_INET) {
        inet_ntop(ptr->ss_family,&(((struct sockaddr_in*) ptr)->sin_addr),b,buf_sz);
        val_port = ((struct sockaddr_in*) ptr)->sin_port;
    }

    std::string mapped4_temp = b;
    if(mapped4_temp.find("::ffff:") == 0) {
        mapped4_temp = mapped4_temp.substr(7);
        family = AF_INET;
    }

    if(dst != nullptr) {
        // function can be useful just to detect mapped IP
        dst->assign(mapped4_temp);
    }
    if(port != nullptr) {
        *port = ntohs(val_port);
    }
    return family;
}


int SocketInfo::inet_ss_address_remap(sockaddr_storage* orig, sockaddr_storage* mapped) {
    std::string ip_part;
    unsigned short port_part;

    int fa = inet_ss_address_unpack(orig,&ip_part,&port_part);

    if(fa == AF_INET) {
        inet_pton(fa,ip_part.c_str(),&((struct sockaddr_in*)mapped)->sin_addr);
        ((struct sockaddr_in*)mapped)->sin_port = htons(port_part);
        mapped->ss_family = fa;
    }
    else if(fa == AF_INET6) {
        inet_pton(fa,ip_part.c_str(),&((struct sockaddr_in6*)mapped)->sin6_addr);
        ((struct sockaddr_in6*)mapped)->sin6_port = htons(port_part);
        mapped->ss_family = fa;
    }

    return fa;
}

std::string SocketInfo::inet_ss_str(sockaddr_storage* s) {
    std::string ip;
    unsigned short port;

    int fa = inet_ss_address_unpack(s,&ip,&port);

    return string_format("%s/%s:%d", inet_family_str(fa).c_str(),ip.c_str(),port);
}