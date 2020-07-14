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

#include <random>

#include <packetinfo.hpp>
#include <common/internet.hpp>

uint32_t packet_info::create_session_key4(sockaddr_storage* from, sockaddr_storage* orig, bool shift) {

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

uint32_t packet_info::create_session_key6(sockaddr_storage* from, sockaddr_storage* orig, bool shift) {

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


std::pair<int,int> packet_info::create_socketpair() const {

    std::stringstream ss;

    auto socket_setup = [&]() -> int {
        int fd = socket(src_family, SOCK_DGRAM, 0);

        if (fd < 0) {
            _cons("socket failed");
            throw packet_info_error("socket call failed");

        }

        if(! dst_ss.has_value()) {
            throw packet_info_error("cannot create socket, src storage is null");
        }
        if(! dst_ss.has_value()) {
            throw packet_info_error("cannot create socket, dst storage is null");
        }


        int n = 1;

        if (0 != ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(int))) {
            ss << string_format("cannot set socket %d option SO_REUSEADDR\n", fd);
        }
        n = 1;

        if (0 != ::setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &n, sizeof(int))) {
            ss << string_format("cannot set socket %d option IP_RECVORIGDSTADDR\n", fd);
        }
        n = 1;

        if (0 != ::setsockopt(fd, SOL_IP, SO_BROADCAST, &n, sizeof(int))) {
            ss << string_format("cannot set socket %d option SO_BROADCAST\n", fd);
        }
        n = 1;

        if(src_family == AF_INET) {
            if (0 != ::setsockopt(fd, SOL_IP, IP_TRANSPARENT, &n, sizeof(int))) {
                ss << string_format("cannot set socket %d option IP_TRANSPARENT\n", fd);
            }
            n = 1;
        }
        else if (src_family == AF_INET6) {
            if (0 != ::setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &n, sizeof(int))) {
                ss << string_format("cannot set socket %d option IPV6_TRANSPARENT\n", fd);
            }
            n = 1;
        }
        else {
            throw packet_info_error("cannot set transparency for unknown family");
        }

        return fd;
    };

    int fd_left = socket_setup();
    int fd_right = socket_setup();

    sockaddr_storage ss_src{0};
    sockaddr_storage ss_dst{0};

    auto p_ip4_src = (sockaddr_in*) &ss_src;
    auto p_ip4_dst = (sockaddr_in*) &ss_dst;

    inet_pton(AF_INET,str_src_host.c_str(),&p_ip4_src->sin_addr); ss_src.ss_family=AF_INET; p_ip4_src->sin_port = htons(sport);
    inet_pton(AF_INET,str_dst_host.c_str(),&p_ip4_dst->sin_addr); ss_dst.ss_family=AF_INET; p_ip4_dst->sin_port = htons(dport);


    auto plug_socket = [&](int fd, sockaddr* bind_ss, sockaddr* connect_ss) {
        if(::bind(fd, bind_ss, sizeof(struct sockaddr_storage))) {
            ss << string_format("cannot bind port %d to %s:%d\n", fd, str_dst_host.c_str(), dport);
        } else {
            ss << string_format("OK bind port %d to %s:%d\n", fd, str_dst_host.c_str(), dport);
        }

        if (::connect(fd, connect_ss, sizeof(struct sockaddr_storage))) {
            ss << string_format("cannot connect port %d to %s:%d\n", fd, str_src_host.c_str(), sport);
        } else {
            ss << string_format("OK connect port %d to %s:%d\n", fd, str_src_host.c_str(), sport);
        }

    };

    plug_socket(fd_left, (sockaddr*) &ss_dst, (sockaddr*) &ss_src);
    plug_socket(fd_right, (sockaddr*) &ss_src, (sockaddr*) &ss_dst);


    ::send(fd_left, "ABCEFG", 6, MSG_DONTWAIT);
    ::send(fd_right, "XYZ123", 6, MSG_DONTWAIT);


    _cons(ss.str().c_str());

    return std::make_pair(fd_left, fd_right);
}
