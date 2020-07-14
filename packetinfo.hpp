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

#ifndef _PACKETINFO_HPP_
#define _PACKETINFO_HPP_

#include <sys/socket.h>
#include <unistd.h>

#include <log/logger.hpp>

#include <string>

class packet_info_error : public std::runtime_error{
public:
    explicit packet_info_error(const char* w) : std::runtime_error(w) {};
};

struct packet_info {

    std::optional<struct sockaddr_storage> src_ss;
    inline void unpack_src_ss() {

        if(! src_ss.has_value()) throw packet_info_error("cannot obtain source details");

        src_family = inet_ss_address_unpack(& src_ss.value(), &str_src_host, &sport);
    };

    int src_family = AF_INET;
    std::string str_src_host;
    unsigned short sport = 0;

    std::optional<struct sockaddr_storage> dst_ss;
    inline void unpack_dst_ss() {

        if(! dst_ss.has_value()) throw packet_info_error("cannot obtain destination details");

        dst_family = inet_ss_address_unpack(& dst_ss.value(), &str_dst_host, &dport);
    };


    int dst_family = AF_INET;
    std::string str_dst_host;
    unsigned short dport = 0;

    static uint32_t create_session_key4(sockaddr_storage *from, sockaddr_storage* orig,  bool shift=false);
    static uint32_t create_session_key6(sockaddr_storage *from, sockaddr_storage* orig, bool shift=false);

    std::pair<int,int> create_socketpair() const;
};

#endif //_PACKETINFO_HPP_