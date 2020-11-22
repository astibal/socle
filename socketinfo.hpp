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

#ifndef _SOCKETINFO_HPP_
#define _SOCKETINFO_HPP_

#include <sys/socket.h>
#include <unistd.h>

#include <log/logger.hpp>

#include <string>

class socket_info_error : public std::runtime_error{
public:
    explicit socket_info_error(const char* w) : std::runtime_error(w) {};
};

struct SocketInfo {


    void unpack_src_ss();
    void unpack_dst_ss();

    void pack_dst_ss();
    void pack_src_ss();
    int create_socket_left (int l4_proto);


    // create pseudo-unique session id. If @shift is true, returning value is "signed" (most significant bit set to 1)
    uint32_t create_session_key(bool shift=false);
    static uint32_t create_session_key4(sockaddr_storage *from, sockaddr_storage* orig,  bool shift=false);
    static uint32_t create_session_key6(sockaddr_storage *from, sockaddr_storage* orig, bool shift=false);

    // convert socket family to human readable string. ie.: AF_INET into "ip4"
    static std::string inet_family_str(int fa);

    // unpack low-level sockaddr_storage into string and port, returning family.
    // Recognizes IPv4 to IPv6 mapped socket and returns correctly AF_INET with correct IPv4 address.
    static int inet_ss_address_unpack(sockaddr_storage* ptr, std::string* dst, unsigned short* port);

    // converts one @orig sockaddr_storage into @mapped (with ipv4 to ipv6 mapped address detection).
    static int inet_ss_address_remap(sockaddr_storage* orig, sockaddr_storage* mapped);

    // returns sockaddr_storage in human readable string description
    static std::string inet_ss_str(sockaddr_storage* s);

    // data are packed into optionals, or unpacked from them -- depending on particular use case.
    // data members - source info
    std::optional<struct sockaddr_storage> src_ss;

    int src_family = AF_INET;
    std::string str_src_host;
    unsigned short sport = 0;


    // data members - destination info
    std::optional<struct sockaddr_storage> dst_ss;

    int dst_family = AF_INET;
    std::string str_dst_host;
    unsigned short dport = 0;

};

#endif //_SOCKETINFO_HPP_