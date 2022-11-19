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
#include <optional>

class socket_info_error : public std::runtime_error{
public:
    explicit socket_info_error(const char* w) : std::runtime_error(w) {};
};

struct SockOps {
    static sockaddr_in* ss_v4(struct sockaddr_storage* what) { return reinterpret_cast<sockaddr_in*>(what); }
    static sockaddr_in6* ss_v6(struct sockaddr_storage* what) { return reinterpret_cast<sockaddr_in6*>(what); }
    static std::string family_str(int fa);

    // unpack low-level sockaddr_storage into string and port, returning family.
    // Recognizes IPv4 to IPv6 mapped socket and returns correctly AF_INET with correct IPv4 address.
    static int ss_address_unpack(const sockaddr_storage *ptr, std::string* dst, unsigned short* port);

    // converts one @orig sockaddr_storage into @mapped (with ipv4 to ipv6 mapped address detection).
    static int ss_address_remap(const sockaddr_storage *orig, sockaddr_storage* mapped);

    // returns sockaddr_storage in human readable string description
    static std::string ss_str(const sockaddr_storage *s);

    static void socket_transparent(int fd, int family);
    static int socket_create(int family ,int l4proto, int protocol);
};

struct AddressInfo {
    std::optional<struct sockaddr_storage> ss;

    int family = AF_INET;
    std::string str_host;
    unsigned short port = 0;

    void unpack();
    void pack();

    sockaddr_in* as_v4() { return SockOps::ss_v4(&ss.value()); }
    sockaddr_in6* as_v6() { return SockOps::ss_v6(&ss.value()); }
    sockaddr_storage* as_ss() { return &ss.value(); }

    explicit operator bool() const { return ss.has_value(); };

    [[nodiscard]] std::string family_str() const { return SockOps::family_str(family); }

};

struct SocketInfo {

    void unpack() { src.unpack(); dst.unpack(); }
    void unpack_src() { src.unpack(); };
    void unpack_dst() { dst.unpack(); };

    void pack() { src.pack(); dst.pack(); }
    void pack_src() { src.pack(); };
    void pack_dst() { dst.pack(); };


    int create_socket_left (int l4_proto);


    // create pseudo-unique session id. If @negative is true, returning value is "signed" (most significant bit set to 1)
    // Note: return value is uint
    uint32_t create_session_key(bool negative=false);
    static uint32_t create_session_key4(sockaddr_storage *from, sockaddr_storage* orig,  bool negative=false);
    static uint32_t create_session_key6(sockaddr_storage *from, sockaddr_storage* orig, bool negative=false);

    // convert socket family to human-readable string. ie: AF_INET into "ip4"

    std::string src_ss_str() const { if(src) return SockOps::ss_str(&src.ss.value()); return "<src-?>"; }
    std::string dst_ss_str() const { if(dst) return SockOps::ss_str(&dst.ss.value()); return "<dst-?>"; }

    // data are packed into optionals, or unpacked from them -- depending on particular use case.
    // data members - source info

    AddressInfo src;
    AddressInfo dst;
};

#endif //_SOCKETINFO_HPP_