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
#include <tcpcom.hpp>
#include <socketinfo.hpp>
#include <internet.hpp>

#include <vars.hpp>

using namespace socle;

void TCPCom::init(baseHostCX* owner) { 
    
    baseCom::init(owner); 
}


bool TCPCom::make_transparent(int sfd) {

    int bind_status = namesocket(sfd, nonlocal_src_host(), nonlocal_src_port(), l3_proto());
    if (bind_status != 0) {
        _war("cannot bind this %s socket to %s:%d: %s", SocketInfo::inet_family_str(l3_proto()).c_str(),
             nonlocal_src_host().c_str(), nonlocal_src_port(), string_error(bind_status).c_str());

        return false;
    }

    return true;
}

int TCPCom::connect(const char* host, const char* port) {
    struct addrinfo hints{};
    struct addrinfo *gai_result, *rp;
    int sfd = -1;
    int gai;

    /* Obtain address(es) matching host/port */

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = connect_sock_family;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = connect_sock_type; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    gai = getaddrinfo(host, port, &hints, &gai_result);
    if (gai != 0) {
        _deb("TCPCom::connect[%s:%s]: getaddrinfo: %s", host, port, gai_strerror(gai));
        return -2;
    }

    auto gai_r = raw::lax<addrinfo*>(gai_result, [](auto& r) { freeaddrinfo(r); } );

    /* getaddrinfo() returns a list of address structures.
    Try each address until we successfully connect(2).
    If socket(2) (or connect(2)) fails, we (close the socket
    and) try the next address. */

    for (rp = gai_result; rp != nullptr; rp = rp->ai_next) {
        _deb("TCPCom::connect[%s:%s]: gai info found", host, port);

        sfd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if(sfd < 0) {
            _err("TCPCom::connect[%s:%s]:cannot create socket: family %d, socktype %d, protocol %d", host, port,
                                                    rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            continue;
        }

        on_new_socket(sfd);
        // Keep it here: would be good if we can do something like this in the future

        if(nonlocal_src() and make_transparent(sfd)) {
            _dia("TCPCom::connect[%s:%s]: socket[%d] transparency for %s:%d OK", host, port, sfd, nonlocal_src_host().c_str(), nonlocal_src_port());
        } else {
            _war("TCPCom::connect[%s:%s]: socket[%d] transparency for %s:%d failed", host, port, sfd, nonlocal_src_host().c_str(), nonlocal_src_port());
        }


        if (not GLOBAL_IO_BLOCKING()) {
            unblock(sfd);

            if (::connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
                break;

            if (errno == EINPROGRESS ) {
                _deb("TCPCom::connect[%s:%s]: socket[%d]: connect errno: EINPROGRESS", host, port, sfd);
                break;
            }

        } else {
            if (::connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
                break;

            _not("TCPCom::connect[%s:%s]: socket[%d]: connect errno: %s", host, port, sfd, string_error(errno).c_str());
        }

        // all captive continue op - close fd
        if(sfd >= 0) {
            ::close(sfd);
            sfd = -1;
        }
    }

    
    if(sfd < 0) {
        _err("TCPCom::connect[%s:%s]: socket[%d]: connect failed", host, port, sfd);
    }

    return socket(sfd);

}

int TCPCom::bind(unsigned short port) {

    sockaddr_storage sa{};

    sa.ss_family = bind_sock_family;
    
    if(sa.ss_family == AF_INET) {
        inet::to_sockaddr_in(&sa)->sin_port = htons(port);
        inet::to_sockaddr_in(&sa)->sin_addr.s_addr = INADDR_ANY;
    }
    else if(sa.ss_family == AF_INET6) {
        inet::to_sockaddr_in6(&sa)->sin6_port = htons(port);
        inet::to_sockaddr_in6(&sa)->sin6_addr = in6addr_any;
    }

    int sock = ::socket(bind_sock_family, bind_sock_type, bind_sock_protocol);

    if (sock == -1)
        return -129;

    so_reuseaddr(sock);
    
    if(nonlocal_dst_) {
        // allows socket to accept connections for non-local IPs
        _dia("TCPCom::bind[%d]: setting it transparent", sock);


        // NOTE: we need to set both, IPv4 and IPv6 on bound socket to get correct transparency.
        // leave matching INET6 twice, it's correct!
        if(sa.ss_family == AF_INET or sa.ss_family == AF_INET6 or sa.ss_family == AF_UNSPEC) {
            so_transparent_v4(sock);
        }
        if (sa.ss_family == AF_INET6) {
            so_transparent_v6(sock);
        }
    }
    
    if (::bind(sock, (sockaddr *)&sa, sizeof(sa)) == -1) {
        ::close(sock);   // coverity: 1407959
        return -130;
    }
    if (listen(sock, config.listen_backlog) == -1)  return -131;
    
    return sock;
}


int TCPCom::accept ( int sockfd, sockaddr* addr, socklen_t* addrlen_ ) {
    int news = ::accept(sockfd, addr, addrlen_);

    if(news < 0) {
        if(not (errno == EAGAIN or errno == EWOULDBLOCK)) {
            // report uncommon error
            _err("failed to accept socket: %s", string_error().c_str());
        }
        return -1;
    }

    on_new_socket(news);
    return news;
}

bool TCPCom::is_connected(int s) {
    
    if(socket() == 0) {
        _deb("TCPCom::is_connected: called for non-connecting socket");
        return true;
    }
    
    int error_code = 0;
    socklen_t l = sizeof(error_code);

    // tcp socket will stay in EINPROGRESS unless there is ANY stat call! Don't ask why. 
    // fstating socket seemed to me cheapest/fastest.
    // fstating with stat struct buffer wasn't working too!
    // 2016-01-16: seems not needed anymore. But keep to easy revert in case.

    // Keeping for reference and curiosity. This was really a thing.
    // struct stat stb{};
    // fstat(s, &stb);

    int r_getsockopt = getsockopt(s, SOL_SOCKET, SO_ERROR, &error_code, &l);
    error_code = errno;
    
    if ( r_getsockopt == 0 ) {
                                
        if(error_code != 0) {
                _deb("TCPCom::is_connected[%d]: getsockopt errno %d = %s", s, error_code, string_error(error_code).c_str());
        }
        else {
                _dum("TCPCom::is_connected[%d]: getsockopt errno %d = %s", s, error_code, string_error(error_code).c_str());
        }
        
        if(error_code == EINPROGRESS) return false;

        // optimized-out in Release
        _if_deb {
            if(master()->poller.in_write_set(s)) {
                _deb("TCP::is_connected[%d]: writable", s);
            } else {
                _deb("TCP::is_connected[%d]: not writable", s);
            }
        }

        return true;

    } else {
        _dia("TCPCom::is_connected[%d]: getsockopt failed, returned %d = %s", s, r_getsockopt, string_error(error_code).c_str());
        return false;
    } 
}


bool TCPCom::com_status() {
    
    if(baseCom::com_status()) {
        bool r = is_connected(socket());
        _deb("TCPCom::com_status: returning %d", r);
        return r;
    }
    
    _deb("TCPCom::com_status: returning 0");
    return false;    
}

void TCPCom::on_new_socket(int _fd) {
    if(_fd >= 0) {
        so_nodelay(_fd);
        so_quickack(_fd);
    }

    baseCom::on_new_socket(_fd);
}
