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
#include <netinet/tcp.h>
#include <tcpcom.hpp>
#include <socketinfo.hpp>
#include <internet.hpp>


void TCPCom::init(baseHostCX* owner) { 
    
    baseCom::init(owner); 
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

    /* getaddrinfo() returns a list of address structures.
    Try each address until we successfully connect(2).
    If socket(2) (or connect(2)) fails, we (close the socket
    and) try the next address. */

    for (rp = gai_result; rp != nullptr; rp = rp->ai_next) {
        _deb("TCPCom::connect[%s:%s]: gai info found", host, port);

        sfd = ::socket(rp->ai_family, rp->ai_socktype,
                    rp->ai_protocol);

        on_new_socket(sfd);
        // Keep it here: would be good if we can do something like this in the future
        
        if(nonlocal_src()) {
            _deb("TCPCom::connect[%s:%s]: about to name socket[%d] after: %s:%d", host, port, sfd, nonlocal_src_host().c_str(), nonlocal_src_port());
            int bind_status = namesocket(sfd, nonlocal_src_host(), nonlocal_src_port(), l3_proto());
            if (bind_status != 0) {
                    _war("cannot bind this %s socket to %s:%d: %s", SocketInfo::inet_family_str(l3_proto()).c_str(), nonlocal_src_host().c_str(), nonlocal_src_port(), strerror(bind_status));
            } else {
                _dia("TCPCom::connect[%s:%s]: socket[%d] transparency for %s:%d OK", host, port, sfd, nonlocal_src_host().c_str(), nonlocal_src_port());
            }
        }

        //if (DDEB(110)) 
        
        
        if (sfd == -1) {
            _deb("TCPCom::connect[%s:%s]: socket[%d]: failed to create socket", host, port, sfd);
            continue;
        }
        
        if (not GLOBAL_IO_BLOCKING()) {
            unblock(sfd);

            if (::connect(sfd, rp->ai_addr, rp->ai_addrlen) < 0) {
                if ( errno == EINPROGRESS ) {

                    _deb("TCPCom::connect[%s:%s]: socket[%d]: connnect errno: EINPROGRESS", host, port, sfd);
                    break;
                    
                    
                } else {
                    close(sfd);
                    sfd = 0;

                    _not("TCPCom::connect[%s:%s]: socket[%d]: connnect errno: %s", host, port, sfd, strerror(errno));
                }

                _dum("new attempt, socket reset");
                
            } 
        } else {
            if (::connect(sfd, rp->ai_addr, rp->ai_addrlen) != 0) {
                continue;
            } else {
                break;
            }
        }
    }

    
    if(sfd == 0) {
        _err("TCPCom::connect[%s:%s]: socket[%d]: connect failed", host, port, sfd);
    }
    
    if (rp == nullptr) {
        _err("TCPCom::connect[%s:%s]: socket[%d]: connect failed", host, port, sfd);
        freeaddrinfo(gai_result);  //coverity: 1408023
        return -2;
    }

    freeaddrinfo(gai_result);

    return socket(sfd);

}

int TCPCom::bind(unsigned short port) {

    auto sso_error = [this](int rv, const char* msg) {
        _err("TCPCom::bind: setsockopt error: %d, %s when setting %s", rv, string_error().c_str(), msg);
    };


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
    
    int optval = 1;
    int sso = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
    if(sso != 0) sso_error(sso, "SOL_SOCKET/SO_SEUSEADDR");
    
    if(nonlocal_dst_) {
        // allows socket to accept connections for non-local IPs
        _dia("TCPCom::bind[%d]: setting it transparent", sock);
        setsockopt(sock, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval));
        if(sso != 0) sso_error(sso, "SOL_IP/IP_TRANSPARENT");
    }
    
    if (::bind(sock, (sockaddr *)&sa, sizeof(sa)) == -1) {
        ::close(sock);   // coverity: 1407959
        return -130;
    }
    if (listen(sock, 10) == -1)  return -131;
    
    return sock;
}


int TCPCom::accept ( int sockfd, sockaddr* addr, socklen_t* addrlen_ ) {
    int news = ::accept(sockfd, addr, addrlen_);
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
    char str_err[256];
    
    // tcp socket will stay in EINPROGRESS unless there is ANY stat call! Don't ask why. 
    // fstating socket seemed to me cheapest/fastest.
    // fstating with stat struct buffer wasn't working too!
    // 2016-01-16: seems not needed anymore. But keep to easy revert in case.

    struct stat stb{};
    fstat(s, &stb);

    int r_getsockopt = getsockopt(s, SOL_SOCKET, SO_ERROR, &error_code, &l);
    error_code = errno;
    
    if ( r_getsockopt == 0 ) {
                                
        if(error_code != 0) {
                _deb("TCPCom::is_connected[%d]: getsockopt errno %d = %s", s, error_code, strerror_r(error_code, str_err, 256));
        }
        else {
                _dum("TCPCom::is_connected[%d]: getsockopt errno %d = %s", s, error_code, strerror_r(error_code, str_err, 256));
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
        _dia("TCPCom::is_connected[%d]: getsockopt failed, returned %d = %s", s, r_getsockopt, strerror_r(r_getsockopt, str_err, 256));
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
    int optval = 1;

    if(0 != setsockopt(_fd, IPPROTO_TCP, TCP_NODELAY , &optval, sizeof optval)) {
        _err("TCPCom::on_new_socket[%d]: setsockopt TCP_NODELAY failed: %s", _fd, string_error().c_str());
    }
    optval = 1;
    if(0 != setsockopt(_fd, IPPROTO_TCP, TCP_QUICKACK , &optval, sizeof optval)) {
        _err("TCPCom::on_new_socket[%d]: setsockopt TCP_QUICKACK failed: %s", _fd, string_error().c_str());
    }

    baseCom::on_new_socket(_fd);
}
