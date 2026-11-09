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
#include <ancillary_ifindex.hpp>
#include <socketinfo.hpp>
#include <privileged_socket.hpp>
#include <internet.hpp>
#include <hostcx.hpp>

#include <poll.h>

#include <vars.hpp>
#include <convert.hpp>

using namespace socle;

void TCPCom::init(baseHostCX* owner) { 
    
    baseCom::init(owner);
    if(socket() > 0) {
        capture_ingress_interface(socket());
    }
}


bool TCPCom::make_transparent(int sfd) {

    int bind_status = namesocket(sfd, nonlocal_src_host(), nonlocal_src_port(),
                                 raw::down_cast_signed<sa_family_t>(l3_proto()).value_or(AF_INET));
    if (bind_status != 0) {
        _war("cannot bind this %s socket to %s:%d: %s", SockOps::family_str(l3_proto()).c_str(),
             nonlocal_src_host().c_str(), nonlocal_src_port(), string_error(bind_status).c_str());

        return false;
    }

    return true;
}

int TCPCom::connect(const char* host, const char* port) {
    connect_traced = false;
    protocol_trace(socle::trace_component::tcp,
                   socle::trace_scope::connection,
                   socle::trace_event::connect_started,
                   socle::trace_status::pending);
    connect_proven = false;
    connected_fd_ = 0;
    error(ERROR_NONE);
    connect_failed_ = false;
    connect_error_ = 0;

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

        sfd = socle::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

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

            if (::connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
                _deb("TCPCom::connect[%s:%s]: socket[%d]: connect successful", host, port, sfd);
                connect_proven = true;
                trace_connected_once();
                connected_fd_ = sfd;
                break;
            }

            if (errno == EINPROGRESS ) {
                _deb("TCPCom::connect[%s:%s]: socket[%d]: connect errno: EINPROGRESS", host, port, sfd);
                break;
            }

        } else {
            if (::connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
                connect_proven = true;
                connected_fd_ = sfd;
                break;
            }

            _not("TCPCom::connect[%s:%s]: socket[%d]: connect errno: %s", host, port, sfd, string_error(errno).c_str());
        }

        // all captive continue op - close fd
        _not("TCPCom::connect[%s:%s]: socket[%d]: closing", host, port, sfd);
        ::close(sfd);
        sfd = -1;
    }

    
    if(sfd < 0) {
        _err("TCPCom::connect[%s:%s]: socket[%d]: connect failed", host, port, sfd);
        protocol_trace(socle::trace_component::tcp,
                       socle::trace_scope::connection,
                       socle::trace_event::closed,
                       socle::trace_status::failed,
                       "connect failed");
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

    int sock = socle::socket(bind_sock_family, bind_sock_type, bind_sock_protocol);

    if (sock == -1)
        return -129;

    // Required Linux API; do not silently create listeners without metadata.
    const int enabled = 1;
    if(::setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &enabled, sizeof enabled) != 0 ||
       (sa.ss_family == AF_INET6 &&
        ::setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &enabled, sizeof enabled) != 0)) {
        ::close(sock);
        return -132;
    }

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
    
    const socklen_t address_size = sa.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if (socle::bind(sock, reinterpret_cast<sockaddr*>(&sa), address_size) == -1) {
        ::close(sock);   // coverity: 1407959
        return -130;
    }
    if (socle::listen(sock, config.listen_backlog) == -1) {
        ::close(sock);
        return -131;
    }
    
    return sock;
}


int TCPCom::accept ( int sockfd, sockaddr* addr, socklen_t* addrlen_ ) {

    int news;
    do {
        news = ::accept4(sockfd, addr, addrlen_, SOCK_NONBLOCK | SOCK_CLOEXEC);
    } while (news < 0 && errno == EINTR);

    if (news < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            _err("accept[%d]: failed: %s", sockfd, string_error().c_str());
            return -1;
        } else {
            _dia("accept[%d]: not ready: %s", sockfd, string_error().c_str());
        }
    } else {
        _dia("accept[%d->%d]: ok ", sockfd, news);
        on_new_socket(news);
    }

    return news;
}

bool TCPCom::is_connected(int s) {
    // Never treat "no socket" as ready, including contexts awaiting connect().
    if(s <= 0) return false;
    if(connect_failed_) return false;
    if(connect_proven && connected_fd_ == s) return true;

    // Reuse the worker's readiness observation when available. Standalone
    // callers still need a nonblocking probe, without allocating another epoll.
    bool ready = master() && (master()->in_writeset(s) || master()->in_readset(s));
    if(!ready) {
        pollfd descriptor{s, POLLOUT, 0};
        if(::poll(&descriptor, 1, 0) <= 0) return false;
        ready = (descriptor.revents & (POLLOUT | POLLERR | POLLHUP)) != 0;
        if(!ready) return false;
    }

    int failure = 0;
    socklen_t size = sizeof(failure);
    if(::getsockopt(s, SOL_SOCKET, SO_ERROR, &failure, &size) < 0) {
        failure = errno;
        if(failure == EINTR) return false;
    }
    if(failure == EINPROGRESS || failure == EALREADY || failure == EWOULDBLOCK)
        return false;

    if(failure != 0) {
        // SO_ERROR is consumed by getsockopt. Preserve the failure for later
        // callers, including the explicit proxy's CONNECT/SOCKS reply path.
        connect_failed_ = true;
        connect_error_ = failure;
        return false;
    }

    // A fresh, unconnected socket can also be writable with SO_ERROR == 0.
    // Confirm a peer once before caching success (also covers accepted sockets).
    sockaddr_storage peer{};
    socklen_t peer_size = sizeof(peer);
    if(::getpeername(s, reinterpret_cast<sockaddr*>(&peer), &peer_size) < 0)
        return false;

    connected_fd_ = s;
    connect_proven = true;
    trace_connected_once();
    return true;
}

bool TCPCom::shutdown_write() {
    int result;
    do {
        result = ::shutdown(socket(), SHUT_WR);
    } while(result < 0 && errno == EINTR);
    return result == 0;
}

bool TCPCom::com_status() {
    if(error()) return false;
    return is_connected(socket());
}

void TCPCom::on_new_socket(int _fd) {
    if(_fd >= 0) {
        so_nodelay(_fd);
        so_quickack(_fd);
    }

    baseCom::on_new_socket(_fd);
}

void TCPCom::capture_ingress_interface(int fd) {
    // Called on the newly owned Com, never on the shared accepting listener.
    sockaddr_storage address{};
    socklen_t address_size = sizeof address;
    if(::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
        return;
    }

    const bool ipv6 = address.ss_family == AF_INET6;
    if(!ipv6 && address.ss_family != AF_INET) {
        return;
    }

    alignas(cmsghdr) unsigned char control[256]{};
    socklen_t control_size = sizeof control;
    const int level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
    const int option = ipv6 ? IPV6_2292PKTOPTIONS : IP_PKTOPTIONS;
    if(::getsockopt(fd, level, option, control, &control_size) != 0) {
        return;
    }

    msghdr message{};
    message.msg_control = control;
    message.msg_controllen = control_size;
    ingress_ifindex(socle::ancillary_ifindex(message));
}
