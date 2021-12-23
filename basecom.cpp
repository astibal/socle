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

#include <basecom.hpp>
#include <hostcx.hpp>
#include <internet.hpp>

#include <vars.hpp>

#include <netinet/tcp.h>
#include <linux/in6.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

using namespace socle;

void baseCom::init(baseHostCX* owner) {

	if(!_static_init) {
		static_init();
        _static_init = true;
	} 	
	
	owner_cx_ = owner;
	
	// non-local sockets support
	nonlocal_dst_ = false;
	nonlocal_dst_resolved_ = false;
	nonlocal_dst_host_ = "";
	nonlocal_dst_port_ = 0;
	memset(&nonlocal_dst_peer_info_,0,sizeof(nonlocal_dst_peer_info_));
}


int baseCom::nonlocal_bind (unsigned short port) {
	nonlocal_dst(true);
	
	int r = bind(port);
	if (r < 0) {
		nonlocal_dst(false);
	}
	
	return r;
}

int baseCom::unblock(int s) const {
    int client_oldFlag = fcntl(s, F_GETFL, 0);

    if (! (client_oldFlag & O_NONBLOCK)) {
        if (fcntl(s, F_SETFL, client_oldFlag | O_NONBLOCK) < 0) {
            _err("Error setting socket %d as non-blocking",s);
            
            return -1;
        } else {
            _deb("Setting socket %d as non-blocking",s);
        }
    }
    
    return 0;
}

int baseCom::namesocket(int sockfd, std::string& addr, unsigned short port, sa_family_t family) {
    sockaddr_storage sa {};
    sa.ss_family = family;
    
    if(family == AF_INET or family == AF_UNSPEC) {
        inet::to_sockaddr_in(&sa)->sin_port = htons(port);
        inet_pton(family,addr.c_str(),&inet::to_sockaddr_in(&sa)->sin_addr);

        if(so_transparent_v4(sockfd) != 0) {
            _err("baseCom::namesocket[%d]: making transparent failed (IPv4)", sockfd);
        }
    }
    else if(family == AF_INET6) {
        inet::to_sockaddr_in6(&sa)->sin6_port = htons(port);
        inet_pton(family,addr.c_str(),&inet::to_sockaddr_in6(&sa)->sin6_addr);

        if(so_transparent_v6(sockfd) != 0) {
            _err("baseCom::namesocket[%d]: making transparent failed (IPv6)", sockfd);
        }
    }
    else {
        _err("cannot name socket: unsupported protocol family");
    }

    int ret_bind = ::bind(sockfd, (sockaddr*)&sa, sizeof(sockaddr_storage));
    if(ret_bind != 0) {
        err_errno(string_format("baseCom::namesocket[%d]: bind", sockfd).c_str(), "<nil>", ret_bind);
        ret_bind = errno;
    }
    
    return ret_bind;
}


bool baseCom::resolve_redirected(int s, std::string* target_host, std::string* target_port, sockaddr_storage* target_storage) {

    char orig_host[INET6_ADDRSTRLEN];
    struct sockaddr_storage peer_info_{};
    struct sockaddr_storage *ptr_peer_info = &peer_info_;

    //clear peer info struct
    socklen_t addrlen = sizeof(peer_info_);
    memset(ptr_peer_info, 0, addrlen);

    const char* op = "getsockopt(redir)";

    int ret =  getsockopt( s, SOL_IP, SO_ORIGINAL_DST, ptr_peer_info, &addrlen );
    if ( ret != 0) {
        // including netfilter includes produce compile error, so this is the only working possibility.
        // yes, I am aware this may (and probably will) break one day. :/
        #define IP6T_SO_ORIGINAL_DST            80

        ret = getsockopt( s, SOL_IPV6, IP6T_SO_ORIGINAL_DST, ptr_peer_info, &addrlen );
    }

    if( ret != 0) {
        _err("error getting original DST: %s", string_error().c_str());
    }
    else {
        unsigned short orig_port = 0;

        if (ptr_peer_info->ss_family == AF_INET) {
            inet_ntop(AF_INET, &(((struct sockaddr_in *) ptr_peer_info)->sin_addr), orig_host, INET_ADDRSTRLEN);
            orig_port = ntohs(((struct sockaddr_in *) ptr_peer_info)->sin_port);

            _deb("baseCom::resolve_socket(ipv4-redir): %s returns %s:%d", op, orig_host, orig_port);

            l3_proto(AF_INET);
        } else if (ptr_peer_info->ss_family == AF_INET6) {
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) ptr_peer_info)->sin6_addr), orig_host, INET6_ADDRSTRLEN);
            orig_port = ntohs(((struct sockaddr_in6 *) ptr_peer_info)->sin6_port);

            _deb("baseCom::resolve_socket(ipv6-redir): %s returns %s:%d", op, orig_host, orig_port);

            l3_proto(AF_INET6);
        }

        std::string mapped4_temp = orig_host;
        if (mapped4_temp.find("::ffff:") == 0) {
            _deb("baseCom::resolve_socket: mapped IPv4 detected, removing mapping prefix");
            mapped4_temp = mapped4_temp.substr(7);

            l3_proto(AF_INET);
        }

        if (target_host != nullptr) *target_host = mapped4_temp;
        if (target_port != nullptr) *target_port = std::to_string(tainted::var<unsigned>(orig_port, tainted::any<unsigned>));
        if (target_storage != nullptr) *target_storage = peer_info_;
        return true;
    }

    return false;
}


bool baseCom::resolve_socket(bool source, int s, std::string* target_host, std::string* target_port, sockaddr_storage* target_storage) {

    char orig_host[INET6_ADDRSTRLEN];
    struct sockaddr_storage peer_info_{};
    struct sockaddr_storage *ptr_peer_info = &peer_info_;

    //clear peer info struct
    socklen_t addrlen = sizeof(peer_info_);
    memset(ptr_peer_info, 0, addrlen);
    
    //For UDP transparent proxying:
    //Set IP_RECVORIGDSTADDR socket option for getting the original
    //destination of a datagram

    //Socket is bound to original destination
    
    int ret = -1;
    const char* op = str_unknown;
    
    if (source) {
        op = str_getpeername;
        ret = getpeername(s, (struct sockaddr*) ptr_peer_info, &addrlen);
    } else {
        op = str_getsockname;
        ret = getsockname(s, (struct sockaddr*) ptr_peer_info, &addrlen);
    }
    
    if(ret < 0) {
        _dia("baseCom::resolve_socket: %s failed!",op);
        return false;
    } 
    else {
        unsigned short orig_port = 0;

        if(ptr_peer_info->ss_family == AF_INET){
            inet_ntop(AF_INET, &(((struct sockaddr_in*) ptr_peer_info)->sin_addr),orig_host, INET_ADDRSTRLEN);
            orig_port = ntohs(((struct sockaddr_in*) ptr_peer_info)->sin_port);
            
            _deb("baseCom::resolve_socket(ipv4): %s returns %s:%d",op,orig_host,orig_port);
            
            l3_proto(AF_INET);
        } 
        else if(ptr_peer_info->ss_family == AF_INET6){
            inet_ntop(AF_INET6, &(((struct sockaddr_in6*) ptr_peer_info)->sin6_addr), orig_host, INET6_ADDRSTRLEN);
            orig_port = ntohs(((struct sockaddr_in6*) ptr_peer_info)->sin6_port);
            
            _deb("baseCom::resolve_socket(ipv6): %s returns %s:%d",op,orig_host,orig_port);

            l3_proto(AF_INET6);
        }

        std::string mapped4_temp = orig_host;
        if(mapped4_temp.find("::ffff:") == 0) {
            _deb("baseCom::resolve_socket: mapped IPv4 detected, removing mapping prefix");
            mapped4_temp = mapped4_temp.substr(7);
            
            l3_proto(AF_INET);
        }
        
        if(target_host != nullptr) *target_host = mapped4_temp;
        if(target_port != nullptr) *target_port = std::to_string(tainted::var<unsigned>(orig_port, tainted::any<unsigned>));
        if(target_storage != nullptr) *target_storage = peer_info_;
        return true;
    }
    
    return false;
}

bool baseCom::resolve_nonlocal_dst_socket(int sock) {

    std::string h("0.0.0.0");
    std::string p("0");
    struct sockaddr_storage s; memset(&s,0,sizeof(s));
    
    nonlocal_dst_resolved_ = resolve_socket_dst(sock, &h, &p, &s);
    if(nonlocal_dst_resolved()) {
        nonlocal_dst_host_ = h;
        nonlocal_dst_port_ = std::stoi(p);
        nonlocal_dst_peer_info_ = s;
    }
    _dia("baseCom::resolve_nonlocal_dst_socket: nonlocal dst: %s:%s", h.c_str(), p.c_str());
    return nonlocal_dst_resolved_;
}

bool baseCom::resolve_redirected_dst_socket(int sock) {

    std::string h("0.0.0.0");
    std::string p("0");
    struct sockaddr_storage s; memset(&s,0,sizeof(s));

    nonlocal_dst_resolved_ = resolve_redirected(sock, &h, &p, &s);

    if(nonlocal_dst_resolved()) {
        nonlocal_dst_host_ = h;
        nonlocal_dst_port_ = std::stoi(p);
        nonlocal_dst_peer_info_ = s;
    }

    _dia("baseCom::resolve_redirected_dst_socket: nonlocal redirected dst: %s:%s", h.c_str(), p.c_str());
    return nonlocal_dst_resolved_;
}


int baseCom::poll() {
    
    _ext("baseCom::poll: called");
    //int r = ::select( poll_sockmax + 1, &read_socketSet, &write_socketSet, NULL, &n_tv);
    int r = poller.wait(poll_msec);
    _ext("baseCom::poll: poller returned %d",r);
    if (r < 0) {
        _dia("baseCom::poll: returned by poll: %s",string_error().c_str());
    }

    poll_result = r;
    
    return r;
}


void baseCom::close(int _fd) {
    //really close the socket! Beware, from this point it can be reused!
    if(_fd > 0) {
            
        shutdown(_fd);
        
        int r = ::close(_fd);
        if(r < 0) _dia("baseCom::close[%d]: error: %s", _fd, string_error().c_str());
    }
}

std::string baseCom::full_flags_str() {
    std::string msg = flags_str();
    
    if(peer() != nullptr) {
        msg += "|" + peer()->flags_str();
    } else {
        msg += "|X";
    }
    
    return msg;
}

void baseCom::err_errno(const char* fn, const char* params, int rv) const {
    _err("%s: error: %d params: %s: %s", fn, rv, params, string_error().c_str());
};



int baseCom::so_reuseaddr(int sock) const {
    constexpr int optval = 1;
    int sso = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
    if(sso != 0) err_errno(string_format("baseCom::so_reuseaddr: setsockopt[%d]", sock).c_str(),
                           "SOL_SOCKET/SO_REUSEADDR", sso);

    return sso;
}

int baseCom::so_broadcast(int sock) const {
    constexpr int optval = 1;
    int sso = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof optval);
    if(sso != 0) err_errno(string_format("baseCom::so_broadcast: setsockopt[%d]", sock).c_str(),
                           "SOL_SOCKET/SO_BROADCAST", sso);

    return sso;
}

int baseCom::so_nodelay(int sock) const {
    constexpr int optval = 1;
    int sso = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof optval);
    if(sso != 0) err_errno(string_format("baseCom::so_nodelay: setsockopt[%d]", sock).c_str(),
                           "IPPROTO_TCP/TCP_NODELAY", sso);

    return sso;
}

int baseCom::so_quickack(int sock) const {
    constexpr int optval = 1;
    int sso = setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK , &optval, sizeof optval);
    if(sso != 0) err_errno(string_format("baseCom::so_quickack: setsockopt[%d]", sock).c_str(),
                            "IPPROTO_TCP/TCP_QUICKACK", sso);

    return sso;
}

int baseCom::so_transparent_v4(int sock) const {
    constexpr int optval = 1;
    int sso = setsockopt(sock, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval));
    if(sso != 0) err_errno(string_format("baseCom::so_transparent_v4: setsockopt[%d]", sock).c_str(),
                           "SOL_IP/IP_TRANSPARENT", sso);

    return sso;
}

int baseCom::so_transparent_v6(int sock) const {
    constexpr int optval = 1;
    int sso = setsockopt(sock, SOL_IPV6, IPV6_TRANSPARENT, &optval, sizeof(optval));
    if(sso != 0) err_errno(string_format("baseCom::so_transparent_v6: setsockopt[%d]", sock).c_str(),
                           "SOL_IPV6/IPV6_TRANSPARENT", sso);

    return sso;
}

int baseCom::so_recvorigdstaddr_v4(int sock) const {
    constexpr int optval = 1;
    int sso = setsockopt(sock, SOL_IP, IP_RECVORIGDSTADDR, &optval, sizeof optval);
    if (sso != 0)
        err_errno(string_format("baseCom::so_recvorigdstaddr_v4[%d]", sock).c_str(),
                  "SOL_IP/IP_RECVORIGDSTADDR", sso);

    return sso;
}

int baseCom::so_recvorigdstaddr_v6(int sock) const {
    constexpr int optval = 1;
    int sso = setsockopt(sock, SOL_IPV6, IPV6_RECVORIGDSTADDR, &optval, sizeof optval);
    if (sso != 0)
        err_errno(string_format("baseCom::so_recvorigdstaddr_v6[%d]", sock).c_str(),
                  "SOL_IPV6/IPV6_RECVORIGDSTADDR", sso);

    return sso;
}