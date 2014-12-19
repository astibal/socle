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

bool baseCom::debug_log_data_crc = false;

void baseCom::init(baseHostCX* owner) {

	if(!__static_init) { 
		static_init(); 
		__static_init = true; 
	} 	
	
	owner_cx_ = owner;
	
	// non-local sockets support
	nonlocal_dst_ = false;
	nonlocal_dst_resolved_ = false;
	nonlocal_dst_host_ = "";
	nonlocal_dst_port_ = 0;
	memset(&nonlocal_dst_peer_info_,0,sizeof(nonlocal_dst_peer_info_));
    
    polltime(0,350);
}


int baseCom::nonlocal_bind (unsigned short port) {
	nonlocal_dst(true);
	
	int r = bind(port);
	if (r < 0) {
		nonlocal_dst(false);
	}
	
	return r;
}

int baseCom::unblock(int s) {
    int client_oldFlag = fcntl(s, F_GETFL, 0);

    if (! (client_oldFlag & O_NONBLOCK)) {
        if (fcntl(s, F_SETFL, client_oldFlag | O_NONBLOCK) < 0) {
            ERR_("Error setting socket %d as non-blocking",s);
            
            return -1;
        } else {
            DEB_("Setting socket %d as non-blocking",s);
        }
    }
    
    return 0;
}

int baseCom::namesocket(int sockfd, std::string& addr, unsigned short port) {
    sockaddr_in sockName;
    
    sockName.sin_family = AF_INET;
    sockName.sin_port = htons(port);

    inet_aton(addr.c_str(),&sockName.sin_addr);
    
    int optval = 1;
    setsockopt(sockfd, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval));
    
    if (::bind(sockfd, (sockaddr *)&sockName, sizeof(sockName)) == 0) {
        return 0;
    }
    
    return errno;
}

bool baseCom::__same_target_check(const char* host, const char* port, int existing_socket) {
    struct addrinfo hints;
    struct addrinfo *gai_result, *rp;
    int gai;

    /* Obtain address(es) matching host/port */

    ::memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    // Obtain address family to limit search
    struct sockaddr_storage peer_info_s;
    socklen_t addr_len = sizeof(peer_info_s);
    ::memset(&peer_info_s, 0,addr_len);
    struct sockaddr_storage* p_peer_info_s = &peer_info_s;
    getsockname(existing_socket,(struct sockaddr*)&peer_info_s,&addr_len);

    hints.ai_family = peer_info_s.ss_family;
    
    gai = getaddrinfo(host, port, &hints, &gai_result);
    if (gai != 0) {
        DEB_("getaddrinfo: %s",gai_strerror(gai));
        return false;
    }

    /* getaddrinfo() returns a list of address structures.
    Try each address until we successfully connect(2).
    If socket(2) (or connect(2)) fails, we (close the socket
    and) try the next address. */

    for (rp = gai_result; rp != NULL; rp = rp->ai_next) {
        // ::connect(sfd, rp->ai_addr, rp->ai_addrlen)
        if(peer_info_s.ss_family == AF_INET) {
            
            DEB_("Existing socket address: %d",*(uint32_t*)&((struct sockaddr_in*)p_peer_info_s)->sin_addr);
            DEB_("Existing socket    port: %d",ntohs(((struct sockaddr_in*)p_peer_info_s)->sin_port));
            DEB_("Connecting socket addrs: %d",*(uint32_t*)&((struct sockaddr_in*)rp->ai_addr)->sin_addr);
            DEB_("Connecting socket  port: %d",(unsigned short)std::stoul(port));
            
            if( *(uint32_t*)&((struct sockaddr_in*)p_peer_info_s)->sin_addr == *(uint32_t*)&((struct sockaddr_in*)rp->ai_addr)->sin_addr
                //rp->ai_addr->sin_addr
                &&
                ntohs(((struct sockaddr_in*)p_peer_info_s)->sin_port) == (unsigned short)std::stoul(port)
                ) {
                
                freeaddrinfo(gai_result);
                return true;
            }
        }
        
        // FIXME: IPv6

        freeaddrinfo(gai_result);
    }

    return false;
}

bool baseCom::__deprecated_check_same_destination(int s, int ss) {

    struct sockaddr_storage peer_info_s;
    struct sockaddr_storage peer_info_ss;
    socklen_t addr_len = sizeof(peer_info_ss);
    
    struct sockaddr_storage* p_peer_info_s = &peer_info_s;
    struct sockaddr_storage* p_peer_info_ss = &peer_info_ss;
    
    ::memset(&peer_info_s, 0,addr_len);
    ::memset(&peer_info_ss, 0,addr_len);
    
    
    int r_s  = getsockname(s,(struct sockaddr*)&peer_info_s,&addr_len);
    int r_ss = getsockname(ss,(struct sockaddr*)&peer_info_ss,&addr_len);
    
    // if both are negative, consider them the same
    if (r_s < 0 && r_ss < 0) return true;
    
    // if r_s xor r_ss is negative, consider them diferrent
    if (r_s < 0 || r_ss < 0) return false;
    
    // families are different, consider them different (FIXME: it can cause issues on dual stack machines, no easy fix)
    if (peer_info_s.ss_family != peer_info_ss.ss_family) return false;
    
    if(peer_info_s.ss_family == AF_INET) {
        if( *(uint32_t*)&((struct sockaddr_in*)p_peer_info_s)->sin_addr == *(uint32_t*)&((struct sockaddr_in*)p_peer_info_ss)->sin_addr 
                && 
            ((struct sockaddr_in*)p_peer_info_s)->sin_port == ((struct sockaddr_in*)p_peer_info_ss)->sin_port) {
            return true;
        }
        return false;
    }
    if(peer_info_s.ss_family == AF_INET6) {
        if( *(unsigned long long int*)&((struct sockaddr_in6*)p_peer_info_s)->sin6_addr == *(unsigned long long int*)&((struct sockaddr_in6*)p_peer_info_ss)->sin6_addr 
                && 
            ((struct sockaddr_in6*)p_peer_info_s)->sin6_port == ((struct sockaddr_in6*)p_peer_info_ss)->sin6_port) {
            return true;
        }
        return false;
    }   
    
    return false;    
}


bool baseCom::resolve_socket(bool source, int s, std::string* target_host, std::string* target_port, sockaddr_storage* target_storage) {

    char orig_host[INET6_ADDRSTRLEN];
    struct sockaddr_storage peer_info_;
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
        DIA_("baseCom::resolve_socket: %s failed!",op);
        return false;
    } 
    else {
        unsigned short orig_port = 0;

        if(ptr_peer_info->ss_family == AF_INET){
            inet_ntop(AF_INET, &(((struct sockaddr_in*) ptr_peer_info)->sin_addr),orig_host, INET_ADDRSTRLEN);
            orig_port = ntohs(((struct sockaddr_in*) ptr_peer_info)->sin_port);
            
            DEB_("baseCom::resolve_socket: %s returns %s:%d",op,orig_host,orig_port);
            
        } 
        else if(ptr_peer_info->ss_family == AF_INET6){
            inet_ntop(AF_INET6, &(((struct sockaddr_in6*) ptr_peer_info)->sin6_addr), orig_host, INET6_ADDRSTRLEN);
            orig_port = ntohs(((struct sockaddr_in6*) ptr_peer_info)->sin6_port);
            
            DEB_("baseCom::resolve_socket: %s returns %s:%d",op,orig_host,orig_port);
        }

        *target_host = orig_host;
        *target_port = std::to_string(orig_port);
        if(target_storage != NULL) *target_storage = peer_info_;
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
        
        return true;
    }
    
    return false;
}


int baseCom::poll() {
    
    timeval n_tv = poll_tv;
    EXTS_("baseCom::poll: called");
    int r = ::select( poll_sockmax + 1, &read_socketSet, &write_socketSet, NULL, &n_tv);
    EXT_("baseCom::poll: select returned %d",r);
    if (r < 0) {
        DIA_("baseCom::poll: error returned by select: errno %d",errno);
    }
    
    poll_sockmax = 0;
    poll_result = r;
    
    return r;
}


void baseCom::close(int __fd) {
    //really close the socket! Beware, from this point it can be reused!
    if(__fd > 0) {
        int r = ::close(__fd);
        if(r < 0) DIA_("baseCom::close[%d]: error: %s",string_error().c_str());
    }
}
