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

int baseCom::namesocket(int sockfd, std::string& addr, unsigned short port, sa_family_t family) {
    sockaddr_storage sa;
    
    sa.ss_family = family;
    
    if(family == AF_INET) {
        inet::to_sockaddr_in(&sa)->sin_port = htons(port);
        inet_pton(family,addr.c_str(),&inet::to_sockaddr_in(&sa)->sin_addr);
        
    } else
    if(family == AF_INET6) {
        inet::to_sockaddr_in6(&sa)->sin6_port = htons(port);
        inet_pton(family,addr.c_str(),&inet::to_sockaddr_in6(&sa)->sin6_addr);
    }

    
    int optval = 1;
    setsockopt(sockfd, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval));
    
    if (::bind(sockfd, (sockaddr*)&sa, sizeof(sockaddr_storage)) == 0) {
        return 0;
    }
    
    return errno;
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
            
            DEB_("baseCom::resolve_socket(ipv4): %s returns %s:%d",op,orig_host,orig_port);
            
        } 
        else if(ptr_peer_info->ss_family == AF_INET6){
            inet_ntop(AF_INET6, &(((struct sockaddr_in6*) ptr_peer_info)->sin6_addr), orig_host, INET6_ADDRSTRLEN);
            orig_port = ntohs(((struct sockaddr_in6*) ptr_peer_info)->sin6_port);
            
            DEB_("baseCom::resolve_socket(ipv6): %s returns %s:%d",op,orig_host,orig_port);
        }

        std::string mapped4_temp = orig_host;
        if(mapped4_temp.find("::ffff:") == 0) {
            DEBS_("baseCom::resolve_socket: mapped IPv4 detected, removing mapping prefix");
            mapped4_temp = mapped4_temp.substr(7);
        }
        
        *target_host = mapped4_temp;
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
    
    EXTS_("baseCom::poll: called");
    //int r = ::select( poll_sockmax + 1, &read_socketSet, &write_socketSet, NULL, &n_tv);
    int r = poller.wait(poll_msec);
    EXT_("baseCom::poll: poller returned %d",r);
    if (r < 0) {
        DIA_("baseCom::poll: returned by poll: %s",string_error().c_str());
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

std::string baseCom::full_flags_str() {
    std::string msg = flags_str();
    
    if(peer() != nullptr) {
        msg += "|" + peer()->flags_str();
    } else {
        msg += "|X";
    }
    
    return msg;
}
