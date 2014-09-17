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

void baseCom::init() {

	if(!__static_init) { 
		static_init(); 
		__static_init = true; 
	} 	
	
	// non-local sockets support
	nonlocal_ = false;
	nonlocal_resolved_ = false;
	nonlocal_host_ = "";
	nonlocal_port_ = 0;
	memset(&nonlocal_peer_info_,0,sizeof(nonlocal_peer_info_));		
}


int baseCom::nonlocal_bind (unsigned short port) {
	nonlocal(true);
	
	int r = bind(port);
	if (r < 0) {
		nonlocal(false);
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
    
    if (::bind(sockfd, (sockaddr *)&sockName, sizeof(sockName)) == 0) {
        return 0;
    }
    
    return errno;
}


void TCPCom::init() { 
	
	baseCom::init(); 
};

	
int TCPCom::connect(const char* host, const char* port, bool blocking) { 
	struct addrinfo hints;
	struct addrinfo *gai_result, *rp;
	int sfd = -1;
	int gai;

	/* Obtain address(es) matching host/port */

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;          /* Any protocol */

	gai = getaddrinfo(host, port, &hints, &gai_result);
	if (gai != 0) {
		DEB_("getaddrinfo: %s",gai_strerror(gai));
		return -2;
	}

	/* getaddrinfo() returns a list of address structures.
	Try each address until we successfully connect(2).
	If socket(2) (or connect(2)) fails, we (close the socket
	and) try the next address. */

	for (rp = gai_result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype,
					rp->ai_protocol);

		//if (DDEB(110)) 
		DEBS_("gai info found");
		
		if (sfd == -1) {
            DEBS_("failed to create socket");
			continue;
        }
		
		if (not blocking) {
			unblock(sfd);

			if (::connect(sfd, rp->ai_addr, rp->ai_addrlen) < 0) {
				if ( errno == EINPROGRESS ) {
                    DUMS_("socket connnected with EINPROGRESS");
					break;
					
				} else {
					;
				}
			} 
			close(sfd);
			sfd = -1;
            DUMS_("new attempt, socket reset");
		} else {
			if (::connect(sfd, rp->ai_addr, rp->ai_addrlen) != 0) {
				continue;
			} else {
				break;
			}
		}
	}

	
	if(sfd <= 0) {
        ERRS_("connect failed");
    }
	
	if (rp == NULL) {
		ERRS_("Could not connect");
		return -2;
	}

	freeaddrinfo(gai_result);

    tcpcom_fd = sfd;
    
	return sfd;

};

int TCPCom::bind(unsigned short port) {
	int s;
	sockaddr_in sockName;

	sockName.sin_family = AF_INET;
	sockName.sin_port = htons(port);
	sockName.sin_addr.s_addr = INADDR_ANY;

	if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) return -129;
	
	int optval = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
	
	if(nonlocal_) {
		// allows socket to accept connections for non-local IPs
		setsockopt(s, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval));		
	}
	
	if (::bind(s, (sockaddr *)&sockName, sizeof(sockName)) == -1) return -130;
	if (listen(s, 10) == -1)  return -131;
	
	return s;
};	


int TCPCom::accept ( int sockfd, sockaddr* addr, socklen_t* addrlen_ ) {
	return ::accept(sockfd,addr,addrlen_);
}


// FIXME: use baseCom::resolve_socket
// int NonlocalTCPCom::resolve_nonlocal_peer(int s) {
// 
// 	// Code borrowed from:
// 	// https://github.com/kristrev/tproxy-example/blob/master/tproxy_example_conn.c
// 	
// 	char orig_host[INET6_ADDRSTRLEN];
// 	unsigned short orig_port = 0;
// 	struct sockaddr_storage peer_info_;
// 	struct sockaddr_storage *ptr_peer_info = &peer_info_;
// 
// 	//clear peer info struct
// 	socklen_t addrlen = sizeof(peer_info_);
// 	memset(ptr_peer_info, 0, addrlen);
// 	
// 	//For UDP transparent proxying:
// 	//Set IP_RECVORIGDSTADDR socket option for getting the original
// 	//destination of a datagram
// 
// 	//Socket is bound to original destination
// 	if(getsockname(s, (struct sockaddr*) ptr_peer_info, &addrlen) < 0) {
// 		DIAS_("NonlocalTCPCom::get_original_peer: getsockname failed!");
// 		return -1;
// 	} 
// 	else {
// 		if(ptr_peer_info->ss_family == AF_INET){
// 			inet_ntop(AF_INET, &(((struct sockaddr_in*) ptr_peer_info)->sin_addr),orig_host, INET_ADDRSTRLEN);
// 			orig_port = ntohs(((struct sockaddr_in*) ptr_peer_info)->sin_port);
// 			
// 			DIA_("NonlocalTCPCom::get_original_peer: original destination %s:%d\n", orig_host,orig_port);
// 			
// 		} 
// 		else if(ptr_peer_info->ss_family == AF_INET6){
// 			inet_ntop(AF_INET6, &(((struct sockaddr_in6*) ptr_peer_info)->sin6_addr), orig_host, INET6_ADDRSTRLEN);
// 			orig_port = ntohs(((struct sockaddr_in6*) ptr_peer_info)->sin6_port);
// 			
// 			DIA_("NonlocalTCPCom::get_original_peer: original destination %s:%d\n", orig_host,orig_port);
// 		}
// 
// 		nonlocal_host_ = orig_host;
// 		nonlocal_port_ = orig_port;
// 		nonlocal_peer_info_ = peer_info_;
// 		nonlocal_resolved_ = true;
// 		return 0;
// 	}
// 	
// 	return -1;
// }
