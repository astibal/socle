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

#ifndef BASECOM_HPP
#define BASECOM_HPP

#include <string>
#include <cstring>
#include <ctime>
#include <csignal>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <logger.hpp>

static const char str_unknown[] = "unknown";
static const char str_getsockname[] = "getsockname";
static const char str_getpeername[] = "getpeername";

class baseHostCX;

class baseCom {
public:
    
    friend class baseHostCX;
    
	// select variables
    fd_set read_socketSet;
	fd_set write_socketSet;	
	
	bool __static_init = false;
	
    virtual ~baseCom() {};
protected:
    // non-local socket support
    bool nonlocal_;
	bool nonlocal_resolved_;
	std::string nonlocal_host_;
	unsigned short nonlocal_port_;
	struct sockaddr_storage nonlocal_peer_info_;

    // feedback mechanism to get if the communication level is up/down
    // necessary for some mitm scenarios and connection status feedback between 2 sockets

    baseCom* peer_ = nullptr;

    // this is log buffer inteded for upper layer logger. Whatever is not only about to be printed out, but also stored, 
    // should appear here.    
    std::string log_buffer_;

public:
    virtual bool com_status() {
        DUMS_("baseCom::com_status: returning 1");
        return true;
    }
    inline std::string& log() { return log_buffer_; };       

    
    baseCom* peer() { return peer_; }
    // make it settable only by baseHostCX->peer() call
//     void peer(baseCom* p) { peer_ = p; }
    
public:
	virtual void init();
	
	virtual void static_init() {
		signal(SIGPIPE, SIG_IGN);
	};
	
    virtual baseCom* replicate() = 0;
    
    virtual int connect(const char* , const char* , bool = false) = 0;
    virtual int read(int __fd, void* __buf, size_t __n, int __flags) = 0;
    virtual int peek(int __fd, void* __buf, size_t __n, int __flags) = 0;
	virtual int write(int __fd, const void* __buf, size_t __n, int __flags) = 0;
	virtual void close(int __fd) = 0;
	virtual int bind(unsigned short __port) = 0;
	
	// syscall wrapper 
	virtual int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen_) = 0;
	// call to init already accepted socket
	virtual void accept_socket(int sockfd) {
		if(nonlocal_) {
			resolve_nonlocal_socket(sockfd);
		}
	};

    int unblock(int s);   
    inline int is_blocking(int s) {
        return !(::fcntl(s, F_GETFL, 0) & O_NONBLOCK);
    }
    
	virtual void cleanup() = 0;

    virtual bool is_connected(int s) = 0;
    
	// those two need to be virtual, since e.g. OpenSSL read/write cannot be managed only with FD_SET due reads 
	// sometimes do writes on themselves and another read is necessary
	virtual bool readable(int s) { return FD_ISSET(s, &read_socketSet); };
	virtual bool writable(int s) { return FD_ISSET(s, &write_socketSet); };	
	
	inline void zeroize_read_fdset() { FD_ZERO(&read_socketSet); };
	inline void zeroize_write_fdset() { FD_ZERO(&write_socketSet); };
	inline void set_read_fdset(int s) { FD_SET(s, &read_socketSet); };
	inline void set_write_fdset(int s) { FD_SET(s, &write_socketSet); };
	
    virtual bool __same_target_check(const char* host, const char* port, int existing_socket) { 
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
	};	
	
	
	bool __deprecated_check_same_destination(int s, int ss) {
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
	
	bool resolve_socket_src(int s, std::string *target_host, std::string *target_port, struct sockaddr_storage *target_storage = NULL ) {
		return resolve_socket_(true, s, target_host, target_port, target_storage);
	}
	
	bool resolve_socket_dst(int s, std::string *target_host, std::string *target_port, struct sockaddr_storage *target_storage = NULL ) {
		return resolve_socket_(false, s, target_host, target_port, target_storage);
	}	
	
	bool resolve_socket_(bool source,int s, std::string *target_host, std::string *target_port, struct sockaddr_storage *target_storage = NULL ) {

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
			return -1;
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

	
	// non-local socket support
	inline bool nonlocal() { return nonlocal_; }
	inline void nonlocal(bool b) { nonlocal_ = b; }	
    virtual int namesocket(int, std::string&, unsigned short);

	inline bool nonlocal_resolved(void) { return nonlocal_resolved_; }
	inline std::string& nonlocal_host(void) { return nonlocal_host_; }
	inline unsigned short& nonlocal_port(void) { return nonlocal_port_; }
	inline struct sockaddr_storage* nonlocal_peer_info() { return &nonlocal_peer_info_; }	
	
	virtual int nonlocal_bind(unsigned short port);
	
	bool resolve_nonlocal_socket(int sock) {
		std::string h,p;
		struct sockaddr_storage s; memset(&s,0,sizeof(s));
		
		nonlocal_resolved_ = resolve_socket_dst(sock, &h, &p, &s);
		if(nonlocal_resolved()) {
			nonlocal_host_ = h;
			nonlocal_port_ = std::stoi(p);
			nonlocal_peer_info_ = s;
			
			return true;
		}
		
		return false;
	}
};

class TCPCom : public baseCom {
public:
	virtual void init();
    virtual baseCom* replicate() { return new TCPCom(); };
    
    virtual int connect(const char* host, const char* port, bool blocking = false);
	virtual int bind(unsigned short port);	
    virtual int accept ( int sockfd, sockaddr* addr, socklen_t* addrlen_ );
	
    virtual int read(int __fd, void* __buf, size_t __n, int __flags) { return ::recv(__fd,__buf,__n,__flags); };
    virtual int peek(int __fd, void* __buf, size_t __n, int __flags) { return read(__fd,__buf,__n, __flags | MSG_PEEK );};
	virtual int write(int __fd, const void* __buf, size_t __n, int __flags)  { return ::send(__fd,__buf,__n,__flags); };
	virtual void close(int __fd) { ::close(__fd); };
	
	virtual void cleanup() {};	
    
    virtual bool is_connected(int s) {
        
        if(tcpcom_fd == 0) {
            DEBS_("TCPCom::is_connected: called for non-connecting socket");
            return true;
        }
        
        unsigned int error_code;
        socklen_t l = sizeof(error_code);
        char str_err[256];
        
        int r_getsockopt = getsockopt(s, SOL_SOCKET, SO_ERROR, &error_code, &l);
        error_code = errno;
        
        if ( r_getsockopt == 0 ) {
                                    
            if(error_code != 0) {
                    DEB_("TCPCom::is_connected[%d]: getsockopt errno %d = %s",s,error_code,strerror_r(error_code,str_err,256));
            }
            else {
                    DUM_("TCPCom::is_connected[%d]: getsockopt errno %d = %s",s,error_code,strerror_r(error_code,str_err,256));
            }
            
            return (error_code != EINPROGRESS);
    //      return true;
    //      return (error_code == 0);
    
        } else {
            DIA_("TCPCom::is_connected[%d]: getsockopt failed, returned %d = %s",s,r_getsockopt,strerror_r(r_getsockopt,str_err,256));
            return false;
        } 
    }
    
    virtual bool com_status() {
        if(baseCom::com_status()) {
            bool r = is_connected(tcpcom_fd);
            //T_DIA_("tcpcom_status_ok",1,"TCPCom::com_status: returning %d",r);
            DEB_("TCPCom::com_status: returning %d",r);
            return r;
        }
        
        // T_DUMS_("tcpcom_status_nok",1,"TCPCom::com_status: returning 0");
        DEBS_("TCPCom::com_status: returning 0");
        return false;
    }
protected:
    int tcpcom_fd = 0;
};



# endif
