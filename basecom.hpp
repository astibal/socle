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
#include <sys/stat.h>
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
    static bool debug_log_data_crc;
    
    friend class baseHostCX;
    
    // select variables
    fd_set read_socketSet;
    fd_set write_socketSet;
    fd_set ex_socketSet;
    timeval poll_tv;
    int     poll_sockmax = 0;
    int     poll_result = 0;
    
    int poll();
    void polltime(unsigned int sec, unsigned int usec)
    {
        poll_tv.tv_sec = sec;
        poll_tv.tv_usec = usec;
    };    
	
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

    // feedback to read from socket regardless of select result ONCE
    bool forced_read_ = false;
    bool forced_write_ = false;
    
    // if set forced_read/write, don't reset it once used => always attempt to read | write
    bool forced_read_always_ = false;
    bool forced_write_always_ = false;
      

    void forced_read_always(bool b)  { forced_read(b); forced_read_always_ = b; }
    void forced_write_always(bool b) { forced_write(b); forced_write_always_ = b; }
  
public:
    void forced_read(bool b)  { forced_read_ = b; }
    void forced_write(bool b) { forced_write_ = b; }    
    bool forced_read_reset() { bool r = forced_read_; if (!forced_read_always_) { forced_read_ = false; } return r; }
    bool forced_write_reset() { bool r = forced_write_; if (!forced_write_always_) {forced_write_ = false; } return r; }
    
    virtual bool com_status() { DUMS_("baseCom::com_status: returning 1"); return true; }
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
    virtual const char* name() = 0;
    
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
    inline int is_blocking(int s) { return !(::fcntl(s, F_GETFL, 0) & O_NONBLOCK);  }
    
	virtual void cleanup() = 0;

    virtual bool is_connected(int s) = 0;
    
	// those two need to be virtual, since e.g. OpenSSL read/write cannot be managed only with FD_SET due reads 
	// sometimes do writes on themselves and another read is necessary
    virtual bool readable(int s) { return true; };
    virtual bool writable(int s) { return true; }; 
    
    // operate on FD_SETs
    inline bool in_readset(int s) { return FD_ISSET(s, &read_socketSet); };
	inline bool in_writeset(int s) { return FD_ISSET(s, &write_socketSet); };
    inline bool in_exset(int s) { return FD_ISSET(s, &ex_socketSet); };  
	inline void zeroize_readset() { FD_ZERO(&read_socketSet); };
	inline void zeroize_writeset() { FD_ZERO(&write_socketSet); };
    inline void zeroize_exset() { FD_ZERO(&ex_socketSet); };
	inline void set_readset(int s) { FD_SET(s, &read_socketSet); if(s > poll_sockmax) { poll_sockmax = s; } };
	inline void set_writeset(int s) { FD_SET(s, &write_socketSet); if(s > poll_sockmax) { poll_sockmax = s; } };
    inline void set_exset(int s) { FD_SET(s, &ex_socketSet); if(s > poll_sockmax) { poll_sockmax = s; } };
	
    virtual bool __same_target_check(const char* host, const char* port, int existing_socket);
	
	bool __deprecated_check_same_destination(int s, int ss);

    bool resolve_socket_(bool source,int s, std::string *target_host, std::string *target_port, struct sockaddr_storage *target_storage = NULL );    
	bool resolve_socket_src(int s, std::string *target_host, std::string *target_port, struct sockaddr_storage *target_storage = NULL ) { 
		return resolve_socket_(true, s, target_host, target_port, target_storage);
	}
	bool resolve_socket_dst(int s, std::string *target_host, std::string *target_port, struct sockaddr_storage *target_storage = NULL ) {
		return resolve_socket_(false, s, target_host, target_port, target_storage);
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
	bool resolve_nonlocal_socket(int sock);
};

# endif
