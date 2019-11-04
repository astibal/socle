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

#include <epoll.hpp>
#include <logger.hpp>

static const char str_unknown[] = "unknown";
static const char str_getsockname[] = "getsockname";
static const char str_getpeername[] = "getpeername";

class baseHostCX;

class baseCom {
public:
    static bool& GLOBAL_IO_BLOCKING() { static bool b = false; return b; }
    static bool debug_log_data_crc;
    
    friend class baseHostCX;
    
    static int poll_msec;
    static int rescan_poll_multiplier;
    int     poll_sockmax = 0;
    int     poll_result = 0;
    baseHostCX* owner_cx_ = nullptr;
    inline baseHostCX* owner_cx() { return owner_cx_; }
    
    virtual int poll();
    inline void polltime(int msec) { poll_msec = msec; }

    bool __static_init = false;

    // my master: add me to the poll monitor at the right time
    baseCom* master_ = nullptr;
    baseCom* master(baseCom* b) { master_ = b; return b; }
    baseCom* master() { 
        if(master_ != nullptr) 
            return master_->master(); 
        return this;
    }
    
    // create slave Com object (replicate is virtual). My master will master it, or me, if I don't have a master.
    baseCom* slave() { 
        baseCom* r = replicate(); 
        r->master(master());
        return r;
    }

    struct epoller poller;

    // mark connection as invalid, owning cx is responsible to react on it
    typedef enum { ERROR_NONE=0, ERROR_UNSPEC=1, ERROR_READ, ERROR_WRITE } err_flags;
    int  error_flag_ = ERROR_NONE;

    bool error() { return error_flag_ != ERROR_NONE; }
    int error_flags() { return error_flag_; };    
    inline void error(baseCom::err_flags e) { error_flag_ = e;}
    
    baseCom() {
        log = logan_attached<baseCom>(this, "com");
    }
    virtual ~baseCom() {};
    virtual std::string flags_str() { return "0"; };
    virtual std::string full_flags_str();
private:
    unsigned long flags_;
protected:
    // non-local socket support
    bool nonlocal_dst_;
    bool nonlocal_dst_resolved_;
    std::string nonlocal_dst_host_;
    unsigned short nonlocal_dst_port_;
    struct sockaddr_storage nonlocal_dst_peer_info_;
    
    int l3_proto_ = AF_INET;
    int l4_proto_ = 0;
    
    bool nonlocal_src_ = false;
    std::string nonlocal_src_host_;
    unsigned short nonlocal_src_port_;
    

    // feedback mechanism to get if the communication level is up/down
    // necessary for some mitm scenarios and connection status feedback between 2 sockets

    baseCom* peer_ = nullptr;

    // this is log buffer inteded for upper layer logger. Whatever is not only about to be printed out, but also stored, 
    // should appear here.    
    std::string log_buffer_;

    // feedback to read/write from socket regardless of select result ONCE
    bool forced_read_ = false;
    bool forced_write_ = false;
    
    // feedback to read/write from socket on write/read op (SSL is doing that)
    bool forced_read_on_write_ = false;
    bool forced_write_on_read_ = false;
    
    
    // if set forced_read/write, don't reset it once used => always attempt to read | write
    bool forced_read_always_ = false;
    bool forced_write_always_ = false;
      

    void forced_read_always(bool b)  { forced_read(b); forced_read_always_ = b; }
    void forced_write_always(bool b) { forced_write(b); forced_write_always_ = b; }
  
public:
    void forced_read(bool b)  { forced_read_ = b; }
    void forced_write(bool b) { forced_write_ = b; }    

    void forced_read_on_write(bool b)  { forced_read_on_write_ = b; }
    void forced_write_on_read(bool b) { forced_write_on_read_ = b; }    
    bool forced_read_on_write(void)  { return forced_read_on_write_; }
    bool forced_write_on_read(void) { return forced_write_on_read_; }    
    
    bool forced_read_on_write_reset() { bool r = forced_read_on_write_; forced_read_on_write_= false;  return r; }
    bool forced_write_on_read_reset() { bool r = forced_write_on_read_; forced_write_on_read_ = false;  return r; }

    
    bool forced_read_reset() { bool r = forced_read_; if (!forced_read_always_) { forced_read_ = false; } return r; }
    bool forced_write_reset() { bool r = forced_write_; if (!forced_write_always_) {forced_write_ = false; } return r; }
    
    virtual bool com_status() { _dum("baseCom::com_status: returning 1"); return true; }
    inline std::string& logbuf() { return log_buffer_; };
    
    baseCom* peer() { return peer_; }
    
public:
    virtual void init(baseHostCX* owner);

    virtual void static_init() {
        signal(SIGPIPE, SIG_IGN);
    };

    virtual baseCom* replicate() = 0;
//     virtual std::string& name() = 0;
    
    virtual int connect(const char* , const char*) = 0;
    virtual int read(int __fd, void* __buf, size_t __n, int __flags) = 0;
    virtual int peek(int __fd, void* __buf, size_t __n, int __flags) = 0;
    virtual int write(int __fd, const void* __buf, size_t __n, int __flags) = 0;
    virtual void shutdown(int __fd) = 0;
    virtual void close(int __fd); 
    virtual int bind(unsigned short __port) = 0;
    virtual int bind(const char* __path) = 0;
    
    // support for pseudo-socket, we call it virtual socket. It's negative numbered socket 
    // which can ne used by Com classes for socket translations (see UDPCom, for example)
    virtual int translate_socket(int vsock) { return vsock; };
    virtual void on_new_socket(int __fd) {};

    // syscall wrapper 
    virtual int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen_) = 0;

    // call to init already accepted socket
    virtual void accept_socket(int sockfd) {
        if(nonlocal_dst_) {
            resolve_nonlocal_dst_socket(sockfd);
        }
    };

    // call to init socket about to be accepted in the future but waiting_for_peercom for now
    virtual void delay_socket(int sockfd) {
        /* do nothing */
    }

    int unblock(int s);
    static inline int is_blocking(int s) { return !(::fcntl(s, F_GETFL, 0) & O_NONBLOCK);  }
    
    virtual void cleanup() = 0;

    virtual bool is_connected(int s) = 0;
    
    // those two need to be virtual, since e.g. OpenSSL read/write cannot be managed only with FD_SET due reads 
    // sometimes do writes on themselves and another read is necessary
    virtual bool readable(int s) { return true; };
    virtual bool writable(int s) { return true; }; 
    
    // operate on FD_SETs
    virtual bool in_readset(int s) { return master()->poller.in_read_set(s); };
    virtual bool in_writeset(int s) { return master()->poller.in_write_set(s); };
    virtual bool in_idleset(int s) { return master()->poller.in_idle_set(s); };

    inline void set_monitor(int s) { 
        _dia("basecom::set_monitor: called to add %d",s);
        if (s > 0 ) { 
            master()->poller.add(s,EPOLLIN); 
        } 
    };
    inline void unset_monitor(int s) { 
        _dia("basecom::unset_monitor: called to remove %d",s);
        if (s > 0 ) { 
            master()->poller.del(s);
            master()->poller.cancel_rescan_in(s);
            master()->poller.cancel_rescan_out(s);
        } 
    };    
    inline void set_write_monitor(int s) {
        _dia("basecom::set_write_monitor: called to add EPOLLOUT %d",s);
        if (s > 0 ) { 
            master()->poller.modify(s,EPOLLIN|EPOLLOUT); 
        } 
    }
    inline void set_write_monitor_only(int s) {
        _dia("basecom::set_write_monitor: called to add EPOLLOUT %d only",s);
        if (s > 0 ) { 
            master()->poller.modify(s,EPOLLOUT); 
        } 
    }    

    inline void change_monitor(int s, int new_mode) { 
        _dia("basecom::change_monitor: change mode of %d to %d",s, new_mode);
        if (s > 0 ) { 
            master()->poller.modify(s, new_mode);
        } 
    };       
    
    inline void set_hint_monitor(int s) {
        _dia("basecom::set_hint_monitor: called: %d",s);
        master()->poller.hint_socket(s); 
    }

    inline void set_poll_handler(int s, epoll_handler* h) {
        _dia("basecom::set_poll_handler: called to add %d monitored by %x",s,h);
        master()->poller.set_handler(s,h);
    };

    inline epoll_handler* get_poll_handler(int s) {
        _deb("basecom::set_poll_handler: called to get handler of %d",s);
        epoll_handler* h =  master()->poller.get_handler(s);
        _dia("basecom::set_poll_handler: handler of %d is 0x%x",s,h);
        return h;
    };

    inline void set_idle_watch(int s) {
        if(s > 0) {
            master()->poller.set_idle_watch(s);
        }
    }
    inline void clear_idle_watch(int s) {
        if(s > 0) {
            master()->poller.clear_idle_watch(s);
        }
    }


    inline void rescan_read(int s) {
        _dia("basecom::rescan_read: called to rescan EPOLLIN %d",s);
        if (s > 0 ) { 
            master()->poller.rescan_in(s);
        } 
    }

    inline void rescan_write(int s) {
        _dia("basecom::rescan_read: called to rescan EPOLLOUT %d",s);
        if (s > 0 ) { 
            master()->poller.rescan_out(s);
        } 
    }
        
    virtual bool resolve_socket(bool source,int s, std::string *target_host, std::string *target_port, struct sockaddr_storage *target_storage = NULL );    
    bool resolve_socket_src(int s, std::string *target_host, std::string *target_port, struct sockaddr_storage *target_storage = NULL ) { 
        return resolve_socket(true, s, target_host, target_port, target_storage);
    }
    bool resolve_socket_dst(int s, std::string *target_host, std::string *target_port, struct sockaddr_storage *target_storage = NULL ) {
        return resolve_socket(false, s, target_host, target_port, target_storage);
    }	

    // non-local socket support
    inline bool nonlocal_dst() { return nonlocal_dst_; }
    inline void nonlocal_dst(bool b) { nonlocal_dst_ = b; }	
    virtual int namesocket(int, std::string&, unsigned short,sa_family_t=AF_INET);

    inline void nonlocal_dst_resolved(bool b) { nonlocal_dst_resolved_ = b; }
    inline bool nonlocal_dst_resolved(void) { return nonlocal_dst_resolved_; }
    inline std::string& nonlocal_dst_host(void) { return nonlocal_dst_host_; }
    inline unsigned short& nonlocal_dst_port(void) { return nonlocal_dst_port_; }
    inline struct sockaddr_storage* nonlocal_dst_peer_info() { return &nonlocal_dst_peer_info_; }	

    inline bool nonlocal_src() { return nonlocal_src_; }
    inline void nonlocal_src(bool b) { nonlocal_src_ = b; } 
    inline std::string& nonlocal_src_host(void) { return nonlocal_src_host_; }
    inline unsigned short& nonlocal_src_port(void) { return nonlocal_src_port_; }
    


    virtual int nonlocal_bind(unsigned short port);
    virtual bool resolve_nonlocal_dst_socket(int sock);
    
    inline int l3_proto() const { return l3_proto_; };
    inline void l3_proto(int p) { l3_proto_ = p; }
    
    inline int l4_proto() const { return l4_proto_; };
    inline void l4_proto(int p) { l4_proto_ = p; }    

    DECLARE_C_NAME("baseCom");
    virtual std::string to_string(int verbosity=iINF) { return this->class_name(); };
    DECLARE_LOGGING(to_string);
    
    virtual const std::string shortname() const { return std::string("com"); }

protected:
    logan_attached<baseCom> log;
};

# endif
