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
#include <atomic>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>

#include <epoll.hpp>
#include <log/logger.hpp>


class baseHostCX;

class baseCom {
public:
    friend class baseHostCX;

    static bool& GLOBAL_IO_BLOCKING() { static bool b = false; return b; }

    static inline bool debug_log_data_crc = false;
    static inline const char str_unknown[] = "unknown";
    static inline const char str_getsockname[] = "getsockname-tproxy";
    static inline const char str_getpeername[] = "getpeername-tproxy";

    static inline long poll_msec = 10000;
    static inline long rescan_msec = 100;

    int     poll_result = 0;
    baseHostCX* owner_cx_ = nullptr;
    inline baseHostCX* owner_cx() const { return owner_cx_; }

    [[maybe_unused]] static void polltime(int msec) { poll_msec = msec; }

    bool _static_init = false;

    // my master: add me to the poll monitor at the right time
    baseCom* master_ = nullptr;
    baseCom* master(baseCom* b) noexcept { master_ = b; return b; }
    baseCom* master() noexcept {
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
    typedef enum { ERROR_NONE=0, ERROR_UNSPEC=1, ERROR_READ, ERROR_WRITE, ERROR_SOCKET } err_flags;
    int  error_flag_ = ERROR_NONE;

    bool error() const { return error_flag_ != ERROR_NONE; }
    int error_flags() const { return error_flag_; };
    inline void error(baseCom::err_flags e) { error_flag_ = e;}
    
    explicit baseCom() =default;
    virtual ~baseCom() = default;
    virtual std::string flags_str() { return "0"; };
    virtual std::string full_flags_str();
private:

    int fd_ = 0;

    // feedback mechanism to get if the communication level is up/down
    // necessary for some mitm scenarios and connection status feedback between 2 sockets
    baseCom* peer_ = nullptr;

protected:
    // non-local socket support
    bool nonlocal_dst_ = false;
    bool nonlocal_dst_resolved_ = false;
    std::string nonlocal_dst_host_;
    unsigned short nonlocal_dst_port_ = 0;
    struct sockaddr_storage nonlocal_dst_peer_info_{};
    
    int l3_proto_ = AF_INET;
    int l4_proto_ = 0;
    
    bool nonlocal_src_ = false;
    std::string nonlocal_src_host_;
    unsigned short nonlocal_src_port_ =  0;

    // this is log buffer intended for upper layer logger. Whatever is not only about to be printed out, but also stored,
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
    [[nodiscard]] bool forced_read_on_write() const  { return forced_read_on_write_; }
    [[nodiscard]] bool forced_write_on_read() const { return forced_write_on_read_; }
    
    bool forced_read_on_write_reset() { bool r = forced_read_on_write_; forced_read_on_write_= false;  return r; }
    bool forced_write_on_read_reset() { bool r = forced_write_on_read_; forced_write_on_read_ = false;  return r; }

    
    bool forced_read_reset() { bool r = forced_read_; if (!forced_read_always_) { forced_read_ = false; } return r; }
    bool forced_write_reset() { bool r = forced_write_; if (!forced_write_always_) {forced_write_ = false; } return r; }
    
    virtual bool com_status() { _dum("baseCom::com_status: returning 1"); return true; }
    inline std::string& logbuf() { return log_buffer_; };
    
    baseCom* peer() const { return peer_; }
    void peer(baseCom* p) { peer_ = p; }
    
public:
    virtual void init(baseHostCX* owner);

    virtual void static_init() {
        signal(SIGPIPE, SIG_IGN);
    };

    virtual baseCom* replicate() = 0;
    
    virtual int connect(const char* , const char*) = 0;
    virtual int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen_) = 0;
    virtual ssize_t read(int _fd, void* _buf, size_t _n, int _flags) = 0;
    virtual ssize_t peek(int _fd, void* _buf, size_t _n, int _flags) = 0;
    virtual ssize_t write(int _fd, const void* _buf, size_t _n, int _flags) = 0;
    virtual void shutdown(int _fd) = 0;
    virtual void close(int _fd);
    virtual int bind(unsigned short _port) = 0;
    virtual int bind(const char* _path) = 0;

    /// @brief poll socket with supported poll technique. Works automagically.
    virtual int poll();

    /// @brief standardized error log with description from errno
    void err_errno(const char* fn, const char* params, int rv) const;

    /// @brief so_<> functions set some well-known socket feature, typically using **setsockopt**
    int so_reuseaddr(int sock) const;
    int so_broadcast(int sock) const;
    int so_nodelay(int sock) const;
    int so_quickack(int sock) const;
    int so_keepalive(int sock) const;
    int so_transparent_v4(int sock) const;
    int so_transparent_v6(int sock) const;
    int so_transparent(int sock) const;
    int so_recvorigdstaddr_v4(int sock) const;
    int so_recvorigdstaddr_v6(int sock) const;

    /// @brief - support for pseudo-socket, so called 'virtual socket'. Com's socket can be negative numbered
    /// which indicates socket is virtual identifier which should be looked for somewhere else.
    /// It is known UDPCom is using this feature.
    /// This base version is just returning back the original value.
    virtual int translate_socket(int vsock) const { return vsock; };
    virtual int socket() const { return fd_; }

    // sets a socket and closes previous socket if set
    virtual int socket(int sock) {

        if( sock !=  fd_ && fd_ > 0) {
            _err("basecom::socket: orphaned fd %d, new socket %d", fd_, sock);

            // prepared to fix https://github.com/astibal/smithproxy/issues/7
            // auto bts = bt(true);
            // _err("trace: \r\n%s", bts.c_str());
            //::close(fd_);

            _war("baseCom::socket(%d): possibly leaking previously held socket %d", sock, fd_);
        }

        fd_ = sock;
        return fd_;
    }


    virtual void on_new_socket(int _fd) {};

    // syscall wrapper 

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


    [[maybe_unused]] inline int unblock() const { return unblock(socket()); };
    int unblock(int s) const;
    [[maybe_unused]] static inline int is_blocking(int s) { return !(::fcntl(s, F_GETFL, 0) & O_NONBLOCK);  }
    
    virtual void cleanup() = 0;

    virtual bool is_connected(int s) = 0;
    
    // those two need to be virtual, since e.g. OpenSSL read/write cannot be managed only with FD_SET due reads 
    // sometimes do writes on themselves and another read is necessary
    virtual bool readable(int s) { return true; };
    virtual bool writable(int s) { return true; };
    
    // check if socket is changed
    virtual bool in_readset(int s) { return master()->poller.in_read_set(s); };
    virtual bool in_writeset(int s) { return master()->poller.in_write_set(s); };
    virtual bool in_idleset(int s) { return master()->poller.in_idle_set(s); };

    inline void set_monitor(int xs) {
        _deb("basecom::set_monitor: called to add %d", xs);

        int s = xs;
        if(xs < 0) {
            s = master()->translate_socket(s);
            _deb("   virtual socket, translated to real %d", s);
        }

        if (s > 0) {
            master()->poller.add(s,EPOLLIN); 
        } 
    };
    inline void set_enforce(int xs) {
        _deb("basecom::set_enforce: called to add %d", xs);

        int s = xs;
        if(xs < 0) {
            s = master()->translate_socket(s);
            _deb("   virtual socket, translated to real %d", s);
        }

        if (s > 0 ) {
            master()->poller.enforce_in(s);
        }
    };

    inline void unset_monitor(int xs) {
        _deb("basecom::unset_monitor: called to remove %d", xs);

        int s = xs;
        if(xs < 0) {
            s = master()->translate_socket(s);
            _deb("   virtual socket, translated to real %d", s);
        }

        if (s > 0 ) { 
            master()->poller.del(s);
            master()->poller.cancel_rescan_in(s);
            master()->poller.cancel_rescan_out(s);
        } 
    };    
    inline void set_write_monitor(int xs) {
        _deb("basecom::set_write_monitor: called to add EPOLLOUT %d", xs);

        int s = xs;
        if(xs < 0) {
            s = master()->translate_socket(s);
            _deb("   virtual socket, translated to real %d", s);
        }

        if (s > 0 ) { 
            master()->poller.modify(s,EPOLLIN|EPOLLOUT); 
        } 
    }
    inline void set_write_monitor_only(int xs) {
        _deb("basecom::set_write_monitor: called to add EPOLLOUT %d only", xs);

        int s = xs;
        if(xs < 0) {
            s = master()->translate_socket(s);
            _deb("   virtual socket, translated to real %d", s);
        }

        if (s > 0 ) { 
            master()->poller.modify(s,EPOLLOUT); 
        } 
    }    

    inline void change_monitor(int xs, int new_mode) {
        _deb("basecom::change_monitor: change mode of %d to %d", xs, new_mode);

        int s = xs;
        if(xs < 0) {
            s = master()->translate_socket(s);
            _deb("   virtual socket, translated to real %d", s);
        }

        if (s > 0 ) { 
            master()->poller.modify(s, new_mode);
        } 
    };       
    
    inline void set_hint_monitor(int s) {
        _deb("basecom::set_hint_monitor: called: %d", s);
        master()->poller.hint_socket(s); 
    }

    inline void set_poll_handler(int xs, epoll_handler* h) {
        _deb("basecom::set_poll_handler: add %d monitored by 0x%x", xs, h);

        int s = xs;
        if(xs < 0) {
            s = master()->translate_socket(s);
            _deb("   virtual socket, translated to real %d", s);
        }

        master()->poller.set_handler(s, h);

        // add also virtual handler
        if(xs < 0) {
            _deb("basecom::set_poll_handler: add also virtual %d monitored by 0x%x", xs, h);
            master()->poller.set_handler(xs, h);
        }
    };

    inline epoll_handler* get_poll_handler(int s) {
        _dum("basecom::get_poll_handler: called to get handler of %d", s);
        epoll_handler* h =  master()->poller.get_handler(s);
        _deb("basecom::get_poll_handler: handler of %d is 0x%x", s, h);
        return h;
    };

    inline void set_idle_watch(int xs) {

        _deb("basecom::set_idle_watch: called: %d", xs);

        int s = xs;
        if(xs < 0) {
            s = master()->translate_socket(s);
            _deb("   virtual socket, translated to real %d", s);
        }

        if(s > 0) {
            master()->poller.set_idle_watch(s);
        }
    }
    inline void clear_idle_watch(int xs) {
        _deb("basecom::clear_idle_watch: called: %d", xs);

        int s = xs;
        if(xs < 0) {
            s = master()->translate_socket(s);
            _deb("   virtual socket, translated to real %d", s);
        }

        if(s > 0) {
            master()->poller.clear_idle_watch(s);
        }
    }


    inline void rescan_read(int xs) {
        _deb("basecom::rescan_read: called to rescan EPOLLIN %d", xs);

        int s = xs;
        if(xs < 0) {
            s = master()->translate_socket(s);
            _deb("   virtual socket, translated to real %d", s);
        }

        if (s > 0 ) { 
            master()->poller.rescan_in(s);
        } 
    }

    inline void rescan_write(int xs) {
        _deb("basecom::rescan_read: called to rescan EPOLLOUT %d", xs);

        int s = xs;
        if(xs < 0) {
            s = master()->translate_socket(s);
            _deb("   virtual socket, translated to real %d", s);
        }

        if (s > 0 ) { 
            master()->poller.rescan_out(s);
        } 
    }
        
    virtual bool resolve_socket(bool source,int s, std::string *target_host, std::string *target_port, struct sockaddr_storage *target_storage);
    bool resolve_socket_src(int s, std::string *target_host, std::string *target_port, struct sockaddr_storage *target_storage = nullptr ) {
        return resolve_socket(true, s, target_host, target_port, target_storage);
    }
    bool resolve_socket_dst(int s, std::string *target_host, std::string *target_port, struct sockaddr_storage *target_storage = nullptr ) {
        return resolve_socket(false, s, target_host, target_port, target_storage);
    }

    // resolve destination if REDIRECTed
    bool resolve_redirected(int s, std::string* target_host, std::string* target_port, sockaddr_storage* target_storage);
    bool resolve_redirected_dst_socket(int sock);

    // non-local socket support
    [[nodiscard]] inline bool nonlocal_dst() const { return nonlocal_dst_; }
    inline void nonlocal_dst(bool b) { nonlocal_dst_ = b; }	
    virtual int namesocket(int, std::string&, unsigned short, sa_family_t);

    inline void nonlocal_dst_resolved(bool b) { nonlocal_dst_resolved_ = b; }
    [[nodiscard]] inline bool nonlocal_dst_resolved() const { return nonlocal_dst_resolved_; }
    inline std::string& nonlocal_dst_host() { return nonlocal_dst_host_; }
    inline unsigned short& nonlocal_dst_port() { return nonlocal_dst_port_; }
    inline struct sockaddr_storage* nonlocal_dst_peer_info() { return &nonlocal_dst_peer_info_; }	

    [[nodiscard]] inline bool nonlocal_src() const { return nonlocal_src_; }
    inline void nonlocal_src(bool b) { nonlocal_src_ = b; } 
    inline std::string& nonlocal_src_host() { return nonlocal_src_host_; }
    inline unsigned short& nonlocal_src_port() { return nonlocal_src_port_; }
    


    virtual int nonlocal_bind(unsigned short port);
    virtual bool resolve_nonlocal_dst_socket(int sock);
    
    inline int l3_proto() const { return l3_proto_; };
    inline void l3_proto(int p) { l3_proto_ = p; }
    
    inline int l4_proto() const { return l4_proto_; };
    inline void l4_proto(int p) { l4_proto_ = p; }

    virtual std::string to_string(int verbosity) const = 0;
    [[nodiscard]] inline std::string str() const { return to_string(iINF); }

    virtual std::string shortname() const = 0;

    TYPENAME_BASE("baseCom")
    DECLARE_LOGGING(to_string)

private:
    logan_lite log {"com.base"};
};

# endif
