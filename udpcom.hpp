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

#ifndef UDPCOM_HPP
# define UDPCOM_HPP

#include <string>
#include <array>
#include <optional>

#include <cstring>
#include <ctime>
#include <csignal>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>


#include <buffer.hpp>
#include <log/logger.hpp>
#include <basecom.hpp>
#include <baseproxy.hpp>

#include <linux/ipv6.h>

//  If including linux/ipv6.h fails, use these constants as a dirty trick to make it work
//  constant value should not change, but they may eventually, you have been warned.

//#define IPV6_ORIGDSTADDR        74
//#define IPV6_RECVORIGDSTADDR    IPV6_ORIGDSTADDR


struct Datagram {

    Datagram() = default;

    Datagram(Datagram const& r) {
        dst = r.dst;
        src = r.src;
        socket_left = r.socket_left;
        reuse = r.reuse;
        cx = r.cx;
        rx_queue = r.rx_queue;
    }

    Datagram& operator=(Datagram const& r) {

        dst = r.dst;
        src = r.src;
        socket_left = r.socket_left;

        reuse = r.reuse;
        cx = r.cx;
        rx_queue = r.rx_queue;

        return *this;
    }

    sockaddr_storage dst{};
    sockaddr_storage src{};

    mutable std::mutex rx_queue_lock;
    std::array<buffer,5> rx_queue;

    inline size_t queue_bytes() const {
        size_t elem_bytes = 0;

        for(auto const& r: rx_queue) {
            if (!r.empty()) {
                elem_bytes += r.size();
            }
        }

        return elem_bytes;
    }

    size_t queue_bytes_l() const {
        auto l_ = std::scoped_lock(rx_queue_lock);
        return queue_bytes();
    }

    inline bool empty() const {
        return (queue_bytes() == 0);
    }

    inline bool empty_l() const {
        return (queue_bytes_l() == 0);
    }

    inline size_t enqueue(unsigned char* data, size_t len) {
        for(auto& elem: rx_queue) {
            if(elem.empty()) {
                elem.append(data, len);
                return len;
            }
        }
        return 0;
    }


    std::optional<int> socket_left;

    bool reuse = false;         // make this true if there is e.g. clash and closed CX/Com should not
                                // trigger it's removal from the pool: com()->close() will otherwise
                                // erase it.
                                // It's toggle type, whenever used, it should be again set to false,
                                // in order to be deleted once in the future.
    baseHostCX* cx = nullptr;
    

    inline sockaddr_in* src_sockaddr_in() { sockaddr_in* ptr = (sockaddr_in*)&src; return ptr; }
    inline sockaddr_in6* src_sockaddr_in6() { sockaddr_in6* ptr = (sockaddr_in6*)&src; return ptr; }
    
    inline bool src_ipv4() const { return src.ss_family == AF_INET; } 
    inline bool src_ipv6() const { return src.ss_family == AF_INET6; } 
    inline in_addr& src_in_addr4() { return src_sockaddr_in()->sin_addr; };
    inline in6_addr& src_in_addr6() { return src_sockaddr_in6()->sin6_addr; };
    inline unsigned short src_port4() { return src_sockaddr_in()->sin_port; }
    inline unsigned short src_port6() { return src_sockaddr_in6()->sin6_port; }
    inline sa_family_t src_family() { return src.ss_family; }
    
    inline sockaddr_in* dst_sockaddr_in() { sockaddr_in* ptr = (sockaddr_in*)&dst; return ptr; }
    inline sockaddr_in6* dst_sockaddr_in6() { sockaddr_in6* ptr = (sockaddr_in6*)&dst; return ptr; }
    
    inline bool dst_ipv4() const { return dst.ss_family == AF_INET; } 
    inline bool dst_ipv6() const { return dst.ss_family == AF_INET6; } 
    inline in_addr& dst_in_addr4() { return dst_sockaddr_in()->sin_addr; };
    inline in6_addr& dst_in_addr6() { return dst_sockaddr_in6()->sin6_addr; };
    inline unsigned short dst_port4() { return dst_sockaddr_in()->sin_port; }
    inline unsigned short dst_port6() { return dst_sockaddr_in6()->sin6_port; }
    inline sa_family_t dst_family() { return dst.ss_family; }
    
};    

class DatagramCom {
public:
    static inline std::recursive_mutex lock;
    static inline std::map<uint64_t,std::shared_ptr<Datagram>> datagrams_received;
  
    // set with all virtual sockets which have data to read
    static inline epoll::set_type in_virt_set;
};

class UDPCom : public virtual baseCom, public DatagramCom {
public:
    using buffer_guard = locked_guard<lockbuffer>;

    UDPCom(): baseCom() {
        l4_proto(SOCK_DGRAM);
        bind_sock_family = default_sock_family;

        log.sub_area("com.udp");
    };
    
    void init(baseHostCX* owner) override;
    baseCom* replicate() override { return new UDPCom(); };
    
    int connect(const char* host, const char* port) override;
    int bind(unsigned short port) override;
    int bind([[maybe_unused]] const char* path) override { return -1; };
    int accept ( int sockfd, sockaddr* addr, socklen_t* addrlen_ ) override;
    int translate_socket(int vsock) const override;
    
    bool in_readset(int s) override;
    bool in_writeset(int s) override;
    virtual bool in_exset(int s);
    int poll() override ;
    ssize_t read(int _fd, void* _buf, size_t _n, int _flags) override;
    virtual int read_from_pool(int _fd, void* _buf, size_t _n, int _flags);
    virtual ssize_t recv(int _fd, void* _buf, size_t _n, int _flags) { return ::recv(_fd, _buf, _n, _flags); }
    ssize_t peek(int _fd, void* _buf, size_t _n, int _flags) override { return read(_fd, _buf, _n, static_cast<uint8_t>(_flags) | MSG_PEEK );};
    
    
    ssize_t write(int _fd, const void* _buf, size_t _n, int _flags) override;
    virtual ssize_t write_to_pool(int _fd, const void* _buf, size_t _n, int _flags);
    
    void shutdown(int _fd) override;
    
    void cleanup() override {};
    
    bool is_connected(int s) override;
    bool com_status() override;

    virtual bool resolve_nonlocal_socket(int sock);
    bool resolve_socket(bool source, int s, std::string* target_host, std::string* target_port, sockaddr_storage* target_storage) override;

    struct embryon {
        uint32_t id = 0;     // is it a new connection? If non-zero, we should look in datagram store before reading real
                             // sockets. After all datagram early data are processed, we should set it to 0
                             // and not read from store anymore

        bool pool_depleted = false;     // should we read from pool, or we already depleted it? It's cache value to not check pool again.
    };

    embryon embryonics() const { return embryonics_; };
    embryon& embryonics() { return embryonics_; };
    embryon embryonics(uint32_t n, bool p) { auto tmp = embryonics_; embryonics_ = { .id = n, .pool_depleted = p }; return tmp; };
protected:
    embryon embryonics_= {0, false };

    unsigned int bind_sock_family = AF_INET6;
    int bind_sock_type = SOCK_DGRAM;
    int bind_sock_protocol = IPPROTO_UDP;
    
    sockaddr_storage udpcom_addr {};
    socklen_t udpcom_addrlen {0};
    
    // Connection socket pool
    //
    // If the same source IP:PORT connection is already in place
    // transparent bind to source IP:PORT fails, delaying DNS resolution. 
    // this connection database maintains opened sockets, which will be reused.
    
    // Since we don't want one Com to close another's Com opened socket,
    // we implement value as tuple of <fd,refcount>.
    static inline std::map<std::string,std::pair<int,int>> connect_fd_cache;
    static inline std::recursive_mutex connect_fd_cache_lock;
    
public:
    
    // allow older kernels to use UDP -- we have to set bind_sock_family to IPv4 variant
    static inline unsigned int default_sock_family = AF_INET6;

    std::string to_string(int verbosity) const override { return c_type(); }
    std::string shortname() const override { static  std::string s("udp"); return s; }

    TYPENAME_OVERRIDE("UDPCom")
    DECLARE_LOGGING(to_string)

};

#endif
