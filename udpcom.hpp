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

#include <buffer.hpp>
#include <logger.hpp>
#include <basecom.hpp>
#include <baseproxy.hpp>

// FIXME: including linux/ipv6.h fails
// #include <linux/ipv6.h>

#define IPV6_ORIGDSTADDR        74
#define IPV6_RECVORIGDSTADDR    IPV6_ORIGDSTADDR


struct Datagram {
    sockaddr_storage dst;
    sockaddr_storage src;
    lockbuffer rx;
    int socket;
    bool real_socket = false;   // indicate if inbound connection was suceessfully bound, so we can use
                                // real socket instead of virtual.
    
    bool embryonic = true;
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
    static std::recursive_mutex lock;
    static std::map<uint64_t,Datagram> datagrams_received;
  
    // set with all virtal sockets which have data to read
    static std::set<int> in_virt_set;    
};

class UDPCom : public virtual baseCom, public DatagramCom {
public:
    UDPCom(): baseCom() {
        l4_proto(SOCK_DGRAM);
        bind_sock_family = default_sock_family;

        log.sub_area("com.udp");
    };
    
    static std::string udpcom_name_;
    
    virtual void init(baseHostCX* owner);
    virtual baseCom* replicate() { return new UDPCom(); };
    
    int connect(const char* host, const char* port) override;
    virtual int bind(unsigned short port);
    virtual int bind(const char* path) { return -1; };  
    virtual int accept ( int sockfd, sockaddr* addr, socklen_t* addrlen_ );
    virtual int translate_socket(int vsock);
    
    virtual bool in_readset(int s);
    virtual bool in_writeset(int s);
    virtual bool in_exset(int s);
    virtual int poll();
    virtual int read(int __fd, void* __buf, size_t __n, int __flags);
    virtual int read_from_pool(int __fd, void* __buf, size_t __n, int __flags);
    virtual int recv(int __fd, void* __buf, size_t __n, int __flags) { return ::recv(__fd,__buf,__n,__flags);}; 
    virtual int peek(int __fd, void* __buf, size_t __n, int __flags) { return read(__fd,__buf,__n, __flags | MSG_PEEK );};
    
    
    virtual int write(int __fd, const void* __buf, size_t __n, int __flags);
    virtual int write_to_pool(int __fd, const void* __buf, size_t __n, int __flags);
    
    virtual void shutdown(int __fd);
    
    virtual void cleanup() {};  
    
    virtual bool is_connected(int s);
    virtual bool com_status();

    virtual bool resolve_nonlocal_socket(int sock);
    virtual bool resolve_socket(bool source, int s, std::string* target_host, std::string* target_port, sockaddr_storage* target_storage = 0);
protected:
    int udpcom_fd = 0;
    unsigned int bind_sock_family = AF_INET6;
    unsigned int bind_sock_type = SOCK_DGRAM;
    unsigned int bind_sock_protocol = IPPROTO_UDP;
    
    sockaddr_storage udpcom_addr;
    socklen_t udpcom_addrlen;
    
    // Connection socket pool
    //
    // If the same source IP:PORT connection is already in place
    // transparent bind to source IP:PORT fails, delaying DNS resolution. 
    // this connection database maintains opened sockets, which will be reused.
    
    // Since we don't want one Com to close another's Com opened socket,
    // we implement value as tuple of <fd,refcount>.
    static std::map<std::string,std::pair<int,int>> connect_fd_cache;
    static std::recursive_mutex connect_fd_cache_lock;
    
public:
    
    // allow older kernels to use UDP -- we have to set bind_sock_family to IPv4 variant
    static unsigned int default_sock_family;

    DECLARE_C_NAME("UDPCom");
    DECLARE_LOGGING(to_string);

    std::string to_string(int verbosity=iINF) const override { return class_name(); }
    const std::string shortname() const override { static  std::string s("udp"); return s; }
};

#endif
