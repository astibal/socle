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

struct Datagram {
    sockaddr_in dst;
    sockaddr_in src;
    buffer rx;
    int socket;
    
    bool embryonic = true;
};    

class DatagramCom {
public:
    static std::map<uint64_t,Datagram> datagrams_received;
};

class UDPCom : public baseCom, public DatagramCom {
public:
    virtual void init();
    virtual baseCom* replicate() { return new UDPCom(); };
    virtual const char* name() { return "udp"; };
    
    virtual int connect(const char* host, const char* port, bool blocking = false);
    virtual int bind(unsigned short port);  
    virtual int accept ( int sockfd, sockaddr* addr, socklen_t* addrlen_ );
    
    virtual bool in_readset(int s);
    virtual bool in_writeset(int s);
    virtual bool in_exset(int s);
    virtual int poll();
    virtual int read(int __fd, void* __buf, size_t __n, int __flags);
    virtual int read_from_pool(int __fd, void* __buf, size_t __n, int __flags);
    virtual int peek(int __fd, void* __buf, size_t __n, int __flags) { return read(__fd,__buf,__n, __flags | MSG_PEEK );};
    
    
    virtual int write(int __fd, const void* __buf, size_t __n, int __flags);
    virtual int write_to_pool(int __fd, const void* __buf, size_t __n, int __flags);
    
    virtual void close(int __fd) { ::close(__fd); };
    
    virtual void cleanup() {};  
    
    virtual bool is_connected(int s);
    virtual bool com_status();

    virtual bool resolve_nonlocal_socket(int sock);
    virtual bool resolve_socket(bool source, int s, std::string* target_host, std::string* target_port, sockaddr_storage* target_storage = 0);
protected:
    int udpcom_fd = 0;
    sockaddr udpcom_addr;
    socklen_t udpcom_addrlen;
    
};

#endif