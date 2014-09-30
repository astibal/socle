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

#include <logger.hpp>
#include <basecom.hpp>

class UDPCom : public baseCom {
public:
    virtual void init();
    virtual baseCom* replicate() { return new UDPCom(); };
    virtual const char* name() { return "udp"; };
    
    virtual int connect(const char* host, const char* port, bool blocking = false);
    virtual int bind(unsigned short port);  
    virtual int accept ( int sockfd, sockaddr* addr, socklen_t* addrlen_ );
    
    virtual int read(int __fd, void* __buf, size_t __n, int __flags) { return ::recvfrom(__fd,__buf,__n,__flags,&udpcom_addr,&udpcom_addrlen); };
    virtual int peek(int __fd, void* __buf, size_t __n, int __flags) { return read(__fd,__buf,__n, __flags | MSG_PEEK );};
    virtual int write(int __fd, const void* __buf, size_t __n, int __flags)  { return ::sendto(__fd,__buf,__n,__flags,&udpcom_addr, udpcom_addrlen); };
    virtual void close(int __fd) { /* don't close udp socket, it's not accepted */ };
    
    virtual void cleanup() {};  
    
    virtual bool is_connected(int s);
    virtual bool com_status();

protected:
    int udpcom_fd = 0;
    sockaddr udpcom_addr;
    socklen_t udpcom_addrlen;
    
};

#endif