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

#ifndef __INTERNET_HPP__
#define __INTERNET_HPP__

#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
 
#include <string>
#include <sstream>
#include <vector>
#include <iostream>
#include <buffer.hpp>
 
 
std::vector<std::string> dns_lookup(const std::string &host_name, int ipv=4); //ipv: default=4
bool is_ipv6_address(const std::string& str);
bool is_ipv4_address(const std::string& str);
int socket_connect(std::string ip_address, int port);
int http_get(const std::string& request, const std::string& ip_address, int port, buffer& buf, int timout=10);
int download(const std::string& url, buffer& buf, int timout=10);
 

namespace inet {
    inline sockaddr_in* to_sockaddr_in(sockaddr_storage* st) { sockaddr_in* ptr = (sockaddr_in*)st; return ptr; }
    inline sockaddr_in6* to_sockaddr_in6(sockaddr_storage* st) { sockaddr_in6* ptr = (sockaddr_in6*)st; return ptr; }

}


#endif //__INTERNET_HPP__