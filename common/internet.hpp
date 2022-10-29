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

#include <cstdio>
#include <memory.h>
#include <cerrno>
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
#include <log/logan.hpp>

namespace inet {

    struct Factory {
        static logan_lite& log() {
            static logan_lite l("inet");
            return l;
        }
    };

    /// @brief retrieve vector of strings from getaddrinfo() respecting IP version parameter
    /// @param host_name 'host_name' to resolve to IP address list
    /// @param ipv 'ipv' specify IP version. Can be 4 or 6. Anything else implies IPv4.
    /// @return list of strings with IP addresses of desired IP family.
    std::vector<std::string> dns_lookup(const std::string &host_name, int ipv = 4);


    /// @brief download resource via HTTP/1.0. All magic included.
    /// @param url 'url' full resource URL
    /// @param buf 'buf' buffer where to save the content. Note: buffer doesn't have to be pre-allocated.
    /// @param ipv 'ipv' specify IP version. Can be 4 or 6. Anything else implies IPv4.
    /// @param timout 'timeout' timeout of the operation
    /// @return returns the size of retrieved content bytes (not size of data received on socket). Negative on error.
    int download(const std::string& url, buffer& buf, int timout, int ipv = 4);

    /// @brief Opens a socket to IP address and sends raw bytes. Expects HTTP response.
    /// @param request 'request' raw string with request body
    /// @param port 'port' port number to connect to
    /// @param buf 'buf' buffer where to save the content. Note: buffer doesn't have to be pre-allocated.
    /// @param timout 'timeout' timeout of the operation
    /// @return returns the size of retrieved content bytes (not size of data received on socket). Negative on error.
    int http_get(const std::string& request, const std::string& ip_address, int port, buffer& buf, int timout=10);

    /// @brief is it IPv4?
    bool is_ipv4_address(const std::string& str);
    /// @brief is it IPv6?
    bool is_ipv6_address(const std::string& str);
    int socket_connect(std::string const& ip_address, unsigned short port);

    /// @brief convert conveniently sockaddr_storage pointer to sockaddr_in pointer
    inline sockaddr_in* to_sockaddr_in(sockaddr_storage* st) { return reinterpret_cast<sockaddr_in*>(st); }
    /// @brief convert conveniently sockaddr_storage pointer to sockaddr_in6 pointer
    inline sockaddr_in6* to_sockaddr_in6(sockaddr_storage* st) { return reinterpret_cast<sockaddr_in6*>(st); }

}


#endif //__INTERNET_HPP__