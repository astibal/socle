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

#ifndef TCPCOM_HPP
# define TCPCOM_HPP

#include <string>
#include <cstring>
#include <csignal>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>

#include <ctime>

#include <log/logger.hpp>
#include <basecom.hpp>
#include <display.hpp>

class TCPCom : public virtual baseCom {
public:
    TCPCom(): baseCom() {
        l4_proto(SOCK_STREAM);
        log.sub_area("com.tcp");
    };
    ~TCPCom() override = default;

    struct config_t {
        unsigned char _x{0};
        static inline int listen_backlog = 50;

    } config;
    
    void init(baseHostCX* owner) override;
    baseCom* replicate() override { return new TCPCom(); };
    
    int connect(const char* host, const char* port) override;
    int bind(unsigned short port) override;
    int bind(const char* _path) override { return -1; };
    int accept (int sockfd, sockaddr* addr, socklen_t* addrlen_) override;
    
    ssize_t read(int _fd, void* _buf, size_t _n, int _flags) override { return static_cast<int>(::recv(_fd, _buf, _n, _flags)); };
    ssize_t peek(int _fd, void* _buf, size_t _n, int _flags) override { return read(_fd, _buf, _n, _flags | MSG_PEEK );};
    ssize_t write(int _fd, const void* _buf, size_t _n, int _flags) override {
        auto r = ::send(_fd, _buf, _n, _flags);
        if(r < 0) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
        }
        return static_cast<int>(r);
    };
    void shutdown(int _fd) override {
        int r = ::shutdown(_fd, SHUT_RDWR);
        if(r > 0)
            _dia("%s::shutdown[%d]: %s", c_type(), _fd, string_error().c_str());
    };
    
    void cleanup() override {};
    
    bool is_connected(int s) override;
    bool com_status() override;

    void on_new_socket(int _fd) override;


    std::string shortname() const override { static std::string s("tcp"); return s; }
    std::string to_string(int verbosity) const override { return c_type(); };

protected:
    int connect_sock_family = AF_UNSPEC;
    int connect_sock_type = SOCK_STREAM;
    int bind_sock_family = AF_INET6;
    int bind_sock_type = SOCK_STREAM;
    int bind_sock_protocol = IPPROTO_TCP;
    
    TYPENAME_OVERRIDE("TCPCom")
    DECLARE_LOGGING(to_string)
    
};

#endif