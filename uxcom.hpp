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

#ifndef UXCOM_HPP
# define UXCOM_HPP

#include <string>
#include <cstring>
#include <ctime>
#include <csignal>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <logger.hpp>
#include <basecom.hpp>
#include <display.hpp>
#include <tcpcom.hpp>

class UxCom : public TCPCom {
public:
    UxCom(): TCPCom() {
        // change socket properties
        connect_sock_family = AF_UNIX;
        connect_sock_type = SOCK_STREAM;
        bind_sock_family = AF_UNIX;
        bind_sock_type = SOCK_STREAM;
        bind_sock_protocol = 0;
    };
    
    virtual baseCom* replicate() { return new UxCom(); };
    virtual const char* name() { return "unix"; };
    
    virtual int connect(const char* host, const char* port, bool blocking = false);
    virtual int bind(unsigned short port);  //this bind is deprecated, returning always -1. Use bind(const char*).
    virtual int bind(const char* name);

};

#endif