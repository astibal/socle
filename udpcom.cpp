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

#include <udpcom.hpp>

int UDPCom::accept(int sockfd, sockaddr* addr, socklen_t* addrlen_) {
    return sockfd;
}

int UDPCom::bind(short unsigned int port) {
    int s;
    sockaddr_in sockName;

    sockName.sin_family = AF_INET;
    sockName.sin_port = htons(port);
    sockName.sin_addr.s_addr = INADDR_ANY;

    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) return -129;
    
    int optval = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
    
    optval = 1;
    setsockopt(s, IPPROTO_IP,IP_RECVORIGDSTADDR, &optval, sizeof optval);
    
    if(nonlocal_) {
        // allows socket to accept connections for non-local IPs
        setsockopt(s, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval));     
    }
    
    if (::bind(s, (sockaddr *)&sockName, sizeof(sockName)) == -1) return -130;
   
    return s;    
}

bool UDPCom::com_status() {
    return baseCom::com_status();
}

int UDPCom::connect(const char* host, const char* port, bool blocking) {
    struct addrinfo hints;
    struct addrinfo *gai_result, *rp;
    int sfd = -1;
    int gai;

    /* Obtain address(es) matching host/port */

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    gai = getaddrinfo(host, port, &hints, &gai_result);
    if (gai != 0) {
        DEB_("getaddrinfo: %s",gai_strerror(gai));
        return -2;
    }

    /* getaddrinfo() returns a list of address structures.
    Try each address until we successfully connect(2).
    If socket(2) (or connect(2)) fails, we (close the socket
    and) try the next address. */

    for (rp = gai_result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype,
                    rp->ai_protocol);

        //if (DDEB(110)) 
        DEBS_("UDPCom::connect: gai info found");
        
        if (sfd == -1) {
            DEBS_("UDPCom::connect: failed to create socket");
            continue;
        }

        udpcom_addr = *rp->ai_addr;
        udpcom_addrlen = rp->ai_addrlen;
        break;
    }

    
    if(sfd <= 0) {
        ERRS_("connect failed");
    }
    
    if (rp == NULL) {
        ERRS_("Could not connect");
        return -2;
    }

    freeaddrinfo(gai_result);

    udpcom_fd = sfd;
    
    return sfd;
}

void UDPCom::init()
{
    baseCom::init();
}

bool UDPCom::is_connected(int s) {
    return true;
}



