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

#include <tcpcom.hpp>

void TCPCom::init(baseHostCX* owner) { 
    
    baseCom::init(owner); 
};

int TCPCom::connect(const char* host, const char* port, bool blocking) { 
    struct addrinfo hints;
    struct addrinfo *gai_result, *rp;
    int sfd = -1;
    int gai;

    /* Obtain address(es) matching host/port */

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = connect_sock_family;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = connect_sock_type; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    gai = getaddrinfo(host, port, &hints, &gai_result);
    if (gai != 0) {
        DEB_("TCPCom::connect[%s:%s]: getaddrinfo: %s",host,port,gai_strerror(gai));
        return -2;
    }

    /* getaddrinfo() returns a list of address structures.
    Try each address until we successfully connect(2).
    If socket(2) (or connect(2)) fails, we (close the socket
    and) try the next address. */

    for (rp = gai_result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype,
                    rp->ai_protocol);

        DEB_("TCPCom::connect[%s:%s]: gai info found",host,port);
        // Keep it here: would be good if we can do something like this in the future
        
        if(nonlocal_src()) {
            DEB_("TCPCom::connect[%s:%s]: about to name socket[%d] after: %s:%d",host,port,sfd,nonlocal_src_host().c_str(),nonlocal_src_port());
            int bind_status = namesocket(sfd,nonlocal_src_host(),nonlocal_src_port());
            if (bind_status != 0) {
                    WAR_("cannot bind this port: %s",strerror(bind_status));
            } else {
                DIA_("TCPCom::connect[%s:%s]: socket[%d] transparency for %s:%d OK",host,port,sfd,nonlocal_src_host().c_str(),nonlocal_src_port());
            }
        }

        //if (DDEB(110)) 
        
        
        if (sfd == -1) {
            DEB_("TCPCom::connect[%s:%s]: socket[%d]: failed to create socket",host,port,sfd);
            continue;
        }
        
        if (not blocking) {
            unblock(sfd);

            if (::connect(sfd, rp->ai_addr, rp->ai_addrlen) < 0) {
                if ( errno == EINPROGRESS ) {
                    DEB_("TCPCom::connect[%s:%s]: socket[%d]: connnect errno: EINPROGRESS",host,port,sfd);
                    break;
                    
                    
                } else {
                    NOT_("TCPCom::connect[%s:%s]: socket[%d]: connnect errno: %s",host,port,sfd,strerror(errno));
                }

                close(sfd);
                sfd = 0;
                DUMS_("new attempt, socket reset");
                
            } 
        } else {
            if (::connect(sfd, rp->ai_addr, rp->ai_addrlen) != 0) {
                continue;
            } else {
                break;
            }
        }
    }

    
    if(sfd == 0) {
        ERR_("TCPCom::connect[%s:%s]: socket[%d]: connect failed",host,port,sfd);
    }
    
    if (rp == NULL) {
        ERR_("TCPCom::connect[%s:%s]: socket[%d]: connect failed",host,port,sfd);
        return -2;
    }

    freeaddrinfo(gai_result);

    tcpcom_fd = sfd;
    
    return sfd;

};

int TCPCom::bind(unsigned short port) {
    int s;
    sockaddr_in sockName;

    sockName.sin_family = bind_sock_family;
    sockName.sin_port = htons(port);
    sockName.sin_addr.s_addr = INADDR_ANY;

    if ((s = socket(bind_sock_family, bind_sock_type, bind_sock_protocol)) == -1) return -129;
    
    int optval = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
    
    if(nonlocal_dst_) {
        // allows socket to accept connections for non-local IPs
        DIA_("TCPCom::bind[%d]: setting it transparent",s);
        setsockopt(s, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval));     
    }
    
    if (::bind(s, (sockaddr *)&sockName, sizeof(sockName)) == -1) return -130;
    if (listen(s, 10) == -1)  return -131;
    
    return s;
};  


int TCPCom::accept ( int sockfd, sockaddr* addr, socklen_t* addrlen_ ) {
    return ::accept(sockfd,addr,addrlen_);
}

bool TCPCom::is_connected(int s) {
    
    if(tcpcom_fd == 0) {
        DEBS_("TCPCom::is_connected: called for non-connecting socket");
        return true;
    }
    
    int error_code = 0;
    socklen_t l = sizeof(error_code);
    char str_err[256];
    
    // tcp socket will stay in EINPROGRESS unless there is ANY stat call! Don't ask why. 
    // fstating socket seemed to me cheapest/fastest.
    // fstating with stat struct buffer wasn't working too!
    // 2016-01-16: seems not needed anymore. But keep to easy revert in case.

#pragma GCC diagnostic ignored "-Wnonnull"
#pragma GCC diagnostic push        
    //fstat(s,nullptr);
#pragma GCC diagnostic pop
    
    int r_getsockopt = getsockopt(s, SOL_SOCKET, SO_ERROR, &error_code, &l);
    error_code = errno;
    
    if ( r_getsockopt == 0 ) {
                                
        if(error_code != 0) {
                DEB_("TCPCom::is_connected[%d]: getsockopt errno %d = %s",s,error_code,strerror_r(error_code,str_err,256));
        }
        else {
                DUM_("TCPCom::is_connected[%d]: getsockopt errno %d = %s",s,error_code,strerror_r(error_code,str_err,256));
        }
        
        if(error_code == EINPROGRESS) return false;

        if(LEV_(DEB)) {
            if(poller.in_write_set(s)) {
                DEB_("TCP::is_connected[%d]: writable",s);
            } else {
                DEB_("TCP::is_connected[%d]: not writable",s);
            }
        }

        return true;

    } else {
        DIA_("TCPCom::is_connected[%d]: getsockopt failed, returned %d = %s",s,r_getsockopt,strerror_r(r_getsockopt,str_err,256));
        return false;
    } 
}


bool TCPCom::com_status() {
    
    if(baseCom::com_status()) {
        bool r = is_connected(tcpcom_fd);
        //T_DIA_("tcpcom_status_ok",1,"TCPCom::com_status: returning %d",r);
        DEB_("TCPCom::com_status: returning %d",r);
        return r;
    }
    
    // T_DUMS_("tcpcom_status_nok",1,"TCPCom::com_status: returning 0");
    DEBS_("TCPCom::com_status: returning 0");
    return false;    
}
