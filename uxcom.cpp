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

#include <uxcom.hpp>

// obviously, port is ignored
int UxCom::connect(const char* host, const char* noop_port, bool blocking) { 

    const char* port = "";
    int sfd = -1;

    
    sfd = socket(connect_sock_family, connect_sock_type, 0);


    if (sfd == -1) {
        DEB_("UxCom::connect[%s:%s]: socket[%d]: failed to create socket",host,port,sfd);
        return sfd;
    }

    struct sockaddr_un server;
    server.sun_family = connect_sock_family;
    strcpy(server.sun_path,host);
    
    if (not blocking) {
        unblock(sfd);

        if (::connect(sfd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0) {
            if ( errno == EINPROGRESS ) {
                DEB_("UxCom::connect[%s:%s]: socket[%d]: connnect errno: EINPROGRESS",host,port,sfd);
                
            } else {
                NOT_("UxCom::connect[%s:%s]: socket[%d]: connnect errno: %s",host,port,sfd,strerror(errno));
            }

            close(sfd);
            sfd = 0;
        } 
    } else {
        if (::connect(sfd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) != 0) {
            close(sfd);
            sfd = 0;
        }
    }

    if(sfd == 0) {
        ERR_("UxCom::connect[%s:%s]: socket[%d]: connect failed",host,port,sfd);
    }

    tcpcom_fd = sfd;
    
    return sfd;

};

int UxCom::bind(short unsigned int port) {
    ERR_("UxCom::bind(int): bind failed, cannot bind to any port number",port);
    return -1;
}

int UxCom::bind(const char* name) {
    int s;

    struct sockaddr_un server;
    server.sun_family = bind_sock_family;
    strcpy(server.sun_path,name);    

    if ((s = socket(bind_sock_family, bind_sock_type, bind_sock_protocol)) == -1) return -129;
    
    int optval = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
    
    if (::bind(s, (sockaddr *)&server, sizeof(server)) == -1) return -130;
    if (listen(s, 10) == -1)  return -131;
    
    return s;
};  


