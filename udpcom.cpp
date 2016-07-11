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
#include <display.hpp>

std::map<uint64_t,Datagram> DatagramCom::datagrams_received;
std::mutex DatagramCom::lock;

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
    
    if(nonlocal_dst_) {
        // allows socket to accept connections for non-local IPs
        DIA_("UDPCom::bind[%d]: setting it transparent",s);
        setsockopt(s, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval));     
    }

    optval = 1;
//     setsockopt(s, IPPROTO_IP,IP_RECVORIGDSTADDR, &optval, sizeof optval);
    if (setsockopt(s, SOL_IP,IP_RECVORIGDSTADDR, &optval, sizeof optval) != 0) return -131;

    
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

        
        int optval = 1;
        if(setsockopt(sfd, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval)) != 0) {
            WAR_("UDPCom::connect[%d]: cannot set transparency sockopt: %s",sfd,string_error().c_str());
        }
        
        
        if(nonlocal_src()) {
            DEB_("UDPCom::connect[%s:%s]: About to name socket[%d] after: %s:%d",host,port,sfd,nonlocal_src_host().c_str(),nonlocal_src_port());
            int bind_status = namesocket(sfd,nonlocal_src_host(),nonlocal_src_port());
            if (bind_status != 0) {
                DIA_("UDPCom::connect[%s:%s]: socket[%d] transparency for %s:%d failed, cannot bind",host,port,sfd,nonlocal_src_host().c_str(),nonlocal_src_port());
            } else {
                DIA_("UDPCom::connect[%s:%s]: socket[%d] transparency for %s:%d OK",host,port,sfd,nonlocal_src_host().c_str(),nonlocal_src_port());
            }
        }        
        
        udpcom_addr = *rp->ai_addr;
        udpcom_addrlen = rp->ai_addrlen;
        
        ::connect(sfd,&udpcom_addr,udpcom_addrlen);
        
        break;
    }

    
    if(sfd <= 0) {
        ERRS_("UDPCom::connect failed");
    }
    
    if (rp == NULL) {
        ERRS_("UDPCom::Could not connect");
        return -2;
    }

    freeaddrinfo(gai_result);

    udpcom_fd = sfd;
    
    return sfd;
}

void UDPCom::init(baseHostCX* owner)
{
    baseCom::init(owner);
}

bool UDPCom::is_connected(int s) {
    return true;
}



bool UDPCom::resolve_nonlocal_socket(int sock) {

    std::lock_guard<std::mutex> l(DatagramCom::lock);
    
    auto it_record = DatagramCom::datagrams_received.find((unsigned int)sock);
    if(it_record != DatagramCom::datagrams_received.end()) {  
        Datagram& record = (*it_record).second;
        
        DIA_("UDPCom::resolve_nonlocal_socket[%x]: found datagram pool entry",sock);
        

        nonlocal_dst_host() = inet_ntoa(record.dst_in_addr4());
        nonlocal_dst_port() = ntohs(record.dst_port4());
        nonlocal_dst_resolved_ = true;
         
        return true;
    }
    
    DIA_("UDPCom::resolve_nonlocal_socket[%x]: datagram pool entry NOT FOUND",sock);
    return false;
}

bool UDPCom::in_readset(int s) {
    
    std::lock_guard<std::mutex> l(DatagramCom::lock);
    
    auto it_record = DatagramCom::datagrams_received.find((unsigned int)s);
    if(it_record != DatagramCom::datagrams_received.end()) {  
        Datagram& record = (*it_record).second;    
        
        if(record.rx.size() > 0) {
            DIA_("UDPCom::in_readset[%d]: record found, data size %dB",s,record.rx.size());
        }
        
        return (record.rx.size() > 0);
        
    } else {
        EXT_("UDPCom::in_readset[%d]: record NOT found",s);
        if( s > 0) return baseCom::in_readset(s);
    }
    
    return false;
}

bool UDPCom::in_writeset(int s) {
    
    std::lock_guard<std::mutex> l(DatagramCom::lock);

    auto it_record = DatagramCom::datagrams_received.find((unsigned int)s);
    if(it_record != DatagramCom::datagrams_received.end()) {  
        EXT_("UDPCom::in_writeset: found data for %d (thus virtual socket is writable)",s);
        return true;
    } else {
        if( s > 0) return true; //return baseCom::in_writeset(s);
    }
    
    return false;
}

bool UDPCom::in_exset(int s) {
    
    std::lock_guard<std::mutex> l(DatagramCom::lock);
    
    auto it_record = DatagramCom::datagrams_received.find((unsigned int)s);
    if(it_record != DatagramCom::datagrams_received.end()) {  
        return false;
    } 

    return false;
}


int UDPCom::poll() {
    EXTS_("UDPCom::poll: start");
    
    int r = baseCom::poll();
    
    EXTS_("UDPCom::poll: end");
    return r;
}




int UDPCom::read(int __fd, void* __buf, size_t __n, int __flags) {

    if (__fd < 0) {
        return read_from_pool(__fd,__buf,__n,__flags);
    } else {
        return ::recv(__fd,__buf,__n,__flags);
    }
};

int UDPCom::read_from_pool(int __fd, void* __buf, size_t __n, int __flags) {

    std::lock_guard<std::mutex> l(DatagramCom::lock);
    
    auto it_record = DatagramCom::datagrams_received.find((unsigned int)__fd);
    if(it_record != DatagramCom::datagrams_received.end()) {  
        Datagram& record = (*it_record).second;

        if(record.rx.size() == 0) {
//            return ::recv(record.socket,__buf,__n,__flags);
        } else {
        
            int to_copy = __n;
            if(record.rx.size() <= __n) {
                to_copy = record.rx.size();
            }
            
            memcpy(__buf,record.rx.data(),to_copy);

            if(! (__flags & MSG_PEEK)) {
                record.rx.flush(to_copy);
                DIA_("UDPCom::read_from_pool[%x]: retrieved %d bytes from receive pool, in buffer left %d bytes",__fd,to_copy,record.rx.size());
            } else {
                DIA_("UDPCom::read_from_pool[%x]: peek %d bytes from receive pool, in buffer is %d bytes",__fd,to_copy,record.rx.size());
            }

            
            return to_copy;
        }
    } else {
        return 0; // return hard error, terminate
    }
    
    return 0;
}

int UDPCom::write(int __fd, const void* __buf, size_t __n, int __flags)
{
    if(__n <= 0) {
        return 0;
    }
    
    if(__fd < 0) {
        return write_to_pool(__fd,__buf,__n,__flags);
    } else {
        return ::sendto(__fd,__buf,__n,__flags,&udpcom_addr, udpcom_addrlen);
    }
    return -1;
}

int UDPCom::write_to_pool(int __fd, const void* __buf, size_t __n, int __flags) {
    
    std::lock_guard<std::mutex> l(DatagramCom::lock);
    
    auto it_record = DatagramCom::datagrams_received.find((unsigned int)__fd);
    if(it_record != DatagramCom::datagrams_received.end()) {  
        Datagram& record = (*it_record).second;
        
        DIA_("UDPCom::write_to_pool[%d]: about to write %d bytes into socket %d",__fd,__n,record.socket);
        
        msghdr m;
        struct iovec io;
        char cmbuf[128];
        memset(cmbuf,0,sizeof(cmbuf));
        
        io.iov_base = (void*)__buf;
        io.iov_len = __n;
        
        m.msg_iov = &io;
        m.msg_iovlen = 1;
        m.msg_name = (void*)&record.src;
        m.msg_namelen = sizeof(struct sockaddr_in);
        m.msg_control = cmbuf;
        m.msg_controllen = sizeof(cmbuf);            
        
        struct cmsghdr *cmsg;
        struct in_pktinfo *pktinfo;
        cmsg = CMSG_FIRSTHDR(&m);
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        pktinfo = (struct in_pktinfo*) CMSG_DATA(cmsg);
        pktinfo->ipi_spec_dst = record.dst_in_addr4();
        pktinfo->ipi_ifindex = 0;
        m.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

        int l = 0;
        int n = 1;
        int d = socket (AF_INET, SOCK_DGRAM, 0);
        int ret = setsockopt (d, SOL_IP, IP_TRANSPARENT, &n, sizeof(n));
        setsockopt(d, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n));
        setsockopt(d, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n));         
        
        
        // avoid other threads to potentially bind to the same source IP:PORT and fail on that.
        std::recursive_mutex send_lock;
        send_lock.lock();
        
        ret = ::bind (d, (struct sockaddr*)&(record.dst), sizeof (struct sockaddr_in));
        if(ret != 0) {
            ERRS_("UDPCom::write_to_pool[%d]: cannot bind to destination!",__fd);
        } else {
            DIA_("UDPCom::write_to_pool[%d]: custom transparent socket: %d",__fd,d);
            l = ::sendmsg(d,&m,0);
            DIA_("UDPCom::write_to_pool[%d]: socket: %d: written %d bytes",__fd,d,l);
        }
        ::close(d);
        send_lock.unlock();
        
        //l = send(record.socket,__buf,__n,__flags);
        return l;
        
    } else {
        return -1;
    }
}

bool UDPCom::resolve_socket(bool source, int s, std::string* target_host, std::string* target_port, sockaddr_storage* target_storage) {
    
    std::lock_guard<std::mutex> l(DatagramCom::lock);
    
    auto it_record = DatagramCom::datagrams_received.find((unsigned int)s);
    if(it_record != DatagramCom::datagrams_received.end()) {  
        Datagram& record = (*it_record).second;
        
        if(source == true) {
            target_host->assign(inet_ntoa(record.src_in_addr4()));
            target_port->assign(std::to_string(ntohs(record.src_port4())));
        } else {
            target_host->assign(inet_ntoa(record.dst_in_addr4()));
            target_port->assign(std::to_string(ntohs(record.dst_port4())));
        }
        
    } else {
        return baseCom::resolve_socket(source,s,target_host,target_port,target_storage);
    }
    
    return true;
}


void UDPCom::shutdown(int __fd) {
    if(__fd > 0) {
        int r = ::shutdown(__fd,SHUT_RDWR);
        if(r > 0) DIA_("UDPCom::close[%d]: %s",__fd,string_error().c_str());
    } else {
        
        std::lock_guard<std::mutex> l(DatagramCom::lock);
        
        auto it_record = DatagramCom::datagrams_received.find((unsigned int)__fd);
        if(it_record != DatagramCom::datagrams_received.end()) {  
                Datagram& it = DatagramCom::datagrams_received[(unsigned int)__fd];
                
                if(! it.reuse) {
                    DIA_("UDPCom::close[%d]: datagrams_received entry erased",__fd);
                    DatagramCom::datagrams_received.erase((unsigned int)__fd);
                } else {
                    DIA_("UDPCom::close[%d]: datagrams_received entry reuse flag set, entry  not deleted.",__fd);
                    it.reuse = false;
                }
                
        } else {
            DIA_("UDPCom::close[%d]: datagrams_received entry NOT found, thus not erased",__fd);
        }
    }
}
