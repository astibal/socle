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
#include <internet.hpp>
#include <linux/in6.h>


std::map<uint64_t,Datagram> DatagramCom::datagrams_received;
std::mutex DatagramCom::lock;

std::map<std::string,int> UDPCom::connect_fd_cache;
std::mutex UDPCom::connect_fd_cache_lock;


int UDPCom::accept(int sockfd, sockaddr* addr, socklen_t* addrlen_) {
    return sockfd;
}

int UDPCom::bind(short unsigned int port) {
    int s;
    sockaddr_storage sa;

    sa.ss_family = bind_sock_family;
    //sa.ss_family = AF_INET;
    
    if(sa.ss_family == AF_INET) {
        inet::to_sockaddr_in(&sa)->sin_port = htons(port);
        inet::to_sockaddr_in(&sa)->sin_addr.s_addr = INADDR_ANY;
    }
    else
    if(sa.ss_family == AF_INET6) {
        inet::to_sockaddr_in6(&sa)->sin6_port = htons(port);
        inet::to_sockaddr_in6(&sa)->sin6_addr = in6addr_any;
    }

    if ((s = socket(sa.ss_family, bind_sock_type, bind_sock_protocol)) == -1) return -129;
    
    int optval = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
    
    optval = 1;
    
    if(nonlocal_dst_) {
        // allows socket to accept connections for non-local IPs
        DIA_("UDPCom::bind[%d]: setting it transparent",s);
        setsockopt(s, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval));
        setsockopt(s, SOL_IPV6, IPV6_TRANSPARENT, &optval, sizeof(optval));
    }

    optval = 1;
//     setsockopt(s, IPPROTO_IP,IP_RECVORIGDSTADDR, &optval, sizeof optval);
    if (setsockopt(s, SOL_IP,IP_RECVORIGDSTADDR, &optval, sizeof optval) != 0) return -131;
    if (setsockopt(s, SOL_IPV6,IPV6_RECVORIGDSTADDR, &optval, sizeof optval) != 0) return -132;
    
    if (::bind(s, (sockaddr *)&sa, sizeof(sa)) == -1) return -130;

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
    hints.ai_family = l3_proto();    /* Allow IPv4 or IPv6 */
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
        
        //sfd = socket(AF_INET6, SOCK_DGRAM, 0);

        //if (DDEB(110)) 
        DEBS_("UDPCom::connect: gai info found");
        
        if (sfd == -1) {
            DEBS_("UDPCom::connect: failed to create socket");
            continue;
        }

        int optval = 1;
        
        if(l3_proto() == AF_INET)
        if(setsockopt(sfd, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval)) != 0) {
            WAR_("UDPCom::connect[%d]: cannot set IPv4 transparency sockopt: %s",sfd,string_error().c_str());
        }
        if(l3_proto() == AF_INET6)
        if(setsockopt(sfd, SOL_IPV6, IPV6_TRANSPARENT, &optval, sizeof(optval)) != 0) {
            WAR_("UDPCom::connect[%d]: cannot set IPv6 transparency sockopt: %s",sfd,string_error().c_str());
        }        
        
        if(nonlocal_src()) {
            
            const int bind_count_max = 20;
            int bind_count = bind_count_max;
            bind_again:
            
            DIA_("UDPCom::connect[%s:%s]: About to name socket[%d] after: %s:%d",host,port,sfd,nonlocal_src_host().c_str(),nonlocal_src_port());
            
            int bind_status = namesocket(sfd,nonlocal_src_host(),nonlocal_src_port(),l3_proto());
            
            std::string connect_cache_key = string_format("%s:%d-%s:%s",nonlocal_src_host().c_str(),nonlocal_src_port(),host,port);
            if (bind_status != 0) {
                bind_count--;
                ERR_("UDPCom::connect[%s:%s]: socket[%d] transparency for %s/%s:%d failed, cannot bind",host,port,
                                                    sfd,
                                                        inet_family_str(l3_proto()).c_str(),nonlocal_src_host().c_str(),nonlocal_src_port());
                
                if(bind_count > 0) {
                    //goto bind_again;
                    
                    connect_fd_cache_lock.lock();
                    auto it_fd = connect_fd_cache.find(connect_cache_key);
                    
                    if(it_fd != connect_fd_cache.end()) {
                        int cached_fd = it_fd->second;
                        INF_("UDPCom::connect[%s:%s]: socket[%d] transparency for %s failed, but found fd %d in connect cache.",host,port,sfd,connect_cache_key.c_str(),cached_fd);
                        ::close(sfd);
                        sfd = cached_fd;
                    } else {
                        INF_("UDPCom::connect[%s:%s]: socket[%d] transparency for %s failed and not cached.",host,port,sfd, connect_cache_key.c_str());
                    }
                    
                    connect_fd_cache_lock.unlock();
                }
            } else {
                
                connect_fd_cache_lock.lock();
                connect_fd_cache[connect_cache_key] = sfd;
                connect_fd_cache_lock.unlock();
                
                if(bind_count != bind_count_max) {
                    NOT_("UDPCom::connect[%s:%s]: socket[%d] transparency for %s:%d OK (attempt %d)",host,port,sfd,nonlocal_src_host().c_str(),nonlocal_src_port(),bind_count_max-bind_count);
                } else {
                    DIA_("UDPCom::connect[%s:%s]: socket[%d] transparency for %s:%d OK",host,port,sfd,nonlocal_src_host().c_str(),nonlocal_src_port());
                }
            }
        }        
        
        //udpcom_addr =    rp->ai_addr;
        //udpcom_addrlen = rp->ai_addrlen;
        udpcom_addrlen = rp->ai_addrlen;
        ::memcpy(&udpcom_addr,rp->ai_addr,udpcom_addrlen);
        
        std::string rps; unsigned short port;
        int fa = inet_ss_address_unpack(((sockaddr_storage*)&udpcom_addr),&rps,&port);
        DEB_("connect[%d]: rp contains: %s/%s:%d", sfd, inet_family_str(fa).c_str(),rps.c_str(),port );
        
        ::connect(sfd,(sockaddr*)&udpcom_addr,sizeof(sockaddr));
        
//         sockaddr_storage sa;
//         inet::to_sockaddr_in6(&sa)->sin6_port = htons(std::atoi(port));
//         inet_pton(l3_proto(),host,&inet::to_sockaddr_in6(&sa)->sin6_addr);
        
        //::connect(sfd,&udpcom_addr,udpcom_addrlen);
        
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
        char b[64]; memset(b,0,64);
        
        DIA_("UDPCom::resolve_nonlocal_socket[%x]: found datagram pool entry",sock);
        
        if(record.dst_family() == AF_INET || record.dst_family() == 0) {
            inet_ntop(AF_INET, &record.dst_in_addr4(), b, 64);
            nonlocal_dst_host().assign(b);
            nonlocal_dst_port() = ntohs(record.dst_port4());
            
            l3_proto(AF_INET);
        }
        else if(record.dst_family() == AF_INET6) {
            inet_ntop(AF_INET6, &record.dst_in_addr6(), b, 64);
            
            std::string mapped4_temp = b;
            if(mapped4_temp.find("::ffff:") == 0) {
                DEBS_("udpCom::resolve_socket: mapped IPv4 detected, removing mapping prefix");
                mapped4_temp = mapped4_temp.substr(7);
                
                l3_proto(AF_INET);
            }                
            
            nonlocal_dst_host().assign(mapped4_temp);
            nonlocal_dst_port() = ntohs(record.dst_port6());
        }
        

//         nonlocal_dst_host() = inet_ntoa(record.dst_in_addr4());
//         nonlocal_dst_port() = ntohs(record.dst_port4());
        nonlocal_dst_resolved_ = true;
         
        return true;
    }
    
    if(sock > 0) {
        resolve_socket_src(sock, nullptr, nullptr, nullptr);
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
        
        
        std::string rps;
        unsigned short port;
        int fa = inet_ss_address_unpack(((sockaddr_storage*)&udpcom_addr),&rps, &port);
        
        int ret =  ::sendto(__fd,__buf,__n,__flags, &udpcom_addr, sizeof(sockaddr_storage));
        DEB_("write[%d]: sendto %s/%s:%d returned %d", __fd,inet_family_str(fa).c_str(),rps.c_str(), port, ret);
        
        if(ret < 0) {
            ERR_("write[%d]: sendto %s/%s:%d returned %d: %s", __fd,inet_family_str(fa).c_str(),rps.c_str(), port, ret, string_error().c_str());
        }
        
        return ret;
        //return ::send(__fd,__buf, __n, __flags);
    }
    return -1;
}

int UDPCom::write_to_pool(int __fd, const void* __buf, size_t __n, int __flags) {
    
    std::lock_guard<std::mutex> l(DatagramCom::lock);
    
    auto it_record = DatagramCom::datagrams_received.find((unsigned int)__fd);
    if(it_record != DatagramCom::datagrams_received.end()) {  
        Datagram& record = (*it_record).second;
        
        std::string ip_src, ip_dst;
        unsigned short port_src, port_dst;
        inet_ss_address_unpack(&record.src,&ip_src,&port_src);
        sockaddr_storage record_src_4fix;
        
        inet_ss_address_unpack(&record.dst,&ip_dst,&port_dst);
        std::string af_src = inet_family_str(record.src_family());
        std::string af_dst = inet_family_str(record.dst_family());
        
        DIA_("UDPCom::write_to_pool[%d]: about to write %d bytes into socket %d",__fd,__n,record.socket);
        DEB_("UDPCom::write_to_pool[%d]: %s:%s:%d - %s:%s:%d",__fd,
                                         af_src.c_str(),ip_src.c_str(), port_src,
                                                            af_dst.c_str(),ip_dst.c_str(), port_dst
            );


        int d = 0; // socket will be created later
        
        msghdr m;
        struct iovec io;
        char cmbuf[128];
        memset(cmbuf,0,sizeof(cmbuf));
        
        io.iov_base = (void*)__buf;
        io.iov_len = __n;
        
        m.msg_iov = &io;
        m.msg_iovlen = 1;
        m.msg_name = (void*)&record.src;
        m.msg_namelen = sizeof(struct sockaddr_storage);
        m.msg_control = cmbuf;
        m.msg_controllen = sizeof(cmbuf);            
        
        struct cmsghdr *cmsg;
        struct in_pktinfo *pktinfo;
        struct in6_pktinfo *pktinfo6;
        
        cmsg = CMSG_FIRSTHDR(&m);
        cmsg->cmsg_type = IP_PKTINFO;
        
        //IPV4
        if(record.dst_family() == AF_INET) {

            
            DEBS_("Constucting IPv4 pktinfo");
            
            if(record.src_family() == AF_INET6) {
                DEBS_("reconstructing mapped IPv4 src address record");
                record_src_4fix.ss_family = AF_INET;
                inet_pton(AF_INET,ip_src.c_str(), &((sockaddr_in*)&record_src_4fix)->sin_addr);
                ((sockaddr_in*)&record_src_4fix)->sin_port = record.src_port6();
                m.msg_name = (void*)&record_src_4fix;
            }
            
            cmsg->cmsg_level = IPPROTO_IP;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            pktinfo = (struct in_pktinfo*) CMSG_DATA(cmsg);
            pktinfo->ipi_spec_dst = record.dst_in_addr4();
            pktinfo->ipi_ifindex = 0;
            m.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
            
            
            d = socket (record.dst_family(), SOCK_DGRAM, 0);
            
            int n = 1;
            setsockopt(d, SOL_IP, IP_TRANSPARENT, &n, sizeof(n));
            setsockopt(d, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n));
            setsockopt(d, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n));         
            
        }
        else if(record.dst_family() == AF_INET6){
            
            DEBS_("Constucting IPv6 pktinfo");
            
            cmsg->cmsg_level = IPPROTO_IPV6;
            cmsg->cmsg_type = IPV6_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
            pktinfo6 = (struct in6_pktinfo*) CMSG_DATA(cmsg);
            pktinfo6->ipi6_addr = record.dst_in_addr6();
            pktinfo6->ipi6_ifindex = 0;
            m.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
            
            d = socket (record.dst_family(), SOCK_DGRAM, 0);
            
            int n = 1;
            setsockopt(d, SOL_IPV6, IPV6_TRANSPARENT, &n, sizeof(n));
            setsockopt(d, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n));
            setsockopt(d, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n));         
        }


        // avoid other threads to potentially bind to the same source IP:PORT and fail on that.
        std::recursive_mutex send_lock;
        send_lock.lock();
        
        int l = 0;
        int ret = ::bind (d, (struct sockaddr*)&(record.dst), sizeof (struct sockaddr_storage));
        if(ret != 0) {
            ERRS_("UDPCom::write_to_pool[%d]: cannot bind to destination!",__fd);
        } else {
            DEB_("UDPCom::write_to_pool[%d]: about to write %d bytes into socket %d",__fd,__n,record.socket);
            DEB_("UDPCom::write_to_pool[%d]: custom transparent socket: %d",__fd,d);
            l = ::sendmsg(d,&m,0);
            
            if(l < 0) {
                ERR_("UDPCom::write_to_pool[%d]: socket: %d: written %d bytes",__fd,d,l);
            } else {
                DEB_("UDPCom::write_to_pool[%d]: socket: %d: written %d bytes",__fd,d,l);
            }
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
        
        char b[64]; memset(b,0,64);
        
        DEBS_("UDPCom::resolve_socket: found in datagrams");
        
        if(source == true) {
            
            if(record.src_family() == AF_INET || record.src_family() == 0) {
                inet_ntop(AF_INET, &record.src_in_addr4(), b, 64);
                l3_proto(AF_INET);

                if(target_host) target_host->assign(b);
                if(target_port) target_port->assign(std::to_string(ntohs(record.src_port4())));
            }
            else if(record.src_family() == AF_INET6) {
                inet_ntop(AF_INET6, &record.src_in_addr6(), b, 64);
                l3_proto(AF_INET6);
                
                std::string mapped4_temp = b;
                if(mapped4_temp.find("::ffff:") == 0) {
                    l3_proto(AF_INET);
                    
                    DEBS_("udpCom::resolve_socket: mapped IPv4 detected, removing mapping prefix");
                    mapped4_temp = mapped4_temp.substr(7);
                }                
                
                if(target_host) target_host->assign(mapped4_temp);
                if(target_port) target_port->assign(std::to_string(ntohs(record.src_port6())));
            }
            
        } else {
            
            if(record.dst_family() == AF_INET || record.dst_family() == 0) {
                inet_ntop(AF_INET, &record.dst_in_addr4(), b, 64);
                l3_proto(AF_INET);
                
                if(target_host) target_host->assign(b);
                if(target_port) target_port->assign(std::to_string(ntohs(record.dst_port4())));
                
            }
            else if(record.dst_family() == AF_INET6) {
                inet_ntop(AF_INET6, &record.dst_in_addr6(), b, 64);
                l3_proto(AF_INET6);
                
                std::string mapped4_temp = b;
                if(mapped4_temp.find("::ffff:") == 0) {
                    l3_proto(AF_INET);
                    
                    DEBS_("udpCom::resolve_socket: mapped IPv4 detected, removing mapping prefix");
                    mapped4_temp = mapped4_temp.substr(7);
                    
                }                
                
                if(target_host) target_host->assign(mapped4_temp);
                if(target_port) target_port->assign(std::to_string(ntohs(record.dst_port6())));
            }
        }
        
    } else {
        return baseCom::resolve_socket(source,s,target_host,target_port,target_storage);
    }
    
    return true;
}


void UDPCom::shutdown(int __fd) {
    if(__fd > 0) {
        std::string sip, sport;
        std::string dip, dport;
        
        // it's oposite in this case, so following is CORRECT
        
        if(resolve_socket_dst(__fd,&sip,&sport) && resolve_socket_src(__fd,&dip,&dport)) {
        
            std::string key = string_format("%s:%s-%s:%s", sip.c_str(), sport.c_str(),dip.c_str(), dport.c_str());

            INF_("UDPCom::shutdown[%d]: removing connect cache %s",__fd,key.c_str());
            connect_fd_cache_lock.lock();
            int count = connect_fd_cache.erase(key);
            connect_fd_cache_lock.unlock();

            INF_("UDPCom::shutdown[%d]: %d removed",__fd,count);
        }
        
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
