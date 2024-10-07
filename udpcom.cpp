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
#include <socketinfo.hpp>
#include <internet.hpp>
#include <linux/in6.h>

#include <vars.hpp>

using namespace socle;


UDPCom::UDPCom(): baseCom(), connections(*this) {
    l4_proto(SOCK_DGRAM);
    bind_sock_family = default_sock_family;

    datagram_com_ = datagram_com_static();
};


std::shared_ptr<DatagramCom> UDPCom::datagram_com_static() {

    if(not datagram_com_static_) {
        static std::mutex only_one;
        auto lc_ = std::scoped_lock(only_one);

        // guard threads who entered this branch
        if(not datagram_com_static_)
            datagram_com_static_ = std::make_shared<DatagramCom>();
    }
    return datagram_com_static_;
}

inline std::shared_ptr<DatagramCom> UDPCom::datagram_com() const {
    if( not datagram_com_) datagram_com_ = datagram_com_static();
    return datagram_com_;
}

int UDPCom::translate_socket(int vsock) const {
    
    if(vsock >= 0) { 
        _dia("UDPCom::translate_socket[%d]: non-virtual",vsock);
        return vsock; 
        
    } else {
        
        
        auto lc = std::scoped_lock(datagram_com()->lock);
        
        auto it_dgram = datagram_com()->datagrams_received.find((unsigned int)vsock);
        if(it_dgram != datagram_com()->datagrams_received.end())  {
            auto d = it_dgram->second;
            
            _dia("UDPCom::translate_socket[%d]: found in table",vsock);
            if(d->socket_left.has_value()) {
                _dia("UDPCom::translate_socket[%d]: translated to real %d", vsock, d->socket_left.value_or(-1));
                return d->socket_left.value();
            }
            else {
                _dia("UDPCom::translate_socket[%d]: no value entry, using virtual socket", vsock);
            }
            // real socket is here bound/connected socket back to source IP.
            // if there is no backward socket, we don't want return TPROXY bound socket, since it can't 
            // send anything. So resist temptation to return d.socket in else statement.
        }
    }

    _dia("UDPCom::translate_socket[%d]: NOT found in table", vsock);
    return baseCom::translate_socket(vsock);
}


int UDPCom::accept(int sockfd, sockaddr* addr, socklen_t* addrlen_) {
    return sockfd;
}

int UDPCom::bind(short unsigned int port) {
    int new_socket;
    sockaddr_storage sa {};

    sa.ss_family = bind_sock_family;
    //sa.ss_family = AF_INET;
    
    if(sa.ss_family == AF_INET) {
        inet::to_sockaddr_in(&sa)->sin_port = htons(port);
        inet::to_sockaddr_in(&sa)->sin_addr.s_addr = INADDR_ANY;
    }
    else if(sa.ss_family == AF_INET6) {
        inet::to_sockaddr_in6(&sa)->sin6_port = htons(port);
        inet::to_sockaddr_in6(&sa)->sin6_addr = in6addr_any;
    }

    if ((new_socket = ::socket(sa.ss_family, bind_sock_type, bind_sock_protocol)) == -1)
        return -129;

    so_reuseaddr(new_socket);
    so_broadcast(new_socket);
    
    // NOTE: by default is family AF_INET6, which will work for AF_INET too.
    // Bound sockets must be therefore set for all, IPv4 and IPv6 transparency.

    if(sa.ss_family == AF_INET or sa.ss_family == AF_INET6 or sa.ss_family == AF_UNSPEC) {
        if(nonlocal_dst_) {
            _dia("UDPCom::bind[%d]: setting socket transparent (IPv4)", new_socket);
            so_transparent_v4(new_socket);
        }

        if(so_recvorigdstaddr_v4(new_socket) != 0) {
            ::close(new_socket);
            return -131;
        }
    }
    if(sa.ss_family == AF_INET6) {
        if(nonlocal_dst_) {
            _dia("UDPCom::bind[%d]: setting socket transparent (IPv6)", new_socket);
            so_transparent_v6(new_socket);
        }

        if(so_recvorigdstaddr_v6(new_socket) != 0) {
            ::close(new_socket);
            return -132;
        }
    }
    
    if (::bind(new_socket, (sockaddr *)&sa, sizeof(sa)) == -1) {
        ::close(new_socket);  // coverity: 1408014
        return -130;
    }

    
    _dia("UDPCom::bind[%d]: successful", new_socket);
    return new_socket;
}


int UDPCom::connect(const char* host, const char* port) {

    auto use_cached_connection = [this](std::string const& cache_key) -> std::optional<int> {
        std::scoped_lock<std::recursive_mutex> l(connections.lock);
        auto it_fd = connections.cache.find(cache_key);

        if (it_fd != connections.cache.end()) {
            std::pair<int, int> &cached_fd_ref = it_fd->second;


            int cached_fd = cached_fd_ref.first;
            cached_fd_ref.second++;

            _dia("UDPCom::connect[%s]: found socket %d in connect cache (refcount %d).", cache_key.c_str(), cached_fd,
                 cache_key.c_str(), cached_fd, cached_fd_ref.second);

            // reuse already opened socket
            connections.my_key = cache_key;

            return std::make_optional<int>(cached_fd);
        }
        return std::nullopt;
    };

    struct addrinfo hints {};
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
        _deb("getaddrinfo: %s",gai_strerror(gai));
        return -2;
    }

    /* getaddrinfo() returns a list of address structures.
    Try each address until we successfully connect(2).
    If socket(2) (or connect(2)) fails, we (close the socket
    and) try the next address. */

    for (rp = gai_result; rp != nullptr; rp = rp->ai_next) {


        _deb("UDPCom::connect: gai info found");

        bool from_cache = false;
        std::string connect_cache_key_cur;


        try {
            if (nonlocal_src()) {

                connect_cache_key_cur = connections.gen_cache_key(host, port).value_or("");

                auto c_sfd = use_cached_connection(connect_cache_key_cur);
                if (c_sfd.has_value()) {
                    sfd = c_sfd.value_or(-1);
                    from_cache = true;

                    _dia("UDPCom::connect[%s:%s]: socket[%d] from cache (key: %s)",host,port,sfd, connect_cache_key_cur.c_str());

                } else {

                    sfd = SockOps::socket_create(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

                    if (so_transparent(sfd) != 0) {
                        _err("UDPCom::connect[%s:%s]: nonlocal socket[%d] transparency failed", host, port, sfd);
                        ::close(sfd);
                        sfd = -1;
                        continue;
                    } else {
                        _dia("UDPCom::connect[%s:%s]: socket[%d] transparency for %s:%d OK", host, port, sfd,
                             nonlocal_src_host().c_str(), nonlocal_src_port());
                    }

                    _dia("UDPCom::connect[%s:%s]: About to name socket[%d] after: %s:%d", host, port, sfd,
                         nonlocal_src_host().c_str(), nonlocal_src_port());

                    int bind_status = namesocket(sfd, nonlocal_src_host(), nonlocal_src_port(), l3_proto());
                    if (bind_status != 0) {
                        ::close(sfd);
                        sfd = -1;

                        _err("UDPCom::connect[%s:%s]: socket[%d] transparency for %s/%s:%d failed, cannot bind, not cached.",
                             host, port,
                             sfd,
                             SockOps::family_str(l3_proto()).c_str(), nonlocal_src_host().c_str(),
                             nonlocal_src_port());
                        continue;
                    }
                }

            } else {
                sfd = SockOps::socket_create(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            }
        }
        catch(socket_info_error const& e) {
            if(sfd >= 0) ::close(sfd);
            sfd = -1;

            _err("UDPCom::connect[%s:%s]: error: %s", host, port, e.what());
            continue;
        }
        
        udpcom_addrlen = rp->ai_addrlen;
        ::memcpy(&udpcom_addr,rp->ai_addr,udpcom_addrlen);
        
        if(not from_cache) {
            std::string rps;
            unsigned short rp_port;

            int fa = SockOps::ss_address_unpack(((sockaddr_storage *) &udpcom_addr), &rps, &rp_port);

            int con_ret = 0;
            if(l3_proto() != AF_INET6) {
                con_ret = ::connect(sfd, (sockaddr *) &udpcom_addr, sizeof(sockaddr));
            } else {
                _dia("connect[%d]: not attempted to %s/%s:%d", sfd, SockOps::family_str(fa).c_str(),
                     rps.c_str(), rp_port);
            }


            if (con_ret != 0) {
                _err("connect[%d]: failed to %s/%s:%d : %s ", sfd, SockOps::family_str(fa).c_str(),
                     rps.c_str(), rp_port,
                     string_error().c_str());

                ::close(sfd);
                sfd = -1;
                continue;

            } else {
                // connect OK
                std::scoped_lock<std::recursive_mutex> l(connections.lock);
                connections.cache[connect_cache_key_cur] = std::pair<int, int>(sfd, 1);
                connections.my_key = connect_cache_key_cur;

                _dia("UDPCom::connect[%s:%s]: socket[%d] connection %s:%d OK", host, port, sfd,
                     nonlocal_src_host().c_str(), nonlocal_src_port());

            }
        }


        if(! GLOBAL_IO_BLOCKING() ) {
            unblock(sfd);
        }

        break;
    }

    freeaddrinfo(gai_result);
    
    if(sfd <= 0) {
        _err("UDPCom::all connect attempts failed");
    }
    
    if (rp == nullptr) {
        _err("UDPCom::Could not connect");
        return -2;
    }

    
    return socket(sfd);
}

void UDPCom::init(baseHostCX* owner)
{
    baseCom::init(owner);
}

bool UDPCom::is_connected(int s) {
    return true;
}



bool UDPCom::resolve_nonlocal_socket(int sock) {

    std::lock_guard<std::recursive_mutex> l(datagram_com()->lock);
    
    auto it_record = datagram_com()->datagrams_received.find((unsigned int)sock);
    if(it_record != datagram_com()->datagrams_received.end()) {
        auto record = (*it_record).second;
        char b[64]; memset(b,0,64);
        
        _dia("UDPCom::resolve_nonlocal_socket[%x]: found datagram pool entry",sock);
        
        if(record->dst_family() == AF_INET || record->dst_family() == 0) {
            inet_ntop(AF_INET, &record->dst_in_addr4(), b, 64);
            nonlocal_dst_host().assign(b);
            nonlocal_dst_port() = ntohs(record->dst_port4());
            
            l3_proto(AF_INET);
        }
        else if(record->dst_family() == AF_INET6) {
            inet_ntop(AF_INET6, &record->dst_in_addr6(), b, 64);
            
            std::string mapped4_temp = b;
            if(mapped4_temp.find("::ffff:") == 0) {
                _deb("udpCom::resolve_socket: mapped IPv4 detected, removing mapping prefix");
                mapped4_temp = mapped4_temp.substr(7);
                
                l3_proto(AF_INET);
            }                
            
            nonlocal_dst_host().assign(mapped4_temp);
            nonlocal_dst_port() = ntohs(record->dst_port6());
        }
        

//         nonlocal_dst_host() = inet_ntoa(record->dst_in_addr4());
//         nonlocal_dst_port() = ntohs(record->dst_port4());
        nonlocal_dst_resolved_ = true;
         
        return true;
    }
    
    if(sock > 0) {
        resolve_socket_src(sock, nullptr, nullptr, nullptr);
    }
    
    _dia("UDPCom::resolve_nonlocal_socket[%x]: datagram pool entry NOT FOUND",sock);
    return false;
}

bool UDPCom::in_readset(int s) {

    if(s < 0) {

        std::lock_guard<std::recursive_mutex> l(datagram_com()->lock);

        auto it_record = datagram_com()->datagrams_received.find((unsigned int) s);
        if (it_record != datagram_com()->datagrams_received.end()) {
            auto record = (*it_record).second;

            if (record->socket_left.has_value()) {
                _deb("UDPCom::in_readset[%d]: fyi - record contains real socket %d", s, record->socket_left.value());
            } else {
                _war("UDPCom::in_readset[%d]: fyi - no real socket", s);
            }

            // even though record contains real socket, we will always return true as long as there are pending early data
            {
                auto l_ = std::scoped_lock(record->rx_queue_lock);

                int elem = 0;
                int elem_bytes = 0;
                for (auto const &r: record->rx_queue) {
                    if (!r.empty()) {
                        elem_bytes += r.size();
                        _deb("UDPCom::in_readset[%d]: record found, data size %dB at pos #%d", s, r.size(), elem);
                    }
                }

                bool ret = (elem_bytes > 0);
                if (ret) {
                    _deb("UDPCom::in_readset[%d]: returning %d, because entry contains %dB of embryonic data", s, ret,
                         elem_bytes);
                    return ret;
                } else {
                    if(record->socket_left.has_value()) {
                        int real_ret = baseCom::in_readset(record->socket_left.value());
                        _deb("UDPCom::in_readset[%d]: no embryonic data, real socket %d check - returning %d", s,
                             record->socket_left,
                             real_ret);

                        return real_ret;
                    }
                    else {
                        _deb("UDPCom::in_readset[%d]: no embryonic data, real socket %d invalid, returning 0", s, record->socket_left);
                        return false;
                    }
                }
            }
        } else {
            _deb("UDPCom::in_readset[%d]: record not found, returning 0", s);
            return false;
        }
    } else if (s > 0) {
        bool r = baseCom::in_readset(s);
        _deb("UDPCom::in_readset[%d]: real socket, returning %d", s, r);
        return r;

    } else {
        _err("calling in_readset(0), returning 0");
        return false;
    }
}

bool UDPCom::in_writeset(int s) {
    
    std::lock_guard<std::recursive_mutex> l(datagram_com()->lock);

    auto it_record = datagram_com()->datagrams_received.find((unsigned int)s);
    if(it_record != datagram_com()->datagrams_received.end()) {
        _ext("UDPCom::in_writeset: found data for %d (thus virtual socket is writable)",s);
        return true;
    } else {
        if( s > 0) return true; //return baseCom::in_writeset(s);
    }
    
    return false;
}

bool UDPCom::in_exset(int s) {
    
    std::lock_guard<std::recursive_mutex> l(datagram_com()->lock);
    
    auto it_record = datagram_com()->datagrams_received.find((unsigned int)s);
    if(it_record != datagram_com()->datagrams_received.end()) {
        return false;
    } 

    return false;
}


int UDPCom::poll() {
    _ext("UDPCom::poll: start");
    
    int r = baseCom::poll();
    
    _ext("UDPCom::poll: end");
    return r;
}




ssize_t UDPCom::read(int _fd, void* _buf, size_t _n, int _flags) {

    _deb("UDPCom::read[%d] read", _fd);


    if(embryonics().id != 0 && !embryonics().pool_depleted) {

        _deb("embryonic: reading from pool");

        auto  r = read_from_pool(embryonics().id, _buf, _n, _flags);

        if(! in_readset(embryonics().id)) {
            datagram_com()->in_virt_set.erase(embryonics().id);
            embryonics().pool_depleted = true;
        }

        return r;
    }

    if (_fd < 0) {
        return read_from_pool(_fd, _buf, _n, _flags);
    } else {
        return recv(_fd, _buf, _n, _flags);
    }
}

int UDPCom::read_from_pool(int _fd, void* _buf, size_t _n, int _flags) {

    auto lc_ =  std::scoped_lock(datagram_com()->lock);
    
    auto it_record = datagram_com()->datagrams_received.find((unsigned int)_fd);
    if(it_record != datagram_com()->datagrams_received.end()) {
        auto record = (*it_record).second;

        if(record->socket_left.has_value() && record->queue_bytes() == 0) {
            _dia("UDPCom::read_from_pool[%d]: pool empty, reading  from real socket %d", _fd, record->socket_left.value());
            return recv(record->socket_left.value(), _buf, _n, _flags);
        }
        
        auto dl_ = std::scoped_lock(record->rx_queue_lock);
        
        if(! record->empty()) {


            int copied = 0;

            int elem_index = -1;
            for(auto& queue_elem : record->rx_queue) {
                elem_index++;

                _dia("UDPCom::read_from_pool[%d]: pool entry %d", _fd, elem_index);

                int elem_size = queue_elem.size();
                if(elem_size <= 0) continue;

                int to_copy = std::min<int>(_n, elem_size);

                memcpy(_buf, queue_elem.data(), to_copy);
                copied += to_copy;

                //_cons(string_format("read_from_pool: copying %dB from buffer of size %d", to_copy, elem_size).c_str());

                if(! (_flags & MSG_PEEK)) {

                    queue_elem.flush(to_copy);
                    _dia("UDPCom::read_from_pool[%d]: retrieved %d bytes from receive pool, in buffer left %d bytes", _fd, copied, queue_elem.size());

                    if(copied >= elem_size) {

                        int rem_count = 0;
                        {
                            auto ul_ = std::scoped_lock(datagram_com()->lock);
                            rem_count = datagram_com()->in_virt_set.erase(_fd);
                        }

                        if(rem_count > 0) {
                            _dia("buffer read to zero, erased %d entries in in_virt_set", rem_count);
                        }
                    }

                } else {
                    _dia("UDPCom::read_from_pool[%x]: peek %d bytes from receive pool, in buffer is %d bytes", _fd, copied, queue_elem.size());
                }

                // perform only one read to 'packetized' behaviour
                break;
            }

            // because we did not necessarily traverse all entries, we need to make sure there is nothing left
            // if more data, we *must* add it back to in_set - expect timeouts and delays otherwise.

            int bytes_left = 0;
            [[maybe_unused]] int elems_left = 0;
            for(auto& queue_elem : record->rx_queue) {
                if(! queue_elem.empty()) {
                    bytes_left += queue_elem.size();
                    elems_left++;
                }
            }

            // keeping for debug
            //_cons(string_format("read_from_pool: %dB in %d entries has been left behind", bytes_left, elems_left).c_str());
            if(bytes_left > 0) {

                //_cons(string_format("adding %d to inset", _fd).c_str());
                auto ul_ = std::scoped_lock(datagram_com()->lock);
                datagram_com()->in_virt_set.insert(_fd);
            }


            return copied;
        }
    } else {
        return 0; // return hard error, terminate
    }
    
    return 0;
}

ssize_t UDPCom::write(int _fd, const void* _buf, size_t _n, int _flags)
{
    if(_n <= 0) {
        return 0;
    }
    
    if(_fd < 0) {
        return write_to_pool(_fd, _buf, _n, _flags);
    } else {

        std::string rps;
        unsigned short port;
        int fa = SockOps::ss_address_unpack(&udpcom_addr, &rps, &port);
        
        ssize_t ret =  ::sendto(_fd, _buf, _n, _flags, (sockaddr*)&udpcom_addr, sizeof(sockaddr_storage));
        _deb("write[%d]: sendto %s/%s:%d returned %d", _fd, SockOps::family_str(fa).c_str(), rps.c_str(), port, ret);
        
        if(ret < 0) {
            _err("write[%d]: sendto %s/%s:%d returned %d: %s", _fd, SockOps::family_str(fa).c_str(), rps.c_str(), port, ret, string_error().c_str());
        }
        
        return ret;
    }
    return -1;
}

ssize_t UDPCom::write_to_pool(int _fd, const void* _buf, size_t _n, int _flags) {
    
    auto lc_ = std::scoped_lock(datagram_com()->lock);
    
    auto it_record = datagram_com()->datagrams_received.find((unsigned int)_fd);
    if(it_record != datagram_com()->datagrams_received.end()) {
        auto record = (*it_record).second;


        if(record->socket_left.has_value()) {
            _dia("UDPCom::write_to_pool[%d]: about to write %d bytes into real socket %d", _fd, _n, record->socket_left.value());
            ssize_t l = ::send(record->socket_left.value(), _buf, _n, 0);

            //_deb("UDPCom::write_to_pool[%d]: %d written to socket %d", _fd , l, record->socket_left.value());

            if(l < 0) {
                _dia("UDPCom::write_to_pool[%d]: real socket %d, %d bytes to send - error %s", _fd, record->socket_left.value(), _n, string_error().c_str());
            }

            return l;
        } else {
            _dia("UDPCom::write_to_pool[%d]: no real socket", _fd);
        }


        std::string ip_src;
        std::string ip_dst;
        unsigned short port_src;
        unsigned short port_dst;

        SockOps::ss_address_unpack(&record->src, &ip_src, &port_src);
        
        sockaddr_storage record_src_4fix{};

        SockOps::ss_address_unpack(&record->dst, &ip_dst, &port_dst);
        std::string af_src = SockOps::family_str(record->src_family());
        std::string af_dst = SockOps::family_str(record->dst_family());

        if(record->socket_left.has_value()) {
            _dia("UDPCom::write_to_pool[%d]: about to write %d bytes into socket %d", _fd, _n, record->socket_left.value());
        }
        _deb("UDPCom::write_to_pool[%d]: %s:%s:%d - %s:%s:%d", _fd,
             af_src.c_str(), ip_src.c_str(), port_src,
             af_dst.c_str(), ip_dst.c_str(), port_dst
            );


        int da_socket = 0; // socket will be created later
        
        msghdr message_header {};
        struct iovec io {};
        char cmbuf[128];
        memset(cmbuf, 0, sizeof(cmbuf));
        
        io.iov_base = const_cast<void*>(_buf);
        io.iov_len = _n;

        message_header.msg_iov = &io;
        message_header.msg_iovlen = 1;
        message_header.msg_name = (void*)&record->src;
        message_header.msg_namelen = sizeof(struct sockaddr_storage);
        message_header.msg_control = cmbuf;
        message_header.msg_controllen = sizeof(cmbuf);
        
        struct cmsghdr *cmsg;
        struct in_pktinfo *pktinfo;
        struct in6_pktinfo *pktinfo6;
        
        cmsg = CMSG_FIRSTHDR(&message_header);
        cmsg->cmsg_type = IP_PKTINFO;
        
        if(record->dst_family() == AF_INET6){
            
            if(record->socket_left.has_value()) {
                da_socket = record->socket_left.value();
            } else {
                _deb("Constucting IPv6 pktinfo");
                
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_PKTINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
                pktinfo6 = (struct in6_pktinfo*) CMSG_DATA(cmsg);
                pktinfo6->ipi6_addr = record->dst_in_addr6();
                pktinfo6->ipi6_ifindex = 0;
                message_header.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
                da_socket = ::socket (record->dst_family(), SOCK_DGRAM, 0);
            }
        }
        else { //AF_INET and others - we assume AF_INET

            if(record->socket_left.has_value()) {
                da_socket = record->socket_left.value();
            } else {
                _deb("Constructing IPv4 pktinfo");

                if(record->src_family() == AF_INET6) {
                    _deb("reconstructing mapped IPv4 src address record");
                    record_src_4fix.ss_family = AF_INET;
                    inet_pton(AF_INET,ip_src.c_str(), &((sockaddr_in*)&record_src_4fix)->sin_addr);
                    ((sockaddr_in*)&record_src_4fix)->sin_port = record->src_port6();
                    message_header.msg_name = (void*)&record_src_4fix;
                }

                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
                pktinfo = (struct in_pktinfo*) CMSG_DATA(cmsg);
                pktinfo->ipi_spec_dst = record->dst_in_addr4();
                pktinfo->ipi_ifindex = 0;
                message_header.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

                da_socket = ::socket (record->dst_family(), SOCK_DGRAM, 0);
            }
        }

        ssize_t l = 0;
        int ret_bind = 0;

        sockaddr_storage ss_s {};
        sockaddr_storage ss_d {};
        SockOps::ss_address_remap(&record->dst, &ss_d);
        SockOps::ss_address_remap(&record->src, &ss_s);

        if(log_level() >= DIA) {
            if (record->socket_left.has_value()) {
                _dia("UDPCom::write_to_pool[%d]: real=%d", _fd, record->socket_left.value());
            } else {
                _dia("UDPCom::write_to_pool[%d]: no real socket", _fd);
            }
        }

        _deb("UDPCom::write_to_pool[%d]: about to write %d bytes into socket %d", _fd, _n, record->socket_left);
        _deb("UDPCom::write_to_pool[%d]: custom transparent socket: %d", _fd, da_socket);

        if(ss_d.ss_family == AF_INET or ss_d.ss_family == AF_INET6 or ss_d.ss_family == AF_UNSPEC) {
            so_transparent_v4(da_socket);
        }
        if(ss_d.ss_family == AF_INET6) {
            so_transparent_v6(da_socket);
        }

        so_reuseaddr(da_socket);
        so_broadcast(da_socket);

        ret_bind = ::bind (da_socket, (struct sockaddr*)&(ss_d), sizeof (struct sockaddr_storage));
        if(0 != ret_bind) {
            err_errno(string_format("UDPCom::write_to_pool[%d]: bind:", da_socket).c_str(), "<nil>", ret_bind);
        }

        int ret_conn = ::connect(da_socket, (struct sockaddr*)&(ss_s), sizeof (struct sockaddr_storage));
        if(ret_conn != 0) {
            err_errno(string_format("UDPCom::write_to_pool[%d]: connect:", da_socket).c_str(), "<nil>", ret_conn);
        }

        l = ::sendmsg(da_socket, &message_header, 0);

        if(l < 0) {
            _err("UDPCom::write_to_pool[%d]: socket: %d: written %d bytes: %s", _fd, da_socket, l, string_error().c_str());
        } else {
            _deb("UDPCom::write_to_pool[%d]: socket: %d: written %d bytes", _fd, da_socket, l);
        }

        if(!record->socket_left.has_value()) {
            ::close(da_socket);
        }
        
        return l;
        
    } else {
        return -1;
    }
}

bool UDPCom::resolve_socket(bool source, int s, std::string* target_host, std::string* target_port, sockaddr_storage* target_storage) {
    
    auto lc_ = std::scoped_lock(datagram_com()->lock);
    
    auto it_record = datagram_com()->datagrams_received.find((unsigned int)s);
    if(it_record != datagram_com()->datagrams_received.end()) {
        auto record = it_record->second;
        
        char b[64]; memset(b,0,64);
        
        _deb("UDPCom::resolve_socket: found in datagrams");
        
        if(source) {
            
            if(record->src_family() == AF_INET || record->src_family() == 0) {
                inet_ntop(AF_INET, &record->src_in_addr4(), b, 64);
                l3_proto(AF_INET);

                if(target_host) target_host->assign(b);
                if(target_port) target_port->assign(std::to_string(ntohs(record->src_port4())));
            }
            else if(record->src_family() == AF_INET6) {
                inet_ntop(AF_INET6, &record->src_in_addr6(), b, 64);
                l3_proto(AF_INET6);
                
                std::string mapped4_temp = b;
                if(mapped4_temp.find("::ffff:") == 0) {
                    l3_proto(AF_INET);
                    
                    _deb("udpCom::resolve_socket: mapped IPv4 detected, removing mapping prefix");
                    mapped4_temp = mapped4_temp.substr(7);
                }                
                
                if(target_host) target_host->assign(mapped4_temp);
                if(target_port) target_port->assign(std::to_string(
                        tainted::var<unsigned>(ntohs(record->src_port6()),tainted::any<unsigned>))
                        );
            }
            
        } else {
            
            if(record->dst_family() == AF_INET || record->dst_family() == 0) {
                inet_ntop(AF_INET, &record->dst_in_addr4(), b, 64);
                l3_proto(AF_INET);
                
                if(target_host) target_host->assign(b);
                if(target_port) target_port->assign(std::to_string(ntohs(record->dst_port4())));
                
            }
            else if(record->dst_family() == AF_INET6) {
                inet_ntop(AF_INET6, &record->dst_in_addr6(), b, 64);
                l3_proto(AF_INET6);
                
                std::string mapped4_temp = b;
                if(mapped4_temp.find("::ffff:") == 0) {
                    l3_proto(AF_INET);
                    
                    _deb("udpCom::resolve_socket: mapped IPv4 detected, removing mapping prefix");
                    mapped4_temp = mapped4_temp.substr(7);
                    
                }                
                
                if(target_host) target_host->assign(mapped4_temp);
                if(target_port) target_port->assign(std::to_string(ntohs(record->dst_port6())));
            }
        }
        
    } else {
        return baseCom::resolve_socket(source,s,target_host,target_port,target_storage);
    }
    
    return true;
}

std::optional<std::string> UDPCom::ConnectionsCache::gen_cache_key(const char* host, const char* port) {
    auto const& log = self.log;

    if (self.nonlocal_src()) {
        _dia("UDPCom::ConnectionsCache::gen_cache_key: from nonlocal+connect info");
        return string_format("%s:%d-%s:%s", self.nonlocal_src_host().c_str(), self.nonlocal_src_port(), host, port);
    }

    return std::nullopt;
}


std::optional<std::string> UDPCom::ConnectionsCache::gen_cache_key(int fd) {
    auto const& log = self.log;

    std::string sip;
    std::string sport;
    std::string dip;
    std::string dport;

    _dia("UDPCom::ConnectionsCache::gen_cache_key(%d) from fd", fd);


    if(self.resolve_socket_dst(fd, &sip, &sport) && self.resolve_socket_src(fd, &dip, &dport)) {

        std::string key = string_format("%s:%s-%s:%s", sip.c_str(), sport.c_str(),dip.c_str(), dport.c_str());
        return std::make_optional(key);
    }

    return std::nullopt;
};

int UDPCom::remove_datagram_entry(int fd) {
    std::size_t count = 0;

    auto lc_ = std::scoped_lock(datagram_com()->lock);

    auto& db = datagram_com()->datagrams_received;
    auto key = (unsigned int)fd;
    _deb("UDPCom::remove_datagram_entry[%d]: socket mapped to %d", fd, key);

    auto it_record = db.find(key);

    if(it_record != db.end()) {
        auto it = db[key];

        if(not it->reuse) {
            if(it->socket_left.has_value() && it->socket_left.value() > 0) {
                int left = it->socket_left.value();

                if(kill_socket(left) != 0) {
                    _war("UDPCom::remove_datagram_entry[%d]/[%d]: socket close error", fd, left);
                } else {
                    _deb("UDPCom::remove_datagram_entry[%d]/[%d]: socket closed", fd, left);
                }
            }

        } else {
            _dia("UDPCom::remove_datagram_entry[%d]: datagrams_received entry reuse flag set, entry not deleted.", fd);
            it->reuse = false;
        }

        _dia("UDPCom::remove_datagram_entry[%d]: datagrams_received entry erased", fd);
        count = db.erase(key);
    } else {
        _dia("UDPCom::remove_datagram_entry[%d]: datagrams_received entry NOT found, thus not erased", fd);
    }

    return count;
};

int UDPCom::kill_socket(int fd) {

    int ret = 0;

    int shutdown_ret = ::shutdown(fd, SHUT_RDWR);
    if(shutdown_ret < 0) {
        _not("UDPCom::kill_socket[%d] shutdown error: %s", fd, string_error().c_str());
        ret = shutdown_ret;
    } else {
        _deb("UDPCom::kill_socket[%d] shut down", fd);
    }

    int close_ret = ::close(fd);
    if(close_ret < 0) {
        _not("UDPCom::kill_socket[%d] close error: %s", fd, string_error().c_str());
        ret = close_ret;
    } else {
        _deb("UDPCom::kill_socket[%d] closed", fd);
    }

    return ret;
};


size_t UDPCom::kill_and_deref_from_connnect(std::string const& key)  {

    size_t count = 0;

    auto it_fd = ConnectionsCache::cache.find(key);

    if(it_fd != ConnectionsCache::cache.end()) {
        std::pair<int,int>& cached_fd_ref = it_fd->second;
        auto& [sock, counter] = cached_fd_ref;

        if(counter <= 1) {

            if(kill_socket(sock) != 0) {
                _war("UDPCom::kill_and_deref_from_connnect[%s]: socket close error", key.c_str());
            } else {
                _deb("UDPCom::kill_and_deref_from_connnect[%s]: socket closed", key.c_str());
            }

            count = ConnectionsCache::cache.erase(key);
            _dia("UDPCom::kill_and_deref_from_connnect[%s]: %d removed", key.c_str(), count);

        } else {
            counter--;
            _deb("UDPCom::kill_and_deref_from_connnect[%s]: still in use, refcount now %d", key.c_str(), counter);
        }
    } else {
        _deb("UDPCom::kill_and_deref_from_connnect[%s]: not found in connect cache.", key.c_str());
    }

    return count;
};


void UDPCom::shutdown(int _fd) {

    _dia("UDPCom::shutdown[%d]: request to shutdown socket", _fd);

    if(_fd > 0) {

        size_t killed_from_cache = 0;

        {
            auto l_ = std::scoped_lock(ConnectionsCache::lock);

            if (not ConnectionsCache::cache.empty()) {

                // prefer stored connect cache key, or construct own
                auto key = connections.my_key ? connections.my_key : connections.gen_cache_key(_fd);

                if (key) {
                    _deb("UDPCom::shutdown[%d]: removing connect cache key '%s'", _fd, key.value().c_str());

                    killed_from_cache = kill_and_deref_from_connnect(key.value());
                    _dia("UDPCom::shutdown[%d]: removed %d from connect cache", _fd, killed_from_cache);
                } else {
                    _dia("UDPCom::shutdown[%d]: connect cache unchecked - cannot create a session key", _fd);
                }
            }
        }

        if(killed_from_cache == 0)  kill_socket(_fd);

        _deb("UDPCom::shutdown[%d]: eof real socket specific code", _fd);

    } else {

        auto remc = datagram_com()->in_virt_set.erase(_fd);
        _dia("UDPCom::shutdown[%d]: removed %d entries from in_virt_set on shutdown", _fd, remc);

        remc = remove_datagram_entry(_fd);
        _dia("UDPCom::shutdown[%d]: removed %d entries from datagrams on shutdown", _fd, remc);
    }



    if(embryonics().id != 0) {
        auto remc = datagram_com()->in_virt_set.erase(embryonics().id);
        _dia("UDPCom::shutdown[%d]: removed embryonic id=%d from in_virt_set on shutdown (%d entries)", _fd, embryonics().id, remc);

        remc = remove_datagram_entry(embryonics().id);
        _dia("UDPCom::shutdown[%d]: closing embryonic id=%d datagram entry on shutdown (%d entries)", _fd, embryonics().id, remc);

    }
}
