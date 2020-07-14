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

#ifndef _THREADED_RECEIVER_CPP_
#define _THREADED_RECEIVER_CPP_

#include <fcntl.h>
#include <unistd.h>


#include <vector>
#include <thread>
#include <random>

#include <internet.hpp>
#include <display.hpp>
#include <log/logger.hpp>
#include <threadedreceiver.hpp>

#include <linux/in6.h>
#include <udpcom.hpp>

#define USE_SOCKETPAIR

template<class Worker, class SubWorker>
ThreadedReceiver<Worker,SubWorker>::ThreadedReceiver(std::shared_ptr<FdQueue> fdq, baseCom* c, threadedProxyWorker::proxy_type_t t):
    baseProxy(c),
    FdQueueHandler(std::move(fdq)),
    proxy_type_(t) {

    baseProxy::new_raw(true);
}

template<class Worker, class SubWorker>
ThreadedReceiver<Worker,SubWorker>::~ThreadedReceiver() {
    if(! tasks_.empty())  {

        for(auto& thread_worker: tasks_) {
            thread_worker.second->state().dead(true);
        }

        for(unsigned int i = 0; i <= tasks_.size(); i++) {
            auto& t_w =  tasks_[i];
            t_w.first->join();
            delete t_w.first;
            t_w.first = nullptr;
        }
    }
}

template<class Worker, class SubWorker>
bool ThreadedReceiver<Worker,SubWorker>::is_quick_port(int sock, short unsigned int dport) {
    
    bool use_virtual_socket = false;
    
    //  if list is set, use it, otherwise use virtual sockets for everything than udp/443 (DTLS)
    if(get_quick_list() != nullptr) {
        _dum("ThreadedReceiver::is_quick_port[%d]: reading quick list",sock);
        std::vector<int>& ref = *get_quick_list();
        for(int x: ref) {
            if(dport == x || 0 == x) {
                _dum("ThreadedReceiver::is_quick_port[%d]: port %d is quick",sock, dport);
                use_virtual_socket = true;
            } else {
                _dum("ThreadedReceiver::is_quick_port[%d]: port %d is cooked",sock, dport);
            }
        }
    }
    else {
        const int ex_port = 443;
        if(dport != ex_port) {
            _dum("ThreadedReceiver::is_quick_port[%d]: port %d is quick (default)",sock, dport);
            use_virtual_socket = true;
        } else {
            _dum("ThreadedReceiver::is_quick_port[%d]: port %d is cooked (default)",sock, dport);
        }
    }
    
    return use_virtual_socket;
}

template<class Worker, class SubWorker>
uint32_t ThreadedReceiver<Worker,SubWorker>::create_session_key4(sockaddr_storage* from, sockaddr_storage* orig) {
    
    uint32_t s = inet::to_sockaddr_in(from)->sin_addr.s_addr;
    uint32_t d = inet::to_sockaddr_in(orig)->sin_addr.s_addr;
    uint32_t sp = ntohs(inet::to_sockaddr_in(from)->sin_port);
    uint32_t sd = ntohs(inet::to_sockaddr_in(orig)->sin_port);

    std::seed_seq seed1{ s, d, sp, sd };
    std::mt19937 e(seed1);
    std::uniform_int_distribution<> dist;

    uint32_t mirand = dist(e);


    mirand |= (1 << 31); //this will produce negative number, which should determine  if it's normal socket or not



    return mirand; // however we return it as the key, therefore cast to unsigned int
}

template<class Worker, class SubWorker>
uint32_t ThreadedReceiver<Worker,SubWorker>::create_session_key6(sockaddr_storage* from, sockaddr_storage* orig) {

    uint32_t s0 = ((uint32_t*)&inet::to_sockaddr_in6(from)->sin6_addr)[0];
    uint32_t s1 = ((uint32_t*)&inet::to_sockaddr_in6(from)->sin6_addr)[1];
    uint32_t s2 = ((uint32_t*)&inet::to_sockaddr_in6(from)->sin6_addr)[2];
    uint32_t s3 = ((uint32_t*)&inet::to_sockaddr_in6(from)->sin6_addr)[3];

    uint32_t d0 = ((uint32_t*)&inet::to_sockaddr_in6(orig)->sin6_addr)[0];
    uint32_t d1 = ((uint32_t*)&inet::to_sockaddr_in6(orig)->sin6_addr)[1];
    uint32_t d2 = ((uint32_t*)&inet::to_sockaddr_in6(orig)->sin6_addr)[2];
    uint32_t d3 = ((uint32_t*)&inet::to_sockaddr_in6(orig)->sin6_addr)[3];

    uint32_t sp = ntohs(inet::to_sockaddr_in6(from)->sin6_port);
    uint32_t dp = ntohs(inet::to_sockaddr_in6(orig)->sin6_port);

    std::seed_seq seed1{ s0, d0, s1, d1, s2, d2, s3, d3, sp, dp };
    std::mt19937 e(seed1);
    std::uniform_int_distribution<> dist;

    uint32_t mirand = dist(e);
    mirand |= (1 << 31); //this will produce negative number, which should determine  if it's normal socket or not

    return mirand; // however we return it as the key, therefore cast to unsigned int
}

template<class Worker, class SubWorker>
void ThreadedReceiver<Worker,SubWorker>::on_left_new_raw(int sock) {
    
    _dia("ThreadedReceiver::on_left_new_raw[%d]: start",sock);

    unsigned char dummy_buffer[32];
    int iter = 0;
    
    do {
        _deb("receiver read iteration %d",iter++);
        
        unsigned char recv_buf_[2048];
        char cmbuf[256];
        sockaddr_storage from{0};

        iovec io{0};
        msghdr msg{0};

        bool found_origdst = false;
        memset(&msg, 0, sizeof(msg));
        
        msg.msg_name = &from;
        msg.msg_namelen = sizeof(from);
        msg.msg_control = cmbuf;
        msg.msg_controllen = sizeof(cmbuf);
        msg.msg_iov = &io;
        msg.msg_iovlen = 1;
        
        io.iov_base = recv_buf_;
        io.iov_len = sizeof(recv_buf_);
        
        int len = ::recvmsg(sock, &msg, MSG_PEEK);
        
    
        uint32_t session_key = 0;
        struct sockaddr_storage orig{0};
        
        // use virtual socket for plaintext protocols which don't require special treatment (DNS)
        // virtual sockets can't be used for DTLS, for example
        bool use_virtual_socket = false;
        
    //     hdr.client_addr_ = from.sin_addr.s_addr;
    //     hdr.client_port_ = ntohs(from.sin_port);
        
        // iterate through all the control headers
        for ( struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg))   {

            _deb("ThreadedReceiver::on_left_new_raw[%d]: ancillary data level=%d, type=%d",sock,cmsg->cmsg_level,cmsg->cmsg_type);
                
            // ignore the control headers that don't match what we need .. SOL_IP 
            if (
                ( cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type ==  IP_RECVORIGDSTADDR ) ||
                ( cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type ==  IPV6_RECVORIGDSTADDR )
            ){

                found_origdst = true;
                memcpy(&orig,(struct sockaddr_storage*)CMSG_DATA(cmsg),sizeof(struct sockaddr_storage));

                std::string str_src_host;
                unsigned short sport;
                std::string str_dst_host;
                unsigned short dport;
                int src_family = AF_INET;
                int dst_family = AF_INET;

                if(proxy_type() == proxy_type_t::REDIRECT) {
                    src_family = inet_ss_address_unpack(&from, &str_src_host, &sport);
                    str_dst_host = "8.8.8.8";
                    dport = 53;
                } else {
                    src_family = inet_ss_address_unpack(&from, &str_src_host, &sport);
                    dst_family = inet_ss_address_unpack(&orig, &str_dst_host, &dport);
                }
                use_virtual_socket = is_quick_port(sock, dport);
                
                _dia("ThreadedReceiver::on_left_new_raw[%d]: datagram from: %s/%s:%u to %s/%s:%u (%s)",
                            sock, 
                            inet_family_str(src_family).c_str(),str_src_host.c_str(), sport,
                            inet_family_str(dst_family).c_str(),str_dst_host.c_str(), dport,
                            use_virtual_socket ? "quick" : "cooked"
                            );

                if(src_family == AF_INET) {
                    _deb("session key: source socket is IPv4");

                    session_key = create_session_key4(&from,&orig);
                }
                else if(src_family == AF_INET6) {
                    _deb("session key: source socket is IPv6");

                    session_key = create_session_key6(&from,&orig);
                }

                _deb("ThreadedReceiver::on_left_new_raw[%d]: session key %d", sock, session_key );
                break;
            }
        }
        
        if (!found_origdst) {
            _err("ThreadedReceiver::on_left_new_raw[%d]: getting original destination failed, (cmsg->cmsg_type==IP_ORIGDSTADDR)",sock);
        } else {

            _dia("ThreadedReceiver::on_left_new_raw[%d]: new data for key %d",sock,session_key);
            
            auto* c = dynamic_cast<DatagramCom*>(com());
            if(c == nullptr) {
                _war("ThreadedReceiver::on_left_new_raw[%d]: my com() is not Datagram storage!",sock);
                exit(1);
            }
            
            std::lock_guard<std::recursive_mutex> l(DatagramCom::lock);
            
            Datagram dgram;
            struct Datagram& new_dgram = dgram;
            auto it = DatagramCom::datagrams_received.find(session_key);
            bool clashed = false;
            baseHostCX* clashed_cx = nullptr;
            
            
            if(it == DatagramCom::datagrams_received.end()) {
                // new session key (new udp "connection")
                _deb("ThreadedReceiver::on_left_new_raw[%d]: inserting new session key in storage: %d",sock, session_key);

                clash:

                new_dgram.src = from;
                new_dgram.dst = orig;
                //d.rx.size(0);
                new_dgram.socket = sock;
                com()->unblock(new_dgram.socket);
                
                std::string str_src_host; unsigned short sport;
                int src_family = inet_ss_address_unpack(&from,&str_src_host,&sport);
                std::string str_dst_host; unsigned short dport;
                int dst_family = inet_ss_address_unpack(&orig,&str_dst_host,&dport);             
                
                int ret_con = -127;
                int ret_bin = -127;
                
                if(!use_virtual_socket) {
                    if(dst_family == AF_INET) {

                        int n = 1;
                        if(0 != ::setsockopt(new_dgram.socket, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(int))) {
                            _err("cannot set socket %d option SO_REUSEADDR", new_dgram.socket);
                        }
                        n = 1;

                        if(0 != ::setsockopt(new_dgram.socket, SOL_IP, IP_RECVORIGDSTADDR, &n, sizeof(int))) {
                            _err("cannot set socket %d option IP_RECVORIGDSTADDR", new_dgram.socket);
                        }
                        n = 1;

                        if(0 != ::setsockopt(new_dgram.socket, SOL_IP, SO_BROADCAST, &n, sizeof(int))) {
                            _err("cannot set socket %d option SO_BROADCAST", new_dgram.socket);
                        }
                        n = 1;

                        if(0 != ::setsockopt(new_dgram.socket, SOL_IP, IP_TRANSPARENT, &n, sizeof(int))) {
                            _err("cannot set socket %d option IP_TRANSPARENT", new_dgram.socket);
                        }
                        n = 1;

                        if(0 != ::setsockopt(new_dgram.socket, SOL_IPV6, IPV6_TRANSPARENT, &n, sizeof(int))) {
                            _err("cannot set socket %d option IPV6_TRANSPARENT", new_dgram.socket);
                        }
                        n = 1;
                        
                        sockaddr_in ss_src{0};
                        sockaddr_in ss_dst{0};

                        memset(&ss_src,0,sizeof(struct sockaddr_in));
                        memset(&ss_dst,0,sizeof(struct sockaddr_in));
                        
                        int pton = inet_pton(AF_INET,str_src_host.c_str(),&ss_src.sin_addr);
                        if(pton != 1) {
                            _err("inet_pton error for src: %d:%s",pton,string_error().c_str());
                        } else {
                            char b[64]; memset(b,0,64);
                            inet_ntop(AF_INET,&ss_src.sin_addr,b,64);
                            
                            _dum("inet_pton  okay for src: %s", b);
                        } 
                        ss_src.sin_port = htons(sport); 
                        ss_src.sin_family = AF_INET;

                        pton = inet_pton(AF_INET,str_dst_host.c_str(),&ss_dst.sin_addr);
                        if( pton != 1) {
                            _err("inet_pton error for dst: %d:%s",pton,string_error().c_str());
                        }else {
                            char b[64]; memset(b,0,64);
                            inet_ntop(AF_INET,&ss_dst.sin_addr,b,64);
                            
                            _dum("inet_pton  okay for dst: %s", b);
                        } 
                        ss_dst.sin_port = htons(dport);
                        ss_dst.sin_family = AF_INET;
                        
                        ret_bin = ::bind (new_dgram.socket, (sockaddr*)&ss_dst, sizeof (struct sockaddr_in));
                        if(ret_bin != 0) _dia("ipv4 transparenting: bind error: %s",string_error().c_str()); // bind is not succeeding with already bound socket ... => this will create empbryonic connection
                        ret_con = ::connect(new_dgram.socket, (sockaddr*)&ss_src, sizeof (struct sockaddr_in));
                        if(ret_con != 0) _err("ipv4 transparenting: connect error: %s",string_error().c_str());
                        
                    } else {

                        int n = 1;
                        ::setsockopt(new_dgram.socket, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(int)); n = 1;
                        ::setsockopt(new_dgram.socket, SOL_IP, SO_BROADCAST, &n, sizeof(int)); n = 1;
                        ::setsockopt(new_dgram.socket, SOL_IP, IPV6_RECVORIGDSTADDR, &n, sizeof(int)); n = 1;
                        ::setsockopt(new_dgram.socket, SOL_IPV6, IPV6_TRANSPARENT, &n, sizeof(int));

                        sockaddr_storage ss_src{0};
                        sockaddr_storage ss_dst{0};

                        inet_pton(AF_INET6,str_src_host.c_str(),&ss_src); ss_src.ss_family=AF_INET6; ((sockaddr_in6*)&ss_src)->sin6_port = htons(sport);
                        inet_pton(AF_INET6,str_dst_host.c_str(),&ss_dst); ss_dst.ss_family=AF_INET6; ((sockaddr_in6*)&ss_dst)->sin6_port = htons(dport);

                        ret_bin = ::bind (new_dgram.socket, (struct sockaddr*)&(new_dgram.dst), sizeof (struct sockaddr_storage));
                        if(ret_bin != 0) _dia("ipv6 transparency: bind error: %s",string_error().c_str()); // bind is not succeeding with already bound socket ... => this will create empbryonic connection
                        ret_con = ::connect(new_dgram.socket, (struct sockaddr*)&(new_dgram.src), sizeof (struct sockaddr_storage));
                        if(ret_con != 0) _err("ipv6 transparency: connect error: %s",string_error().c_str());
                    }

                }

                _dia("ThreadedReceiver::on_left_new_raw[new %d]: datagram from: %s/%s:%u to %s/%s:%u",
                     new_dgram.socket,
                     inet_family_str(src_family).c_str(), str_src_host.c_str(), sport,
                     inet_family_str(dst_family).c_str(), str_dst_host.c_str(), dport
                            );            
                
                if(use_virtual_socket) {
                    _dia("ThreadedReceiver transparency for inbound connection: connect=%d, bind=%d",ret_con,ret_bin);
                } else {
                    _dia("ThreadedReceiver using virtual socket %d",session_key);
                }
                
                
                // in case of virtual sockets, default ret_con is -127
                if(ret_con == 0) {
                    // if bind succeeded, we have full back-channel socket to the client/client_port_
                    if(ret_bin == 0) {
                        new_dgram.embryonic = false;
                    }
                    
                    // d.socket is now connected to originator!
                    com()->unblock(new_dgram.socket);
                    new_dgram.real_socket = true;


                    // for now, don't monitor this rebuilt socket. It should be handled by new proxy object later.
                    com()->master()->unset_monitor(new_dgram.socket);
                    // also remove this proxy as handler
                    com()->set_poll_handler(new_dgram.socket, nullptr);
                    
                    for (auto bound_cx: left_bind_sockets) {
                        bound_cx->remove_socket();
                        delete bound_cx;
                    }
                    left_bind_sockets.clear(); // all objects are invalidated
                    
                    
                    int s = bind(50081,'L');
                    com()->unblock(s);
                    
                } else {
                    
                    // append data only if socket is virtual
                    len = recv(sock, recv_buf_,len,0);

                    auto l_ = std::scoped_lock(new_dgram.rx_queue_lock);

                    bool success = false;
                    for(auto& elem: new_dgram.rx_queue) {
                        if(elem.empty()) {
                            elem.append(recv_buf_, len);
                            success = true;
                            break;
                        }
                    }

                    if(! success) {
                        _deb("ThreadedReceiver::on_left_new_raw[%d]: key %d - queue full, dropped %d bytes",sock, session_key, len);
                        _cons("udp dropping bytes");
                    }
                }
                
                
                DatagramCom::datagrams_received[session_key] = new_dgram;
                Datagram& n_it = DatagramCom::datagrams_received[session_key];
                
                
                if (clashed) {
                    n_it.reuse = true;
                    
                    // fix crash when cx is already deleted, but not removed for some reason
                    // clashed_cx->error() is no-op anyway, it just returns error state!
                    if(clashed_cx != nullptr) {
                        //clashed_cx->error();
                    } else {
                        n_it.embryonic = true;
                    }
                }
                
                if(clashed) {
                    _dia("ThreadedReceiver::on_left_new_raw[%d]: re-inserting clashed session key in storage: key=%d, bytes=%d",sock, session_key, len);
                } else {
                    _dia("ThreadedReceiver::on_left_new_raw[%d]: inserting new session key in storage: key=%d, bytes=%d",sock, session_key, len);
                }
                push(session_key);
            }
            else {
                Datagram& o_it = DatagramCom::datagrams_received[session_key];

                bool clashed_cond = false;
                
                
                std::string s_dst, s_src;
                std::string d_dst, d_src;
                s_src = inet_ss_str(&from);
                s_dst = inet_ss_str(&orig);
                
                d_src = inet_ss_str(&o_it.src);
                d_dst = inet_ss_str(&o_it.dst);
                
                _deb("ThreadedReceiver::on_left_new_raw[%d]: key %d: clash test %s:%s vs. %s:%s", sock, session_key, s_src.c_str(),s_dst.c_str(),d_src.c_str(),d_dst.c_str());
                                
                
                if( s_src != d_src || s_dst != d_dst) { clashed_cond = true; }
                
                if(clashed_cond) {
                    _dia("ThreadedReceiver::on_left_new_raw[%d]: key %d: session clash with cx@%x!",sock, session_key,o_it.cx);
                    clashed = true;
                    clashed_cx = o_it.cx;
                    
                    goto clash;
                }
                
                
                auto bl_ = std::scoped_lock(o_it.rx_queue_lock);

                auto queue_bytes = o_it.queue_bytes();

                if(queue_bytes > 0) {
                    // If there are data, we apparently can't catch up with the speed.
                    // replace current data. Application is not interested in old UDP datagrams.
                    _dia("ThreadedReceiver::on_left_new_raw[%d]: key %d: already queued %dB of data",sock, session_key, queue_bytes);

                    // no need to iterate current queue and dump it atm
                    //_deb("                              data for key %d\n%s",session_key,hex_dump(o_it.rx,4).c_str());
                }
                    
                
                
                len = recv(sock, recv_buf_,len,0);
                

                auto& picked_buffer = [&o_it]() -> buffer& {
                    auto& fallback = o_it.rx_queue.back();

                    for(auto& r: o_it.rx_queue) {
                        if(r.empty()) {
                            return r;
                        }
                    }
                    return fallback;
                }();
                
                picked_buffer.size(0);
                picked_buffer.append(recv_buf_,len);
                
                if(o_it.cx) {
                    baseCom* com = o_it.cx->com();
                    auto* um = dynamic_cast<DatagramCom*>(com->master());
                    if(um) {
                        std::lock_guard<std::recursive_mutex> l_(DatagramCom::lock);
                        DatagramCom::in_virt_set.insert(session_key);
                    }
                    
                    // mark target cx's socket as write-monitor, triggering proxy session.
                    if(o_it.cx->peercom()) {
                        int ps = o_it.cx->peer()->socket();
                        _deb("write socket hint to peer's socket: %d",ps);
                        o_it.cx->peercom()->set_write_monitor(ps); 
                    } else {
                        _err("write socket hint to peer's socket can't be set, peer or peercom doesn't exist!");
                    } 
                }
/*                
                UDPCom* uc = dynamic_cast<UDPCom*>(com()->master());
                uc->in_virt_set.insert(session_key);*/
                    
                _deb("                          NEW data for key %d\n%s",session_key,hex_dump(picked_buffer,4).c_str());
                
                _dia("ThreadedReceiver::on_left_new_raw[%d]: existing key %d: %dB data buffered",sock, session_key,picked_buffer.size());
            }
        }
    } while(::recv(sock, dummy_buffer,32,O_NONBLOCK|MSG_PEEK) > 0);
}

template<class Worker, class SubWorker>
void ThreadedReceiver<Worker,SubWorker>::on_right_new_raw(int s) {
    _dia("ThreadedReceiver::on_right_new: connection [%d] pushed to the queue",s);
    push(s);

}


template<class Worker, class SubWorker>
int ThreadedReceiver<Worker,SubWorker>::create_workers(int count) {

    auto nthreads = std::thread::hardware_concurrency();
    _dia("Detected %d cores to use, multiplier to apply: %d.", nthreads, core_multiplier());
    nthreads *= core_multiplier();


    if(count > 0) {
        nthreads = count;
        _dia("Threads poolsize overridden: %d", nthreads);

    } else if (count < 0) {
        Worker::workers_total() = count;
        return count;
    }
    
    Worker::workers_total() = nthreads;

    for( unsigned int i = 0; i < nthreads; i++) {

        Worker *w = new Worker(this->com()->replicate(),i,proxy_type_);
        w->com()->nonlocal_dst(this->com()->nonlocal_dst());
        w->parent(this);
        w->pollroot(true);

        _dia("ThreadedReceiver::create_workers setting worker's queue hint pipe socket %d", std::get<0>(hint_pair()));
        w->com()->set_hint_monitor(std::get<0>(hint_pair()));
        
        _dia("Created ThreadedWorkerProxy 0x%x", w);

        tasks_.push_back( {nullptr, w} );
    }
    
    return nthreads;
}


template<class Worker, class SubWorker>
int ThreadedReceiver<Worker,SubWorker>::run() {
    
    pollroot(true);
    create_workers(worker_count_preference());

    for( unsigned int i = 0; i < tasks_.size() ; i++) {
        auto& thread_worker = tasks_[i];
        auto* ptr = new std::thread(&Worker::run, thread_worker.second);
        _dia("ThreadedReceiver::run: started new thread[%d]: ptr=%x, thread_id=%d",i,ptr,ptr->get_id());
        thread_worker.first = ptr;
    }
    
    baseProxy::run();
    
    return tasks_.size();
}

template<class Worker, class SubWorker>
void ThreadedReceiver<Worker,SubWorker>::on_run_round() {
    //std::this_thread::yield();
}


template<class Worker, class SubWorker>
int ThreadedReceiver<Worker, SubWorker>::pop_for_worker(int id) {

    // this is unsolvable data race: we don't know if we pop fd for us or not.
    // auto pop_or_not = pop_if([id](int fd) { ((unsigned int)fd) % Worker::workers_total() == (unsigned int)id; });

    return pop();
}




template<class SubWorker>
int ThreadedReceiverProxy<SubWorker>::handle_sockets_once(baseCom* xcom) {
    
    auto *p = (ThreadedReceiver<ThreadedReceiverProxy<SubWorker>,SubWorker> *)MasterProxy::parent();
    if(p == nullptr) {
        _fat("PARENT is NULL");
    }
    else {
        if (p->state().dead()) {
            // set myself dead too!
            this->state().dead(true);
        }

        uint32_t virtual_socket = p->pop_for_worker(worker_id_);
        if (virtual_socket > 0) {

            // this session key is for us!
            _dia("ThreadedReceiverProxy::handle_sockets_once: new data notification for %d", virtual_socket);

            if (((unsigned int) virtual_socket) % workers_total() == (unsigned int) worker_id_) {
                _dia("ThreadedReceiverProxy::%d is for me!", virtual_socket);

                bool _is_reuse = false;
                int _record_socket = 0;
                baseHostCX *cx = nullptr;
                bool found = false;

                auto l_ = std::scoped_lock(DatagramCom::lock);

                _dia("ThreadedReceiverProxy::handle_sockets_once: DatagramCom::datagrams_received.size() = %d",
                     DatagramCom::datagrams_received.size());

                auto it_record = DatagramCom::datagrams_received.find(virtual_socket);
                found = (it_record != DatagramCom::datagrams_received.end());

                if (found) {

                    _dia("ThreadedReceiverProxy::handle_sockets_once[%d]: found in datagram pool", virtual_socket);

                    Datagram &record = (*it_record).second;
                    _is_reuse = record.reuse;
                    _record_socket = record.socket;
                    cx = nullptr;

                    _deb("Record dump: cx=0x%x dst=%s embryonic=%d real_socket=%d reuse=%d rx_size=0x%x socket=%d src=%s",
                         record.cx, inet_ss_str(&record.dst).c_str(), record.embryonic, record.real_socket,
                         record.reuse, record.queue_bytes_l(), record.socket, inet_ss_str(&record.src).c_str());

                    if (!_is_reuse) {
                        try {
                            cx = this->new_cx(virtual_socket);
                            record.cx = cx;
                        }
                        catch (socle::com_is_null const &e) {
                            _err("cannot handover cx to proxy");
                        }
                    } else {
                        _dia("ThreadedReceiverProxy::handle_sockets_once[%d]: already existing pseudo-connection with bound socket %d",
                             virtual_socket, _record_socket);
                    }
                }


                if(found && cx) {

                    _dia("ThreadedReceiverProxy::handle_sockets_once[%d]: embryonic connection, creating new CX with bound socket %d",
                         virtual_socket, _record_socket);

                    try {

                        if (!cx->read_waiting_for_peercom()) {
                            cx->on_accept_socket(virtual_socket);
                        }
                        cx->idle_delay(120);
                        auto cx_dcom = dynamic_cast<DatagramCom *>(cx->com());
                        auto cx_bcom = dynamic_cast<baseCom *>(cx->com());


                        if (cx_bcom == nullptr || cx_dcom == nullptr) {
                            _war("ThreadedReceiverProxy::handle_sockets_once[%d]: new object's Com is not DatagramCom and baseCom",
                                 virtual_socket);
                            delete cx;
                            cx = nullptr;

                            throw ReceiverProxyError("com is not compatible");

                        }

                        cx_bcom->nonlocal_dst(this->com()->nonlocal_dst());


                        if (proxy_type() == proxy_type_t::TRANSPARENT) {
                            cx_bcom->resolve_nonlocal_dst_socket(virtual_socket);
                        } else {

                            // get REDIR port needed for destination lookup
                            cx_bcom->resolve_nonlocal_dst_socket(virtual_socket);

                            // get port -> target mapping
                            auto o_target = ReceiverRedirectMap::instance().redir_target(cx_bcom->nonlocal_dst_port());

                            if(o_target.has_value()) {

                                auto target = o_target.value();

                                cx_bcom->nonlocal_dst_host() = target.first;
                                cx_bcom->nonlocal_dst_port() = target.second;
                                cx_bcom->nonlocal_dst_resolved(true);

                                _deb("redir map host: %s:%d", target.first.c_str(), target.second);
                            } else {

                                _dia("ThreadedReceiverProxy::handle_sockets_once[%d]: CX created, bound socket %d: no redirection target",
                                     virtual_socket, _record_socket);

                                delete cx;
                                cx = nullptr;
                                throw ReceiverProxyError("no redirection target");
                            }
                        }

                        _dia("ThreadedReceiverProxy::handle_sockets_once[%d]: CX created, bound socket %d ,nonlocal: %s:%u",
                             virtual_socket, _record_socket, cx->com()->nonlocal_dst_host().c_str(),
                             cx->com()->nonlocal_dst_port());
                        this->on_left_new(cx);


                    }
                    catch (socle::com_is_null const& e) {
                        _err("cannot handover cx to proxy");
                    }
                    catch (ReceiverProxyError const& e) {
                        _err("receiver error: %s", e.what());
                    }
                }

            } else {
                _ext("ThreadedReceiverProxy::handle_sockets_once: %d belongs to someone else..", virtual_socket);
            }
        } else if (virtual_socket != 0) {
            _dia("ThreadedReceiverProxy::handle_sockets_once: new unknown data notification for %d", virtual_socket);
        }
    }

    return MasterProxy::handle_sockets_once(com());
}


template<class SubWorker>
void ThreadedReceiverProxy<SubWorker>::on_run_round () {
    std::this_thread::yield();
}


#endif