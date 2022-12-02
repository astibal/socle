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

template<class Worker>
ThreadedReceiver<Worker>::ThreadedReceiver(std::shared_ptr<FdQueue> fdq, baseCom* c, proxyType t):
    baseProxy(c),
    FdQueueHandler(fdq),
    hasWorkers<Worker>(fdq),
    proxy_type_(t) {

    baseProxy::new_raw(true);
}

template<class Worker>
ThreadedReceiver<Worker>::~ThreadedReceiver() {}

template<class Worker>
bool ThreadedReceiver<Worker>::is_quick_port(int sock, short unsigned int dport) {
    
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




template<class Worker>
std::optional<SocketInfo> ThreadedReceiver<Worker>::process_anc_data(int sock, msghdr* msg) {

    bool found_addr = false;
    SocketInfo ret;

    // iterate through all the control headers
    int i = 0;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(msg, cmsg), i++) {
        _deb("new_raw: ancillary msg #%d", i);

        _dia("ThreadedReceiver::on_left_new_raw[%d]: ancillary data level=%d, type=%d",sock,cmsg->cmsg_level,cmsg->cmsg_type);

        // ignore the control headers that don't match what we need .. SOL_IP
        if (
                ( cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type ==  IP_RECVORIGDSTADDR ) ||
                ( cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type ==  IPV6_RECVORIGDSTADDR )
                ){

            found_addr = true;
            _deb("found orig address");


            try {
                if (proxy_type().is_redirect()) {
                    ret.src.ss = std::make_optional(*static_cast<sockaddr_storage *>(msg->msg_name));
                    ret.src.unpack();

                    // there are no dst info data in CMSG in redirect case
                    sockaddr_storage orig{};
                    memcpy(&orig, (struct sockaddr_storage *) CMSG_DATA(cmsg), sizeof(struct sockaddr_storage));

                    ret.dst.ss = std::make_optional(orig);
                    ret.dst.unpack();

                } else {
                    ret.src.ss = std::make_optional(*static_cast<sockaddr_storage *>(msg->msg_name));
                    ret.src.unpack();

                    sockaddr_storage orig{};
                    memcpy(&orig, (struct sockaddr_storage *) CMSG_DATA(cmsg), sizeof(struct sockaddr_storage));

                    ret.dst.ss = std::make_optional(orig);
                    ret.dst.unpack();
                }
                _dia("ThreadedReceiver::on_left_new_raw[%d]: datagram from: %s/%s:%u to %s/%s:%u",
                        sock,
                        SockOps::family_str(ret.src.family).c_str(), ret.src.str_host.c_str(), ret.src.port,
                        SockOps::family_str(ret.dst.family).c_str(), ret.dst.str_host.c_str(), ret.dst.port
                );

            }
            catch (socket_info_error const& e) {
                _err("socket error: %s", e.what());
            }

            break;
        }
    }

    if(found_addr)
        return std::make_optional(ret);

    return std::nullopt;
}


template<class Worker>
bool ThreadedReceiver<Worker>::add_first_datagrams(int sock, SocketInfo& pinfo) {

    auto session_key = pinfo.create_session_key(true);


    // lambda creating a new entry
    auto create_new_entry = [](int sock, SocketInfo& pinfo) -> std::shared_ptr<Datagram> {
        auto entry = std::make_shared<Datagram>();

        entry->src = pinfo.src.ss.value();
        entry->dst = pinfo.dst.ss.value();
        entry->reuse = false;

        return entry;
    };



    // locks shared early datagram pool

    auto udpc = UDPCom::datagram_com_static();
    auto lc_ = std::scoped_lock(udpc->lock);

    std::shared_ptr<Datagram> entry;
    auto it = udpc->datagrams_received.find(session_key);
    bool new_entry = true;

    if(it != udpc->datagrams_received.end()) {

        _dia("existing datagram");

        if(! it->second) {
            _deb("existing datagram - null");
            it->second = create_new_entry(sock, pinfo);
        }
        entry = it->second;
        new_entry = false;
    } else {

        _dia("new datagram");

        entry = create_new_entry(sock, pinfo);
        udpc->datagrams_received[session_key] = entry;
    }


    // receiving data

    constexpr int buff_sz = 2048;
    unsigned char buff[buff_sz];
    memset(buff, 0, buff_sz);

    auto red = com()->read(sock, buff, buff_sz, 0);

    _dia("red: %d bytes from socket %d", red, sock);

    int enk = 0;

    {

        // enqueue them to entry (new or existing)

        auto lc1_ = std::scoped_lock(entry->rx_queue_lock);
        enk = entry->enqueue(buff, red);

        _dia("enk: %d bytes from socket %d", enk, sock);
    }

    if (red != enk) {
        _err("ThreadedReceiver::add_first_datagrams[%d]: cannot enqueue data of size %d", sock, red);
    }

    // crate sockets only for new entries
    if(new_entry) {
        entry->socket_left = pinfo.create_socket_left(com()->l4_proto());
        hint_push_all(session_key);
    }

    _dia("ThreadedReceiver::add_first_datagrams[%d]: early %dB, sk %d, is_new %d", sock, red, session_key, new_entry);
    _dia("ThreadedReceiver::add_first_datagrams[%d]: connected sockets: l: %d", sock, entry->socket_left);

    udpc->in_virt_set.insert(session_key);

    return new_entry;
}


template<class Worker>
void ThreadedReceiver<Worker>::on_left_new_raw(int sock) {

    _dia("ThreadedReceiver::on_left_new_raw[%d]: start", sock);

    constexpr unsigned int recv_buff_sz = 2048;
    constexpr unsigned int cmbuf_sz = 2048;

    unsigned char dummy_buffer[32];
    int iter = 0;



    do {
        _deb("receiver read iteration %d", iter++);

        unsigned char recv_buf_[recv_buff_sz];
        char cmbuf[cmbuf_sz];
        sockaddr_storage from{};
        iovec io{};

        msghdr msg{};

        auto clear_state = [&]() {
            memset(recv_buf_, 0, recv_buff_sz);
            memset(cmbuf, 0, cmbuf_sz);
            memset(&from, 0, sizeof(sockaddr_storage));
            memset(&msg, 0, sizeof(msg));
            memset(&io, 0, sizeof(iovec));

            msg.msg_name = &from;
            msg.msg_namelen = sizeof(from);
            msg.msg_control = cmbuf;
            msg.msg_controllen = sizeof(cmbuf);

            io.iov_base = recv_buf_;
            io.iov_len = sizeof(recv_buf_);

            msg.msg_iov = &io;
            msg.msg_iovlen = 1;

            _deb(" receiver state cleared");
        };

        auto dummy_read = [&]() {
            int l = ::recvmsg(sock, &msg, O_NONBLOCK);
            _deb("receiver dummy read");

            clear_state();

            return l;
        };


        clear_state();


        int len = ::recvmsg(sock, &msg, MSG_PEEK);
        if (len < 0) {
            _dia("[0x%x] new_raw: inner peek returned %d (return)", std::this_thread::get_id(), len);
            return;
        } else {
            _dia("[0x%x] new_raw: inner peek returned %d", std::this_thread::get_id(), len);
        }

        try {
            auto creds = process_anc_data(sock, &msg);

            if (creds.has_value()) {
                _dia("packet headers processing finished");

                // NOTE:
                // keeping it here for reference: this is proof we can bind and create sockets with matching tuples, all can be used
                // to send data (but obviously only one is selected by OS to deliver data from network

                // int fd2 = creds.value().create_client_socket(com()->l4_proto());
                // ::send(fd2, "post2", 5, MSG_DONTWAIT);


                add_first_datagrams(sock, creds.value());

            } else {
                int l = dummy_read();
                _err("packet headers processing failed, %d bytes flushed out", l);
            }
        }
        catch(socket_info_error const& e) {
            _err("socket error: %s", e.what());
            // _cons(string_format("socket error: %s", e.what()).c_str());
        }

    } while(::recv(sock, dummy_buffer,32,O_NONBLOCK|MSG_PEEK) > 0);
}

template<class Worker>
void ThreadedReceiver<Worker>::on_right_new_raw(int s) {
    _dia("ThreadedReceiver::on_right_new: connection [%d] pushed to the queue",s);
    hint_push_all(s);

}


template<class Worker>
int ThreadedReceiver<Worker>::run() {
    
    pollroot(true);
    hasWorkers<Worker>::create_workers(0, com(), proxy_type());

    for( unsigned int i = 0; i < this->tasks().size() ; i++) {
        auto& thread_worker = this->tasks()[i];

        thread_worker.second->com()->nonlocal_dst(com()->nonlocal_dst());
        thread_worker.second->pollroot(true);
        thread_worker.second->parent(this);

        auto* ptr = new std::thread(&Worker::run, thread_worker.second.get());
        _dia("ThreadedReceiver::run: started new thread[%d]: ptr=%x, thread_id=%d",i,ptr,ptr->get_id());
        thread_worker.first.reset(ptr);
    }
    
    baseProxy::run();
    
    return this->tasks().size();
}

template<class Worker>
int ThreadedReceiver<Worker>::pop_for_worker(int id) {

    // this is unsolvable data race: we don't know if we pop fd for us or not.
    // auto pop_or_not = pop_if([id](int fd) { ((unsigned int)fd) % Worker::workers_total() == (unsigned int)id; });

    return pop(id);
}




template<class SubWorker>
int ThreadedReceiverProxy<SubWorker>::handle_sockets_once(baseCom* xcom) {
    
    if(parent() == nullptr) {
        throw proxy_error("PARENT is NULL");
    }

    if (parent()->state().dead()) {
        // set myself dead too!
        this->state().dead(true);
        return -1;
    }

    uint32_t virtual_socket = 0;

    if(auto parent_fd_handler = parent_as_handler.cast(parent()); parent_fd_handler) {

        parent_fd_handler->update_load(worker_id_, proxies().size());
        virtual_socket = parent_fd_handler->pop(worker_id_);

        if (virtual_socket == 0) {
            _dia("ThreadedReceiverProxy::handle_sockets_once: somebody was faster, nothing to pop");
            return -1;
        }
    }


    // this session key is for us!
    _dia("ThreadedReceiverProxy::handle_sockets_once: new data notification for %d", virtual_socket);

    _dia("ThreadedReceiverProxy::%d is for me!", virtual_socket);

    int _record_socket_left = 0;
    int _record_socket_right = 0;
    baseHostCX *cx = nullptr;
    bool found = false;


    bool ready = false;
    // datagram lock
    {
    auto udpc = UDPCom::datagram_com_static();
    auto l_ = std::scoped_lock(udpc->lock);

    _dia("ThreadedReceiverProxy::handle_sockets_once: DatagramCom::datagrams_received.size() = %d",
            udpc->datagrams_received.size());

    auto it_record = udpc->datagrams_received.find(virtual_socket);
    found = (it_record != udpc->datagrams_received.end());

    if (found) {

        _dia("ThreadedReceiverProxy::handle_sockets_once[%d]: found in datagram pool", virtual_socket);

        auto record = it_record->second;

        if(record->socket_left.has_value())
            _record_socket_left = record->socket_left.value();

        cx = nullptr;

        _deb("Record dump: cx=0x%x dst=%s real_socket=%d reuse=%d rx_size=0x%x socket_l=%d src=%s",
             record->cx, SockOps::ss_str(&record->dst).c_str(), record->socket_left.has_value() ? record->socket_left : -1,
             record->reuse, record->queue_bytes_l(), record->socket_left, SockOps::ss_str(&record->src).c_str());

        try {
            cx = this->new_cx(virtual_socket);
            record->cx = cx;

            if(auto ucom = dynamic_cast<UDPCom*>(cx->com()); ucom) {
                // set virtual socket to read early data
                ucom->embryonics().id = virtual_socket;

                // we need to monitor also embryonic socket
                com()->set_monitor(virtual_socket);

            } else {
                throw socle::com_error("cx com is not UDPCom");
            }

        }
        catch (socle::com_error const &e) {
            _err("cannot handover cx to proxy: %s", e.what());
        }
    }


    if(found && cx) {

        _dia("ThreadedReceiverProxy::handle_sockets_once[%d]: new connection, new CX, bound sockets l: %d r: %d",
             virtual_socket, _record_socket_left, _record_socket_right);

        try {

            if (!cx->read_waiting_for_peercom()) {
                cx->on_accept_socket(virtual_socket);
            }
            cx->idle_delay(120);
            auto cx_dcom = dynamic_cast<UDPCom *>(cx->com());
            auto cx_bcom = dynamic_cast<baseCom *>(cx->com());


            if (cx_bcom == nullptr || cx_dcom == nullptr) {
                _war("ThreadedReceiverProxy::handle_sockets_once[%d]: new object's Com is not DatagramCom and baseCom",
                     virtual_socket);
                delete cx;
                cx = nullptr;

                throw ReceiverProxyError("com is not compatible");

            }

            cx_bcom->nonlocal_dst(this->com()->nonlocal_dst());


            if (proxy_type().is_transparent()) {
                _dia("ThreadedReceiverProxy::handle_sockets_once[%d]: type=transparent CX created", virtual_socket);

                cx_bcom->resolve_nonlocal_dst_socket(virtual_socket);

            }
            else if(proxy_type().is_proxy()) {
                _dia("ThreadedReceiverProxy::handle_sockets_once[%d]: type=proxy CX created", virtual_socket);
            }
            else if (proxy_type().is_redirect()) {

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

                    _dia("ThreadedReceiverProxy::handle_sockets_once[%d]: type=redirect CX created, bound socket %d: no redirection target",
                         virtual_socket, _record_socket_left);

                    delete cx;
                    cx = nullptr;
                    throw ReceiverProxyError("no redirection target");
                }
            }

            // signal to run left_new outside datagram lock
            ready = true;


        }
        catch (socle::com_error const& e) {
            _err("cannot handover cx to proxy: %s", e.what());
        }
        catch (ReceiverProxyError const& e) {
            _err("receiver error: %s", e.what());
        }
    }

    } // datagram lock release - prevent mutex deadlock races in generic handler


    // ready signals on_left_new shound be called - outside of datagramCom::lock!
    if(ready) {
        _dia("ThreadedReceiverProxy::handle_sockets_once[%d]: CX created, bound socket %d ,nonlocal: %s:%u",
             virtual_socket, _record_socket_left, cx->com()->nonlocal_dst_host().c_str(),
             cx->com()->nonlocal_dst_port());
        this->on_left_new(cx);
    }

    return MasterProxy::handle_sockets_once(com());
}



#endif