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

#include <vector>
#include <thread>

#include <logger.hpp>
#include <threadedreceiver.hpp>

#include <udpcom.hpp>

template<class SubWorker>
int ThreadedReceiverProxy<SubWorker>::workers_total = 2;

template<class Worker, class SubWorker>
ThreadedReceiver<Worker,SubWorker>::ThreadedReceiver(baseCom* c): baseProxy(c),
threads_(NULL) {
    baseProxy::new_raw(true);
}

template<class Worker, class SubWorker>
ThreadedReceiver<Worker,SubWorker>::~ThreadedReceiver() { 
    if(threads_)  {

        for(unsigned int i = 0; i <= nthreads; i++) {
            Worker* ptr =  workers_[i];
            ptr->dead(true);
        }
        
        for(unsigned int i = 0; i <= nthreads; i++) {
            std::thread* ptr =  threads_[i];
            ptr->join();
            delete ptr;
            threads_[i] = NULL;
        }
        delete[] threads_; 
    }
};


template<class Worker, class SubWorker>
void ThreadedReceiver<Worker,SubWorker>::on_left_new_raw(int sock) {
    
    DIA_("ThreadedReceiver::on_left_new_raw[%d]: start",sock);
    
    unsigned char recv_buf_[2048];
    char cmbuf[128];
    struct sockaddr_in from;
    struct iovec io;
    struct msghdr msg;
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
    
    int len = ::recvmsg(sock, &msg, 0);
    
   
    uint32_t session_key = 0;
    struct sockaddr_in orig;
    
//     hdr.client_addr_ = from.sin_addr.s_addr;
//     hdr.client_port_ = ntohs(from.sin_port);
    
    // iterate through all the control headers
    for ( struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg))   {

        // ignore the control headers that don't match what we need .. SOL_IP 
        if ( cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type ==  IP_RECVORIGDSTADDR ) {

            found_origdst = true;
            memcpy(&orig,(struct sockaddr_in*)CMSG_DATA(cmsg),sizeof(struct sockaddr_in));

            DEB_("ThreadedReceiver::on_left_new_raw[%d]: ancillary data level=%d, type=%d",sock,cmsg->cmsg_level,cmsg->cmsg_type);
            
            std::string str_src_host(inet_ntoa(from.sin_addr));
            std::string str_dst_host(inet_ntoa(orig.sin_addr));
            
            DIA_("ThreadedReceiver::on_left_new_raw[%d]: datagram from: %s:%u to %s:%u", sock, str_src_host.c_str() , ntohs(from.sin_port) , str_dst_host.c_str(), ntohs(orig.sin_port));
            
            uint32_t s = from.sin_addr.s_addr;
            uint16_t sp = ntohs(from.sin_port);
            s = s << 16;
            s += sp;
            
            s |= 2^31; //this will produce negative number, which should determine  if it's normal socket or not
            
    //         uint64_t d = orig->sin_addr.s_addr;
    //         uint32_t dp = orig->sin_port;
    //         d  = d << 32;
    //         d += dp;
            
            session_key = s;
                
            DIA_("ThreadedReceiver::on_left_new_raw[%d]: session key %d", sock, session_key );
        }
        
    }
    
    if (!found_origdst) {
        ERR_("ThreadedReceiver::on_left_new_raw[%d]: getting original destination failed, (cmsg->cmsg_type==IP_ORIGDSTADDR)",sock);
    } else {

        DIA_("ThreadedReceiver::on_left_new_raw[%d]: new data  for key %d - notification sent",sock,session_key);
        
        DatagramCom* c = dynamic_cast<DatagramCom*>(com());
        if(c == nullptr) {
            WAR_("ThreadedReceiver::on_left_new_raw[%d]: my com() is not Datagram storage!",sock);
            exit(1);
        }
        
        Datagram dgram;
        struct Datagram& d = dgram;
        auto it = DatagramCom::datagrams_received.find(session_key);
        bool clashed = false;
        baseHostCX* clashed_cx = nullptr;
        
        
        if(it == DatagramCom::datagrams_received.end()) {
            // new session key (new udp "connection")
            DEB_("ThreadedReceiver::on_left_new_raw[%d]: inserting new session key in storage: %d",sock, session_key);

            clash:
            
            d.src = from;
            d.dst = orig;
            d.rx.size(0);
             d.socket = sock;
            
            // highly experimental
//             int n_sock = ::socket (AF_INET, SOCK_DGRAM, 0);
//             int n = 1;
//             ::setsockopt (n_sock, SOL_IP, IP_TRANSPARENT, &n, sizeof(int));
//             ::connect(n_sock,(struct sockaddr*)&(d.src),sizeof (struct sockaddr_in));
//             ::bind (n_sock, (struct sockaddr*)&(d.dst), sizeof (struct sockaddr_in));
//             
//             d.socket = n_sock;
            
            
            DatagramCom::datagrams_received[session_key] = d;
            Datagram& n_it = DatagramCom::datagrams_received[session_key];
            
            n_it.rx.append(recv_buf_,len);
            
            if (clashed) {
                n_it.reuse = true;
                clashed_cx->error();
            }
            
            if(clashed) {
                DIA_("ThreadedReceiver::on_left_new_raw[%d]: re-inserting clashed session key in storage: key=%d, bytes=%d",sock, session_key,n_it.rx.size());
            } else {
                DIA_("ThreadedReceiver::on_left_new_raw[%d]: inserting new session key in storage: key=%d, bytes=%d",sock, session_key,n_it.rx.size());
            }
//             push(session_key);
            push(session_key);
        }
        else {
            Datagram& o_it = DatagramCom::datagrams_received[session_key];
            
            if( (o_it.src.sin_addr.s_addr != from.sin_addr.s_addr) ||
                (o_it.src.sin_port != from.sin_port) ||
                (o_it.dst.sin_addr.s_addr != orig.sin_addr.s_addr) ||
                (o_it.dst.sin_port != orig.sin_port) ||
                (o_it.src.sin_family != orig.sin_family)
            ) {
                DIA_("ThreadedReceiver::on_left_new_raw[%d]: key %d: session clash!",sock, session_key);
                clashed = true;
                clashed_cx = o_it.cx;
                
                goto clash;
            }
            
            if(o_it.rx.size() != 0) {
                    DIA_("ThreadedReceiver::on_left_new_raw[%d]: key %d: dropped %dB of non-proxied data",sock, session_key,o_it.rx.size());
            }

            o_it.rx.size(0);
            o_it.rx.append(recv_buf_,len);
            DIA_("ThreadedReceiver::on_left_new_raw[%d]: existing key %d: %dB data buffered",sock, session_key,o_it.rx.size());

        }
    }
}

template<class Worker, class SubWorker>
void ThreadedReceiver<Worker,SubWorker>::on_right_new_raw(int s) {
    DIA_("ThreadedReceiver::on_right_new: connection [%d] pushed to the queue",s);
    push(s);

}


template<class Worker, class SubWorker>
int ThreadedReceiver<Worker,SubWorker>::create_workers(void) {  
    nthreads = std::thread::hardware_concurrency();
    nthreads = 1;
    Worker::workers_total = nthreads;
    
    DIA_("Detected %d cores to use.", nthreads);
    
    threads_ = new std::thread*[nthreads];
    workers_ = new Worker*[nthreads];
    
    for( unsigned int i = 0; i < nthreads; i++) {
        Worker *w = new Worker(this->com()->replicate(),i);
        w->com()->nonlocal(this->com()->nonlocal());
        w->parent((baseProxy*)this);
        w->pollroot(true);
        
        DIA_("Created ThreadedWorkerProxy %x",w);
        workers_[i] = w;
        
        // also init threads pool
        threads_[i] = NULL;
    }
    
    return nthreads;
}


template<class Worker, class SubWorker>
int ThreadedReceiver<Worker,SubWorker>::run(void) {
    
    pollroot(true);
    create_workers();
    
    for( unsigned int i = 0; i < nthreads; i++) {
        auto w = workers_[i];
        std::thread* ptr = new std::thread(&Worker::run,w);
        DIA_("ThreadedReceiver::run: started new thread[%d]: ptr=%x, thread_id=%d",i,ptr,ptr->get_id())
        threads_[i] = ptr;
    }
    
    baseProxy::run();
    
    return nthreads;
}


template<class Worker, class SubWorker>
int ThreadedReceiver<Worker,SubWorker>::push(int s) { 
    std::lock_guard<std::mutex> lck(sq_lock_);
    sq_.push_front(s);
    
    return sq_.size();
};

template<class Worker, class SubWorker>
int ThreadedReceiver<Worker,SubWorker>::pop() {
    std::lock_guard<std::mutex> lck(sq_lock_);
    
    if(sq_.size() == 0) {
        return 0;
    }
    
    uint32_t s = sq_.back();
    sq_.pop_back();
    
    return s;
}

template<class Worker, class SubWorker>
int ThreadedReceiver<Worker, SubWorker>::pop_for_worker(int id) {

    if(sq_.size() == 0) {
        return 0;
    }
    
    std::lock_guard<std::mutex> lck(sq_lock_);
    
    uint32_t b = sq_.back();
    
    if(b <= 0) {
        return 0;
    }
    
    if (((unsigned int)b) % Worker::workers_total == (unsigned int)id) {
        int r = sq_.back();
        sq_.pop_back();
        DIA_("ThreadedReceiver::pop_for_worker: pop-ing %d for worker %d",r,id);
        
        return r;
    }
    
    return 0;
}




template<class SubWorker>
int ThreadedReceiverProxy<SubWorker>::handle_sockets_once(baseCom* xcom) {
    
    ThreadedReceiver<ThreadedReceiverProxy<SubWorker>,SubWorker> *p = (ThreadedReceiver<ThreadedReceiverProxy<SubWorker>,SubWorker> *)MasterProxy::parent();
    if(p == NULL) {
        FATS_("PARENT is NULL");
    }
    
    if(p->dead()) {
        // set myself dead too!
        this->dead(true);
    }
    
    uint32_t s = p->pop_for_worker(worker_id_);
    if(s > 0) {
        
        // this session key is for us!
        DIA_("ThreadedReceiverProxy::handle_sockets_once: new data notification for %d",s);

            if (((unsigned int)s) % workers_total == (unsigned int)worker_id_) {
                DIA_("ThreadedReceiverProxy::%d is for me!",s);


                    
                auto it_record = DatagramCom::datagrams_received.find(s);
                
                if(it_record != DatagramCom::datagrams_received.end()) {

                    DIA_("ThreadedReceiverProxy::handle_sockets_once[%d]: found in datagram pool",s);
                    
                    Datagram& record = (*it_record).second;
                    
                    if (record.embryonic) {
                        record.embryonic = false; // it's not embryonic anymore, when we pick it up!
                        
                        DIA_("ThreadedReceiverProxy::handle_sockets_once[%d]: embryonic connection, creating new CX with bound socket %d",s,record.socket);
                        
                        // create new cx
                        auto cx = this->new_cx(s);
                        record.cx = cx;
                        
                        if(!cx->paused()) {
                            cx->accept_socket(s);
                        }
                        cx->idle_delay(120);
                        auto cx_dcom = dynamic_cast<DatagramCom*>(cx->com());
                        auto cx_bcom = dynamic_cast<baseCom*>(cx->com());
                        
                        
                        if(cx_bcom == nullptr || cx_dcom == nullptr) {
                            WAR_("ThreadedReceiverProxy::handle_sockets_once[%d]: new object's Com is not DatagramCom and baseCom",s);
                            delete cx;
                            
                        } else {
                            cx_bcom->nonlocal(this->com()->nonlocal());
                            cx_bcom->resolve_nonlocal_socket(s);
                        
                            DIA_("ThreadedReceiverProxy::handle_sockets_once[%d]: CX created, bound socket %d ,nonlocal: %s:%u",s, record.socket,cx->com()->nonlocal_host().c_str(),cx->com()->nonlocal_port());
                            this->on_left_new(cx);                            
                        }
                        

                    } else {
                        DIA_("ThreadedReceiverProxy::handle_sockets_once[%d]: already existing pseudo-connection with bound socket %d",s,record.socket);
//                         DIA_("ThreadedReceiverProxy::handle_sockets_once[%d]: what to do?",s);
                    }
                }

            } else {
                EXT_("ThreadedReceiverProxy::handle_sockets_once: %d belongs to someone else..",s);
            }
    } else if (s != 0){
        DIA_("ThreadedReceiverProxy::handle_sockets_once: new unknown data notification for %d",s);
    }
    
     return MasterProxy::handle_sockets_once(com());
}
