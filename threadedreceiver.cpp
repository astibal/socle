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
void ThreadedReceiver<Worker,SubWorker>::on_left_new_raw(int s) {
    
    unsigned char recv_buf_[2048];
    char cmbuf[64];
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
    
    int len = ::recvmsg(s, &msg, 0);
    
    uint64_t session_key = 0;
    
//     hdr.client_addr_ = from.sin_addr.s_addr;
//     hdr.client_port_ = ntohs(from.sin_port);
    
    // iterate through all the control headers
    for ( struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg))   {

        // ignore the control headers that don't match what we need
        if (cmsg->cmsg_level != SOL_IP || cmsg->cmsg_type != IP_ORIGDSTADDR) {
            continue;
        }

        found_origdst = true;
        struct sockaddr_in* orig = (struct sockaddr_in*)CMSG_DATA(cmsg);

        INF_("ThreadedReceiver::on_left_new_raw: reading from: %s:%u to %s:%u", inet_ntoa(from.sin_addr), ntohs(from.sin_port) ,inet_ntoa(orig->sin_addr), ntohs(orig->sin_port));
        
        uint64_t s = from.sin_addr.s_addr;
        uint32_t sp = ntohs(from.sin_port);
        s = s << 32;
        s += sp;
        
//         uint64_t d = orig->sin_addr.s_addr;
//         uint32_t dp = orig->sin_port;
//         d  = d << 32;
//         d += dp;
        
        session_key = s;
               
        INF_("ThreadedReceiver::on_left_new_raw:: %016llx", session_key );
        
    }
    
    if (!found_origdst) {
        ERRS_("ThreadedReceiver::on_left_new_raw: getting original destination failed, (cmsg->cmsg_type==IP_ORIGDSTADDR)");
    } else {

        DIA_("ThreadedReceiver::on_left_new_raw: new data  for key %016llx - notification sent",session_key);
        
        push(session_key);
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
    
    DIA_("Detected %d cores to use.", nthreads);
    
    threads_ = new std::thread*[nthreads];
    workers_ = new Worker*[nthreads];
    
    for( unsigned int i = 0; i < nthreads; i++) {
        Worker *w = new Worker(this->com()->replicate());
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
    
    int s = sq_.back();
    sq_.pop_back();
    
    return s;
}




template<class SubWorker>
int ThreadedReceiverProxy<SubWorker>::handle_sockets_once(baseCom* xcom) {
    
    ThreadedAcceptor<ThreadedAcceptorProxy<SubWorker>,SubWorker> *p = (ThreadedAcceptor<ThreadedAcceptorProxy<SubWorker>,SubWorker> *)MasterProxy::parent();
    if(p == NULL) {
        FATS_("PARENT is NULL");
    }
    
    if(p->dead()) {
        // set myself dead too!
        this->dead(true);
    }
    
    int s = p->pop();
    if(s > 0) {
        DIA_("ThreadedReceiverProxy::new data notification for %d",s);

//         auto cx = this->new_cx(s);
//         if(!cx->paused()) {
//             cx->accept_socket(s);
//         }
//         cx->com()->nonlocal(this->com()->nonlocal());
//         cx->com()->resolve_nonlocal_socket(s);
//         this->on_left_new(cx);

    }
    
//     return MasterProxy::handle_sockets_once(com());
}
