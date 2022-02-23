/*
    Socle Library Ecosystem
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

#ifndef _THREADED_ACCEPTOR_CPP_
#define _THREADED_ACCEPTOR_CPP_

#include <fcntl.h>
#include <unistd.h>


#include <vector>
#include <thread>

#include <display.hpp>
#include <threadedacceptor.hpp>
#include <log/logger.hpp>



template<class Worker>
ThreadedAcceptor<Worker>::ThreadedAcceptor (std::shared_ptr<FdQueue> fdq, baseCom *c, proxyType t):
    baseProxy(c),
    FdQueueHandler(fdq),
    hasWorkers<Worker>(fdq),
    proxy_type_(t) {

    baseProxy::new_raw(true);
}

template<class Worker>
ThreadedAcceptor<Worker>::~ThreadedAcceptor() {}


template<class Worker>
void ThreadedAcceptor<Worker>::on_left_new_raw(int s) {
	_dia("ThreadedAcceptor::on_left_new: connection [%d] pushed to the queue",s);
	hint_push_all(s);
}

template<class Worker>
void ThreadedAcceptor<Worker>::on_right_new_raw(int s) {
	_dia("ThreadedAcceptor::on_right_new: connection [%d] pushed to the queue",s);
	hint_push_all(s);

}




template<class Worker>
int ThreadedAcceptor<Worker>::run() {
	
    pollroot(true);
    hasWorkers<Worker>::create_workers(0, com(), proxy_type());
	
	for( unsigned int i = 0; i < this->tasks().size() ; i++) {
		auto& thread_worker = this->tasks()[i];

        thread_worker.second->com()->nonlocal_dst(com()->nonlocal_dst());
        thread_worker.second->pollroot(true);
        thread_worker.second->parent(this);

		auto* ptr = new std::thread(&Worker::run, thread_worker.second.get());
		_dia("ThreadedAcceptor::run: started new thread[%d]: ptr=%x, thread_id=%d",i,ptr,ptr->get_id());
        thread_worker.first.reset(ptr);
	}
	
	baseProxy::run();
	
	return this->tasks().size();
}


template<class SubWorker>
int ThreadedAcceptorProxy<SubWorker>::handle_sockets_once(baseCom* xcom) {
	
	auto *p = (ThreadedAcceptor<ThreadedAcceptorProxy<SubWorker>> *)MasterProxy::parent();
	if(p == nullptr) {
		_fat("PARENT is NULL");
	} else {

        if (p->state().dead()) {
            // set myself dead too!
            this->state().dead(true);
        }

        int s = p->pop(worker_id_);
        if (s > 0) {
            _dia("ThreadedAcceptorProxy::run: removed from queue: 0x%016llx (socket %d)", s, s);

            try {
                auto cx = std::unique_ptr<baseHostCX>(this->new_cx(s));
                if (!cx->read_waiting_for_peercom()) {
                    cx->on_accept_socket(s);
                } else {
                    cx->on_delay_socket(s);
                }

                cx->com()->nonlocal_dst(this->com()->nonlocal_dst());

                if (proxy_type().is_transparent()) {
                    cx->com()->resolve_nonlocal_dst_socket(s);
                } else
                    if (proxy_type().is_redirect()) {
                    cx->com()->resolve_redirected_dst_socket(s);
                }

                this->on_left_new(cx.release());

            } catch (socle::com_error const& e) {
                _err("cannot handover cx to proxy: %s", e.what());
            }

        }
    }
	return MasterProxy::handle_sockets_once(com());
}


#endif