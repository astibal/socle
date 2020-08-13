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
ThreadedAcceptor<Worker>::ThreadedAcceptor (std::shared_ptr<FdQueue> fdq, baseCom *c, proxy_type t):
    baseProxy(c),
    FdQueueHandler(fdq),
    proxy_type_(t) {

    baseProxy::new_raw(true);
}

template<class Worker>
ThreadedAcceptor<Worker>::~ThreadedAcceptor() {
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
int ThreadedAcceptor<Worker>::create_workers(int count) {

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

	    uint32_t this_worker_id = worker_id_max()++;

	    auto pa = hint_new_pair(this_worker_id);

        _deb("acceptor[0x%x][%d]: created queue socket pair %d,%d", std::this_thread::get_id(), i, pa.first, pa.second);

		auto *w = new Worker(this->com()->replicate(), this_worker_id, proxy_type_);
		w->com()->nonlocal_dst(this->com()->nonlocal_dst());
		w->parent(this);
        w->pollroot(true);

        _dia("ThreadedAcceptor::create_workers setting worker's queue hint pipe socket %d", pa.first);
        w->com()->set_hint_monitor(pa.first);

		_dia("Created ThreadedAcceptorProxy 0x%x", w);

		tasks_.push_back( {nullptr, w} );
	}

	return nthreads;
}


template<class Worker>
int ThreadedAcceptor<Worker>::run() {
	
    pollroot(true);
	create_workers(worker_count_preference());
	
	for( unsigned int i = 0; i < tasks_.size() ; i++) {
		auto& thread_worker = tasks_[i];
		auto* ptr = new std::thread(&Worker::run, thread_worker.second);
		_dia("ThreadedAcceptor::run: started new thread[%d]: ptr=%x, thread_id=%d",i,ptr,ptr->get_id());
        thread_worker.first = ptr;
	}
	
	baseProxy::run();
	
	return tasks_.size();
}

template<class Worker>
void ThreadedAcceptor<Worker>::on_run_round() {
    // std::this_thread::yield();
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
                auto cx = this->new_cx(s);
                if (!cx->read_waiting_for_peercom()) {
                    cx->on_accept_socket(s);
                } else {
                    cx->on_delay_socket(s);
                }

                cx->com()->nonlocal_dst(this->com()->nonlocal_dst());

                if (proxy_type() == proxy_type_t::TRANSPARENT) {
                    cx->com()->resolve_nonlocal_dst_socket(s);
                } else
                    if (proxy_type() == proxy_type_t::REDIRECT) {
                    cx->com()->resolve_redirected_dst_socket(s);
                }

                this->on_left_new(cx);

            } catch (socle::com_is_null const& e) {
                _err("cannot handover cx to proxy");
            }

        }
    }
	return MasterProxy::handle_sockets_once(com());
}

template<class SubWorker>
void ThreadedAcceptorProxy<SubWorker>::on_run_round() {
    std::this_thread::yield();
}

#endif