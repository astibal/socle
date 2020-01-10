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

#define USE_SOCKETPAIR

template<class Worker, class SubWorker>
ThreadedAcceptor<Worker,SubWorker>::ThreadedAcceptor(baseCom* c, proxy_type t): baseProxy(c),
    proxy_type_(t) {

    baseProxy::new_raw(true);

    #ifdef USE_SOCKETPAIR
    if(0 == ::socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK,0, sq__hint)) {
        _inf("acceptor: using socketpair");
        sq_type_ = SQ_SOCKETPAIR;
    }
    else if( 0 == pipe2(sq__hint,O_DIRECT|O_NONBLOCK)) {
        _inf("acceptor: using pipe2");
        sq_type_ = SQ_PIPE;
    }

    #else
    if(version_check(get_kernel_version(),"3.4")) {
        _deb("Acceptor: kernel supports O_DIRECT");
        if ( 0 != pipe2(sq__hint,O_DIRECT|O_NONBLOCK)) {
            _err("ThreadAcceptor::new_raw: hint pipe not created, error[%d], %s", errno, string_error().c_str());
        }
    } else {
        _war("Acceptor: kernel doesn't support O_DIRECT");
        if (0 != pipe2(sq__hint,O_NONBLOCK)) {
            _err("ThreadAcceptor::new_raw: hint pipe not created, error[%d], %s", errno, string_error().c_str());
        }
    }
    #endif
}

template<class Worker, class SubWorker>
ThreadedAcceptor<Worker,SubWorker>::~ThreadedAcceptor() { 
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
    ::close(sq__hint[0]);
    ::close(sq__hint[1]);
};


template<class Worker, class SubWorker>
void ThreadedAcceptor<Worker,SubWorker>::on_left_new_raw(int s) {
	_dia("ThreadedAcceptor::on_left_new: connection [%d] pushed to the queue",s);
	push(s);
}

template<class Worker, class SubWorker>
void ThreadedAcceptor<Worker,SubWorker>::on_right_new_raw(int s) {
	_dia("ThreadedAcceptor::on_right_new: connection [%d] pushed to the queue",s);
	push(s);

}


template<class Worker, class SubWorker>
int ThreadedAcceptor<Worker,SubWorker>::create_workers(int count) {

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

		Worker *w = new Worker(this->com()->replicate(),i, proxy_type_);
		w->com()->nonlocal_dst(this->com()->nonlocal_dst());
		w->parent(this);
        w->pollroot(true);

        _dia("ThreadedAcceptor::create_workers setting worker's queue hint pipe socket %d",sq__hint[0]);
        w->com()->set_hint_monitor(sq__hint[0]);

		_dia("Created ThreadedAcceptorProxy 0x%x", w);

		tasks_.push_back( {nullptr, w} );
	}

	return nthreads;
}


template<class Worker, class SubWorker>
int ThreadedAcceptor<Worker,SubWorker>::run(void) {
	
    pollroot(true);
	create_workers(worker_count_preference());
	
	for( unsigned int i = 0; i < tasks_.size() ; i++) {
		auto& thread_worker = tasks_[i];
		std::thread* ptr = new std::thread(&Worker::run, thread_worker.second);
		_dia("ThreadedAcceptor::run: started new thread[%d]: ptr=%x, thread_id=%d",i,ptr,ptr->get_id());
        thread_worker.first = ptr;
	}
	
	baseProxy::run();
	
	return tasks_.size();
}

template<class Worker, class SubWorker>
void ThreadedAcceptor<Worker,SubWorker>::on_run_round() {
    // std::this_thread::yield();
}

template<class Worker, class SubWorker>
int ThreadedAcceptor<Worker,SubWorker>::push(int s) { 
	std::lock_guard<std::mutex> lck(sq_lock_);
	sq_.push_front(s);
    int wr = ::write(sq__hint[1],"A",1);
    if( wr <= 0) {
        _err("ThreadedAcceptor::push: failed to write hint byte - error[%d]: %s", wr, string_error().c_str());
    }
	
	return sq_.size();
};

template<class Worker, class SubWorker>
int ThreadedAcceptor<Worker,SubWorker>::pop() {
    std::lock_guard<std::mutex> lck(sq_lock_);

    if(sq_.size() == 0) {
        return 0;
    }

    int s = sq_.back();
    sq_.pop_back();

    char dummy_buffer[1];

    int red = ::read(sq__hint[0],dummy_buffer,1);
    if(red > 0) {
        _dia("ThreadedAcceptor::pop: clearing sq__hint %c", dummy_buffer[0]);
    } else {
        _dia("ThreadedAcceptor::pop_for_worker: hint not read, read returned %d", red);
    }
    return s;
}



template<class SubWorker>
int ThreadedAcceptorProxy<SubWorker>::handle_sockets_once(baseCom* xcom) {
	
	auto *p = (ThreadedAcceptor<ThreadedAcceptorProxy<SubWorker>,SubWorker> *)MasterProxy::parent();
	if(p == nullptr) {
		_fat("PARENT is NULL");
	} else {

        if (p->state().dead()) {
            // set myself dead too!
            this->state().dead(true);
        }

        int s = p->pop();
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
                cx->com()->resolve_nonlocal_dst_socket(s);
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