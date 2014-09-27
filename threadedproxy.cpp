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

#include <vector>
#include <thread>

#include <threadedproxy.hpp>
#include <logger.hpp>

template<class Worker, class SubWorker>
ThreadedAcceptor<Worker,SubWorker>::ThreadedAcceptor(baseCom* c): baseProxy(c),
threads_(NULL) {
	baseProxy::new_raw(true);
}

template<class Worker, class SubWorker>
ThreadedAcceptor<Worker,SubWorker>::~ThreadedAcceptor() { 
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
void ThreadedAcceptor<Worker,SubWorker>::on_left_new_raw(int s) {
	DIA_("ThreadedAcceptor::on_left_new: connection [%d] pushed to the queue",s);
	push(s);
}

template<class Worker, class SubWorker>
void ThreadedAcceptor<Worker,SubWorker>::on_right_new_raw(int s) {
	DIA_("ThreadedAcceptor::on_right_new: connection [%d] pushed to the queue",s);
	push(s);

}


template<class Worker, class SubWorker>
int ThreadedAcceptor<Worker,SubWorker>::create_workers(void) {	
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
int ThreadedAcceptor<Worker,SubWorker>::run(void) {
	
    pollroot(true);
	create_workers();
	
	for( unsigned int i = 0; i < nthreads; i++) {
		auto w = workers_[i];
		std::thread* ptr = new std::thread(&Worker::run,w);
		DIA_("ThreadedAcceptor::run: started new thread[%d]: ptr=%x, thread_id=%d",i,ptr,ptr->get_id())
		threads_[i] = ptr;
	}
	
	baseProxy::run();
	
	return nthreads;
}


template<class Worker, class SubWorker>
int ThreadedAcceptor<Worker,SubWorker>::push(int s) { 
	std::lock_guard<std::mutex> lck(sq_lock_);
	sq_.push_front(s);
	
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
	
	return s;
}



template<class SubWorker>
int ThreadedWorkerProxy<SubWorker>::handle_sockets_once(baseCom* xcom) {
	
	ThreadedAcceptor<ThreadedWorkerProxy<SubWorker>,SubWorker> *p = (ThreadedAcceptor<ThreadedWorkerProxy<SubWorker>,SubWorker> *)MasterProxy::parent();
	if(p == NULL) {
		FATS_("PARENT is NULL");
	}
	
	if(p->dead()) {
        // set myself dead too!
        this->dead(true);
    }
	
	int s = p->pop();
	if(s > 0) {
		DIA_("ThreadedWorkerProxy::run: removed from queue: %d",s);

		auto cx = this->new_cx(s);
		if(!cx->paused()) {
            cx->accept_socket(s);
        }
		cx->com()->nonlocal(this->com()->nonlocal());
		cx->com()->resolve_nonlocal_socket(s);
		this->on_left_new(cx);

	}
	
	return MasterProxy::handle_sockets_once(com());
}
