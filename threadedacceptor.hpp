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

#ifndef _THREADED_ACCEPTOR_HPP_
#define _THREADED_ACCEPTOR_HPP_

#include <hostcx.hpp>
#include <baseproxy.hpp>
#include <masterproxy.hpp>

#include <vector>
#include <deque>

#include <thread>
#include <mutex>

#include <mpstd.hpp>

template<class Worker, class SubWorker>
class ThreadedAcceptor : public baseProxy {
public:
	ThreadedAcceptor(baseCom* c);
	virtual ~ThreadedAcceptor(); 
	
	virtual void on_left_new_raw(int);
	virtual void on_right_new_raw(int);
	
	virtual int run(void);
	void on_run_round() override;
	
	int push(int);
	int pop();

    inline void worker_count_preference(int c) { worker_count_preference_ = c; };
    inline int worker_count_preference(void) { return worker_count_preference_; };    
protected:
	mutable std::mutex sq_lock_;
	mp::deque<int> sq_;
    
    // pipe created to be monitored by Workers with poll. If pipe is filled with *some* data
    // there is something in the queue to pick-up.
    int sq__hint[2];
	
	size_t nthreads;
	std::thread **threads_;
	Worker **workers_;


    int worker_count_preference_=0;
	int create_workers(int count=0);
};

template<class SubWorker>
class ThreadedAcceptorProxy : public MasterProxy {
public:
	ThreadedAcceptorProxy(baseCom* c, int worker_id): MasterProxy(c), worker_id_(worker_id) {}
	virtual int handle_sockets_once(baseCom*);
    void on_run_round() override;
    
    static int workers_total;
protected:
    int worker_id_ = 0;

};

#include <threadedacceptor.cpp>

#endif // _THREADED_ACCEPTOR_HPP_