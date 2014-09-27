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

#ifndef _THREADED_PROXY_HPP_
#define _THREADED_PROXY_HPP_

#include <hostcx.hpp>
#include <baseproxy.hpp>
#include <masterproxy.hpp>

#include <vector>
#include <deque>

#include <thread>
#include <mutex>

template<class Worker, class SubWorker>
class ThreadedAcceptor : public baseProxy {
public:
	ThreadedAcceptor(baseCom* c);
	virtual ~ThreadedAcceptor(); 
	
	virtual void on_left_new_raw(int);
	virtual void on_right_new_raw(int);
	
	virtual int run(void);
	
	int push(int);
	int pop();
	
protected:
	mutable std::mutex sq_lock_;
	std::deque<int> sq_;
	
	size_t nthreads;
	std::thread **threads_;
	Worker **workers_;
	
	int create_workers();
};

template<class SubWorker>
class ThreadedWorkerProxy : public MasterProxy {
public:
	ThreadedWorkerProxy(baseCom* c): MasterProxy(c) {}
	virtual int handle_sockets_once(baseCom*);	
};

#include <threadedproxy.cpp>

#endif // _THREADED_PROXY_HPP_