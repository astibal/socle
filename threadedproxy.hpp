/*
    Copyright (c) 2013, Ales Stibal <astibal@gmail.com>
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:
        * Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.
        * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.
        * Neither the name of the <organization> nor the
        names of its contributors may be used to endorse or promote products
        derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY Ales Stibal <astibal@gmail.com> ''AS IS'' AND ANY
    EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL Ales Stibal <astibal@gmail.com> BE LIABLE FOR ANY
    DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

template<class Com, class Worker, class SubWorker>
class ThreadedAcceptor : public baseProxy<Com> {
public:
	ThreadedAcceptor();
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

template<class Com,class SubWorker>
class ThreadedWorkerProxy : public MasterProxy<Com> {
public:
	ThreadedWorkerProxy() {}
	virtual int run_once();	
};

#include <threadedproxy.impl>

#endif // _THREADED_PROXY_HPP_