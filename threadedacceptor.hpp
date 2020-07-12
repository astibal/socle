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
#include <threadedworker.hpp>

#include <vector>
#include <deque>

#include <thread>
#include <mutex>

#include <mpstd.hpp>
#include <proxy/fdq.hpp>

template<class Worker, class SubWorker>
class ThreadedAcceptor : public baseProxy, public FdQueueHandler {
public:
    using proxy_type = threadedProxyWorker::proxy_type_t;

	explicit ThreadedAcceptor (std::shared_ptr<FdQueue> fdq, baseCom *c, proxy_type type);
	~ThreadedAcceptor() override;
	
	void on_left_new_raw(int) override;
	void on_right_new_raw(int) override;
	
	int run() override;
	void on_run_round() override;
	

    inline void worker_count_preference(int c) { worker_count_preference_ = c; };
    inline int worker_count_preference() { return worker_count_preference_; };

    int task_count() const { return tasks_.size(); }
    constexpr int core_multiplier() const noexcept { return 4; };

private:
    threadedProxyWorker::proxy_type_t proxy_type_;
	mp::vector<std::pair< std::thread*, Worker*>> tasks_;

    int worker_count_preference_=0;
	int create_workers(int count=0);
};

template<class SubWorker>
class ThreadedAcceptorProxy : public threadedProxyWorker, public MasterProxy {
public:
    ThreadedAcceptorProxy(baseCom* c, int worker_id, threadedProxyWorker::proxy_type_t p):
            threadedProxyWorker(worker_id, p),
            MasterProxy(c) {}

	int handle_sockets_once(baseCom*) override;
    void on_run_round() override;

    static std::atomic_int& workers_total() {
        static std::atomic_int workers_total_ = 2;
        return workers_total_;
    };
};

#include <threadedacceptor.cpp>

#endif // _THREADED_ACCEPTOR_HPP_