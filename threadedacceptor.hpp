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
#include <fdq.hpp>

template<class Worker>
class ThreadedAcceptor : public baseProxy, public FdQueueHandler, public hasWorkers<Worker> {
public:

	explicit ThreadedAcceptor (std::shared_ptr<FdQueue> fdq, baseCom *c, proxyType type);
	~ThreadedAcceptor() override;
	
	void on_left_new_raw(int) override;
	void on_right_new_raw(int) override;
	
	int run() override;
	void on_run_round() override;

    proxyType proxy_type() const { return proxy_type_; };
private:
    proxyType proxy_type_;

    logan_lite log {"com.tcp.acceptor"};
};

template<class SubWorker>
class ThreadedAcceptorProxy : public threadedProxyWorker, public MasterProxy {
public:
    ThreadedAcceptorProxy(baseCom* c, uint32_t worker_id, proxyType p):
            threadedProxyWorker(worker_id, p),
            MasterProxy(c) {}

	int handle_sockets_once(baseCom*) override;
    void on_run_round() override;

    static std::atomic_int& workers_total() {
        static std::atomic_int workers_total_ = 2;
        return workers_total_;
    };
private:
    logan_lite log {"com.tcp.worker"};
};

#endif // _THREADED_ACCEPTOR_HPP_

#include <threadedacceptor.cpp>
