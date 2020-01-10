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

#ifndef _THREADED_RECEIVER_HPP_
#define _THREADED_RECEIVER_HPP_

#include <hostcx.hpp>
#include <baseproxy.hpp>
#include <masterproxy.hpp>
#include <threadedworker.hpp>

#include <vector>
#include <deque>

#include <thread>
#include <mutex>
#include <map>



template<class Worker, class SubWorker>
class ThreadedReceiver : public baseProxy {
public:
    using proxy_type = threadedProxyWorker::proxy_type;
    ThreadedReceiver(baseCom* c, proxy_type t);
    ~ThreadedReceiver() override;
    
    bool     is_quick_port(int sock, short unsigned int dport);
    uint32_t create_session_key4(sockaddr_storage *from, sockaddr_storage* orig);
    uint32_t create_session_key6(sockaddr_storage *from, sockaddr_storage* orig);
    
    void on_left_new_raw(int) override;
    void on_right_new_raw(int) override;
    
    int run() override;
    void on_run_round() override;
    
    int push(int);
    int pop();
    int pop_for_worker(int id);

    inline void worker_count_preference(int c) { worker_count_preference_ = c; };
    inline int worker_count_preference() { return worker_count_preference_; };
    
    
    void set_quick_list(mp::vector<int>* quick_list) { quick_list_ = quick_list; };
    inline mp::vector<int>* get_quick_list() const { return quick_list_;};

    int sq_type() const { return sq_type_; }
    int task_count() const { return tasks_.size(); }
    constexpr int core_multiplier() const noexcept { return 4; };

private:
    threadedProxyWorker::proxy_type proxy_type_;

    mutable std::mutex sq_lock_;
    mp::deque<int> sq_;
    mp::vector<int>* quick_list_ = nullptr;

    // pipe created to be monitored by Workers with poll. If pipe is filled with *some* data
    // there is something in the queue to pick-up.
    int sq__hint[2] = {-1, -1};

    mp::vector<std::pair< std::thread*, Worker*>> tasks_;
    int worker_count_preference_=0;
    int create_workers(int count=0);

    enum  { SQ_PIPE = 0, SQ_SOCKETPAIR = 1 } sq_type_;
};



template<class SubWorker>
class ThreadedReceiverProxy : public threadedProxyWorker, public MasterProxy {
public:
    ThreadedReceiverProxy(baseCom* c, int worker_id, threadedProxyWorker::proxy_type p):
            threadedProxyWorker(worker_id, p),
            MasterProxy(c) {}

    int handle_sockets_once(baseCom*) override;
    void on_run_round() override;

    static int& workers_total() {
        static int workers_total_ = 2;
        return workers_total_;
    };
};

#include <threadedreceiver.cpp>

#endif //_THREADED_RECEIVER_HPP_