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
#include <socketinfo.hpp>

#include <vector>
#include <deque>
#include <fdq.hpp>

#include <thread>
#include <mutex>
#include <map>




template<class Worker>
class ThreadedReceiver : public baseProxy, public FdQueueHandler {
public:

    using buffer_guard = locked_guard<lockbuffer>;
    using proxy_type_t = threadedProxyWorker::proxy_type_t;
    inline proxy_type_t proxy_type() const { return proxy_type_; }

    ThreadedReceiver(std::shared_ptr<FdQueue> fdq, baseCom* c, proxy_type_t t);
    ~ThreadedReceiver() override;
    
    bool     is_quick_port(int sock, short unsigned int dport);



    // get original IP, etc
    std::optional<SocketInfo> process_anc_data(int sock, msghdr* msg);

    // enqueue new data to early received packets from catch-all socket
    // return  tuple:
    // 0: true if the session is new
    // 1: session key
    bool add_first_datagrams(int sock, SocketInfo& pinfo);
    void on_left_new_raw(int) override;


    void on_left_new_raw_old(int);
    void on_right_new_raw(int) override;
    
    int run() override;
    void on_run_round() override;

    int pop_for_worker(int id);

    inline void worker_count_preference(int c) { worker_count_preference_ = c; };
    inline int worker_count_preference() { return worker_count_preference_; };
    
    
    void set_quick_list(mp::vector<int>* quick_list) { quick_list_ = quick_list; };
    inline mp::vector<int>* get_quick_list() const { return quick_list_;};

    int task_count() const { return tasks_.size(); }
    constexpr int core_multiplier() const noexcept { return 4; };

private:
    threadedProxyWorker::proxy_type_t proxy_type_;
    mp::vector<int>* quick_list_ = nullptr;


    mp::vector<std::pair< std::thread*, Worker*>> tasks_;
    int worker_count_preference_=0;
    int create_workers(int count=0);

};



struct ReceiverRedirectMap {
private:
    ReceiverRedirectMap() = default;

public:
    ReceiverRedirectMap(ReceiverRedirectMap const&) = delete;
    ReceiverRedirectMap& operator=(ReceiverRedirectMap const&) = delete;

    // to support iptables redirect target limitation
    using redir_target_t = std::pair<std::string, unsigned short>;
    using redir_target_map_t = std::map<int, redir_target_t>;

    redir_target_map_t  rmap_;
    std::mutex redir_target_lock_;

    void map_add(unsigned short port, redir_target_t entry) {
        std::scoped_lock<std::mutex> l_(redir_target_lock_);
        rmap_[port] = entry;
    }

    void map_clear() {
        std::scoped_lock<std::mutex> l_(redir_target_lock_);
        rmap_.clear();
    }

    // return redir target
    virtual std::optional<redir_target_t> redir_target(unsigned short redir_port) {

        std::scoped_lock<std::mutex> l_(redir_target_lock_);

        if(rmap_.find(redir_port) != rmap_.end()) {
            return  rmap_[redir_port];
        }
        return std::make_optional(std::make_pair("8.8.8.8", 53));
    };

    static ReceiverRedirectMap& instance() {
        static ReceiverRedirectMap r;
        return r;
    }
};


class ReceiverProxyError : public std::runtime_error {
public:
    explicit ReceiverProxyError(const char* w) : std::runtime_error(w) {};
};


template<class SubWorker>
class ThreadedReceiverProxy : public threadedProxyWorker, public MasterProxy {
public:
    ThreadedReceiverProxy(baseCom* c, uint32_t worker_id, threadedProxyWorker::proxy_type_t p):
            threadedProxyWorker(worker_id, p),
            MasterProxy(c) {}

    int handle_sockets_once(baseCom*) override;
    void on_run_round() override;

    static std::atomic_int& workers_total() {
        static std::atomic_int workers_total_ = 2;
        return workers_total_;
    };


};

#endif //_THREADED_RECEIVER_HPP_

#include <threadedreceiver.cpp>

