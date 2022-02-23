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

#ifndef THREADEDWORKER_HPP
#define THREADEDWORKER_HPP

#include <fdq.hpp>

struct proxyType {
    enum class proxy_type_t { NONE, TRANSPARENT, PROXY, REDIRECT } type_;
    std::string str() const;

    bool is_none() const { return type_ == proxy_type_t::NONE; };
    bool is_transparent() const { return type_ == proxy_type_t::TRANSPARENT; };
    bool is_proxy() const { return type_ == proxy_type_t::PROXY; };
    bool is_redirect() const { return type_ == proxy_type_t::REDIRECT; };

    static proxyType none() { return { .type_ = proxy_type_t::NONE }; };
    static proxyType transparent() { return { .type_ = proxy_type_t::TRANSPARENT }; };
    static proxyType proxy() { return { .type_ = proxy_type_t::PROXY }; };
    static proxyType redirect() { return { .type_ = proxy_type_t::REDIRECT }; };
};

class threadedProxyWorker  {

public:
    threadedProxyWorker(uint32_t worker_id, proxyType t): type_(t), worker_id_(worker_id) {}

    proxyType type_;

    [[nodiscard]]
    inline proxyType proxy_type() const { return type_; }
    uint32_t worker_id_ = 0;

};

inline std::string proxyType::str() const {
    switch(type_) {
        case proxy_type_t::NONE:
            return "none";

        case proxy_type_t::TRANSPARENT:
            return "transparent";

        case proxy_type_t::PROXY:
            return "proxy";

        case proxy_type_t::REDIRECT:
            return "redirected";
    }

    return "unknown";
}


template<class WorkerType>
class hasWorkers {

private:
    std::shared_ptr<FdQueue> fdq_;

public:
    hasWorkers() = delete;
    // we need to link this class object to where we register workers (this abstraction costs referencing to child class parent, but it's worth it)
    explicit hasWorkers(std::shared_ptr<FdQueue> fdq) : fdq_(fdq) {
    }

    void worker_count_preference(int c) { worker_count_preference_ = c; };
    int worker_count_preference() const { return worker_count_preference_; };

    auto& tasks() { return tasks_; };
    auto task_count() const { return tasks_.size(); }

    constexpr int core_multiplier() const noexcept { return 1; };

    virtual ~hasWorkers() {
        join_workers();
    };

    void join_workers() {
        if (!tasks_.empty()) {

            for (auto &thread_worker: tasks_) {
                thread_worker.second->state().dead(true);
            }

            for (unsigned int i = 0; i < tasks_.size(); i++) {
                auto &t_w = tasks_.at(i);

                if(t_w.first->joinable())
                    t_w.first->join();

            }

            tasks_.clear();
        }
    }

    int create_workers(int count, baseCom* parent_com, proxyType proxy_type) {

        logan_lite log("service");

        auto nthreads = std::thread::hardware_concurrency();

        // on default , do the magic as pre-set
        if(count == 0) {
            nthreads = worker_count_preference();
            _dia("create_workers: detected %d cores to use, multiplier to apply: %d.", nthreads, core_multiplier());
            nthreads *= core_multiplier();
        }

        // on overridden positive, set count exactly as it has been specified by argument
        else if(count > 0) {
            nthreads = count;
            _dia("create_workers: threads pool-size overridden: %d", nthreads);

        }

        // on overridden negative we want to disable service and not spawning any workers
        else if (count < 0) {
            WorkerType::workers_total() = count;
            return count;
        }

        WorkerType::workers_total() = nthreads;

        for( unsigned int i = 0; i < nthreads; i++) {

            uint32_t this_worker_id = fdq_->worker_id_max()++;

            // register this
            auto pa = fdq_->new_pair(this_worker_id);

            _deb("create_workers: acceptor[0x%x][%d]: created queue socket pair %d,%d", std::this_thread::get_id(), i, pa.first, pa.second);

            auto *w = new WorkerType(parent_com->replicate(), this_worker_id, proxy_type);

            _dia("create_workers: acceptor[0x%x][%d]: new worker id=%d, queue hint pipe socket %d", std::this_thread::get_id(), i, this_worker_id, pa.first);
            w->com()->set_hint_monitor(pa.first);

            tasks_.template emplace_back( std::make_pair(nullptr, std::unique_ptr<WorkerType>(w)) );
        }

        return nthreads;
    };

private:
    int worker_count_preference_=0;
    mp::vector<std::pair< std::unique_ptr<std::thread>, std::unique_ptr<WorkerType>>> tasks_;
};



#endif //THREADEDWORKER_HPP
