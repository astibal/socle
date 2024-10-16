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

#ifndef FDQUEUE_HPP
#define FDQUEUE_HPP

#include <tuple>
#include <optional>

#include <log/logan.hpp>
#include <mpstd.hpp>


struct WorkerPipe {

    using fd_pair_t = std::pair<int,int>;

    explicit WorkerPipe(fd_pair_t const& p): pipe(p){};
    WorkerPipe() = default;

    WorkerPipe(WorkerPipe const& other) : pipe(other.pipe), seen_worker_load(other.seen_worker_load.load()) {};
    WorkerPipe& operator=(WorkerPipe& ref) noexcept {
        pipe = ref.pipe;
        seen_worker_load = ref.seen_worker_load.load();
        return *this;
    }
    WorkerPipe& operator=(WorkerPipe&& ref) noexcept {
        pipe = ref.pipe;
        seen_worker_load = ref.seen_worker_load.load();
        return *this;
    }

    // pair of sockets used to talk between scheduler and worker.
    // scheduler sends one byte whenever wants to wake up worker to pick from task queue.
    fd_pair_t pipe = { -1, -1 };
    inline int pipe_to_scheduler() const noexcept { return  pipe.first; }
    inline int pipe_to_worker() const noexcept { return pipe.second; }

    std::atomic_uint32_t seen_worker_load = 0;
    static inline std::atomic_bool feedback_queue_empty = false;
};

class FdQueue {

public:
    FdQueue();
    virtual ~FdQueue();

    enum  class sq_type_t { SQ_PIPE = 0, SQ_SOCKETPAIR = 1 };
    sq_type_t sq_type() const { return sq_type_; }
    const char* sq_type_str() const;
    std::string stats_str(int indent=0) const;

    int close_all();
    std::size_t push_all(int s);

    void update_load(uint32_t worker_id, uint32_t load);
    int pop(uint32_t worker_id);
    template <typename UnaryPredicate>
    std::optional<int> pop_if(UnaryPredicate);

    std::pair<int, int> new_pair(uint32_t id);
    std::pair<int,int> hint_pair(uint32_t index) const;
    std::mutex& get_lock() const { return sq_lock_; }
    std::atomic_uint32_t& worker_id_max() { return worker_id_max_; }

private:

    // pipe created to be monitored by Workers with poll. If pipe is filled with *some* data
    // there is something in the queue to pick-up.


    sq_type_t sq_type_ = sq_type_t::SQ_SOCKETPAIR;

    mutable std::mutex sq_lock_;
    mp::deque<int> sq_;

    std::atomic_uint32_t worker_id_max_ = 0;

    using worker_id_t = unsigned int;
    mp::map<worker_id_t, WorkerPipe> hint_pairs_;

    logan_lite log;

    friend struct FdQueueHandler;
};


template <typename UnaryPredicate>
std::optional<int> FdQueue::pop_if(UnaryPredicate check_true) {

    auto l_ = std::scoped_lock(sq_lock_);

    if(sq_.empty())
        return {};

    uint32_t val = sq_.back();
    if(check_true(val)) {
        sq_.pop_back();
        return val;
    }

    return {};
}


// proxy and wrapper class for FdQueue
class fdqueue_error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct FdQueueHandler {
    FdQueueHandler() = delete;
    explicit FdQueueHandler(std::shared_ptr<FdQueue> fdq) : fdqueue(std::move(fdq)) {}

    [[nodiscard]] int pop(int worker_id) const {
        if(fdqueue)
            return fdqueue->pop(worker_id);

        throw fdqueue_error("handler: no fdqueue");
    }

    void update_load(uint32_t worker_id, uint32_t load) const {
        if(fdqueue) {
            fdqueue->update_load(worker_id, load);
            return;
        }

        throw fdqueue_error("handler: no fdqueue");
    }

    std::size_t hint_push_all(int s) const {
        if(fdqueue)
            return fdqueue->push_all(s);

        throw fdqueue_error("handler: no fdqueue");
    }

    [[nodiscard]] FdQueue::sq_type_t hint_sq_type() const {
        if(fdqueue)
            return fdqueue->sq_type();

        throw fdqueue_error("handler: no fdqueue");
    }

    [[nodiscard]] const char* sq_type_str() const {
        if(fdqueue)
            return fdqueue->sq_type_str();

        throw fdqueue_error("handler: no fdqueue");
    }

    template <typename UnaryPredicate>
    [[nodiscard]] std::optional<int> hint_pop_if(UnaryPredicate check_true) {
        if(fdqueue)
            return fdqueue->pop_if(check_true);

        throw fdqueue_error("handler: no fdqueue");
    }

    [[nodiscard]] std::pair<int,int> hint_pair(int index) const {
        if(fdqueue)
            return fdqueue->hint_pair(index);

        throw fdqueue_error("handler: no fdqueue");
    }

    [[nodiscard]] std::pair<int,int> hint_new_pair(uint32_t id) const {
        if(fdqueue)
            return fdqueue->new_pair(id);

        throw fdqueue_error("handler: no fdqueue");
    }

    [[nodiscard]] std::atomic_uint32_t& worker_id_max() {
        if(fdqueue)
            return fdqueue->worker_id_max();

        throw fdqueue_error("handler: no fdqueue");
    }

    [[nodiscard]] std::string stats_str(int indent=0) {
        if(fdqueue)
            return fdqueue->stats_str(indent);

        throw fdqueue_error("handler: no fdqueue");
    }

private:
    std::shared_ptr<FdQueue> fdqueue;
};


#endif //FDQUEUE_HPP