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

#ifndef _FDQUEUE_HPP_
#define _FDQUEUE_HPP_

#include <tuple>

#include <log/logan.hpp>
#include <mpstd.hpp>

class FdQueue {

public:
    FdQueue();
    virtual ~FdQueue();

    enum  class sq_type_t { SQ_PIPE = 0, SQ_SOCKETPAIR = 1 } sq_type_;
    sq_type_t sq_type() const { return sq_type_; }
    const char* sq_type_str() const;


    // pipe created to be monitored by Workers with poll. If pipe is filled with *some* data
    // there is something in the queue to pick-up.

    int close_all();
    int push_all(int s);
    int pop(uint32_t worker_id);
    template <typename UnaryPredicate>
    std::optional<int> pop_if(UnaryPredicate);

    std::pair<int, int> new_pair(uint32_t id);
    std::pair<int,int> hint_pair(uint32_t index) const;
    std::mutex& get_lock() const { return sq_lock_; }
    std::atomic_uint32_t& worker_id_max() { return worker_id_max_; }
protected:
    mutable std::mutex sq_lock_;
    mp::deque<int> sq_;

    std::atomic_uint32_t worker_id_max_ = 0;
    using worker_id_t = unsigned int;
    std::map<worker_id_t, std::pair<int,int>> hint_pairs_;

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
    explicit fdqueue_error(const char* what) : std::runtime_error(what) {};
};

struct FdQueueHandler {
    FdQueueHandler() = delete;
    explicit FdQueueHandler(std::shared_ptr<FdQueue> fdq) : fdqueue(std::move(fdq)) {}

    [[nodiscard]] int pop(int worker_id) const {
        if(fdqueue)
            return fdqueue->pop(worker_id);

        throw fdqueue_error("handler: no fdqueue");
    }

    int hint_push_all(int s) const {
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

    [[nodiscard]] int hint_close_all() {
        if(fdqueue)
            return fdqueue->close_all();

        throw fdqueue_error("handler: no fdqueue");
    }

    [[nodiscard]] std::pair<int,int> hint_new_pair(uint32_t id) {
        if(fdqueue)
            return fdqueue->new_pair(id);

        throw fdqueue_error("handler: no fdqueue");
    }

    [[nodiscard]] std::atomic_uint32_t& worker_id_max() {
        if(fdqueue)
            return fdqueue->worker_id_max();

        throw fdqueue_error("handler: no fdqueue");
    }

private:
    std::shared_ptr<FdQueue> fdqueue;
};


#endif //_FDQUEUE_HPP_