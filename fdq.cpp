#include <unistd.h>
#include <sys/fcntl.h>

#include <fdq.hpp>

#define USE_SOCKETPAIR


FdQueue::FdQueue() : log("acceptor.fdqueue") {}

std::pair<int, int> FdQueue::new_pair(uint32_t id) {

    int hint_pair[2] = { -1, -1 };

    auto l_ = std::scoped_lock(get_lock());

#ifdef USE_SOCKETPAIR
    if(0 == ::socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0, hint_pair)) {
        _inf("acceptor: using socketpair");
        sq_type_ = sq_type_t::SQ_SOCKETPAIR;
    }
    else if( 0 == pipe2(hint_pair, O_DIRECT | O_NONBLOCK)) {
        _inf("acceptor: using pipe2");
        sq_type_ = sq_type_t::SQ_PIPE;
    }

#else
    if(version_check(get_kernel_version(),"3.4")) {
        _deb("Acceptor: kernel supports O_DIRECT");
        if ( 0 != pipe2(hint_pair,O_DIRECT|O_NONBLOCK)) {
            _err("ThreadAcceptor::new_raw: hint pipe not created, error[%d], %s", errno, string_error().c_str());
        }
    } else {
        _war("Acceptor: kernel doesn't support O_DIRECT");
        if (0 != pipe2(hint_pair,O_NONBLOCK)) {
            _err("ThreadAcceptor::new_raw: hint pipe not created, error[%d], %s", errno, string_error().c_str());
        }
    }
#endif

    auto pa = std::make_pair(hint_pair[0], hint_pair[1]);
    hint_pairs_[id] = WorkerPipe(pa);

    return pa;
}

FdQueue::~FdQueue() {
    close_all();
}

int FdQueue::close_all() {

    int s = 0;
    std::for_each(hint_pairs_.begin(), hint_pairs_.end(), [&](auto const& pair) {

        auto const& worker_pipe = pair.second;

       ::close(worker_pipe.pipe_to_scheduler());
        ::close(worker_pipe.pipe_to_worker());

        s++;
    });

    hint_pairs_.clear();

    return s;
}

const char* FdQueue::sq_type_str() const {
    switch (sq_type_) {
        case sq_type_t::SQ_PIPE:
            return "pipe";
        case sq_type_t::SQ_SOCKETPAIR:
            return "socketpair";
    }
    return "unknown";
}

std::size_t FdQueue::push_all(int s) {

    {
        auto lc_ = std::scoped_lock(sq_lock_);
        sq_.push_front(s);
    }

    uint64_t entry_count = 0;
    uint64_t written_sum = 0;

    auto write_to_socket = [this](auto sock) {
        auto wr = ::write(sock, "A", 1);
        if (wr <= 0) {
            _err("FdQueue::push: failed to write hint byte - socket[%d] error[%d]: %s", sock, wr,
                 string_error().c_str());
            return 0;
        } else {
            return 1;
        }
    };

    std::multimap<uint64_t, WorkerPipe const*> candidates;

    for(auto const& [ key, pipes ]: hint_pairs_) {
        ++entry_count;
        candidates.insert(std::pair(pipes.seen_worker_load.load(), &pipes));

        _deb("FdQueue::push: candidate with load %d inserted", pipes.seen_worker_load.load());
    }

    for(auto const& candy: candidates) {
        ++written_sum;
        if(written_sum > entry_count/2) break;

        _deb("FdQueue::push: candidate with load %d summoned", candy.second->seen_worker_load.load());
        auto sock = candy.second->pipe_to_worker();
        written_sum += write_to_socket(sock);

        // mechanism to help further avoid spurious wake-ups.
        // if reported from worker, we stop notifying the rest.
        if(WorkerPipe::feedback_queue_empty) {
            _deb("FdQueue::push: feedback - queue is already empty");
            WorkerPipe::feedback_queue_empty = false;
            break;
        }
    }

    return entry_count;
}

void FdQueue::update_load(uint32_t worker_id, uint32_t load) {
     auto it = hint_pairs_.find(worker_id);
     if(it != hint_pairs_.end()) {
         it->second.seen_worker_load = load;
     }
}

int FdQueue::pop(uint32_t worker_id) {

    ssize_t red = 0;
    char dummy_buffer[1];

    int returned_socket = 0;

    {

        // if we have hint-pair for each worker, we should read out hint message to not make a loop
        // because nobody else than us won't.
        try {
            red = ::read(hint_pairs_[worker_id].pipe_to_scheduler(), dummy_buffer, 1);
        } catch (std::out_of_range const&) {
            throw fdqueue_error("hints out of bounds");
        }

        auto lc_ = std::scoped_lock(sq_lock_);

        if (sq_.empty()) {

            // report to scheduler queue is empty. It's not required, but it's nice from us.
            WorkerPipe::feedback_queue_empty = true;
            return 0;
        }
        else {

            returned_socket = sq_.back();
            sq_.pop_back();

            // do another check and report to scheduler
            if (sq_.empty()) {
                WorkerPipe::feedback_queue_empty = true;
            }
        }
    }

    if(red > 0) {
        _dia("FdQueue::pop: clearing sq__hint %c", dummy_buffer[0]);
    } else {
        _dia("FdQueue::pop_for_worker: hint not read, read returned %d", red);
    }
    return returned_socket;
}

std::pair<int,int> FdQueue::hint_pair(uint32_t id) const {
    return hint_pairs_.at(id).pipe;
}