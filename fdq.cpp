#include <unistd.h>
#include <fcntl.h>

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

std::string FdQueue::stats_str(int indent) const {

    std::multimap<uint64_t, WorkerPipe const*> candidates;
    std::stringstream ss;

    for(auto const& [ key, pipes ]: hint_pairs_) {
        candidates.insert(std::pair(pipes.seen_worker_load.load(), &pipes));
    }

    constexpr size_t max_sz = 10240;
    std::array<unsigned char, max_sz> dummy {};

    for(auto const& [ load, pipe]: candidates) {

        // note: the point of view is opposite than you may think (it's from PoV from the using component)
        //       to_scheduler is read by worker
        //       to_worker is written by scheduler
        auto sock_to_scheduler = pipe->pipe_to_scheduler();
        auto sock_to_worker = pipe->pipe_to_worker();

        auto red = ::recv(sock_to_scheduler, dummy.data(), max_sz, MSG_PEEK);

        for (int i = 0; i < indent; ++i) { ss << " "; } // make indent

        ss << string_format("hint pipe[%d][%d] worker_side=%dB load=%d", sock_to_worker, sock_to_scheduler, red, load);
        if(red < 0) {
            if(errno != EAGAIN and errno != EWOULDBLOCK) {
                ss << " ++ error: " << string_error();
            }
            else {
                ss << " ++ ok: (EAGAIN)";
            }
        }
        else if(static_cast<size_t>(red) >= max_sz) {
            ss << " ++ max buffer read (there is probably even more)";
        }

        ss << "\n";
    }

    std::size_t qsz = 0;
    {
        auto lc_ = std::lock_guard(sq_lock_);
        qsz = sq_.size();
    }

    for (int i = 0; i < indent; ++i) { ss << " "; } // make indent
    ss << "Socket queue size: " << qsz << "\n";

    return ss.str();
}

long purge_socket(int socket) {
    constexpr size_t max_sz = 10240;
    std::array<unsigned char, max_sz> dummy{};
    return ::recv(socket, dummy.data(), max_sz, MSG_DONTWAIT);
}

int FdQueue::pop(uint32_t worker_id) {

    ssize_t red = 0;
    char dummy_buffer[1];

    int returned_socket = 0;
    auto my_hint_socket = hint_pairs_[worker_id].pipe_to_scheduler();

    // if we have hint-pair for each worker, we should read out hint message to not make a loop
    // because nobody else than us won't.
    try {
        int last_errno = 0;
        const int max_loop = 42;
        int would_be_blocked_counter = 0;
        for(int i = 0; i < max_loop && red <= 0; ++i) {
            red = ::read(my_hint_socket, dummy_buffer, 1);
            if(red > 0) {
                break;
            }
            else if(red < 0) {
                const timespec t { .tv_sec = 0, .tv_nsec = 1000 };
                timespec rem {};
                last_errno = errno;

                if(last_errno != EAGAIN and last_errno != EWOULDBLOCK) {
                    _cri("FdQueue::pop: unrecoverable error reading socket");
                    return 0;
                }
                nanosleep(&t, &rem);
                ++would_be_blocked_counter;
            }
            else {
                _cri("FdQueue::pop: EOT");
                return 0;
            }
        }

        if(red < 0) {
            if(last_errno == EAGAIN or last_errno == EWOULDBLOCK) {
                _err("FdQueue::pop: all %d attempts reading hint socket would block", max_loop);
            }
            else {
                // this should be unreachable code
                _err("FdQueue::pop: reading hint socket error: ret=%d, errno=%d, attempts=%d", red, last_errno, max_loop);
            }

            // we should not act when we cannot remove data from hint socket
            // Details:
            //   Even though it seems ok to remove task from the list, ignoring
            //   bytes in the hint sockets may lead to fill spuriously socket buffer
            return 0;
        }

        if(would_be_blocked_counter > 0) {
            _dia("FdQueue::pop: from max %d attempts, we hit EAGAIN %d times", max_loop, would_be_blocked_counter);
        }

    } catch (std::out_of_range const&) {
        throw fdqueue_error("hints out of bounds");
    }

    std::optional<long> purged = -1;
    // critical section
    {
        auto lc_ = std::scoped_lock(sq_lock_);

        if (sq_.empty()) {

            // report to scheduler queue is empty. It's not required, but it's nice from us.
            WorkerPipe::feedback_queue_empty = true;
            purged = purge_socket(my_hint_socket);
        } else {

            returned_socket = sq_.back();
            sq_.pop_back();

            // do another check and report to scheduler
            if (sq_.empty()) {
                WorkerPipe::feedback_queue_empty = true;
                purged = purge_socket(my_hint_socket);
            }
        }
    }

    if(red > 0) {
        _dia("FdQueue::pop: clearing sq__hint %c", dummy_buffer[0]);
    } else {
        _dia("FdQueue::pop_for_worker: hint not read, read returned %d", red);
    }

    if (purged.has_value()) {
        if (purged.value() > 0) {
            _dia("FdQueue::pop: heavy load - worker side hint socket dump %d", purged.value());
        }
        else if(purged.value() == 0) {
        _err("FdQueue::pop: heavy load - worker side hint socket dump failed: %d, %s",
             purged.value(), string_error().c_str());
        }
    }


    return returned_socket;
}

std::pair<int,int> FdQueue::hint_pair(uint32_t id) const {
    return hint_pairs_.at(id).pipe;
}