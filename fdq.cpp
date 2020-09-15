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
    hint_pairs_[id] = pa;

    return pa;
}

FdQueue::~FdQueue() {
    close_all();
}

int FdQueue::close_all() {

    int s = 0;
    std::for_each(hint_pairs_.begin(), hint_pairs_.end(), [&](auto& tup) {

        auto const& [ key, p ] = tup;

        ::close(p.first);
        ::close(p.second);

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

int FdQueue::push_all(int s) {
    std::lock_guard<std::mutex> lck(sq_lock_);
    sq_.push_front(s);

    for(auto [ key, pair ]: hint_pairs_) {
        int wr = ::write(pair.second, "A", 1);
        if (wr <= 0) {
            _err("FdQueue::push: failed to write hint byte - error[%d]: %s", wr, string_error().c_str());
        }
    }

    return sq_.size();
};

int FdQueue::pop(uint32_t worker_id) {

    int red = 0;
    char dummy_buffer[1];

    int returned_socket = 0;

    {

        // if we have hint-pair for each worker, we should read out hint message to not make a loop
        // because nobody else than us won't.
        try {
            red = ::read(hint_pairs_[worker_id].first, dummy_buffer, 1);
        } catch (std::out_of_range const& e) {
            throw fdqueue_error("hints out of bounds");
        }

        std::lock_guard<std::mutex> lck(sq_lock_);

        if (sq_.empty()) {
            return 0;
        }

        returned_socket = sq_.back();
        sq_.pop_back();

    }

    if(red > 0) {
        _dia("FdQueue::pop: clearing sq__hint %c", dummy_buffer[0]);
    } else {
        _dia("FdQueue::pop_for_worker: hint not read, read returned %d", red);
    }
    return returned_socket;
}

std::pair<int,int> FdQueue::hint_pair(uint32_t id) const {
    return hint_pairs_.at(id);
}