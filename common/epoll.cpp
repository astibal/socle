#include <epoll.hpp>
#include <hostcx.hpp>


int epoll::init() {
    // size in epoll_create is ignored since 2.6.8, but has to be greater than 0
    int s = epoll_create(1);
    epoll_fd_ = s;

    _dia("epoll::init: epoll socket created: %d", s);
    if (s == -1) {
        _err("epoll::init:%x: epoll_create failed! errno %d", this, errno);
    }
    rescan_timer = std::chrono::high_resolution_clock::now();

    return s;
}

void epoll::_debug_sockets(int nfds) {
    if (nfds > 0) {
        _ext("epoll::wait: %d socket events", nfds);

        std::string ports;
        for (int xi = 0; xi < nfds; ++xi) {
            ports += std::to_string(events[xi].data.fd);

            if (events[xi].events & EPOLLIN) ports += "r";
            if (events[xi].events & EPOLLOUT) ports += "w";
            if (events[xi].events & EPOLLERR) ports += "e";
            if (events[xi].events & EPOLLHUP) ports += "h";
            ports += " ";

        }
        _deb("epoll::wait: ports: %s", ports.c_str());
    } else if (nfds == 0) {
        _deb("epoll::wait: ports: <none>");
    }
    else {
        _deb("epoll::wait: error %d, %s", errno, string_error(errno).c_str());
    }
};

int epoll::process_epoll_events(int nfds) {
    int i = 0;

    for(; i < nfds and i < EPOLLER_MAX_EVENTS; ++i) {
        int socket = events[i].data.fd;
        uint32_t eventset = events[i].events;

        if(eventset & EPOLLIN) {
            if (socket == hint_socket()) {
                _dia("epoll::wait: hint triggered %d", socket);
            }

            _dia("epoll::wait: data received into socket %d", socket);

            // add socket to in_set
            in_set.insert(socket);
            clear_idle_watch(socket);
        }
        else if(eventset & EPOLLOUT) {
            _dia("epoll::wait: socket %d writable (auto_epollout_remove=%d)",socket , auto_epollout_remove);

            out_set.insert(socket);
            clear_idle_watch(socket);

            if(auto_epollout_remove) {
                modify(socket,EPOLLIN);
            }

        }
        else if( eventset & EPOLLERR or eventset & EPOLLHUP ) {
            _dia("epoll::wait: error event %d for socket %d", eventset, socket);
            err_set.insert(socket);
        }
        else {
            _dia("epoll::wait: uncaught event value %d for socket %d", eventset, socket);
            err_set.insert(socket);
        }
    }

    return i;
}

void epoll::process_pre_wait_idles() {
    // idle timer?
    if(idle_counter > idle_timeout_ms) {
        idle_counter = 0;

        // toggle idle round
        idle_round = not idle_round;

        if(not idle_round) {

            mp::set<int> cp;
            {
                auto l = std::scoped_lock(idle_watched_pre.get_lock());

                // moving _pre to idle_watched
                if (!idle_watched_pre.empty_ul())
                    _deb("epoll::wait: idle round %d, moving %d sockets to idle watch", idle_round,
                         idle_watched_pre.size_ul());

                for (auto s: idle_watched_pre.get_ul()) {
                    cp.insert(s);
                }
                idle_watched_pre.clear_ul();
            }
            for(auto s: cp)
                idle_watched.insert(s);


        } else {

            mp::set<int> cp;
            {
                auto l = std::scoped_lock(idle_watched.get_lock());

                // finally idle sockets
                if(! idle_watched.empty_ul())
                    _dia("epoll::wait: idle round %d, %d sockets marked idle", idle_round, idle_watched.size_ul());

                for (auto s: idle_watched.get_ul()) {
                    _dia("epoll::wait: idle socket %d", s);

                    cp.insert(s);
                }
                idle_watched.clear_ul();
            }
            for(auto s: cp)
                idle_set.insert(s);
        }
    }
}

void epoll::process_pre_wait_rescans() {
    // Setting up rescans!
    {
        auto l_ = std::scoped_lock(rescan_set_in.get_lock());

        for (auto isock: rescan_set_in.get_ul()) {
            _deb("epoll::wait rescanning EPOLLIN socket %d", isock);
            add(isock, EPOLLIN);
        }
        rescan_set_in.clear_ul();
    }

    {
        auto l_ = std::scoped_lock(rescan_set_out.get_lock());

        for (auto osock: rescan_set_out.get_ul()) {
            _deb("epoll::wait rescanning EPOLLIN|OUT socket %d", osock);
            add(osock, EPOLLIN | EPOLLOUT);
        }
        rescan_set_out.clear_ul();
    }
}

void epoll::enforced_to_inset() {
    mp::set<int> cp;
    {
        auto l_ = std::scoped_lock(enforce_in_set.get_lock());

        if (!enforce_in_set.empty_ul()) {
            _dia("epoll::wait: enforced sockets set active");
            for (auto enforced_fd: enforce_in_set.get_ul()) {
                cp.insert(enforced_fd);
                _deb("epoll::wait: enforced socket %dr", enforced_fd);
            }
            enforce_in_set.clear_ul();
        }
    }
    for(auto s: cp) {
        in_set.insert(s);
    }
}

void epoll::clear() {

    // memset(events,0,EPOLLER_MAX_EVENTS*sizeof(epoll_event));

    in_set.clear();
    out_set.clear();
    idle_set.clear();
    err_set.clear();
}

int epoll::wait(long timeout) {

    _deb("epoll::wait: == begin, timeout %dms %s", timeout, enforce_in_set.empty() ? "" : "+ enforced sockets");

    clear();
    
    // Pre-populate epoll from rescan lists
    
    if(click_timer_now()) {
        process_pre_wait_rescans();
        process_pre_wait_idles();
    }
    
    // wait for epoll
    
    int nfds = 0;
    int cur_nfds = 0;
    unsigned count = 0;
    do {
        cur_nfds = epoll_wait(epoll_socket(), events, EPOLLER_MAX_EVENTS, timeout);
        if(cur_nfds < 0) {
            if(errno == EINTR) {
                return nfds;
            }
            _err("epoll::wait: epoll_wait fatal error %d: %s", errno, string_error(errno).c_str());
            return -1;
        }
        nfds += cur_nfds;

        // optimized-out in Release builds
        _if_deb {
            _debug_sockets(cur_nfds);
        }

        int proc = process_epoll_events(cur_nfds);
        _deb("epoll::wait: processed %d from %d ready sockets - round %d", proc, nfds, count);

        count++;

    } while (cur_nfds == EPOLLER_MAX_EVENTS);

    enforced_to_inset();

    _dum("epoll::wait: == end, %d loops", count);
    return nfds;
}

bool epoll::add(int socket, int mask) {
    struct epoll_event ev;
    memset(&ev,0,sizeof ev);
    
    ev.events = mask;
    ev.data.fd = socket;

    int fd = epoll_socket();
    
    _deb("epoll:add:%x: epoll_ctl(%d): called to add socket %d ",this, fd, socket);
    
    if (::epoll_ctl(fd, EPOLL_CTL_ADD, socket, &ev) == -1) {
        if(errno == EEXIST) {
            _ext("epoll:add:%x: epoll_ctl(%d): socket %d already added",this, fd, socket);
        }
        else {
            _err("epoll:add:%x: epoll_ctl(%d): cannot add socket %d: %s",this, fd, socket, string_error().c_str());
            return false;
        } 
    } else {
        _deb("epoll:add:%x: epoll_ctl(%d): socket added %d",this, fd, socket);
    }
    
    return true;
}

bool epoll::modify(int socket, int mask) {

    int fd = epoll_socket();
    epoll_event ev{};
    ev.events = mask;
    ev.data.fd = socket;

    _deb("epoll:modify:%x: epoll_ctl(%d): called to modify socket %d, epollin=%d,epollout=%d ",this, fd, socket,flag_check<int>(mask,EPOLLIN),flag_check<int>(mask,EPOLLOUT));


    if (::epoll_ctl(fd, EPOLL_CTL_MOD, socket, &ev) == -1) {
        if(errno == ENOENT) {
            _dia("epoll:modify:%x: epoll_ctl(%d): socket %d not monitored, fixing...",this, fd, socket);
            add(socket,mask);
            return false;
        }
        else {
            _err("epoll:modify:%x: epoll_ctl(%d): cannot modify socket %d: %s",this, fd, socket, string_error().c_str());
            return false;
        } 
    } else {
        _dia("epoll:modify:%x: epoll_ctl(%d): socket added %d",this, fd, socket);
    }
    
    return true;
}

bool epoll::del(int socket) {

    int fd = epoll_socket();
    epoll_event ev{};
    memset(&ev,0,sizeof ev);
    
    ev.events = 0;
    ev.data.fd = socket;
    
    _deb("epoll:del:%x: epoll_ctl(%d): called to delete socket %d ",this, fd, socket);
    
    if (::epoll_ctl(fd, EPOLL_CTL_DEL, socket, &ev) == -1) {

        return false;
    } else {
        _dia("epoll:del:%x: epoll_ctl(%d): socket deleted %d",this, fd, socket);
    }
    
    return true;
}


bool epoll::in_read_set(int check) {
    return in_set.find(check);
}

bool epoll::in_write_set(int check) {
    return true;
}

bool epoll::in_idle_set(int check) {
    return idle_set.find(check);
}

bool epoll::in_idle_watched_set(int check) {
    return idle_watched.find(check);
}


bool epoll::hint_socket(int socket) {

    int fd = epoll_socket();

    if(hint_socket() > 0) {

        int h_fd = hint_socket();

        struct epoll_event rem_ev;
        rem_ev.events = EPOLLIN;
        rem_ev.data.fd = hint_socket();
        
        _dia("epoll:hint_socket:%x: epoll_ctl(%d): removing old hint socket %d",this, fd,hint_socket());
        ::epoll_ctl(fd,EPOLL_CTL_DEL, h_fd, &rem_ev);
    }
    
    if(add(socket,EPOLLIN)) {
        _dia("epoll:hint_socket:%x: epoll_ctl(%d): setting hint socket %d",this, fd, socket);
        hint_fd_ = socket;

    } else {
        _dia("epoll:hint_socket:%x: epoll_ctl(%d): setting hint socket %d FAILED.",this, fd, socket);
        return false;
    }
    return true;
}


bool epoll::rescans_empty() const {
    return ( rescan_set_in.empty() and rescan_set_out.empty() );
}

bool epoll::rescan_in(int socket) {
    if(socket > 0) {

        del(socket);
        
        // re-init timer, otherwise let it be
        if(rescan_set_in.empty()) {
            rescan_timer = std::chrono::high_resolution_clock::now();
        }
        
        rescan_set_in.insert(socket);
        return true;
    }
    
    return false;
}

bool epoll::enforce_in(int socket) {
    if(socket > 0) {
        enforce_in_set.insert(socket);
    }

    return true;
}

unsigned long epoll::cancel_rescan_in(int socket) {
    if(socket > 0) {
        return rescan_set_in.erase(socket);
    }

    return 0L;
}



bool epoll::rescan_out(int socket) {
    if(socket > 0) {

        del(socket);
        
        // re-init timer, otherwise let it be
        if(rescan_set_out.empty()) {
            rescan_timer = std::chrono::high_resolution_clock::now();
        }
        
        rescan_set_out.insert(socket);
        return true;
    }
    
    return false;
}

unsigned long epoll::cancel_rescan_out(int socket) {
    if(socket > 0) {
        return rescan_set_out.erase(socket);
    }

    return 0L;
}


bool epoll::click_timer_now () {

    auto now = std::chrono::high_resolution_clock::now();

    
    auto ms_diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - rescan_timer).count();
    if(ms_diff > baseCom::rescan_msec) {
        rescan_timer = now;
        _ext("epoll::click_timer_now: diff = %d",ms_diff);

        idle_counter += ms_diff;
        if(idle_counter > idle_timeout_ms) {
            _ext("epoll::click_timer_now: idle counter = %d",idle_counter);
        }
        return true;
    }
    return false;
}

void epoll::set_idle_watch(int check){
    idle_watched_pre.insert(check);
}

unsigned long epoll::clear_idle_watch(int check) {

    unsigned long ret = 0L;

    unsigned long ip = idle_watched_pre.erase(check);
    unsigned long iw = 0;
    if (ip <= 0) {
        iw = idle_watched.erase(check);
    }
    if (ip > 0) {
        _deb("epoll::clear_handler %d -> clearing idle watchlist [pre: %ld list: %ld]", check, ip, iw);
    }

    ret = iw + ip;

    return ret;
}



void epoller::init_if_null()
{
    if (poller == nullptr) {

        _deb("creating a new poller instance");

        poller = std::make_unique<epoll>();
        if (poller->init() < 0) {
            poller = nullptr;
            _fat("cannot create poller instance!!!");
            exit(-1);
        }
    }
}

epoller::~epoller() {
    for(auto& [sock, hi]: handler_db) {
        hi.handler->registrant = nullptr;
    }
}

bool epoller::add(int socket, int mask)
{
    init_if_null();
    
    if(poller != nullptr) {
        return poller->add(socket,mask);
    }
    
    return false;
}

bool epoller::modify(int socket, int mask)
{
    init_if_null();
    
    if(poller != nullptr) {
        return poller->modify(socket,mask);
    }
    
    return false;
}

bool epoller::del(int socket)
{
    init_if_null();
    
    if(poller != nullptr) {
        return poller->del(socket);
    }
    clear_handler(socket);
    
    return false;
}

bool epoller::rescans_empty() {

    init_if_null();

    if(poller != nullptr) {
        return poller->rescans_empty();
    }

    // return true if there is no poller!
    return true;

}

bool epoller::rescan_in(int socket)
{
    init_if_null();
    
    if(poller != nullptr) {
        return poller->rescan_in(socket);
    }
    
    return false;
}

bool epoller::enforce_in(int socket) {
    init_if_null();

    if(poller != nullptr) {
        return poller->enforce_in(socket);
    }

    return false;
}

unsigned long epoller::cancel_rescan_in(int socket)
{
    init_if_null();

    if(poller != nullptr) {
        return poller->cancel_rescan_in(socket);
    }

    return 0;
}

bool epoller::rescan_out(int socket)
{
    init_if_null();
    
    if(poller != nullptr) {
        return poller->rescan_out(socket);
    }
    
    return false;
}

unsigned long epoller::cancel_rescan_out(int socket)
{
    init_if_null();

    if(poller != nullptr) {
        return poller->cancel_rescan_out(socket);
    }

    return 0;
}

bool epoller::click_timer_now ()
{
    init_if_null();
    
    if(poller != nullptr) {
        return poller->click_timer_now();
    }
    
    return false;
}


bool epoller::hint_socket(int socket)
{
    init_if_null();
    
    if(poller != nullptr) {
        return poller->hint_socket(socket);
    }
    
    return false;
}


bool epoller::in_read_set(int check)
{
    init_if_null();
    if(poller) return poller->in_read_set(check);
    
    return false;
}

bool epoller::in_write_set(int check)
{
    init_if_null();
    if(poller) return poller->in_write_set(check);
    
    return false;
}
bool epoller::in_idle_set(int check)
{
    init_if_null();
    if(poller) return poller->in_idle_set(check);

    return false;
}


int epoller::wait(long timeout) {
    init_if_null();
    if(poller) return poller->wait(timeout);
    
    return 0;
}

void epoller::set_idle_watch(int check){
    init_if_null();

    if(poller) {
        poller->set_idle_watch(check);
    }
}
void epoller::clear_idle_watch(int check){
    init_if_null();

    if(poller) {
        poller->clear_idle_watch(check);
    }
}

epoll_handler* epoller::get_handler(int check) {

    auto lc_ = std::shared_lock(lock_);

    auto it = handler_db.find(check);
    
    if(it == handler_db.end()) {
        return nullptr;
    } else {
        handler_info_t& ret = it->second;
        return ret.handler;
    }

    return nullptr;
}
void epoller::clear_handler(int check) {

    {
        auto lc_ = std::unique_lock(lock_);

        auto n_removed = handler_db.erase(check);
        if(n_removed > 0) {
            _deb("epoller::clear_handler %d", check);
        }
    }

    if(poller) {
        unsigned long r = poller->rescan_set_in.erase(check);
        unsigned long w = poller->rescan_set_out.erase(check);
        _deb("epoller::clear_handler %d -> clearing rescans [r: %ld w: %ld]",check, r, w);

        poller->clear_idle_watch(check);
    }
}


void epoller::set_handler(int check, epoll_handler* h) {

    if(h != nullptr) {

        {
            auto lc_ = std::unique_lock(lock_);
            handler_info_t &href = handler_db[check];
            href.handler = h;
        }
        _deb("epoller::set_handler %d -> 0x%x",check,h);


        auto l_ = std::scoped_lock(h->registered_sockets.get_lock());

        if(h->registrant && h->registrant != this) {
            _err("epoller::set_handler: setting handler over already existing, different handler. This should not happen!");
            // since registrant will be modified, we need to clear old registrant handlers.
            
            for(auto cur_socket: h->registered_sockets.get_ul()) {
                _err("epoller::set_handler:  moving old socket %d handler to new one", cur_socket);

                auto lc_ = std::unique_lock(lock_);
                // new is created if it doesn't exist yet
                handler_info_t& curhref  = handler_db[cur_socket];
                curhref.handler = h;
                curhref.stats.clear();
            }
        }
        h->registrant = this;
        h->registered_sockets.insert_ul(check);
    }
    else {
        clear_handler(check);
    }
    
}

void socket_state::update(int s) {

    if( com_ && socket_ != 0) {
        switch(s) {
            case socket_state::SS_CLOSING:
                // close, unhandle
                // at any rate, we got all we need. Unmonitor, unhandle and close socket
                com_->unset_monitor(socket_);
                com_->set_poll_handler(socket_ ,nullptr);

                if(owner_) {
                    ::close(socket_);
                    socket_ = 0;
                }

                state_ = SS_NONE;
                break;

            case socket_state::SS_OPENING:
                // set handler

                com_->set_write_monitor(socket_);
                com_->set_poll_handler(socket_, handler_);

                com_->set_idle_watch(socket_);
                break;

            default:
                // socket properties ok, but state is unknown => change the value at least
                state_ = s;
        }
    } else {
        // if there is no specific state handler switch, change at least

        state_ = s;
    }

}


void socket_state::mon_read() {
    if(com_ && socket_ != 0) {
        com_->master()->change_monitor(socket_, EPOLLIN);
    }

}
void socket_state::mon_write() {
    if(com_ && socket_ != 0) {
        com_->master()->change_monitor(socket_, EPOLLOUT);
    }
}

void socket_state::mon_none() {
    if(com_ && socket_ != 0) {
        com_->master()->unset_monitor(socket_);
    }
}


socket_state::~socket_state() {

    // try to behave and at least close file descriptor.
    // we don't want to run closing() within destructor, too unsafe.

    if(owner_ && socket_ > 0) {
        ::close(socket_);
    }
}