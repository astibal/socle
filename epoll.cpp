#include <epoll.hpp>
#include <hostcx.hpp>

loglevel epoll::log_level = INF;

int epoll::init() {
    // size in epoll_create is ignored since 2.6.8, but has to be greater than 0
    fd = epoll_create(1);
    _dia("epoll::init: epoll socket created: %d",fd);
    if (fd == -1) {
        _err("epoll::init:%x: epoll_create failed! errno %d",this,errno);
    }
    ftime(&rescan_timer);
    
    return fd;
}

int epoll::wait(int timeout) {

    if(! enforce_in_set.empty()) {
        _deb("epoll::wait: == begin, timeout %dms, enforce queued sockets ", timeout);
    } else {
        _dum("epoll::wait: == begin, timeout %dms", timeout);
    }
    
    clear();
    
    // Pre-populate epoll from rescan lists
    
    if(click_timer_now()) {

        // Setting up rescans!

        for (auto isock: rescan_set_in) {
            _deb("epoll::wait rescanning EPOLLIN socket %d",isock);
            add(isock,EPOLLIN);
        }
        rescan_set_in.clear();
        
        for (auto osock: rescan_set_out) {
            _deb("epoll::wait rescanning EPOLLIN|OUT socket %d",osock);
            add(osock, EPOLLIN|EPOLLOUT);
        }
        rescan_set_out.clear();

        // idle timer?
        if(idle_counter > idle_timeout_ms) {
            idle_counter = 0;

            // toggle idle round
            idle_round > 0  ? idle_round = 0 : idle_round = 1;

            if(idle_round == 0) {
                // moving _pre to idle_watched
                if(! idle_watched_pre.empty())
                    _deb("epoll::wait: idle round %d, moving %d sockets to idle watch", idle_round, idle_watched_pre.size());

                for (auto s: idle_watched_pre) {
                    idle_watched.insert(s);
                }
                idle_watched_pre.clear();

            } else {
                // finally idle sockets
                if(! idle_watched.empty())
                    _dia("epoll::wait: idle round %d, %d sockets marked idle", idle_round, idle_watched.size());

                for (auto s: idle_watched) {
                    _dia("epoll::wait: idle socket %d", s);

                    idle_set.insert(s);
                }
                idle_watched.clear();
            }
        }
    }
    
    // wait for epoll
    
    int nfds = epoll_wait(fd, events, EPOLLER_MAX_EVENTS, timeout);
    
    if(nfds > 0) {
        _ext("epoll::wait: %d socket events",nfds);
    }
    
    
    if(( *log.level() >= DEB) && nfds > 0) {
        std::string ports;
        for(int xi = 0; xi < nfds; ++xi) {
            ports += std::to_string(events[xi].data.fd);
            
            if(events[xi].events & EPOLLIN) ports += "r";
            if(events[xi].events & EPOLLOUT) ports += "w";
            ports += " ";
            
        }
        _deb("ports: %s",ports.c_str());
    }
    
    for(int i = 0; i < nfds; ++i) {
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

        } else {
            _dia("epoll::wait: uncaught event value %d", eventset);
        }
    }
    if(! enforce_in_set.empty()) {
        _dia("epoll::wait: enforced sockets set active");
        for(auto enforced_fd: enforce_in_set ) {
            in_set.insert(enforced_fd);
            _deb("epoll::wait: enforced socket %dr", enforced_fd);
        }
        enforce_in_set.clear();
    }


    _dum("epoll::wait: == end");
    return nfds;
}

bool epoll::add(int socket, int mask) {
    struct epoll_event ev;
    memset(&ev,0,sizeof ev);
    
    ev.events = mask;
    ev.data.fd = socket;
    
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
        _dia("epoll:add:%x: epoll_ctl(%d): socket added %d",this, fd, socket);
    }
    
    return true;
}

bool epoll::modify(int socket, int mask) {
    epoll_event ev{0};
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
    struct epoll_event ev;
    memset(&ev,0,sizeof ev);
    
    ev.events = 0;
    ev.data.fd = socket;
    
    _deb("epoll:del:%x: epoll_ctl(%d): called to delete socket %d ",this, fd, socket);
    
    if (::epoll_ctl(fd, EPOLL_CTL_DEL, socket, &ev) == -1) {

        //_err("epoll:del:%x: epoll_ctl(%d): cannot delete socket %d: %s",this, fd, socket, string_error().c_str());
        //std::string str_bt = bt();
        //_err(str_bt.c_str());
        
        return false;
    } else {
        _dia("epoll:del:%x: epoll_ctl(%d): socket deleted %d",this, fd, socket);
    }
    
    return true;
}


bool epoll::in_read_set(int check) {
    auto f = in_set.find(check);
    return (f != in_set.end());
}

bool epoll::in_write_set(int check) {
//     auto f = out_set.find(check);
//     return (f != out_set.end());
    return true;
}

bool epoll::in_idle_set(int check) {
    auto f = idle_set.find(check);
    return (f != idle_set.end());
}

bool epoll::in_idle_watched_set(int check) {
    auto f = idle_watched.find(check);
    return (f != idle_watched.end());
}


bool epoll::hint_socket(int socket) {
    
    if(hint_socket() > 0) {
        struct epoll_event rem_ev;
        rem_ev.events = EPOLLIN;
        rem_ev.data.fd = hint_socket();
        
        _dia("epoll:hint_socket:%x: epoll_ctl(%d): removing old hint socket %d",this, fd,hint_socket());
        ::epoll_ctl(fd,EPOLL_CTL_DEL,hint_fd,&rem_ev);
    }
    
    if(add(socket,EPOLLIN)) {
        _dia("epoll:hint_socket:%x: epoll_ctl(%d): setting hint socket %d",this, fd, socket);
        hint_fd = socket;
    } else {
        _dia("epoll:hint_socket:%x: epoll_ctl(%d): setting hint socket %d FAILED.",this, fd, socket);
        return false;
    }
    return true;
}


bool epoll::rescan_in(int socket) {
    if(socket > 0) {

        del(socket);
        
        // re-init timer, otherwise let it be
        if(rescan_set_in.empty()) {
            ftime(&rescan_timer);
        }
        
        auto it = rescan_set_in.find(socket);
        if(it == rescan_set_in.end()) {
            rescan_set_in.insert(socket);
        }
        
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
            ftime(&rescan_timer);
        }
        
        auto it = rescan_set_out.find(socket);
        if(it == rescan_set_out.end()) {
            rescan_set_out.insert(socket);
        }
        
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

    timeb now;
    ftime(&now);
    
    int ms_diff = (int) (1000.0 * (now.time - rescan_timer.time) + (now.millitm - rescan_timer.millitm));
    if(ms_diff > baseCom::rescan_poll_multiplier*baseCom::poll_msec) {
        ftime(&rescan_timer);
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
    if (iw > 0 || ip > 0) {
        _deb("epoll::clear_handler %d -> clearing idle watchlist [pre: %ld list: %ld]", check, ip, iw);
    }

    ret = iw + ip;

    return ret;
}



void epoller::init_if_null()
{
    if (poller == nullptr) {

        _deb("creating a new poller instance");

        poller = new epoll(); 
        if (poller->init() < 0) {
            poller = nullptr;
            _fat("cannot create poller instance!!!");
            exit(-1);
        }
    }
}

bool epoller::add(int socket, int mask)
{
    init_if_null();
    
    if(poller != nullptr) {
        return poller->add(socket,mask);
    }
    
    return false;
};

bool epoller::modify(int socket, int mask)
{
    init_if_null();
    
    if(poller != nullptr) {
        return poller->modify(socket,mask);
    }
    
    return false;
};

bool epoller::del(int socket)
{
    init_if_null();
    
    if(poller != nullptr) {
        return poller->del(socket);
    }
    clear_handler(socket);
    
    return false;
};

bool epoller::rescan_in(int socket)
{
    init_if_null();
    
    if(poller != nullptr) {
        return poller->rescan_in(socket);
    }
    
    return false;
};

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
};

bool epoller::rescan_out(int socket)
{
    init_if_null();
    
    if(poller != nullptr) {
        return poller->rescan_out(socket);
    }
    
    return false;
};
unsigned long epoller::cancel_rescan_out(int socket)
{
    init_if_null();

    if(poller != nullptr) {
        return poller->cancel_rescan_out(socket);
    }

    return 0;
};




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
};


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


int epoller::wait(int timeout) {
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
    std::scoped_lock<std::mutex> l(lock_);

    _deb("epoller::clear_handler %d -> 0x%x -> nullptr", check, get_handler(check));
    handler_info_t& href = handler_db[check];
    href.clear();
;

    if(poller) {
        unsigned long r = poller->rescan_set_in.erase(check);
        unsigned long w = poller->rescan_set_out.erase(check);
        _deb("epoller::clear_handler %d -> clearing rescans [r: %ld w: %ld]",check, r, w);

        poller->clear_idle_watch(check);
    }
}


void epoller::set_handler(int check, epoll_handler* h) {

    handler_info_t& href = handler_db[check];
    href.handler = h;
    _deb("epoller::set_handler %d -> 0x%x",check,h);
    
    if(h != nullptr) {
        if(h->registrant && h->registrant != this) {
            _err("epoller::set_handler: setting handler over already existing, different handler. This should not happen!");
            // since registrant will be modified, we need to clear old registrant handlers.
            
            for(auto cur_socket: h->registered_sockets) {
                _err("epoller::set_handler:  moving old socket %d handler to new one", cur_socket);

                // new is created if it doesn't exist yet
                handler_info_t& curhref  = handler_db[cur_socket];
                curhref.handler = h;
                curhref.stats.clear();
            }
        }
        h->registrant = this;
        h->registered_sockets.insert(check);
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

};


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