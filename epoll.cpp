#include <epoll.hpp>
#include <hostcx.hpp>

loglevel epoll::log_level = INF;

int epoll::init() {
    // size in epoll_create is ignored since 2.6.8, but has to be greater than 0
    fd = epoll_create(1);
    DIA_("epoll::init: epoll socket created: %d",fd);
    if (fd == -1) {
        ERR_("epoll::init:%x: epoll_create failed! errno %d",this,errno);
    }
    ftime(&rescan_timer);
    
    return fd;
}

int epoll::wait(int timeout) {
    DUM_("epoll::wait: == begin, timeout %dms", timeout);
    
    clear();
    
    // Prepopulate epoll from rescan lists 
    
    if(click_timer_now()) {

        // Setting up rescans!

        for (auto isock: rescan_set_in) {
            DEB_("epoll::wait rescanning EPOLLIN socket %d",isock);
            add(isock,EPOLLIN);
        }
        rescan_set_in.clear();
        
        for (auto osock: rescan_set_out) {
            DEB_("epoll::wait rescanning EPOLLIN|OUT socket %d",osock);
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
                DEB_("epoll::wait: idle round %d, moving %d sockets to idle watch", idle_round, idle_watched_pre.size());

                for (auto s: idle_watched_pre) {
                    idle_watched.insert(s);
                }
                idle_watched_pre.clear();

            } else {
                // finally idle sockets
                DIA_("epoll::wait: idle round %d, %d sockets marked idle", idle_round, idle_watched.size());

                for (auto s: idle_watched) {
                    DEB_("epoll::wait: idle socket %d", s);

                    idle_set.insert(s);
                }
                idle_watched.clear();
            }
        }
    }
    
    // wait for epoll
    
    int nfds = epoll_wait(fd, events, EPOLLER_MAX_EVENTS, timeout);
    
    if(nfds > 0) {
        EXT_("epoll::wait: %d socket events",nfds);
    }
    
    
    if((LEV_(DEB) || epoll::log_level >= DEB) && nfds > 0) {
        std::string ports;
        for(int xi = 0; xi < nfds; ++xi) {
            ports += std::to_string(events[xi].data.fd);
            
            if(events[xi].events & EPOLLIN) ports += "r";
            if(events[xi].events & EPOLLOUT) ports += "w";
            ports += " ";
            
        }
        DEB_("ports: %s",ports.c_str());
    }
    
    for(int i = 0; i < nfds; ++i) {
        int socket = events[i].data.fd;
        uint32_t eventset = events[i].events;

        if(eventset & EPOLLIN) {
            if (socket == hint_socket()) {
                DIA_("epoll::wait: hint triggered %d",socket );
            }
            
            DIA_("epoll::wait: data received into socket %d",socket );
            if(socket  == 1) {
                char t[1]; ::read(socket, t, 1);
            }

            // add socket to in_set
            in_set.insert(socket);
            clear_idle_watch(socket);
        }
        else if(eventset & EPOLLOUT) {
            DIA_("epoll::wait: socket %d writable (auto_epollout_remove=%d)",socket,auto_epollout_remove);
            
            out_set.insert(socket);
            clear_idle_watch(socket);
            
            if(auto_epollout_remove) {
                modify(socket,EPOLLIN);
            }

        } else {
            DIA_("epoll::wait: uncaught event value %d",eventset);
        }
    }
   
   DUMS_("epoll::wait: == end");
    return nfds;
}

bool epoll::add(int socket, int mask) {
    struct epoll_event ev;
    memset(&ev,0,sizeof ev);
    
    ev.events = mask;
    ev.data.fd = socket;
    
    DEB_("epoll:add:%x: epoll_ctl(%d): called to add socket %d ",this, fd, socket);
    
    if (::epoll_ctl(fd, EPOLL_CTL_ADD, socket, &ev) == -1) {
        if(errno == EEXIST) {
            EXT_("epoll:add:%x: epoll_ctl(%d): socket %d already added",this, fd, socket);
        }
        else {
            ERR_("epoll:add:%x: epoll_ctl(%d): cannot add socket %d: %s",this, fd, socket, string_error().c_str());
            return false;
        } 
    } else {
        DIA_("epoll:add:%x: epoll_ctl(%d): socket added %d",this, fd, socket);
    }
    
    return true;
}

bool epoll::modify(int socket, int mask) {
    struct epoll_event ev;
    ev.events = mask;
    ev.data.fd = socket;
    
    DEB_("epoll:modify:%x: epoll_ctl(%d): called to modify socket %d, epollin=%d,epollout=%d ",this, fd, socket,flag_check<int>(mask,EPOLLIN),flag_check<int>(mask,EPOLLOUT));
    
    if (::epoll_ctl(fd, EPOLL_CTL_MOD, socket, &ev) == -1) {
        if(errno == ENOENT) {
            DIA_("epoll:modify:%x: epoll_ctl(%d): socket %d not monitored, fixing...",this, fd, socket);
            add(socket,mask);
            return false;
        }
        else {
            ERR_("epoll:modify:%x: epoll_ctl(%d): cannot modify socket %d: %s",this, fd, socket, string_error().c_str());
            return false;
        } 
    } else {
        DIA_("epoll:modify:%x: epoll_ctl(%d): socket added %d",this, fd, socket);
    }
    
    return true;
}

bool epoll::del(int socket) {
    struct epoll_event ev;
    memset(&ev,0,sizeof ev);
    
    ev.events = 0;
    ev.data.fd = socket;
    
    DEB_("epoll:del:%x: epoll_ctl(%d): called to delete socket %d ",this, fd, socket);
    
    if (::epoll_ctl(fd, EPOLL_CTL_DEL, socket, &ev) == -1) {

        //ERR_("epoll:del:%x: epoll_ctl(%d): cannot delete socket %d: %s",this, fd, socket, string_error().c_str());        
        //std::string str_bt = bt();
        //ERRS_(str_bt.c_str());
        
        return false;
    } else {
        DIA_("epoll:del:%x: epoll_ctl(%d): socket deleted %d",this, fd, socket);
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
        
        DIA_("epoll:hint_socket:%x: epoll_ctl(%d): removing old hint socket %d",this, fd,hint_socket());
        ::epoll_ctl(fd,EPOLL_CTL_DEL,hint_fd,&rem_ev);
    }
    
    if(add(socket,EPOLLIN)) {
        DIA_("epoll:hint_socket:%x: epoll_ctl(%d): setting hint socket %d",this, fd, socket);
        hint_fd = socket;
    } else {
        DIA_("epoll:hint_socket:%x: epoll_ctl(%d): setting hint socket %d FAILED.",this, fd, socket);
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



bool epoll::click_timer_now () {

    timeb now;
    ftime(&now);
    
    int ms_diff = (int) (1000.0 * (now.time - rescan_timer.time) + (now.millitm - rescan_timer.millitm));
    if(ms_diff > baseCom::rescan_poll_multiplier*baseCom::poll_msec) {
        ftime(&rescan_timer);
        EXT_("epoll::click_timer_now: diff = %d",ms_diff);

        idle_counter += ms_diff;
        if(idle_counter > idle_timeout_ms) {
            DEB_("epoll::click_timer_now: idle counter = %d",idle_counter);
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
        DEB_("epoll::clear_handler %d -> clearing idle watchlist [pre: %ld list: %ld]", check, ip, iw);
    }

    ret = iw + ip;

    return ret;
}



void epoller::init_if_null()
{
    if (poller == nullptr) { 
        poller = new epoll(); 
        if (poller->init() < 0) {
            poller = nullptr;
            FATS_("cannot create poller instance!!!");
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

bool epoller::rescan_out(int socket)
{
    init_if_null();
    
    if(poller != nullptr) {
        return poller->rescan_out(socket);
    }
    
    return false;
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
    DEB_("epoller::clear_handler %d -> 0x%x -> nullptr",check,get_handler(check));
    handler_info_t& href = handler_db[check];
    href.clear();
;

    if(poller) {
        unsigned long r = poller->rescan_set_in.erase(check);
        unsigned long w = poller->rescan_set_out.erase(check);
        DEB_("epoller::clear_handler %d -> clearing rescans [r: %ld w: %ld]",check, r, w);

        poller->clear_idle_watch(check);
    }
}


void epoller::set_handler(int check, epoll_handler* h) {

    handler_info_t& href = handler_db[check];
    href.handler = h;
    DEB_("epoller::set_handler %d -> 0x%x",check,h);
    
    if(h != nullptr) {
        if(h->registrant && h->registrant != this) {
            ERRS_("epoller::set_handler: setting handler over already existing, different handler. This should not happen!");
            // since registrant will be modified, we need to clear old registrant handlers.
            
            for(auto cur_socket: h->registered_sockets) {
                ERR_("epoller::set_handler:  moving old socket %d handler to new one", cur_socket);

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
