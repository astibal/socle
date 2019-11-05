#ifndef EPOLL_HPP
#define EPOLL_HPP

#include <string>
#include <cstring>
#include <ctime>
#include <csignal>
#include <vector>
#include <set>
#include <unordered_map>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/timeb.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <logger.hpp>

#define EPOLLER_MAX_EVENTS 50
#define HANDLER_FENCE 0xcaba1a


class baseCom;

struct epoll {
    struct epoll_event events[EPOLLER_MAX_EVENTS];
    int fd = 0;
    int hint_fd = 0;
    bool auto_epollout_remove = true;
    std::set<int> in_set;
    std::set<int> out_set;

    // this set is used for sockets where ARE already some data, but we wait for more.
    // because of this, socket will be REMOVED from in_set (so avoiding CPU spikes when there are still not enough of data)
    // but those sockets will be added latest after time set in @rescan_timeout microseconds.
    std::set<int> rescan_set_in;
    std::set<int> rescan_set_out;
    struct timeb rescan_timer;

    bool in_read_set(int check);
    bool in_write_set(int check);


    // idle timeout
    int idle_timeout_ms = 1000;

    // incremented each click and reset on trigger (if greater than idle_timeout_ms)
    int idle_counter = 0;
    // if round is 0, we are waiting. If 1 - we will trigger on watched sockets
    // make it 1, so on start it will flip to 0
    bool idle_round = true;

    //sockets to be added to idle_watched (to ensure defined idle timeout (and possibly slightly more)
    std::set<int> idle_watched_pre;
    //idle socket timer - sockets in this list will be added to idle_set.
    // However, if we receive *any* socket activity (depends on monitoring), socket is
    std::set<int> idle_watched;

    // set with sockets in idle state. Idle list is erased on each poll.
    std::set<int> idle_set;
    bool in_idle_set(int check);
    bool in_idle_watched_set(int check);

    // remove socket from the idle detection machinery.
    unsigned long clear_idle_watch(int check);
    void set_idle_watch(int check);


    int init();
    virtual int wait(int timeout = -1);
    virtual bool add(int socket, int mask=EPOLLIN);
    virtual bool modify(int socket, int mask);
    virtual bool del(int socket);
    virtual bool rescan_in(int socket);
    virtual bool rescan_out(int socket);
    virtual unsigned long cancel_rescan_in(int socket);
    virtual unsigned long cancel_rescan_out(int socket);

    virtual bool click_timer_now (); // return true if we should add them back to in_set (scan their readability again). If yes, reset timer.

    inline void clear() { memset(events,0,EPOLLER_MAX_EVENTS*sizeof(epoll_event)); in_set.clear(); out_set.clear(); idle_set.clear(); }
    bool hint_socket(int socket); // this is the socket which will be additionally monitored for EPOLLIN; each time it's readable, single byte is read from it.
    [[nodiscard]] inline int hint_socket() const { return hint_fd; }

    virtual ~epoll() = default;

    static loglevel log_level;
    logan_lite log = logan_lite("com.epoll");
};


// There is epoll_handler class somewhere around. Promises.
class epoll_handler;

// handler statistics/troubleshooting struct
typedef struct {
    unsigned long call_count;

    void clear() {
        call_count=0L;
    }
} handler_stats_t;

// handler + its stats holder
typedef struct {
    handler_stats_t stats;
    epoll_handler* handler;

    void clear() {
        handler = nullptr;
        stats.clear();
    }
} handler_info_t;
/*
 * Class poller is HOLDER of epoll pointer. Reason for this is to have single point of self-initializing 
 * code. It's kind of wrapper, which doesn't init anything until there is an attempt to ADD something into it.
 */
struct epoller {
    struct epoll* poller = nullptr;
    virtual void init_if_null();
    
    bool in_read_set(int check);
    bool in_write_set(int check);
    bool in_idle_set(int check);
    virtual bool add(int socket, int mask=(EPOLLIN));
    virtual bool modify(int socket, int mask);
    virtual bool del(int socket);
    virtual bool rescan_in(int socket);
    virtual bool rescan_out(int socket);
    unsigned long cancel_rescan_in(int socket);
    unsigned long cancel_rescan_out(int socket);


    virtual bool click_timer_now (); // return true if we should add them back to in_set (scan their readability again). If yes, reset timer.
    
    virtual int wait(int timeout = -1);
    virtual bool hint_socket(int socket); // this is the socket which will be additionally monitored for EPOLLIN; each time it's readable, single byte is read from it.

    // handler hints is a map of socket->handler. We will allow to grow it as needed. No purges. 
    std::unordered_map<int,handler_info_t> handler_db;
    epoll_handler* get_handler(int check);
    void clear_handler(int check);
    void set_handler(int check, epoll_handler*);

    void set_idle_watch(int check);
    void clear_idle_watch(int check);

    virtual ~epoller() { delete poller; }

    logan_lite log = logan_lite("com.epoll");
};

class epoll_handler {
public:
    int fence__ = HANDLER_FENCE;
    virtual void handle_event(baseCom*) = 0;
    virtual ~epoll_handler() {
        std::recursive_mutex m;
        std::lock_guard<std::recursive_mutex> guard(m);

        if(registrant != nullptr) {
            for(auto s: registered_sockets) {

                epoll_handler* owner = registrant->get_handler(s);

                // don't remove foreign handlers!
                if(this == owner) {
                    registrant->clear_handler(s);
                }
            }
        }
    }
    
    friend struct epoller;
protected:
    epoller* registrant = nullptr;
    std::set<int> registered_sockets;
    
};

struct socket_state {

    int socket_;
    epoll_handler *handler_;
    baseCom *com_;
    int state_;
    enum { SS_NONE = -1, SS_CLOSING = 0, SS_OPENING = 1 };
    bool owner_ = true;

    socket_state() : socket_(0), handler_(nullptr), com_(nullptr), state_(socket_state::SS_NONE), owner_(true) {};
    socket_state(int s, epoll_handler *h, baseCom *com, bool owner) :
        socket_(s), handler_(h), com_(com), state_(socket_state::SS_NONE), owner_(owner) {};
    virtual ~socket_state();

    void set(int s, epoll_handler *h, baseCom *com, bool owner=true) {
        socket_ = s;
        handler_ = h;
        com_ = com;
        owner_ = owner;
    }

    virtual void update (int s);
    inline void opening() { update(socket_state::SS_OPENING); };
    inline void closing() { update(socket_state::SS_CLOSING); };

    void mon_write();
    void mon_read();
    void mon_none();

    [[nodiscard]] inline const int state() const { return state_; };
};

#endif //EPOLL_HPP