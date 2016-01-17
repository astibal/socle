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
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <logger.hpp>

#define EPOLLER_MAX_EVENTS 50
#define HANDLER_FENCE 0xcaba1a


class baseCom;
class epoll_handler {
public:
    int fence__ = HANDLER_FENCE;
    virtual void handle_event(baseCom*) = 0;
};

struct epoll {
    struct epoll_event events[EPOLLER_MAX_EVENTS];
    int fd = 0;
    int hint_fd = 0;
    bool auto_epollout_remove = true;
    std::set<int> in_set;
    std::set<int> out_set;
    
    bool in_read_set(int check);
    bool in_write_set(int check);

    int init();
    virtual int wait(int timeout = -1);
    virtual bool add(int socket, int mask=(EPOLLIN));
    virtual bool modify(int socket, int mask);
    inline void clear() { memset(events,0,EPOLLER_MAX_EVENTS*sizeof(epoll_event)); in_set.clear(); out_set.clear(); }
    bool hint_socket(int socket); // this is the socket which will be additinally monitored for EPOLLIN; each time it's readable, single byte is read from it.
    inline int hint_socket(void) const { return hint_fd; }
    
    virtual ~epoll() {}
};

/*
 * Class poller is HOLDER of epoll pointer. Reason for this is to have single point of self-initializing 
 * code. It's kind of wrapper, which doesn't init anything until there is an attempt to ADD something into it.
 */
struct epoller {
    struct epoll* poller = nullptr;
    virtual void init_if_null();
    
    bool in_read_set(int check);
    bool in_write_set(int check);
    virtual bool add(int socket, int mask=(EPOLLIN));
    virtual bool modify(int socket, int mask);
    virtual int wait(int timeout = -1);
    virtual bool hint_socket(int socket); // this is the socket which will be additinally monitored for EPOLLIN; each time it's readable, single byte is read from it.

    // handler hints is a map of socket->handler. We will allow to grow it as needed. No purges. 
    std::unordered_map<int,epoll_handler*> handler_hints;    
    epoll_handler* get_handler(int check);
    void clear_handler(int check);
    void set_handler(int check, epoll_handler*);
    
    virtual ~epoller() { if(poller) delete poller; }
};

#endif //EPOLL_HPP