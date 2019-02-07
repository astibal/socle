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

#ifndef BASEPROXY_HPP
#define BASEPROXY_HPP


#include <iostream>
#include <string>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <vector>

#include <logger.hpp>
#include <hostcx.hpp>

/*
TCPProxy: proxy left<->right socket bytes

received bytes from left socket is proxied to ALL right sockets and vice versa.

Typical use will consists of one left and one right socket.
*/


class Proxy {
public:
    virtual int prepare_sockets(baseCom*) = 0;   // which Com should be set: typically it should be the parent's proxy's Com
    virtual int handle_sockets_once(baseCom*) = 0;    
    virtual int run(void) = 0;
    virtual void shutdown() = 0;
    virtual ~Proxy() = 0;
};


class baseProxy : public epoll_handler
{
protected:
        
    bool dead_;
    bool new_raw_;
    baseProxy* parent_ = nullptr;

    bool error_on_read;
    bool error_on_write;
    
    std::vector<baseHostCX*> left_sockets;
    std::vector<baseHostCX*> right_sockets;

    std::vector<baseHostCX*> left_bind_sockets;
    std::vector<baseHostCX*> right_bind_sockets;
    
    // permantenty maintained connections (if the socket is closed, it will be reconnected) PC => Permanent Connection
    std::vector<baseHostCX*> left_pc_cx;
    std::vector<baseHostCX*> right_pc_cx;

    // NEW feature: don't accept those sockets fully, just on "carrier" level to avoid e.g. SSL handshake prior target SSL socket 
    // is really opened and SSL is fully established
    //     >>> enabled when HostCX is *waiting_for_peercom* in the time being accepted <<<
    //  -- this is important for some features like SSL MiTM, and it also preserves resources 
    //        => it's useful for session *original* direction side (usually and by convention it's the left side)
    std::vector<baseHostCX*> left_delayed_accepts;
    std::vector<baseHostCX*> right_delayed_accepts;   

    
    unsigned int sleep_time; // microseconds
    unsigned int sleep_factor_ = 0; // how many times we slept already. Resets if we woke up.
    
    unsigned int meter_last_read;
    unsigned int meter_last_write;
    unsigned int handle_last_status;
        
    bool pollroot_ = false;    

public:
    static const unsigned int HANDLE_OK = 0;
    static const unsigned int HANDLE_LEFT_ERROR = -1;
    static const unsigned int HANDLE_RIGHT_ERROR = -2;
    static const unsigned int HANDLE_LEFT_PC_ERROR = -5;
    static const unsigned int HANDLE_RIGHT_PC_ERROR = -6;
    
    static const unsigned int HANDLE_NONE = 1;
    static const unsigned int HANDLE_LEFT_NEW = 2;
    static const unsigned int HANDLE_RIGHT_NEW = 4;
    
    static const unsigned int DIE_LEFT_EMPTY = 2;
    static const unsigned int DIE_RIGHT_EMPTY = 1;
    
    baseCom* com_;
    baseCom* com() { return com_; };
    baseProxy(baseCom* c);
    baseProxy(baseCom* c, int left_socket);
    virtual ~baseProxy();
    
    void parent(baseProxy *p) { parent_ = p; }
    baseProxy* parent(void) { return parent_; }

    // add client sockets (left and right ones)
    void ladd(baseHostCX*);
    void radd(baseHostCX*);
        
        // add listen(bind) sockets (generating left and right sockets)
    void lbadd(baseHostCX*);
    void rbadd(baseHostCX*);
    
    // add context for pormanent connections
    void lpcadd(baseHostCX*);
    void rpcadd(baseHostCX*);

    // add client sockets (left and right ones) to delayed accept list
    void ldaadd(baseHostCX*);
    void rdaadd(baseHostCX*);    
    
    int lsize();
    int rsize();
    

    std::vector<baseHostCX*>& ls() { return left_sockets; }
    std::vector<baseHostCX*>& rs() { return right_sockets; }
    std::vector<baseHostCX*>& lbs() { return left_bind_sockets; }
    std::vector<baseHostCX*>& rbs() { return right_bind_sockets; }
    std::vector<baseHostCX*>& lpc() { return left_pc_cx; }
    std::vector<baseHostCX*>& rpc() { return right_pc_cx; }
    std::vector<baseHostCX*>& lda() { return left_delayed_accepts; }
    std::vector<baseHostCX*>& rda() { return right_delayed_accepts; }


    inline bool dead() const { return dead_; }
    inline void dead(bool d) { dead_ = d; /* might be handy sometimes. if(dead_) { INF_("dead bt: %s",bt().c_str()); } */ } 
    
    inline bool new_raw() const { return new_raw_; }
    inline void new_raw(bool r) { new_raw_ = r; } 	
    
    void set_polltime(unsigned int, unsigned int);
    inline void set_sleeptime(unsigned int n) { sleep_time = n; };
    inline unsigned int get_sleeptime() { return sleep_time; }


    
    // bind proxy to a port (typically left side)
    int left_bind(unsigned short);
    int right_bind(unsigned short);
    int bind(unsigned short, unsigned char);
    int bind(const char*, unsigned char); // support for AF_UNIX and similar
        
    // permanently (re)connected sockets
    int left_connect(const char*, const char*,bool=false);
    int right_connect(const char*, const char*,bool=false);
    int connect(const char*, const char*,char,bool=false);


    // shutdown utils, deletes HostCX
    virtual void left_shutdown();
    virtual void right_shutdown();
    virtual void shutdown();
    
    void sleep(void);
    
    virtual int run();
    virtual int prepare_sockets(baseCom*);   // which Com should be set: typically it should be the parent's proxy's Com
    
    // normal sockets (proxying data)
    virtual bool handle_cx_events(unsigned char side, baseHostCX* cx); // return false to break socket loop. Always call this one in your overide.
    virtual bool handle_cx_read(unsigned char side, baseHostCX* cx);   // return false to break socket loop. Always call this one in your overide.
    virtual bool handle_cx_write(unsigned char side, baseHostCX* cx);  // return false to break socket loop. Always call this one in your overide.
    virtual bool handle_cx_read_once(unsigned char side, baseCom* xcom, baseHostCX* cx);
    virtual bool handle_cx_write_once(unsigned char side, baseCom* xcom, baseHostCX* cx);
    
    //bound sockets
    bool handle_cx_new(unsigned char side, baseCom* xcom, baseHostCX* cx);
    
    virtual int handle_sockets_once(baseCom*);
    virtual void handle_event(baseCom* com) {
        handle_sockets_once(com);
    };

    inline bool pollroot() { return pollroot_; };
    inline void pollroot(bool b) { pollroot_ = b; };
        
    // overide to create custom context objects
    virtual baseHostCX* new_cx(int);
    virtual baseHostCX* new_cx(const char*, const char*);
        
        // on_* event functions
    virtual void on_left_bytes(baseHostCX*);
    virtual void on_right_bytes(baseHostCX*);
    virtual void on_left_error(baseHostCX*);
    virtual void on_right_error(baseHostCX*);
    virtual void on_left_message(baseHostCX* cx) {};
    virtual void on_right_message(baseHostCX* cx) {};
        
    virtual void on_left_pc_error(baseHostCX*);
    virtual void on_right_pc_error(baseHostCX*);
    virtual void on_left_pc_restore(baseHostCX*);
    virtual void on_right_pc_restore(baseHostCX*);
    
    // on_*_new events are run only on client sockets!
    virtual void on_left_new(baseHostCX*);
    virtual void on_right_new(baseHostCX*);

    virtual void on_left_new_raw(int sock) {};
    virtual void on_right_new_raw(int sock) {};
        
    virtual void run_timers(void);


    inline bool write_left_bottleneck() const { return  write_left_neck_; }
    void write_left_bottleneck(bool n) { write_left_neck_ = n; }
    inline bool write_right_bottleneck() const { return  write_right_neck_; }
    void write_right_bottleneck(bool n) { write_right_neck_ = n; }

    unsigned int change_monitor_for_cx_vec(std::vector<baseHostCX*>* cx_vec, bool ifread, bool ifwrite,int pause_read, int pause_write);
    unsigned int change_side_monitoring(char side, bool ifread, bool ifwrite, int pause_read, int pause_write);

protected:
    // internal functions which should not be used directly
    int read_socket(int,char);
        
    time_t last_tick_;
    time_t clock_;
    
    void set_clock();
    bool run_timer(baseHostCX*);
    void reset_timer();

    virtual std::string to_string(int verbosity=iINF);
    
    // implement advanced logging
    DECLARE_C_NAME("baseProxy");
    DECLARE_LOGGING(c_name);
    
private:
    unsigned int timer_interval = 1;

    // when writing didn't write all data in writebuf
    bool write_left_neck_ = false;
    bool write_right_neck_ = false;
};

typedef std::vector<baseHostCX*>::iterator cx_iterator;

#endif

