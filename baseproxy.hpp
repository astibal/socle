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

#include <log/logger.hpp>
#include <hostcx.hpp>
#include <mpstd.hpp>

/*
TCPProxy: proxy left<->right socket bytes

received bytes from left socket is proxied to ALL right sockets and vice versa.

Typical use will consists of one left and one right socket.
*/

#include <iproxy.hpp>

class baseProxy : public epoll_handler, public Proxy
{
public:
    template<class T>
    using vector_type = mp::vector<T>;
protected:


    struct proxy_state {
        bool dead_ = false;

        bool error_on_read = false;
        bool error_on_write = false;

        // when writing didn't write all data in writebuf
        bool write_left_neck_ = false;
        bool write_right_neck_ = false;

        inline bool dead() const { return dead_; }
        inline void dead(bool d) { dead_ = d; /* might be handy sometimes. if(dead_) { _inf("dead bt: %s",bt().c_str()); } */ }

        inline bool write_left_bottleneck() const { return  write_left_neck_; }
        void write_left_bottleneck(bool n) { write_left_neck_ = n; }

        inline bool write_right_bottleneck() const { return  write_right_neck_; }
        void write_right_bottleneck(bool n) { write_right_neck_ = n; }
    };

    proxy_state status_;

    bool new_raw_;
    baseProxy* parent_ = nullptr;


    vector_type<baseHostCX*> left_sockets;
    vector_type<baseHostCX*> right_sockets;

    vector_type<baseHostCX*> left_bind_sockets;
    vector_type<baseHostCX*> right_bind_sockets;
    
    // permantenty maintained connections (if the socket is closed, it will be reconnected) PC => Permanent Connection
    vector_type<baseHostCX*> left_pc_cx;
    vector_type<baseHostCX*> right_pc_cx;

    // NEW feature: don't accept those sockets fully, just on "carrier" level to avoid e.g. SSL handshake prior target SSL socket 
    // is really opened and SSL is fully established
    //     >>> enabled when HostCX is *waiting_for_peercom* in the time being accepted <<<
    //  -- this is important for some features like SSL MiTM, and it also preserves resources 
    //        => it's useful for session *original* direction side (usually and by convention it's the left side)
    vector_type<baseHostCX*> left_delayed_accepts;
    vector_type<baseHostCX*> right_delayed_accepts;

    
    unsigned int sleep_time_; // microseconds
    unsigned int sleep_factor_ = 0; // how many times we slept already. Resets if we woke up.


    struct metering {
        unsigned int last_read = 0;
        unsigned int last_write = 0;
    };
    metering meters;

    unsigned int handle_last_status;
        
    bool pollroot_ = false;    

public:
    proxy_state& state() { return status_; }

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
    baseCom const* com() const { return com_; };

    explicit baseProxy(baseCom* c);
    ~baseProxy() override;
    
    void parent(baseProxy *p) { parent_ = p; }
    baseProxy* parent() const { return parent_; }

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


    inline bool new_raw() const { return new_raw_; }
    inline void new_raw(bool r) { new_raw_ = r; } 	
    
    inline void sleep_time(unsigned int n) { sleep_time_ = n; };
    inline unsigned int sleep_time() const { return sleep_time_; }
    void sleep();



    // bind proxy to a port (typically left side)
    int bind(unsigned short, unsigned char);
    int bind(std::string const&, unsigned char); // support for AF_UNIX and similar
        
    // permanently (re)connected sockets
    int left_connect(const char*, const char*,bool=false);
    int right_connect(const char*, const char*,bool=false);
    int connect(const char*, const char*,char,bool=false);


    // shutdown utils, deletes HostCX
    virtual void left_shutdown();
    virtual void right_shutdown();
    void shutdown() override;

    int run() override;
    virtual void on_run_round() {};           // called at the end of single proxy run() cycle
    int prepare_sockets(baseCom*) override;   // which Com should be set: typically it should be the parent's proxy's Com
    
    // normal sockets (proxying data)
    virtual bool handle_cx_events(unsigned char side, baseHostCX* cx); // return false to break socket loop. Always call this one in your override.
    virtual bool handle_cx_read(unsigned char side, baseHostCX* cx);   // return false to break socket loop. Always call this one in your override.
    virtual bool handle_cx_write(unsigned char side, baseHostCX* cx);  // return false to break socket loop. Always call this one in your override.
    virtual bool handle_cx_read_once(unsigned char side, baseCom* xcom, baseHostCX* cx);
    virtual bool handle_cx_write_once(unsigned char side, baseCom* xcom, baseHostCX* cx);
    
    //bound sockets
    bool handle_cx_new(unsigned char side, baseCom* xcom, baseHostCX* cx);
    
    int handle_sockets_once(baseCom*) override;
    void handle_event(baseCom* com) override {
        handle_sockets_once(com);
    };

    inline bool pollroot() const { return pollroot_; };
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
        
    virtual bool run_timers ();


    unsigned int change_monitor_for_cx_vec(std::vector<baseHostCX*>* cx_vec, bool ifread, bool ifwrite,int pause_read, int pause_write);
    unsigned int change_side_monitoring(char side, bool ifread, bool ifwrite, int pause_read, int pause_write);

    std::string to_string(int verbosity=iINF) const override;
protected:

    struct clicker {
        time_t last_tick_;
        time_t clock_;
        unsigned int timer_interval = 1;

        clicker(): last_tick_(0), clock_(0) {
            time(&last_tick_);
            time(&clock_);
        };
        bool reset_timer();
    };
    clicker clicker_;

    bool on_cx_timer(baseHostCX*);
    
    // implement advanced logging
    DECLARE_C_NAME("baseProxy");
    DECLARE_LOGGING(to_string);

protected:
    logan_attached<baseProxy> log;
};

#endif

