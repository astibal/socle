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
#include <vector>
#include <ctime>

#include <sys/socket.h>
#include <unistd.h>

#include <log/logger.hpp>
#include <hostcx.hpp>
#include <mpstd.hpp>
#include <sobject.hpp>

/*
TCPProxy: proxy left<->right socket bytes

received bytes from left socket is proxied to ALL right sockets and vice versa.

Typical use will consists of one left and one right socket.
*/

#include <iproxy.hpp>

struct locks;

template <class K,
          class MutexType = std::shared_mutex>
struct lock_for {
    using MapType = std::map<K, std::shared_ptr<MutexType>>;

    lock_for(lock_for const& r) = delete;
    lock_for& operator=(lock_for const& r) = delete;



    [[nodiscard]] std::shared_ptr<MutexType> lock(K k) {
        auto l_ = std::shared_lock(lock_);

        auto found_mutex_it = lock_db_.find(k);
        if(found_mutex_it != lock_db_.end()) {
            return found_mutex_it->second;
        }

        return nullptr;
    }

    inline bool insert(K k) {
        auto l_ = std::unique_lock(lock_);

        auto [ it, new_item ] = lock_db_.emplace(k, std::make_shared<MutexType>());
        return new_item;
    }

    [[maybe_unused]] MapType& lock_db() { return lock_db_; }
    [[maybe_unused]] std::shared_mutex& lock_db_lock() const { return lock_; }

protected:

    friend struct locks;

    lock_for() = default;
private:

    MapType lock_db_;
    mutable std::shared_mutex lock_;
};


struct locks {

    using lock_for_fd = lock_for<int, std::shared_mutex>;

    static lock_for_fd& fd() {
        static lock_for_fd f;
        return f;
    }

    locks(locks const& r) = delete;
    locks& operator=(locks const& r) = delete;
private:
    locks() = default;
};



class proxy_error : public std::runtime_error {
public:
    using runtime_error::runtime_error;
};

class baseProxy : public epoll_handler, public Proxy
{
    std::vector<std::unique_ptr<baseHostCX>> trashcan {2};

public:
    template<class T>
    using vector_type = mp::vector<T>;
protected:

    struct proxy_state {

        // dead can be written by other threads - make it atomic
        std::atomic_bool dead_ = false;
        std::atomic_uint in_progress_ {0};

        bool error_on_left_read = false;
        bool error_on_right_read = false;
        bool error_on_left_write = false;
        bool error_on_right_write = false;

        // when writing didn't write all data in writebuf
        bool write_left_neck_ = false;
        bool write_right_neck_ = false;

        [[nodiscard]] inline std::atomic_uint& in_progress() { return in_progress_; }

        [[nodiscard]] inline bool dead() const { return dead_.load(); }
        inline void dead(bool d) { dead_ = d; }

        [[nodiscard]] inline bool write_left_bottleneck() const { return  write_left_neck_; }
        void write_left_bottleneck(bool n) { write_left_neck_ = n; }

        [[nodiscard]] inline bool write_right_bottleneck() const { return  write_right_neck_; }
        void write_right_bottleneck(bool n) { write_right_neck_ = n; }
    };

    proxy_state status_;

    bool new_raw_ = false;
    baseProxy* parent_ = nullptr;


    vector_type<baseHostCX*> left_sockets;
    vector_type<baseHostCX*> right_sockets;

    vector_type<baseHostCX*> left_bind_sockets;
    vector_type<baseHostCX*> right_bind_sockets;
    
    // permanently maintained connections (if the socket is closed, it will be reconnected) PC => Permanent Connection
    vector_type<baseHostCX*> left_pc_cx;
    vector_type<baseHostCX*> right_pc_cx;

    // NEW feature: don't accept those sockets fully, just on "carrier" level to avoid e.g. SSL handshake prior target SSL socket 
    // is really opened and SSL is fully established
    //     >>> enabled when HostCX is *waiting_for_peercom* in the time being accepted <<<
    //  -- this is important for some features like SSL MiTM, and it also preserves resources 
    //        => it's useful for session *original* direction side (usually and by convention it's the left side)
    vector_type<baseHostCX*> left_delayed_accepts;
    vector_type<baseHostCX*> right_delayed_accepts;


    struct metering {
        struct poll {
            std::size_t handled_count = 0L;
            std::size_t generic_count = 0L;
            std::size_t hint_count = 0L;
            std::size_t null_count = 0L;

            poll operator+(poll const&) = delete;
            void operator+=(poll const& b) {
                handled_count += b.handled_count;
                generic_count += b.generic_count;
                hint_count += b.hint_count;
                null_count += b.null_count;
            }
        };

        int last_read = 0;
        int last_write = 0;

        poll polls;

        // opt-out metering feature
        bool do_rate_meter = true;
        socle::meter mtr_down;
        socle::meter mtr_up;
    };
    metering stats_;

    unsigned int handle_last_status = 0;
        
    bool pollroot_ = false;    

public:
    metering const& stats() const { return stats_; }
    proxy_state& state() { return status_; }
    proxy_state const& state() const { return status_; }

    static constexpr unsigned int HANDLE_OK = 0;
    static constexpr unsigned int HANDLE_LEFT_ERROR = -1;
    static constexpr unsigned int HANDLE_RIGHT_ERROR = -2;
    static constexpr unsigned int HANDLE_LEFT_PC_ERROR = -5;
    static constexpr unsigned int HANDLE_RIGHT_PC_ERROR = -6;
    
    static constexpr unsigned int HANDLE_NONE = 1;
    static constexpr unsigned int HANDLE_LEFT_NEW = 2;
    static constexpr unsigned int HANDLE_RIGHT_NEW = 4;
    
    static constexpr unsigned int DIE_LEFT_EMPTY = 2;
    static constexpr unsigned int DIE_RIGHT_EMPTY = 1;
    
    baseCom* com_;
    baseCom* com() const { return com_; };
    epoll* poller() const { return com() ? com()->poller.poller.get() : nullptr;  }

    explicit baseProxy(baseCom* c) : com_(c) {};
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
    std::vector<baseHostCX*>& lda() { return left_delayed_accepts; }
    std::vector<baseHostCX*>& rda() { return right_delayed_accepts; }

    [[maybe_unused]] std::vector<baseHostCX*>& lpc() { return left_pc_cx; }
    [[maybe_unused]] std::vector<baseHostCX*>& rpc() { return right_pc_cx; }

    inline bool new_raw() const { return new_raw_; }
    inline void new_raw(bool r) { new_raw_ = r; } 	

    // bind proxy to a port (typically left side)
    int bind(unsigned short port, unsigned char side);
    int bind(std::string const& path, unsigned char side); // support for AF_UNIX and similar

    // listen on specified port and return associated context
    baseHostCX * listen(int sock, unsigned char side);
        
    // permanently (re)connected sockets
    int left_connect(const char*, const char*);
    int right_connect(const char*, const char*);
    int connect(const char*, const char*,char);


    void drop_cx(baseHostCX* cx);
    // shutdown utils, deletes HostCX
    virtual void left_shutdown();
    virtual void right_shutdown();
    void shutdown() override;


    int run() override;

    using socket_set_type = enum name_id { INSET=0, OUTSET=1, IDLESET=2, ERRSET=3, VIRTSET=4 };
    int run_poll();                           // handle proxy after poll(), so it's only called if proxy is pollroot.
                                              // Returns non-zero if it should be immediately re-run.



    metering::poll run_poll_socket(int cur_socket, epoll::set_type &real_set, socket_set_type set_type);          // do actual work with the socket
    metering::poll run_poll_socket_null_handler(int cur_socket, epoll::set_type& real_set, socket_set_type set_type);          // treat specifically sockets without hnadlers set (maybe legit, ie. hint sockets)

    int prepare_sockets(baseCom*) override;   // which Com should be set: typically it should be the parent's proxy's Com
    
    // normal sockets (proxying data)
    // handle_ functions returning false to indicate we should break socket loop. Always call this one in your override.

    virtual bool handle_cx_events(unsigned char side, baseHostCX* cx);
    virtual bool handle_cx_read(unsigned char side, baseHostCX* cx);
    virtual bool handle_cx_write(unsigned char side, baseHostCX* cx);
    virtual bool handle_cx_read_once(unsigned char side, baseCom* xcom, baseHostCX* cx);
    virtual bool handle_cx_write_once(unsigned char side, baseCom* xcom, baseHostCX* cx);

    //bound sockets
    bool handle_sockets_accept(unsigned char side, baseCom* xcom, baseHostCX* thiscx);
    
    int handle_sockets_once(baseCom*) override;
    void handle_event(baseCom* com) override {
        handle_sockets_once(com);
    };

    inline bool pollroot() const { return pollroot_; };
    inline void pollroot(bool b) { pollroot_ = b; };
        
    // override to create custom context objects
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

    // empty virtual to allow the logic without need to implement it via abstract mechanisms
    virtual void on_left_new_raw(int sock) {};
    virtual void on_right_new_raw(int sock) {};
        
    virtual bool run_timers ();


    unsigned int change_monitor_for_cx_vec(std::vector<baseHostCX*>* cx_vec, bool ifread, bool ifwrite,int pause_read, int pause_write);
    unsigned int change_side_monitoring(unsigned char side, bool ifread, bool ifwrite, int pause_read, int pause_write);

    std::string to_string(int verbosity) const override;
protected:

    struct clicker {
        time_t last_tick_ = 0;
        time_t clock_ = 0;
        unsigned int timer_interval = 1;

        clicker() {
            time(&last_tick_);
            time(&clock_);
        };
        bool reset_timer();
    };
    clicker clicker_;

    bool on_cx_timer(baseHostCX*);

public:
    // implement advanced logging
    TYPENAME_BASE("baseProxy")
    DECLARE_LOGGING(to_string)

private:
    logan_lite log {"proxy"};
};

#endif

