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

#define DEBUG_LEVEL 10
#define INFO ( (DEBUG_LEVEL >= 10) )
#define XDEB ( (DEBUG_LEVEL >= 100) )
#define DDEB(x) ( ((XDEB) && (DEBUG_LEVEL) >= (x)) )


/*
 TCPProxy: proxy left<->right socket bytes
 
 received bytes from left socket is proxied to ALL right sockets and vice versa.
 
 Typical use will consists of one left and one right socket.
 */


class Proxy {
public:
	virtual int run(void) = 0;
	virtual int run_once(void) = 0;	
	virtual void shutdown() = 0;
	virtual ~Proxy() = 0;
};


template <class Com>
class baseProxy : public Com
{
protected:
	
	bool dead_;
	bool new_raw_;
	baseProxy<Com>* parent_;
    
	bool error_on_read;
	bool error_on_write;
	
	std::vector<baseHostCX<Com>*> left_sockets;
    std::vector<baseHostCX<Com>*> right_sockets;
    
	std::vector<baseHostCX<Com>*> left_bind_sockets;
    std::vector<baseHostCX<Com>*> right_bind_sockets;
	
	// permantenty maintained connections (if the socket is closed, it will be reconnected) PC => Permanent Connection
	std::vector<baseHostCX<Com>*> left_pc_cx;
	std::vector<baseHostCX<Com>*> right_pc_cx;

    // NEW feature: don't accept those sockets fully, just on "carrier" level to avoid e.g. SSL handshake prior target SSL socket 
    // is really opened and SSL is fully established
    //     >>> enabled when HostCX is *paused* in the time being accepted <<<
    //  -- this is important for some features like SSL MiTM, and it also preserves resources 
    //        => it's useful for session *original* direction side (usually and by convention it's the left side)
    std::vector<baseHostCX<Com>*> left_delayed_accepts;
    std::vector<baseHostCX<Com>*> right_delayed_accepts;   
    
	timeval tv;
	
	//run() loop variables 
	unsigned int sleep_time; // microseconds
	
	unsigned int meter_last_read;
	unsigned int meter_last_write;
	unsigned int handle_last_status;
	
#ifdef WITH_LOG
protected:
	logger log;
public:
	void set_logger(logger l) { log = l;}
#endif

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
	
	
    baseProxy();
    baseProxy(int left_socket);
	virtual ~baseProxy();
	
	void parent(baseProxy<Com> *p) { parent_ = p; }
	baseProxy<Com>* parent(void) { return parent_; }
    
	// add client sockets (left and right ones)
    void ladd(baseHostCX<Com>*);
    void radd(baseHostCX<Com>*);
	
	// add listen(bind) sockets (generating left and right sockets)
    void lbadd(baseHostCX<Com>*);
	void rbadd(baseHostCX<Com>*);
	
	// add context for pormanent connections
	void lpcadd(baseHostCX<Com>*);
	void rpcadd(baseHostCX<Com>*);

    // add client sockets (left and right ones) to delayed accept list
    void ldaadd(baseHostCX<Com>*);
    void rdaadd(baseHostCX<Com>*);    
    
	int lsize();
	int rsize();
	
 
	std::vector<baseHostCX<Com>*>& ls() { return left_sockets; }
	std::vector<baseHostCX<Com>*>& rs() { return right_sockets; }
	std::vector<baseHostCX<Com>*>& lbs() { return left_bind_sockets; }
	std::vector<baseHostCX<Com>*>& rbs() { return right_bind_sockets; }
	std::vector<baseHostCX<Com>*>& lpc() { return left_pc_cx; }
	std::vector<baseHostCX<Com>*>& rpc() { return right_pc_cx; }
    std::vector<baseHostCX<Com>*>& lda() { return left_delayed_accepts; }
    std::vector<baseHostCX<Com>*>& rda() { return right_delayed_accepts; }


	inline bool dead() const { return dead_; }
	inline void dead(bool d) { dead_ = d; } 
	
	inline bool new_raw() const { return new_raw_; }
	inline void new_raw(bool r) { new_raw_ = r; } 	
	
	void set_polltime(unsigned int, unsigned int);
	inline void set_sleeptime(unsigned int n) { sleep_time = n; };
	inline unsigned int get_sleeptime() { return sleep_time; }


	
	// bind proxy to a port (typically left side)
	int left_bind(unsigned short);
	int right_bind(unsigned short);
	int bind(unsigned short, unsigned char);
	
	// permantenty (re)connected sockets
	int left_connect(const char*, const char*,bool=false);
	int right_connect(const char*, const char*,bool=false);
	int connect(const char*, const char*,char,bool=false);


	// shutdown utils, deletes HostCX
	virtual void left_shutdown();
	virtual void right_shutdown();
	virtual void shutdown();
	
	void sleep(void);
	
	virtual int run(void);
	virtual int run_once(void);
	
	// overide to create custom context objects
	virtual baseHostCX<Com>* new_cx(int);
	virtual baseHostCX<Com>* new_cx(const char*, const char*);
	
	// on_* event functions
    virtual void on_left_bytes(baseHostCX<Com>*);
    virtual void on_right_bytes(baseHostCX<Com>*);
	virtual void on_left_error(baseHostCX<Com>*);
	virtual void on_right_error(baseHostCX<Com>*);
	
	virtual void on_left_pc_error(baseHostCX<Com>*);
	virtual void on_right_pc_error(baseHostCX<Com>*);
	virtual void on_left_pc_restore(baseHostCX<Com>*);
	virtual void on_right_pc_restore(baseHostCX<Com>*);
	
	// on_*_new events are run only on client sockets!
	virtual void on_left_new(baseHostCX<Com>*);
	virtual void on_right_new(baseHostCX<Com>*);

	virtual void on_left_new_raw(int sock) {};
	virtual void on_right_new_raw(int sock) {};
	
	std::string hr(void);
protected:
	// internal functions which should not be used directly
	void run_timers(void);
	int prepare_sockets(void);
    int handle_sockets_once(void);
    int read_socket(int,char);
	
// 	inline bool readable(int s) { return FD_ISSET(s, &read_socketSet); };
// 	inline bool writable(int s) { return FD_ISSET(s, &write_socketSet); };
	
	time_t last_tick_;
	time_t clock_;
	
	void set_clock();
	bool run_timer(baseHostCX<Com>*);
	void reset_timer();
	
};

// typedef baseProxy<TCPCom,HostCX> TCPProxy;

#include <baseproxy.impl>

#endif