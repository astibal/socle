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

#ifndef HOSTCX_HPP
#define HOSTCX_HPP

#include <string>
#include <ctime>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>


#include <basecom.hpp>
#include <logger.hpp>
#include <buffer.hpp>
#include <display.hpp>

#define HOSTCX_BUFFSIZE 20480
#define HOSTCX_BUFFMAXSIZE (100*HOSTCX_BUFFSIZE)

//! Basic Host structure class
/*! 
 * This class is intended to be inherited in all other Host context structures
 */
class Host
{
protected:
	std::string host_; //!< hostname 
	std::string port_; //!< port
public:
	Host() {};
	
	//! Contructor filling hostname and the port
	/*!
	 *  Create host strusture
	 *  \param h - hostname string
	 *  \param p - port number (as the string
	 */
	Host(const char* h, const char* p) :
	host_(h),
	port_(p) {}
	
	//! returns host part of the structure
	std::string& host() { return host_; }
	//! returns port part of the structure
	std::string& port() { return port_; }
};




//! Host context class
/*!
 *  HostCX structure maintains the state of the socket, and takes care of buffered reads and writes. 
 * 
 *  HostCX can be constructed using two ways:
 *  + hostname/port and [connect()](@ref HostCX::connect)ed. Note that connect() could be blocking or non-blocking
 *  + directly using socket file descriptor - we call it internally 'reduced' state
 * 
 *  ### Connecting to remote host
 *  You can also take an advantage of 'permanent' HostCX setup. In this case, HostCX will be trying each [reconnect_delay_](@ref reconnect_delay_) seconds
 *  to reconnect the socket. Blocking/non-blocking state is honored. If the connect is called and blocking is set, connect will just return negative value on error,
 *  or socket file descriptor on success.
 *  
 *  However, when non-blocking option is set, then it always return a socket and always succeeds (as ::connect() does). 
 *  Unless bytes are read/written to the socket, nobody really knows if the socket is ready or not. This is tracked for you be HostCX::read and HostCX::write,
 *  and it's reflected in return value of opening(). If true, the connection is still not ready. There is also opening_timeout(), which will return if the non-blocking 
 *  underlying socket is 'opening' too log. For this purpose [reconnect_delay_](@ref reconnect_delay_) is re-used, and opening_timeout() returns true if we are opening
 *  socket longer.
 * 
 *  ### Sending and receiving data
 *  We have here @ref read() and @ref write() methods, both operations are buffered. Pointers to both buffers are returned by @ref readbuf() and 
 *  @ref writebuf() methods. Important thing here is to remember, that @ref read() will be *appending* data read to the readbuf_. On the contrary, @ref write() will be *emptying* writebuf_.
 *  Those buffers really don't know what you will do with data. Those are low-level methods just for the purpose of I/O. 
 * 
 *  #### Processing received data
 *  You already know, that @ref read() will just fill and append to the @ref readbuf_. Calling this method doesn't mean that you did something with received data. 
 *  For removing data from @ref readbuf_, and actually also for doing something useful with data, we call @ref process() method. This method returns number of bytes which you've already processed,
 *  and as such they can be removed from @ref readbuf_ - we call it they can he **finished**, see @ref finish().
 * 
 *  Default implementation of @ref process() returns size of readbuf_ -- when also [auto_finish](@ref auto_finish) returns true, this case consecutive calls of read() 
 *  will just auto- finish() received bytes and new bytes will be copied into @ref readbuf_ . It's clear that @ref process() is good candidate for overiding. Process
 *  received data and return how much of bytes you've processed and you don't need anymore.
 * 
 *  This is happening regardless of [auto_finish] (@ref auto_finish()) feature, since 
 *  only **processed** data are eligible to be *finished*. 
 * For this purpose, virtual int HostCX::process() 
 *  is here. 
 * 
 */

class baseHostCX : public Host
{
    
	/* Basic elements */
	
	std::string name__; //!< human friendly name

	int fds_ = 0;			//!< socket/file descriptor itself
	int closing_fds_ = 0;   // to close com we call shutdown() which actually don't close fds_. We have to store it and close on very object destruction.
	bool error_ = false;//!< indicates that the last read operation on socket returned 0
	
	
	/* Reconnection facility */
	
	bool permanent_; 	      //!< indice if we want to reconnect, if socket fails (unless HostCX is reduced)
	time_t last_reconnect_;   //!< last time of an attempt to reconnect
	int reconnect_delay_ = 30; //!< how often we will reconnect the socket (in seconds)
	int idle_delay_ = 3600;     // when connection is idle for this time, it will timeout

	time_t t_connected; 	  //!< connection timeout facility, useful when socket is opened non-blocking
	
	time_t w_activity;
    time_t r_activity;
	
	
	/* socket I/O facility */
	
	buffer readbuf_;  //!< read buffer
	buffer writebuf_; //!< write buffer
	
	
	ssize_t processed_bytes_; //!< number of bytes processed by last process()
	ssize_t next_read_limit_;  // limit next read() operation to this number. Zero means no restrictions.
	
	/*! 
	 ! If you are not attempting to do something really special, you want it to keep it as true (default). See [HostCX::auto_finish()](@ref HostCX::auto_finish) */
	bool auto_finish_; //!< mark if processed bytes should be automatically removed from read buffer

	
	/* Custom state facility */
	
	// administrative status of the CX. It's not functional attribute inside HostCX framework -- free for use
	bool adm_status_ = true;
	
	// paused hostcx won't be read/written until unpaused.
	bool paused_read_ = false;
    bool paused_write_ = false;
//     bool delayed_accept_ = false;
    
    // Com class can optionally unpause socket, using paused flag as signalling between Com and CX interfaces.
    // You want to keep it true
    bool allow_com_unpause_ = true;

    // after writing all data into the socket we should shutdown the socket
    bool close_after_write_ = false;
    
protected:
    
    baseCom* com_;
    
public:
    
    baseCom* com() { return com_; }
    inline void com(baseCom* c) { com_ = c; if(c != nullptr) {  com_->init(this); } else { DIAS_("baseHostCX:com: setting com_ to nullptr"); } };

    
    bool readable() { return com()->readable(socket());};
    bool writable() { return com()->writable(socket());};
    
    baseHostCX* peer_ = nullptr;
    baseHostCX* peer() { return peer_; } 
    // set both levels of peering: cx and com
    void peer(baseHostCX* p) { peer_ = p; com()->peer_ = peer()->com(); }
    baseCom* peercom() { if(peer()) { return peer()->com(); } return nullptr; }
    
    inline std::string& log() { return com()->log_buffer_; };    
public:
	/* meters */
	unsigned int meter_read_count;
	unsigned int meter_write_count;
	unsigned int meter_read_bytes;
	unsigned int meter_write_bytes;
	
public:
	
    baseHostCX( baseCom* c, const char* h, const char* p );
	baseHostCX(baseCom* c, unsigned int s);
	virtual ~baseHostCX();
	
	std::string& name();
	const char* c_name();
	
    ssize_t processed_bytes() { return processed_bytes_; };
    
	// larval connection facility
	bool opening_ = false;
	inline bool opening() { return opening_; }
	inline void opening(bool b) { opening_ = b; if (b) { time(&t_connected); time(&w_activity); time(&r_activity); } }
	// if we are trying to open socket too long - effective for non-blocking sockets only
	bool opening_timeout();
    bool idle_timeout();

	bool paused_read();
    bool paused_write();
	inline void paused_read(bool p) { paused_read_ = p; }
	inline void paused_write(bool p) { paused_write_ = p; }
	inline void paused(bool p) { paused_read(p); paused_write(p); }
	
	// add the facility to indicate to owning object there something he should pay attention
	// this us dummy implementation returning false
	virtual bool new_message() { return false; }

	inline int unblock() { return com()->unblock(fds_);}
	
	inline bool status() { return adm_status_; }
	inline void status(bool b) { adm_status_ = b; }
	inline bool up() { return status(); }
	inline void up(bool b) { status(b); }
	inline bool down() { return !up(); };
	inline void down(bool b) { status(!b); }
		
	
	void shutdown();
	inline bool valid() { return ( fds_ > 0 && !error() ); };
	inline bool error() { 
        if(com() != nullptr) return (error_ || com()->error());
        return error_ ; 
    }
	inline void error(bool b) { error_ = b; }
	void socket(int s) {
		if (s != 0) {
			fds_ = s;
		}
	};
    inline void remove_socket() { fds_ = 0; closing_fds_ = 0; };
    
	int socket() const { return fds_; };
    bool is_connected();
	
	void permanent(bool p) { permanent_=p; }
	bool permanent(void) const { return permanent_; }

	/*!
	 Before the next *process()* is invoked, 
	 Set to false using *auto_finish(false)* to keep data in the buffer.remove automatically processed bytes from read buffer before next read cycle is run.
	 4 from 5 psychiatrists recommend this  for sake of your own sanity.
	*/		
	void auto_finish(bool a) { auto_finish_ = a; } 
	bool auto_finish() { return auto_finish_; }

	bool reduced() const { return !( host_.size() && port_.size() ); } 
	int connect(bool blocking=false);
	bool reconnect(int delay=5);
	inline int reconnect_delay() { return reconnect_delay_; }
	inline int idle_delay() { return idle_delay_; };
        inline void idle_delay(int d) { idle_delay_ = d; };
    
	inline bool should_reconnect_now() { time_t now = time(NULL); return (now - last_reconnect_ > reconnect_delay() && !reduced()); }
	
	inline buffer* readbuf() { return &readbuf_; }
	inline buffer* writebuf() { return &writebuf_; } 
	
	inline void send(buffer& b) { writebuf_.append(b); }
	inline int  peek(buffer& b) { int r = com()->peek(this->socket(),b.data(),b.capacity(),0); if (r > 0) { b.size(r); } return r; }
	
	inline ssize_t next_read_limit() { return next_read_limit_; }
	inline void next_read_limit(ssize_t s) { next_read_limit_ = s; }
	
	int read();
	int process_() { return process(); };
	int write();
	
	
	//overide this, and return number of bytes to be possible to passed to application/another hostcx
	//
	virtual int process();
	
	virtual void to_write(buffer b);
	virtual void to_write(unsigned char* c, unsigned int l); 
	inline bool close_after_write() { return close_after_write_; };
	inline void close_after_write(bool b) { close_after_write_ = b; };
	
	virtual buffer to_read();
	virtual ssize_t finish();
	
	// pre- and post- functions/hooks called as the very first or last command in the read() function
	virtual void pre_read();
	virtual void post_read();
	
	// pre- and post- functions/hooks called as the very first or last command in the write() function
	virtual void pre_write();
	virtual void post_write(); //note: write buffer is emptied AFTER this call, but data are already sent.
	
	virtual void on_timer() {};
	
	// call com()->on_accept_socket(int fd) on bind->accepted socket and initialize upper level Com
	void on_accept_socket(int fd);
    // call com()->on_delay_socket(int fd) on bind->accepted socket to init upper level Com. This is analogy to accept_socket,
    // but is called on socket which is not accepted yet (CX is paused and if baseProxy is used, put in delay list).
    void on_delay_socket(int fd);
	
    // return human readable details of this object
	std::string hr();
    std::string full_name(unsigned char);
    
    // debug options
    static bool socket_in_name;
    static bool online_name;

};

#endif