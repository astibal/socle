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
#include <unistd.h>


#include <basecom.hpp>
#include <log/logger.hpp>
#include <lockbuffer.hpp>
#include <display.hpp>

#define HOSTCX_BUFFSIZE 2048
#define HOSTCX_BUFFMAXSIZE (1024*HOSTCX_BUFFSIZE)

//! Basic Host structure class
/*! 
 * This class is intended to be inherited in all other Host context structures
 */
class Host
{
protected:
	mutable std::string host_; //!< hostname
	mutable std::string port_; //!< port
	mutable std::shared_mutex host_lock_;

public:

	Host() = default;

	Host(Host const& r) {
	    host_ = r.host_;
	    port_ = r.port_;
	}

	Host& operator=(Host const& r) {

	    if(&r != this) {
            host_ = r.host_;
            port_ = r.port_;
        }

        return *this;
    }

	//! Constructor filling hostname and the port
	/*!
	 *  Create host structure
	 *  \param h - hostname string
	 *  \param p - port number (as the string
	 */
	Host(const char* h, const char* p) : host_(h),port_(p) {}
	
	//! returns host part of the structure
	std::string host() { return host_; }
	//! returns port part of the structure
	std::string port() { return port_; }

    void host(std::string const& s) const {

         auto l_ = std::unique_lock(host_lock_);
        host_ = s;
    }
    void port(std::string const& s) const {

        auto l_ = std::unique_lock(host_lock_);
        port_ = s;
    }

	std::string chost() const {
        auto l_ = std::shared_lock(host_lock_);
	    return host_;
	}
	std::string cport() const {
        auto l_ = std::shared_lock(host_lock_);
	    return port_;
	}

    virtual std::string to_string(int verbosity) const { return string_format("%s:%s", chost().c_str(), cport().c_str()); };
	[[nodiscard]] inline std::string str() const { return to_string(iINF); };
};

namespace std
{
    template <>
    struct hash<Host>
    {
        size_t operator()(const Host& h) const;
    };
}
bool operator==(const Host& h, const Host& hh);


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

class Proxy;


namespace socle {

    class com_error : public std::runtime_error {
    public:
        explicit com_error(const char* w) : std::runtime_error(w) {};
    };

    class com_is_null : public socle::com_error {
    public:
        com_is_null() : com_error("com is null") {};
    };

    class create_socket_failed : public com_error{
    public:
        create_socket_failed() : com_error("failed to create a socket") {};
    };
}

class baseHostCX : public Host
{
    using buffer_guard = locked_guard<lockbuffer>;

	/* Basic elements */
	
	mutable std::string name_;      //!< human friendly name
	mutable std::mutex name_mutex_;  // protect name_

	int fds_ = 0;			//!< socket/file descriptor itself
	int closing_fds_ = 0;   // to close com we call shutdown() which actually don't close fds_. We have to store it and close on very object destruction.
	bool error_ = false;//!< indicates that the last read operation on socket returned 0
	
	
	/* Reconnection facility */
	
	bool permanent_; 	      //!< indice if we want to reconnect, if socket fails (unless HostCX is reduced)
	time_t last_reconnect_;   //!< last time of an attempt to reconnect
	unsigned short reconnect_delay_ = 7; //!< how often we will reconnect the socket (in seconds)
	unsigned short idle_delay_ = 3600;     // when connection is idle for this time, it will timeout

	time_t t_connected{0}; 	  //!< connection timeout facility, useful when socket is opened non-blocking
	
	time_t w_activity{0};
    time_t r_activity{0};
	
	
	/* socket I/O facility */
	
	lockbuffer readbuf_;  //!< read buffer
	lockbuffer writebuf_; //!< write buffer
	
	
	ssize_t processed_bytes_; //!< number of bytes processed by last process()
	int next_read_limit_;     // limit next read() operation to this number. Zero means no restrictions.
	                          // <0 means don't read at all
	
	/*! 
	 ! If you are not attempting to do something really special, you want it to keep it as true (default). See [HostCX::auto_finish()](@ref HostCX::auto_finish) */
	bool auto_finish_; //!< mark if processed bytes should be automatically removed from read buffer

	
	/* Custom state facility */
	
	
	// waiting_for_peercom hostcx won't be read/written until unpaused.
	bool read_waiting_for_peercom_ = false;
    bool write_waiting_for_peercom_ = false;

    // after writing all data into the socket we should shutdown the socket
    bool close_after_write_ = false;

    // larval connection facility
    bool opening_ = false;

    baseHostCX* peer_ = nullptr;

    // if io is disabled, no read/write should be called.
    // This is admin indication flag, if you call read() or write(), it will succeed.
    // Setting is not enforced to prevent EAGAIN loops
    bool io_disabled_ = false;
protected:
    
    baseCom* com_ = nullptr;
    Proxy* parent_proxy_ = nullptr;
    unsigned char parent_flag_ = '0';

    bool rescan_out_flag_ = false;

    logan_lite log = logan_lite("proxy");
public:

    baseCom* com() const { return com_; }
    void com(baseCom* c);
    void rename(const char* str) {
        auto l_ = std::scoped_lock(name_mutex_);
        name_ = str;
    }

    inline Proxy* parent_proxy() const { return parent_proxy_; };
    inline unsigned char parent_flag() const { return parent_flag_; }
    inline void parent_proxy(Proxy* p, unsigned char flag) { parent_proxy_ = p; parent_flag_ = flag; };
    
    bool readable() const { return com()->readable(socket()) && !io_disabled(); };
    bool writable() const { return com()->writable(socket()) && !io_disabled(); };

    baseHostCX* peer() const { return peer_; }
    // set both levels of peering: cx and com
    void peer(baseHostCX* p) {
        peer_ = p;
        com()->peer(peer()->com());
    }

    baseCom* peercom() const { if(peer()) { return peer()->com(); } return nullptr; }
    
    inline std::string& comlog() const { if(com()) return com()->log_buffer_; throw socle::com_is_null(); };
public:
	/* meters */
	unsigned int  meter_read_count;
    unsigned int  meter_write_count;
    buffer::size_type  meter_read_bytes;
    buffer::size_type  meter_write_bytes;
	
public:
	
    baseHostCX( baseCom* c, const char* h, const char* p );
	baseHostCX(baseCom* c, int s);

	baseHostCX() = delete;
	baseHostCX(const baseHostCX&) = delete;
	baseHostCX& operator=(const baseHostCX&) = delete;

	virtual ~baseHostCX();

	// forcing rename or calling name with force=true is ok for const, name is mutable and protected by mutex
    void rename() const { name(true); }
	std::string& name(bool force=false) const;
	const char* c_name() const;
	
    inline ssize_t processed_bytes() const noexcept { return processed_bytes_; };
    

	inline bool opening() const { return opening_; }
	inline void opening(bool b) { opening_ = b; if (b) { time(&t_connected); time(&w_activity); time(&r_activity); } }
	// if we are trying to open socket too long - effective for non-blocking sockets only
	bool opening_timeout();
    bool idle_timeout();

	bool read_waiting_for_peercom ();
    bool write_waiting_for_peercom ();
	inline void read_waiting_for_peercom (bool p) { read_waiting_for_peercom_ = p; }
	inline void write_waiting_for_peercom (bool p) { write_waiting_for_peercom_ = p; }
	inline void waiting_for_peercom (bool p) {
	    read_waiting_for_peercom(p);
        write_waiting_for_peercom(p);
	}
	
	// add the facility to indicate to owning object there something he should pay attention
	// this us dummy implementation returning false
	virtual bool new_message() const { return false; }

	inline int unblock() const { return com()->unblock(fds_); }

	virtual void shutdown();
	inline bool valid() const { return ( fds_ > 0 && !error() ); };
	inline bool error() const {
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

    [[nodiscard]] int socket() const { return fds_; };
    [[nodiscard]] int real_socket() const { if(com_) { return com_->translate_socket(fds_); } return socket(); }

    [[maybe_unused]] [[nodiscard]] bool is_connected();
    [[nodiscard]] int closed_socket() const { return closing_fds_; };

    void permanent(bool p) { permanent_=p; }
    [[nodiscard]] bool permanent() const { return permanent_; }

	/*!
	 Before the next *process()* is invoked, 
	 Set to false using *auto_finish(false)* to keep data in the buffer.remove automatically processed bytes from read buffer before next read cycle is run.
	 4 from 5 psychiatrists recommend this  for sake of your own sanity.
	*/
    [[maybe_unused]] void auto_finish(bool a) { auto_finish_ = a; }
	bool auto_finish() const { return auto_finish_; }

    [[nodiscard]] bool reduced() const { return host_.empty() && port_.empty() ; }
	int connect();
	bool reconnect(int delay=5);
	inline int reconnect_delay() const { return reconnect_delay_; }
	inline int idle_delay() const { return idle_delay_; };
        inline void idle_delay(int d) { idle_delay_ = d; };
    
	inline bool should_reconnect_now() const { time_t now = time(nullptr); return (now - last_reconnect_ > reconnect_delay() && !reduced()); }
	
	inline lockbuffer* readbuf() { return &readbuf_; }
	inline lockbuffer const* readbuf() const { return &readbuf_; }

	inline lockbuffer* writebuf() { return &writebuf_; }
    [[maybe_unused]] inline lockbuffer const* writebuf() const { return &readbuf_; }
	
	inline void send(buffer& b) { writebuf_.append(b); }
	inline int  peek(buffer& b) const { int r = com()->peek(this->socket(),b.data(),b.capacity(),0); if (r > 0) { b.size(r); } return r; }
	
	inline int next_read_limit() const { return next_read_limit_; }
	inline void next_read_limit(int s) { next_read_limit_ = s; }



	inline bool io_disabled() const {
	    if(io_disabled_)
	        _deb(" => io is administratively disabled");
	    return io_disabled_;
	}
	inline void io_disabled(bool n) {
	    _deb("setting io disabled: %d", n);
        io_disabled_ = n;
	}

	int read();
	int io_read(void* where, size_t len, int flags);

	int process_() { return process(); };
	int write();
	int io_write(unsigned char* data, size_t tx_size, int flags) const;
	
	
	//overide this, and return number of bytes to be possible to passed to application/another hostcx
	//
	virtual int process();
	
	virtual void to_write(buffer b);
    virtual void to_write(const std::string&);
	virtual void to_write(unsigned char* c, unsigned int l); 
	inline bool close_after_write() const { return close_after_write_; };
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
    // but is called on socket which is not accepted yet (CX is waiting_for_peercom and if baseProxy is used, put in delay list).
    void on_delay_socket(int fd);
	
    // return human readable details of this object
	std::string to_string(int verbosity) const override;
    std::string full_name(unsigned char);
    
    // debug options
    static bool socket_in_name;
    static bool online_name;

};

#endif