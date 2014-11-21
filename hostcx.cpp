/*
    Socle Library Ecosystem
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

#include "hostcx.hpp"
#include "logger.hpp"
#include "display.hpp"
#include "crc32.hpp"

extern logger lout;

bool baseHostCX::socket_in_name = false;

baseHostCX::baseHostCX(baseCom* c, const char* h, const char* p): Host(h, p) {

    permanent_ = false;
    last_reconnect_ = 0;
    reconnect_delay_ = 30;
    fds_ = 0;
    error_ = false;
    
    writebuf_ = buffer(HOSTCX_BUFFSIZE);
    writebuf_.clear();
    
    readbuf_ = buffer(HOSTCX_BUFFSIZE);
    readbuf_.clear();
    processed_bytes_ = 0;
    next_read_limit_ = 0;
    auto_finish_ = true;
    adm_status_ = true;
    paused_ = false;
    
    meter_read_count = 0;
    meter_write_count = 0;
    meter_read_bytes = 0;
    meter_write_bytes = 0;
    
    com_ = c;
    com()->init(this);
}

baseHostCX::baseHostCX(baseCom* c, unsigned int s) {
    
    permanent_ = false;
    last_reconnect_ = 0;
    reconnect_delay_ = 30;
    fds_ = s;   
    error_ = false;
    
    writebuf_ = buffer(HOSTCX_BUFFSIZE);
    writebuf_.clear();
    
    readbuf_ = buffer(HOSTCX_BUFFSIZE);     
    readbuf_.clear();
    processed_bytes_ = 0;
    next_read_limit_ = 0;
    auto_finish_ = true;
    adm_status_ = true;
    paused_ = false;

    meter_read_count = 0;
    meter_write_count = 0;
    meter_read_bytes = 0;
    meter_write_bytes = 0;
    
    //whenever we initialize object with socket, we will be already opening!
    opening(true);
    
    com_ = c;
    com()->init(this);
}

baseHostCX::~baseHostCX() {
    com()->cleanup();
    delete com_;
}


int baseHostCX::connect(bool blocking) {
	
	opening(true);
	
	DEB_("HostCX::connect[%s]: blocking=%d",c_name(),blocking);
	fds_ = com()->connect(host_.c_str(),port_.c_str(),blocking);
	error_ = false;
	
	if (fds_ > 0 && blocking) {
		DEB_("HostCX::connect[%s]: blocking, connected successfully, socket %d",c_name(),fds_);
		opening(false);
	}
	else if (blocking) {
		DEB_("HostCX::connect[%s]: blocking, failed!",c_name());
		opening(false);
	}
	
	return fds_;
}


bool baseHostCX::opening_timeout() {

    if (!opening()) { 
        DUMS_("already opened")
        return false; 
    } else { 
        time_t now = time(NULL); 
        if (now - t_connected > reconnect_delay()) {
            DIAS_("opening timeout");
            return true;
        } 
    } 
    
    return false;
}


bool baseHostCX::idle_timeout() {
    time_t now = time(NULL); 
    if (now - w_activity > idle_delay() && now - w_activity) {
        DIAS_("idle timeout");
        return true;
    }     
    
    return false;
}


bool baseHostCX::paused() {

    if(paused_ && peercom()) {
        if(peercom()->com_status()) {
            DIAS_("Peer's Com status is OK, unpausing");
            paused(false);
        }
    }
    else if(paused_) {
        // peer() == NULL !
        DUMS_("baseHostCX::paused: paused, but no peer set => no peer to wait for => manual mode");
    }
    
    return paused_; 
}


bool baseHostCX::is_connected() {
    bool status = com()->is_connected(socket());
    DIA_("com()->is_connected[%s]: getsockopt(%d,SOL_SOCKET,SO_ERROR,..,..) reply %d",c_name(),socket(),status);
    
    return status;
}

void baseHostCX::close() {
	
 if(fds_ != 0) {
	com()->close(fds_); 
	DEB_("HostCX::close[%s]: socket closed",c_name());
	fds_ = 0; 
 } else {
	 DEB_("HostCX::close[%s]: no-op, cannot be closed",c_name());
 }
}

std::string& baseHostCX::name() {

	if (reduced()) {
        std::string com_name = "?";
        if(com() != nullptr) {
            com_name = com()->name();
        }        
        
		if (valid()) {

            if(com() != nullptr) {
                com()->resolve_socket_src(fds_, &host_,&port_);
            }
            
            if(socket_in_name) {
                name__ = string_format("%d::%s_%s:%s",socket(), com()->name() , host().c_str(),port().c_str());
            } else {
                name__ = string_format("%s_%s:%s",com()->name() , host().c_str(),port().c_str());
            }
            
			//name__ = string_format("%d:<reduced>",socket());
		}
		else {
			name__ = std::string("?:<reduced>");
        }
		
	} else {
        if(name__.size() > 0) {
            return name__;
        }
        
        if(socket_in_name) {
            name__ = string_format("%d::%s_%s:%s",socket(), com()->name() ,host().c_str(),port().c_str());
        } else {
            name__ = string_format("%s_%s:%s",com()->name() ,host().c_str(),port().c_str());
        }
	}

	return name__;
}


const char* baseHostCX::c_name() {
	name();
	return name__.c_str();
}

bool baseHostCX::reconnect(int delay) {

	if (should_reconnect_now() and permanent()) {
		close();
		connect();
		
		DEB_("HostCX::reconnect[%s]: reconnect attempt (previous at %u)",c_name(),last_reconnect_);
		last_reconnect_ = time(NULL);
		
		return true;
	} 
	else
	if (!permanent()) {
		NOT_("Attempted to reconnect non-permanent CX: %s",c_name());
		return false;
	} 
	else
	if (reduced() ) {
		ERR_("HostCX::reconnect[%s]: reconnecting reduced CX is not possible",c_name());
		last_reconnect_ = time(NULL);
		return false;
	}
	
	
	return false;
}
	
int baseHostCX::read() {
	
	if(paused()) {
		DUM_("HostCX::read[%s]: paused, returning -1",c_name());
		return -1;
	}
	
	DUM_("HostCX::read[%s]: calling pre_read",c_name());
	pre_read();
	
	DUM_("HostCX::read[%s]: readbuf_ size=%d, capacity=%d, previously processed=%d finished",c_name(),readbuf_.size(),readbuf_.capacity(),processed_bytes_);
	
	if (auto_finish()) {
		finish();
	}
	
	// append-like behavior: append to the end of the buffer, don't exceed max. capacity!
	void *ptr = &(readbuf_.data()[readbuf_.size()]);
	size_t max_len = readbuf_.capacity()-readbuf_.size();
	
	if (max_len > next_read_limit_ && next_read_limit_ > 0) {
        DUM_("HostCX::read[%s]: read buffer limiter: %d",c_name(), next_read_limit_);
        max_len = next_read_limit_;
	}
	
	DUM_("HostCX::read[%s]: readbuf_ base=%x, wr at=%x, maximum to write=%d",c_name(),readbuf_.data(),ptr,max_len);
	
	ssize_t l = com()->read(socket(), ptr, max_len, 0);
	//int l = recv(socket(), ptr, max_len, MSG_PEEK);

	
	if (l > 0) {
	
		meter_read_bytes += l;
		meter_read_count++;
        time(&r_activity);
	
		// claim opening socket already opened
		if (opening()) {
			DIA_("HostCX::read[%s]: connection established",c_name());
			opening(false);
		}
		
		// change size of the buffer accordingly
		readbuf_.size(readbuf_.size()+l);
		
		// DEB_("HostCX::read[%s]: readbuf_ read %d bytes",c_name(),l);
		
		processed_bytes_ = process_();
		DEB_("HostCX::read[%s]: readbuf_ read %d bytes, process()-ed %d bytes, incomplete readbuf_ %d bytes",c_name(),l, processed_bytes_,l-processed_bytes_);
		
		
		// data are already processed
		DEB_("HostCX::read[%s]: calling post_read",c_name());
		post_read();
    
        if(com()->debug_log_data_crc) {
            DEB_("HostCX::read[%s]: after: buffer crc = %X",c_name(), socle_crc32(0,readbuf()->data(),readbuf()->size()));         
        }
        
	} else if (l == 0) {
		DIA_("HostCX::read[%s]: error while reading",c_name());
		error(true);
	} else {
		processed_bytes_ = 0;
	}
	
	// before return, don't forget to reset read limiter
	next_read_limit_ = 0;
	
	return l;
}

void baseHostCX::pre_read() {
}

void baseHostCX::post_read() {
}

int baseHostCX::write() {
	
	if(paused()) {
		DEB_("HostCX::write[%s]: paused, returning 0",c_name());	
		return 0;
	}

	
	int tx_size_orig = writebuf_.size();	
	pre_write();
	
	int tx_size = writebuf_.size();	
	
	if (tx_size != tx_size_orig) {
		DEB_("HostCX::write[%s]: calling pre_write modified data, size %d -> %d",c_name(),tx_size_orig,tx_size);
	}
	
	if (tx_size <= 0) {
        DUM_("HostCX::write[%s]: writebuf_ %d bytes pending",c_name(),tx_size);
        // return 0; // changed @ 20.9.2014 by astib. 
                     // Let com() decide what to do if we want to send 0 (or less :) bytes
                     // keep it here for studying purposes. 
                     // For example, if we stop here, no SSL_connect won't happen!
	}
	else {
        DEB_("HostCX::write[%s]: writebuf_ %d bytes pending",c_name(),tx_size);
	}

	int l = com()->write(socket(), writebuf_.data(), tx_size, MSG_NOSIGNAL);
	
	if (l > 0) {
		meter_write_bytes += l;
		meter_write_count++;
        time(&w_activity);
	
		if (opening()) {
			DEB_("HostCX::write[%s]: connection established",c_name());
			opening(false);
		}		
		DEB_("HostCX::write[%s]: %d from %d bytes sent from tx buffer at %x",c_name(),l,tx_size,writebuf_.data());
		if (l < tx_size) {
			// rather log this: not a big deal, but we couldn't have sent all data!
			DIA_("HostCX::write[%s]: only %d from %d bytes sent from tx buffer!",c_name(),l,tx_size);
		}
		
		DUM_("HostCX::write[%s]: calling post_write",c_name());
		post_write();
		
        writebuf_.flush(l);
        
        if(com()->debug_log_data_crc) {
            DEB_("HostCX::write[%s]: after: buffer crc = %X",c_name(), socle_crc32(0,writebuf()->data(),writebuf()->size()));
        }
	}
	
	return l;
}


void baseHostCX::pre_write() {
}


void baseHostCX::post_write() {
}

int baseHostCX::process() {
	return readbuf()->size();
}


ssize_t baseHostCX::finish() { 
	if( readbuf()->size() >= (unsigned int)processed_bytes_ && processed_bytes_ > 0) {
		DEB_("HostCX::finish[%s]: flushing %d bytes in readbuf_ size %d",c_name(),processed_bytes_,readbuf()->size());
		readbuf()->flush(processed_bytes_); 
		return processed_bytes_;
	} else if (readbuf()->size() == 0) {
		DUM_("HostCX::finish[%s]: already flushed",c_name());
		return 0;
	} else {
		WAR_("HostCX::finish[%s]: attempt to flush more data than in buffer",c_name());
		WAR_("HostCX::finish[%s]: best-effort recovery: flushing all",c_name());
		auto s = readbuf()->size();
		readbuf()->flush(s);
		return s;
	}
}

buffer baseHostCX::to_read() { 
	DEB_("HostCX::to_read[%s]: returning buffer::view for %d bytes",c_name(),processed_bytes_);
	return readbuf()->view(0,processed_bytes_); 
}

void baseHostCX::to_write(buffer b) {
    DEB_("HostCX::to_write[%s]: appending to write %d bytes, from buffer struct",c_name(),b.size());
    writebuf_.append(b); 
    DEB_("HostCX::to_write[%s]: write buffer size %d bytes",c_name(),writebuf_.size());
}

void baseHostCX::to_write(unsigned char* c, unsigned int l) {
	DEB_("HostCX::to_write[%s]: appending to write %d bytes from pointer",c_name(),l);
	writebuf_.append(c,l);
	DEB_("HostCX::to_write[%s]: write buffer size %d bytes",c_name(),writebuf_.size());
}

void baseHostCX::on_accept_socket(int fd) { 
	com()->accept_socket(fd); 
	
	if(reduced()) {
        com()->resolve_socket_src(fd, &host_,&port_);
	}
}

void baseHostCX::on_delay_socket(int fd) {
    com()->delay_socket(fd);
}

std::string baseHostCX::hr() {
	std::string r;
	r+= this->name() + " " + string_format("R:%d/%d W:%d/%d",meter_read_count,meter_read_bytes,
								meter_write_count,meter_write_bytes) + " " 
					 + string_format("Rb:%d Wb:%d",readbuf()->size(),writebuf()->size())
					 + string_format(" %p",this);
					 
	return r;
}

std::string baseHostCX::full_name(unsigned char side) {
    const char* t = host().c_str();
    const char* t_p = port().c_str();
    const char* t_c = "";
    if (com() != nullptr)  t_c = com()->name();
    
    const char* p = "";
    const char*  p_p = "";
    const char*  p_c = "";

    if (peer() != nullptr) {
         p =  peer()->host().c_str();
         p_p =  peer()->port().c_str();
    
         if (peer()->com() != nullptr)  p_c = peer()->com()->name();
//         p =  "peerip";
//         p_p =  "pport";
        
    } else {
        return string_format("%s/%s:%s",t_c,t,t_p);
    }

    if ( (side == 'l') || ( side == 'L') ) {
        return string_format("%s/%s:%s to %s/%s:%s",t_c,t,t_p,p_c,p,p_p);
    } 

    //else
    return string_format("%s/%s:%s to %s/%s:%s",p_c,p,p_p,t_c,t,t_p);

}

