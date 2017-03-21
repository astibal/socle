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

bool baseHostCX::socket_in_name = false;
bool baseHostCX::online_name = false;

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
    paused_read_ = false;
    paused_write_ = false;

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
    paused_read_ = false;
    paused_write_ = false;

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

    if(fds_ > 0) {
        com()->set_poll_handler(fds_,nullptr);
        com()->close(fds_);
    }

    if(closing_fds_ > 0) {
        com()->set_poll_handler(closing_fds_,nullptr);
        com()->close(closing_fds_);
    }
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


bool baseHostCX::paused_read() {

    if(paused_read_ && peercom()) {
        if(peercom()->com_status()) {
            DIAS_("Peer's Com status is OK, unpausing");
            paused_read(false);
        }
    }
    else if(paused_read_) {
        // peer() == NULL !
        DUMS_("baseHostCX::paused: paused, but no peer set => no peer to wait for => manual mode");
    }

    return paused_read_;
}

bool baseHostCX::paused_write() {

    if(paused_write_ && peercom()) {
        if(peercom()->com_status()) {
            DIA_("baseHostCX::paused_write[%s]: peer's com status ok, unpausing write",c_name());
            paused_write(false);
        }
    }
    else if(paused_write_) {
        // peer() == NULL !
        DUMS_("baseHostCX::paused: paused, but no peer set => no peer to wait for => manual mode");
    }

    return paused_write_;
}



bool baseHostCX::is_connected() {
    bool status = com()->is_connected(socket());
    DIA_("com()->is_connected[%s]: getsockopt(%d,SOL_SOCKET,SO_ERROR,..,..) reply %d",c_name(),socket(),status);

    return status;
}

void baseHostCX::shutdown() {

    if(fds_ != 0) {
        com()->shutdown(fds_);
        DEB_("HostCX::shutdown[%s]: socket shutdown",c_name());
        closing_fds_ = fds_;
        fds_ = 0;
        
        if(com()) {
            com()->master()->unset_monitor(com()->translate_socket(closing_fds_));
        }
    } else {
        DEB_("HostCX::shutdown[%s]: no-op, cannot be shutdown",c_name());
    }
}

std::string& baseHostCX::name(bool force) {

    if(name__.size() == 0 || online_name || force) {
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
                    name__ = string_format("%d::%s_%s:%s",socket(), com()->name().c_str() , host().c_str(),port().c_str());
                } else {
                    name__ = string_format("%s_%s:%s",com()->name().c_str() , host().c_str(),port().c_str());
                }

                //name__ = string_format("%d:<reduced>",socket());
            }
            else {
                name__ = std::string("?:<reduced>");
            }

        } else {

            if(socket_in_name) {
                name__ = string_format("%d::%s_%s:%s",socket(), com()->name().c_str() ,host().c_str(),port().c_str());
            } else {
                name__ = string_format("%s_%s:%s",com()->name().c_str() ,host().c_str(),port().c_str());
            }
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
        shutdown();
        connect();

        DEB_("HostCX::reconnect[%s]: reconnect attempt (previous at %u)",c_name(),last_reconnect_);
        last_reconnect_ = time(NULL);

        return true;
    }
    else if (!permanent()) {
        NOT_("Attempted to reconnect non-permanent CX: %s",c_name());
        return false;
    }
    else if (reduced() ) {
        ERR_("HostCX::reconnect[%s]: reconnecting reduced CX is not possible",c_name());
        last_reconnect_ = time(NULL);
        return false;
    }


    return false;
}

int baseHostCX::read() {

    if(paused_read()) {
        DUM_("HostCX::read[%s]: read operation is paused, returning -1",c_name());
        return -1;
    }
    
    if(peer() && peer()->writebuf()->size() > 200000) {
        DEB_("baseHostCX::read[%d]: deferring read operation",socket());
        com()->rescan_read(socket());
        return -1;
    }

    DUM_("HostCX::read[%s]: calling pre_read",c_name());
    pre_read();

    DUM_("HostCX::read[%s]: readbuf_ size=%d, capacity=%d, previously processed=%d finished",c_name(),readbuf_.size(),readbuf_.capacity(),processed_bytes_);

    if (auto_finish()) {
        finish();
    }

    ssize_t l = 0;

    while(1) {

        // append-like behavior: append to the end of the buffer, don't exceed max. capacity!
        void *ptr = &(readbuf_.data()[readbuf_.size()]);

        ssize_t max_len = readbuf_.capacity()-readbuf_.size();

        if (max_len + l > next_read_limit_ && next_read_limit_ > 0) {
            DUM_("HostCX::read[%s]: read buffer limiter: %d",c_name(), next_read_limit_ - l);
            max_len = next_read_limit_ - l;
        }

        DUM_("HostCX::read[%s]: readbuf_ base=%x, wr at=%x, maximum to write=%d",c_name(),readbuf_.data(),ptr,max_len);


        //read on last position in buffer
        int cur_l = com()->read(socket(), ptr, max_len, 0);

        // no data to read!
        if(cur_l < 0) {

            // if this is first attempt, l is still zero. Fix it.
            if(l == 0) {
                l = -1;
            }
            break;
        }
        else if(cur_l == 0) {
            DIA_("HostCX::read[%s]: error while reading. %d bytes read.",c_name(),l);
            error(true);

            break;
        }


        // change size of the buffer accordingly
        readbuf_.size(readbuf_.size()+cur_l);

        //increment read counter
        l += cur_l;

        if(next_read_limit_ > 0 &&  l >= next_read_limit_) {
            DIA_("HostCX::read[%s]: read limiter hit on %d bytes.",c_name(),l);
            break;
        }

        // in case next_read_limit_ is large and we read less bytes than it, we need to decrement also next_read_limit_

        next_read_limit_ -= cur_l;

        // if buffer is full, let's reallocate it and try read again (to save system resources)

        // testing break
        break;

        if(readbuf_.size() >= readbuf_.capacity()) {
            DIA_("HostCX::read[%s]: read buffer reached it's current capacity %d/%d bytes",c_name(),readbuf_.size(),readbuf_.capacity());
            if(readbuf_.capacity() + HOSTCX_BUFFSIZE <= HOSTCX_BUFFMAXSIZE) {

                if (readbuf_.capacity(readbuf_.capacity() + HOSTCX_BUFFSIZE)) {
                    DIA_("HostCX::read[%s]: read buffer resized capacity %d/%d bytes",c_name(),readbuf_.size(),readbuf_.capacity());
                    continue;

                } else {
                    NOT_("HostCX::read[%s]: memory tension: read buffer cannot be resized!",c_name());
                    // we left potentially some bytes in system buffer
                    com()->forced_read(true);
                }
            }
            else {
                DIA_("HostCX::read[%s]: buffer already reached it's maximum capacity.",c_name());
                // we left potentially some bytes in system buffer
                com()->forced_read(true);
            }
        }

        // reaching code here means that we don't want other iterations
        break;

    }

    //int l = com()->read(socket(), ptr, max_len, 0);
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

    if(paused_write()) {
        DEB_("HostCX::write[%s]: write operation is paused, returning 0",c_name());
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

    ssize_t l = com()->write(socket(), writebuf_.data(), tx_size, MSG_NOSIGNAL);

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

        if(l < static_cast<ssize_t>(writebuf_.size())) {
            DIA_("HostCX::write[%s]: %d bytes written out of %d -> setting socket write monitor",c_name(),l,writebuf_.size());
            // we need to check once more when socket is fully writable
            
            //com()->set_write_monitor(socket());
            com()->rescan_write(socket());
            rescan_out_flag_ = true;
            
        } else {
            // write buffer is empty
            if(rescan_out_flag_) {
                rescan_out_flag_ = false;
                
                // stop monitoring write which results in loop an unnecesary write() calls
                com()->change_monitor(socket(), EPOLLIN);
            }
        }

        writebuf_.flush(l);

        if(com()->debug_log_data_crc) DEB_("HostCX::write[%s]: after: buffer crc = %X",c_name(), socle_crc32(0,writebuf()->data(),writebuf()->size()));

        if(close_after_write() && writebuf()->size() == 0) {
            shutdown();
        }
    }
    else if(l == 0 && writebuf()->size() > 0) {
        // write unsuccessful, we have to try immediatelly socket is writable!
        DIA_("HostCX::write[%s]: %d bytes written out of %d -> setting socket write monitor",c_name(),l,writebuf_.size());
        // com()->set_write_monitor(socket());

        com()->rescan_write(socket());
        rescan_out_flag_ = true;
    }
    else if(l < 0) {
        DIA_("write failed: %s. Unrecoverable.", string_error().c_str());
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

std::string baseHostCX::to_string(int verbosity) {
    std::string r;
    r+= this->name() + ( verbosity > INF ? string_format(" | fd=%d | rx_cnt=%d rx_b=%d / tx_cnt=%d tx_b=%d", com() ? com()->translate_socket(socket()) : socket(), meter_read_count,meter_read_bytes,
                         meter_write_count,meter_write_bytes) : "");
    return r;
}

std::string baseHostCX::full_name(unsigned char side) {
    const char* t = host().c_str();
    const char* t_p = port().c_str();
    int t_s = socket();
    std::string  t_ss;
    if(socket_in_name) t_ss  = string_format("::%d:",t_s);
    std::string t_c = "";
    if (com() != nullptr)  t_c = com()->name();

    const char* p = "?";
    const char*  p_p = "?";
    int          p_s = 0;
    const char*  p_c = "?";
    std::string  p_ss;

    if (peer() != nullptr) {
        p =  peer()->host().c_str();
        p_p =  peer()->port().c_str();
        p_s = peer()->socket();
        if(socket_in_name) p_ss  = string_format("::%d:",p_s);

        if (peer()->com() != nullptr) {
            if(peer()->com() != nullptr) {
                p_c = peer()->com()->name().c_str();
            }
        }
//         p =  "peerip";
//         p_p =  "pport";

    } else {
        return string_format("%s_%s%s:%s",t_c.c_str(),t_ss.c_str(),t,t_p);
    }

    if ( (side == 'l') || ( side == 'L') ) {
        return string_format("%s_%s%s:%s to %s_%s%s:%s",t_c.c_str(),t_ss.c_str(),t,t_p,p_c,p_ss.c_str(),p,p_p);
    }

    //else
    return string_format("%s_%s%s:%s to %s_%s%s:%s",p_c,p_ss.c_str(),p,p_p,t_c.c_str(),t_ss.c_str(),t,t_p);

}

