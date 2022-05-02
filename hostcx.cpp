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
#include "log/logger.hpp"
#include "display.hpp"
#include "crc32.hpp"
#include "iproxy.hpp"


namespace std
{
    size_t hash<Host>::operator()(const Host& h) const
        {
            const std::string hs = h.chost();
            const std::string hp = h.cport();
            // Compute individual hash values for two data members and combine them using XOR and bit shifting
            return ((hash<string>()(hs) ^ (hash<string>()(hp) << 1)) >> 1);
        }
}

bool operator==(const Host& h, const Host& hh) {
    std::string s = h.chost() + ":" + h.cport();
    std::string ss = hh.chost() + ":" + hh.cport();

    return s == ss;
}


baseHostCX::baseHostCX(baseCom* c, const char* h, const char* p): Host(h, p) {

    writebuf_.capacity(baseHostCX::params_t::buffsize);
    readbuf_.capacity(baseHostCX::params_t::buffsize);

    //whenever we initialize object with socket, we will be already opening!
    opening(true);

    if(!c) {
        throw socle::com_is_null();
    }

    com_ = std::unique_ptr<baseCom>(c);
    com()->init(this);
}

baseHostCX::baseHostCX(baseCom* c, int s): fds_(s) {

    writebuf_.capacity(baseHostCX::params_t::buffsize);
    readbuf_.capacity(baseHostCX::params_t::buffsize);

    //whenever we initialize object with socket, we will be already opening!
    opening(true);

    if(!c) {
        throw socle::com_is_null();
    }

    com_ = std::unique_ptr<baseCom>(c);
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
}


void baseHostCX::com(baseCom* c) {
    com_ = std::unique_ptr<baseCom>(c);
}

int baseHostCX::connect() {

    if(! com()) {
        return -1;
    }

    opening(true);

    _deb("HostCX::connect[%s]: blocking=%d",c_type(), baseCom::GLOBAL_IO_BLOCKING());
    fds_ = com()->connect(host_.c_str(),port_.c_str());
    error_ = false;

    if (fds_ > 0 && baseCom::GLOBAL_IO_BLOCKING()) {
        _deb("HostCX::connect[%s]: blocking, connected successfully, socket %d",c_type(),fds_);
        opening(false);
    }
    else if (baseCom::GLOBAL_IO_BLOCKING()) {
        _deb("HostCX::connect[%s]: blocking, failed!",c_type());
        opening(false);
    }

    return fds_;
}


bool baseHostCX::opening_timeout() {

    if (!opening()) {
        _dum("baseHostCX::opening_timeout: already opened");
        return false;
    } else {
        time_t now = time(nullptr);
        if (now - t_connected > reconnect_delay()) {
            _dia("opening_timeout: timeout!");
            return true;
        }
    }

    return false;
}


bool baseHostCX::idle_timeout() const {
    time_t now = time(nullptr);
    bool read_timeout = false;
    bool write_timeout = false;

    if (now - w_activity > idle_delay() && now - w_activity) {
        write_timeout = true;
    }
    if (now - r_activity > idle_delay() && now - r_activity) {
        read_timeout = true;
    }

    if(write_timeout and read_timeout) {
        _dia("baseHostCX::idle_timeout: timeout");
        return true;
    }

    return false;
}


bool baseHostCX::read_waiting_for_peercom () {

    if(read_waiting_for_peercom_ && peercom()) {
        if(peercom()->com_status()) {
            _dia("baseHostCX::read_waiting_for_peercom: peer's com status is OK after %dx, un-pausing", peer_stats.com_not_ready_counter);
            read_waiting_for_peercom(false);
            peer_stats.com_not_ready_counter = 0;
        } else {
            _dia("baseHostCX::read_waiting_for_peercom: peer's com status not ready (%dx), rescanning read", peer_stats.com_not_ready_counter);

            ++peer_stats.com_not_ready_counter > baseHostCX::params_t::com_not_ready_slowdown ?
                peercom()->rescan_read(peercom()->socket()) : peercom()->set_monitor(peercom()->socket());
        }
    }
    else if(read_waiting_for_peercom_) {
        // peer() == nullptr !
        _dum("baseHostCX::read_waiting_for_peercom: no peer set => no peer to wait for => manual mode");
    }

    return read_waiting_for_peercom_;
}

bool baseHostCX::write_waiting_for_peercom () {

    if(write_waiting_for_peercom_) {
        if(peercom()) {
            if(peercom()->com_status()) {
                _dia("baseHostCX::write_waiting_for_peercom: peer's com status ok after %dx, un-pausing write", peer_stats.com_not_ready_counter);
                write_waiting_for_peercom(false);
                peer_stats.com_not_ready_counter = 0;
            }
            else {
                _dia("baseHostCX::write_waiting_for_peercom: peer's com status not ready (%dx), rescanning write", peer_stats.com_not_ready_counter);
                ++peer_stats.com_not_ready_counter > baseHostCX::params_t::com_not_ready_slowdown ?
                peercom()->rescan_write(peercom()->socket()) : peercom()->set_write_monitor(peercom()->socket());
            }
        }
        else  {
            // peer() == nullptr !
            _err("baseHostCX::write_waiting_for_peercom: no peer set => no peer to wait for => manual mode");
            error(true);
        }
    }

    return write_waiting_for_peercom_;
}



bool baseHostCX::is_connected() {
    bool status = com()->is_connected(socket());
    _dia("baseHostCX::is_connected[%s]: getsockopt(%d,SOL_SOCKET,SO_ERROR,..,..) reply %d", c_type(), socket(), status);

    return status;
}


void baseHostCX::unhandle() const {

    if (com()) {
        int closed_s = closed_socket();
        if (closed_s != 0) {
            com()->unset_monitor(closed_s);
            com()->set_poll_handler(closed_s, nullptr);
        }
        else {
            int opened_s = socket();
            if (opened_s != 0) {
                com()->unset_monitor(opened_s);
                com()->set_poll_handler(opened_s, nullptr);
            }
        }
    }
}

void baseHostCX::shutdown() {

    parent_proxy(nullptr, '-');

    if(fds_ != 0) {
        closing_fds_ = fds_;

        if(com()) {
            com()->shutdown(closing_fds_);
            _deb("baseHostCX::shutdown[%s]: socket shutdown on com", c_type());

            unhandle();
            _deb("baseHostCX::shutdown[%s]: socket unhandled on com", c_type());
        }
        fds_ = 0;
    } else {
        _deb("baseHostCX::shutdown[%s]: no-op, cannot be shutdown",c_type());
    }
}

std::string& baseHostCX::name(int level, bool force) const {

    if(name_empty() || online_name || force) {

        if (reduced()) {
            std::string com_name = "?";
            if(com() != nullptr) {
                com_name = com()->c_type();
            }

            std::string res_host;
            std::string res_port;

            if (valid()) {

                if(com() != nullptr) {
                    com()->resolve_socket_src(fds_, &res_host, &res_port);
                    host(res_host);
                    port(res_port);
                }

                if(socket_in_name) {
                    name(string_format("%d::%s_%s:%s", socket(), com()->shortname().c_str() , chost().c_str(), cport().c_str()));
                } else {
                    name(string_format("%s_%s:%s", com()->shortname().c_str() , chost().c_str(), cport().c_str()));
                }

                //name__ = string_format("%d:<reduced>",socket());
            }
            else {
                name(std::string("?:<reduced>"));
            }

        } else {

            if(socket_in_name) {
                name(string_format("%d::%s_%s:%s", socket(), com()->shortname().c_str() , chost().c_str(), cport().c_str()));
            } else {
                name(string_format("%s_%s:%s", com()->shortname().c_str() , chost().c_str(), cport().c_str()));
            }
        }
    }

    return name_;
}


const char* baseHostCX::c_type() const {
    name();
    return name_.c_str();
}

bool baseHostCX::reconnect(int delay) {

    if (should_reconnect_now() and permanent()) {
        shutdown();
        connect();

        _deb("baseHostCX::reconnect[%s]: reconnect attempt (previous at %u)",c_type(),last_reconnect_);
        last_reconnect_ = time(nullptr);

        return true;
    }
    else if (!permanent()) {
        _not("baseHostCX::reconnect: attempt to reconnect non-permanent CX: %s",c_type());
        return false;
    }
    else if (reduced() ) {
        _err("baseHostCX::reconnect[%s]: reconnecting reduced CX is not possible",c_type());
        last_reconnect_ = time(nullptr);
        return false;
    }


    return false;
}


ssize_t baseHostCX::io_read(void* where, size_t len, int flags = 0) const {
    return com()->read(socket(), where, len, flags);
}

int baseHostCX::read() {

    if(io_disabled()) {
        _war("io is disabled, but read() called");
    }

    if(read_waiting_for_peercom()) {
        _deb("baseHostCX::read[%s]: read operation is waiting_for_peercom, returning -1",c_type());
        return -1;
    }

    if(peer() && peer()->writebuf()->size() > baseHostCX::params_t::write_full) {
        _deb("baseHostCX::read[%d]: deferring read operation",socket());
        com()->rescan_read(socket());
        return -1;
    }

    buffer_guard bg(readbuf());


    _dum("HostCX::read[%s]: calling pre_read",c_type());
    pre_read();

    if(next_read_limit_ < 0) {
        next_read_limit_ = 0;
        return -1;
    }

    _dum("HostCX::read[%s]: readbuf_ size=%d, capacity=%d, previously processed=%d finished", c_type(),
         readbuf_.size(), readbuf_.capacity(), processed_in_);

    if (auto_finish()) {
        finish();
    }

    ssize_t l = 0;

    while(true) {

        // append-like behavior: append to the end of the buffer, don't exceed max. capacity!
        void *cur_read_ptr = &(readbuf_.data()[readbuf_.size()]);

        // read only amount of bytes fitting the buffer capacity
        auto cur_read_max = static_cast<ssize_t>(readbuf_.capacity()-readbuf_.size());

        if (cur_read_max + l > next_read_limit() && next_read_limit() > 0) {
            _deb("HostCX::read[%s]: read buffer limiter: %d",c_type(), next_read_limit() - l);
            cur_read_max = next_read_limit() - l;
        }

        _ext("HostCX::read[%s]: readbuf_ base=%x, wr at=%x, maximum to write=%d", c_type(),
                readbuf_.data(), cur_read_ptr,cur_read_max);


        //read on last position in buffer
        int cur_l = io_read(cur_read_ptr, cur_read_max);

        // no data to read!
        if(cur_l < 0) {

            // if this is first attempt, l is still zero. Fix it.
            if(l == 0) {
                l = -1;
            }
            break;
        }
        else if(cur_l == 0) {
            _dia("baseHostCX::read[%s]: error while reading. %d bytes read.", c_type(), l);
            error(true);

            break;
        }


        // change size of the buffer accordingly
        readbuf_.size(readbuf_.size()+cur_l);

        //increment read counter
        l += cur_l;

        if(next_read_limit_ > 0 &&  l >= next_read_limit_) {
            _dia("baseHostCX::read[%s]: read limiter hit on %d bytes.", c_type(), l);
            break;
        }

        // in case next_read_limit_ is large and we read less bytes than it, we need to decrement also next_read_limit_

        next_read_limit_ -= cur_l;

        // if buffer is full, let's reallocate it and try read again (to save system resources)

        // testing break
        // break;

        if(readbuf_.size() >= readbuf_.capacity()) {
            _dia("baseHostCX::read[%s]: read buffer reached it's current capacity %d/%d bytes", c_type(),
                    readbuf_.size(), readbuf_.capacity());

            if(readbuf_.capacity() * 2  <= get_max_buffsize()) {

                if (readbuf_.capacity(readbuf_.capacity() * 2)) {
                    _dia("baseHostCX::read[%s]: read buffer resized capacity %d/%d bytes", c_type(),
                            readbuf_.size(), readbuf_.capacity());

                } else {
                    _not("baseHostCX::read[%s]: memory tension: read buffer cannot be resized!", c_type());
                }
            }
            else {
                _dia("baseHostCX::read[%s]: buffer already reached it's maximum capacity.", c_type());
            }
        }

        // reaching code here means that we don't want other iterations
        break;

    }

    if (l > 0) {

        meter_read_bytes += l;
        meter_read_count++;
        r_activity = time(nullptr);

        // claim opening socket already opened
        if (opening()) {
            _dia("baseHostCX::read[%s]: connection established", c_type());
            opening(false);
        }



        _ext("baseHostCX::read[%s]: readbuf_ read %d bytes", c_type(), l);

        processed_in_ = 0L;

        if(meter_read_bytes > processed_in_total_) {
            processed_in_ = process_in_();
            processed_in_total_ += processed_in_;
        }

        _deb("baseHostCX::read[%s]: readbuf_ read %d bytes, process()-ed %d bytes, incomplete readbuf_ %d bytes",
             c_type(), l, processed_in_, l - processed_in_);


        // data are already processed
        _deb("baseHostCX::read[%s]: calling post_read",c_type());
        post_read();

        _if_deb {
            if (baseCom::debug_log_data_crc) {
                _deb("baseHostCX::read[%s]: after: buffer crc = %X", c_type(),
                     socle::tools::crc32::compute(0, readbuf()->data(), readbuf()->size()));
            }
        }

    } else if (l == 0) {
        _dia("baseHostCX::read[%s]: error while reading", c_type());
        error(true);
    } else {
        processed_in_ = 0;
    }

    // before return, don't forget to reset read limiter
    next_read_limit_ = 0;

    return static_cast<int>(l);
}

void baseHostCX::pre_read() {
}

void baseHostCX::post_read() {
}

std::size_t baseHostCX::process_in_() {
    return process_in();
};
std::size_t baseHostCX::process_out_() {
    return process_out();
};

ssize_t baseHostCX::io_write(unsigned char* data, size_t tx_size, int flags = 0) const {
    return com()->write(socket(), data, tx_size, flags);
}

int baseHostCX::write() {

    auto _debug_tx_size = [this](auto tx_size_orig, auto tx_size, const char* fname) {
        if (tx_size != tx_size_orig) {
            _deb("baseHostCX::write[%s]: calling %s modified data, size %d -> %d",c_type(), fname, tx_size_orig,tx_size);
        }

        _deb("baseHostCX::write[%s]: writebuf_ %d bytes pending %s", c_type(), tx_size, opening() ? "(opening)" : "");
    };

    if(io_disabled()) {
        _war("io is disabled, but write() called");
    }


    if(write_waiting_for_peercom()) {
        _deb("baseHostCX::write[%s]: write operation is waiting_for_peercom, returning 0", c_type());
        return 0;
    }

    buffer_guard bg(writebuf());


    // pre-write operation

    auto tx_size_orig = writebuf_.size();
    pre_write();
    auto tx_size = writebuf_.size();

    _if_deb _debug_tx_size(tx_size_orig, tx_size, "pre_write");

    // process-out operation

    tx_size_orig = writebuf_.size();

    tx_size = tx_size_orig;
    processed_out_ = 0L;

    // check for unseen data to be yet written
    if(meter_write_bytes + tx_size > processed_out_total_) {
        processed_out_ = process_out_();
        processed_out_total_ += processed_out_;
    }
    else {
        // there are still data in buffer, but we have seen them all already
        processed_out_ = tx_size;
    }

    _if_deb {
        _debug_tx_size(tx_size_orig, tx_size, "process_out");
        if(processed_out_ != tx_size) {
            _deb("baseHostCX::write[%s]: process_out processed %d of %d bytes in writebuf", c_type(), tx_size_orig, processed_out_);
        }
    };



    ssize_t l = io_write(writebuf_.data(), std::min(tx_size, processed_out_), MSG_NOSIGNAL);

    if (l > 0) {
        meter_write_bytes += l;
        meter_write_count++;
        w_activity = time(nullptr);

        if (opening()) {
            _deb("baseHostCX::write[%s]: connection established", c_type());
            opening(false);
        }
        _deb("baseHostCX::write[%s]: %d from %d bytes sent from tx buffer at %x", c_type(), l, tx_size, writebuf_.data());
        if (l < static_cast<ssize_t>(tx_size)) {
            // rather log this: not a big deal, but we couldn't have sent all data!
            _dia("baseHostCX::write[%s]: only %d from %d bytes sent from tx buffer!", c_type(), l, tx_size);
        }

        _dum("baseHostCX::write[%s]: calling post_write", c_type());
        post_write();

        if(l < static_cast<ssize_t>(writebuf_.size())) {
            _dia("baseHostCX::write[%s]: %d bytes written out of %d -> setting socket write monitor",
                    c_type(), l, writebuf_.size());
            // we need to check once more when socket is fully writable

            com()->set_write_monitor(socket());
            //com()->rescan_write(socket());
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

        if(baseCom::debug_log_data_crc) {
            _deb("baseHostCX::write[%s]: after: buffer crc = %X", c_type(),
                    socle::tools::crc32::compute(0, writebuf()->data(), writebuf()->size()));
        }

        if(close_after_write() && writebuf()->empty()) {
            shutdown();
        }
    }
    else if(l == 0 and not writebuf()->empty()) {
        // write unsuccessful, we have to try immediately socket is writable!
        _dia("baseHostCX::write[%s]: %d bytes written out of %d -> setting socket write monitor",
                c_type(), l, writebuf_.size());
        //com()->set_write_monitor(socket());

        // write was not successful, wait a while
        com()->rescan_write(socket());
        rescan_out_flag_ = true;
    }
    else if(l < 0) {
        _dia("baseHostCX::write[%s] write failed: %s, unrecoverable.", c_type(), string_error().c_str());
    }

    return l;
}


void baseHostCX::pre_write() {
}


void baseHostCX::post_write() {
}

std::size_t baseHostCX::process_in() {
    return readbuf()->size();
}

std::size_t baseHostCX::process_out() {
    return writebuf()->size();
}


ssize_t baseHostCX::finish() {
    if( readbuf()->size() >= (unsigned int)processed_in_ && processed_in_ > 0) {
        _deb("baseHostCX::finish[%s]: flushing %d bytes in readbuf_ size %d", c_type(), processed_in_, readbuf()->size());
        readbuf()->flush(processed_in_);
        return processed_in_;
    } else if (readbuf()->empty()) {
        _dum("baseHostCX::finish[%s]: already flushed",c_type());
        return 0;
    } else {
        _war("baseHostCX::finish[%s]: attempt to flush more data than in buffer", c_type());
        _war("baseHostCX::finish[%s]: best-effort recovery: flushing all", c_type());
        auto s = readbuf()->size();
        readbuf()->flush(s);
        return s;
    }
}

buffer & baseHostCX::to_read() {
    _deb("baseHostCX::to_read[%s]: returning buffer::view for %d bytes", c_type(), processed_in_);
    return *readbuf();
}

void baseHostCX::to_write(buffer& b) {

    bool fastlane = false;
    if(writebuf()->empty()) {
        if(meter_write_bytes > params_t::fast_copy_start) {
            _deb("baseHostCX::to_write(buf)[%s]: fastlane swap %dB buffer", c_type(), b.size());


            b.swap(*writebuf());

            // resize to original capacity
            b.capacity(writebuf()->capacity());
            b.size(0);

            fastlane = true;
        } else {
            _deb("baseHostCX::to_write(buf)[%s]: going slow mode, detection phase", c_type());
        }
    } else {
        _deb("baseHostCX::to_write(buf)[%s]: going slow mode, %dB in writebuf", c_type(), writebuf()->size());
    }

    if(not fastlane) {
        writebuf_.append(b);
        _deb("baseHostCX::to_write(buf)[%s]: appending %d bytes, buffer size now %d bytes", c_type(), b.size(),
             writebuf_.size());
    }

    com()->set_write_monitor(socket());
}

void baseHostCX::to_write(const std::string& s) {

    writebuf_.append((unsigned char*)s.data(), s.size());
    com()->set_write_monitor(socket());
    _deb("baseHostCX::to_write(ptr)[%s]: appending %d bytes, buffer size now %d bytes", c_type(), s.size(), writebuf_.size());

}

void baseHostCX::to_write(unsigned char* c, unsigned int l) {
    writebuf_.append(c,l);
    com()->set_write_monitor(socket());
    _deb("baseHostCX::to_write(ptr)[%s]: appending %d bytes, buffer size now %d bytes", c_type(), l, writebuf_.size());
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

std::string baseHostCX::to_string(int verbosity) const {

    std::stringstream r_str;

    r_str << name(verbosity);

    if(verbosity > INF) {
        r_str << string_format(" | fd=%d | rx_cnt=%d rx_b=%d / tx_cnt=%d tx_b=%d",
                               com() ? com()->translate_socket(socket()) : socket(),
                               meter_read_count, meter_read_bytes,
                               meter_write_count, meter_write_bytes);
    }
    return r_str.str();
}

std::string baseHostCX::full_name(unsigned char side) {
    std::string self = host();
    std::string self_p = port();
    int self_s = socket();

    std::string  self_ss;
    if(socket_in_name) self_ss  = string_format("::%d:", self_s);

    std::string self_c;
    if (com())  self_c = com()->shortname();

    std::string  peeer = "?";
    std::string  peeer_p = "?";
    int          peeer_s = 0;
    std::string  peeer_c = "?";
    std::string  peeer_ss;

    if (peer()) {
        peeer =  peer()->host();
        peeer_p =  peer()->port();
        peeer_s = peer()->socket();
        if(socket_in_name) peeer_ss  = string_format("::%d:", peeer_s);

        if (peer()->com()) {
            peeer_c = peer()->com()->shortname();
        }

    } else {
        return string_format("%s_%s%s:%s", self_c.c_str(), self_ss.c_str(), self.c_str(), self_p.c_str());
    }

    if ( (side == 'l') || ( side == 'L') ) {
        return string_format("%s_%s%s:%s to %s_%s%s:%s", self_c.c_str(), self_ss.c_str(), self.c_str(), self_p.c_str(),
                             peeer_c.c_str(), peeer_ss.c_str(), peeer.c_str(), peeer_p.c_str());
    }

    //else
    return string_format("%s_%s%s:%s to %s_%s%s:%s", peeer_c.c_str(), peeer_ss.c_str(), peeer.c_str(), peeer_p.c_str(),
                                                        self_c.c_str(), self_ss.c_str(), self.c_str(), self_p.c_str());

}

