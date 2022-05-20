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

#include <apphostcx.hpp>
#include <sslcom.hpp>

AppHostCX::AppHostCX(baseCom* c, const char* h, const char* p) : baseHostCX(c, h, p) {

    if(c->l4_proto() != 0) {
        flow().domain(c->l4_proto());
    }
}
AppHostCX::AppHostCX(baseCom* c, int s) :baseHostCX(c, s) {

    if(c->l4_proto() != 0) {
        flow().domain(c->l4_proto());
    }
}

std::string AppHostCX::to_string(int verbosity) const {

    std::string ts = baseHostCX::to_string(verbosity);
    std::stringstream ss;
    if(verbosity > iINF) {
        auto sz = flow().flow_queue().size();
        ss << string_format("AppHostCX: sz:%ld m:%d ", sz, mode());
    }

    ss << ts;
    return ss.str();
}

int AppHostCX::make_sig_states(std::shared_ptr<sensorType> sig_states, std::shared_ptr<sensorType> source_signatures) {
    auto const& log = log_instance();

    sig_states->clear();
    int r = 0;
    
    _deb("AppHostCX::zip_signatures: zipper start");
    auto& ref = *source_signatures;
    for( auto& [ _, sh_ptr ] : ref ) {
        if(! sh_ptr ) {
            _deb("AppHostCX::zip_signatures: attempt to zip nullptr signature");
            continue;
        }

        _deb("AppHostCX::zip_signatures: sensor 0x%x, adding %s at 0x%x",&sig_states, sh_ptr->name().c_str(), sh_ptr.get());

        // copy over only signature shared pointers, flow match state is fresh one
        sig_states->emplace_back(flowMatchState(),sh_ptr);
        ++r;
    }

    _deb("AppHostCX::zip_signatures: loaded %d of %d",r, source_signatures->size());
    return r;
}


// iterate over all enabled signature trees
bool AppHostCX::detect () {

    bool ret = false;

    // start with 1 - skip starttls signatures
    for(unsigned int i = 1; i < SignatureTree::max_groups ; ++i) {

        auto sensor_ptr = signatures_.sensors_[i];

        if(sensor_ptr) {
            _dia("AppHostCX::detect: tree group %d valid", i);

            if (signatures_.filter_.test(i)) {
                _dia("AppHostCX::detect: tree group %d enabled", i);

                if(detect(sensor_ptr)) {
                    ret = true;
                }
            }
        }
        else {
            _dia("AppHostCX::detect: tree group %d - no signatures", i);
            break;
            // end of first nullptr sensor
        }
    }

    return ret;
}

bool AppHostCX::detect (const std::shared_ptr<sensorType> &cur_sensor) {

    if(not cur_sensor) return false;

    bool matched = false;
    
    if(cur_sensor->empty()) {
        _dia("AppHostCX::detect[%s]: Sensor %x is empty!",c_type(), base_sensor().get());
    }

    auto& ref = *cur_sensor;
    for (auto& [ sig_res, sig_sig ]: ref) {

        if (! sig_res.hit()) {
            _dia("AppHostCX::detect[%s]: Sensor %x, signature name %s", c_type(), base_sensor().get(), sig_sig->name().c_str());
            
            bool r = sig_res.update(&flow(),sig_sig);
            
            vector_range& ret = sig_res.result();
            
            if (r) {
                sig_res.hit() = true;
                on_detect(sig_sig,sig_res,ret);
                
                matched = true;
                // log only in debug - it's up to library user to log it his way
                _deb("AppHostCX::detect[%s]: Signature matched: %s",c_type(), vrangetos(ret).c_str());
                continue;
                
            } else {
                _ext("AppHostCX::detect[%s]: Signature didn't match: %s",c_type(), vrangetos(ret).c_str());
            } 
        } else {
            _deb("AppHostCX::detect[%s]: Signature %s already matched",c_type(), sig_sig->name().c_str());
        }
    }
    
    
    return matched;
}

void AppHostCX::continuous_mode_keeper(buffer const& data) {

    if (flow().flow_queue().size() > 4) {
        flow().pop();
        flow().pop();
    }

    if(data.size() > continuous_data_left) {
        _dia("continuous mode expired");

        continuous_data_left = 0L;
        mode(mode_t::NONE);

    }
    else {
        continuous_data_left -= data.size();
    }

}

void AppHostCX::post_read() {

    if(to_read().empty()) return;

    if ( mode() == mode_t::POST or mode() == mode_t::CONTINUOUS) {
        if(inside_detect_on_continue()) {

            auto const& b = to_read();
            this->flow().append('r', b);

            if(mode() == mode_t::CONTINUOUS) {
                continuous_mode_keeper(b);
            }


            _dia("AppHostCX::post_read[%s]: side %c, flow path: %s", c_type(), 'r', flow().hr().c_str());

            // we can't detect starttls in POST mode
            detect();
            inspect('r');
        }
        else {
            _deb("AppHostCX::post_read[%s]: OUT OF INSPECT WINDOW: side %c, flow path: %s", c_type(), 'r', flow().hr().c_str());
        }
    }
}

void AppHostCX::post_write() {

    if(writebuf()->empty()) return;

    if ( mode() == mode_t::POST ) {
        if(inside_detect_ranges()) {
            auto b = this->writebuf();

            auto f_s = flow().flow_queue().size();
            auto f_last_data_size = flow().flow_queue().back().size();

            _deb("AppHostCX::post_write[%s]: peek_counter %d, written to socket %d, write buffer size %d, flow size %d, flow data size %d",
                 c_type(), peek_write_counter, meter_write_bytes, b->size(), f_s, f_last_data_size);

            // how many data I am missing?
            auto delta = (meter_write_bytes + b->size()) - peek_write_counter;
            buffer delta_b = b->view(b->size() - delta, b->size());

            if (delta > 0) {
                _dia("AppHostCX::post_write[%s]: flow append new %d bytes", c_type(), delta_b.size());
                this->flow().append('w', delta_b);
                peek_write_counter += delta_b.size();
            } else {
                _dia("AppHostCX::post_write:[%s]: data are already copied in the flow", c_type());
            }

            // we can't detect starttls in POST mode
            _dia("AppHostCX::post_write[%s]: side %c, flow path: %s", c_type(), 'w', flow().hr().c_str());
            detect();
            inspect('w');
        }
        else {
            _deb("AppHostCX::post_write[%s]: OUT OF INSPECT WINDOW: side %c, flow path: %s", c_type(), 'w', flow().hr().c_str());
        }
    }
    
    // react on specific signatures 
    if (mode() == mode_t::PRE and upgrade_starttls) {
        upgrade_starttls = false;
        on_starttls(); // now it's safe to upgrade socket
    }
}

void AppHostCX::pre_read() {

    _dum("AppHostCX::pre_read[%s]: === start",c_type());
    
    bool updated = false;
    bool behind_read = false;
    
    if (mode() == mode_t::PRE) {

        // copy missed readbuf bytes
        if(inside_detect_ranges() and peek_read_counter < meter_read_bytes) {

            behind_read = true;

            _war("AppHostCX::pre_read[%s]: More data read than seen by peek: %d vs. %d", c_type(), meter_read_bytes, peek_read_counter);
            _deb("AppHostCX::pre_read[%s]: METER_READ_COUNT=%d METER_READ_BYTES=%d PEEK_READ_BYTES=%d", c_type(),
                    meter_read_count, meter_read_bytes,peek_read_counter);

            std::size_t delta = this->meter_read_bytes - peek_read_counter;
            std::size_t w = this->readbuf()->size() - delta; // "+1" should be not there

            _deb("AppHostCX::pre_read[%s]: Creating readbuf view at <%d,%d>", c_type(), w, delta);
            buffer v = this->readbuf()->view(w, delta);
            _deb("AppHostCX::pre_read[%s]:  = readbuf: %d bytes (allocated buffer size %d): \r\n%s", c_type(),
                 this->readbuf()->size(), this->readbuf()->capacity(),
                 hex_dump(this->readbuf()->data(), this->readbuf()->size(), 4, 0, true).c_str());
            _deb("AppHostCX::pre_read[%s]:  = view of %d bytes (allocated buffer size %d): \r\n%s", c_type(), v.size(),
                 v.capacity(), hex_dump(v.data(), v.size(), 4, 0, true).c_str());


            if(not v.empty()) {
                this->flow().append('r', v);
                _dia("AppHostCX::pre_read[%s]: detection pre-mode: salvaged %d bytes from readbuf", c_type(),
                       v.size());
                _deb("AppHostCX::pre_read[%s]: Appended from readbuf to flow %d bytes (allocated buffer size %d): \r\n%s",
                     c_type(), v.size(), v.capacity(), hex_dump(v.data(), v.size(), 4, 0, true).c_str());

                updated = true;

                // adapt peek_counter so we know we recovered data from readbuf
                peek_read_counter += v.size();

            } else {
                _war("AppHostCX::pre_read[%s]: FIXME: peek counter behind read counter, but readbuf is empty!",
                     c_type());
                _war("AppHostCX::pre_read[%s]:   s attempt to create readbuf view at <%d,%d> ptr %p", c_type(), w,
                     delta, readbuf()->data());
            }
        }

        // peek from I/O
        if(meter_read_bytes < config::max_detect_bytes) {
            constexpr size_t max_peek_one = 5000;
            buffer b(max_peek_one);
            b.size(0);

            auto peek_all = [&]() {

                constexpr int max_rounds = 10;
                int l = -1;
                for (int i = 0; i < max_rounds; ++i) {
                    l = this->peek(b);

                    // return what we got
                    if(l <= 0) break;

                    // return if we fit the buffer
                    if(l < static_cast<int>( b.capacity()) ) break;

                    b.capacity(b.capacity() + max_peek_one);
                }
                return l;
            };

            int l = peek_all();

            if(behind_read) {
                _war("AppHostCX::pre_read[%s]: peek returns %d bytes",c_type(),l);
            } else {
                _dum("AppHostCX::pre_read[%s]: peek returns %d bytes",c_type(),l);
            }

            if(l < 0) {
                // if peek (it's a read without moving out data from OS buffer) returns -1
                // simulate EAGAIN behaviour
                next_read_limit(-1);
                _deb("AppHostCX::pre_read[%s]: peek() returned %d", c_type(), l);

            } else if(l > 0) {
                peek_read_counter += l;
                flow().append('r',b);

                _deb("AppHostCX::pre_read[%s]: Appended to flow %d bytes (allocated buffer size %d): \r\n%s",c_type(),b.size(),b.capacity(),
                            hex_dump(b.data(),b.size(), 4, ' ', true).c_str());
                next_read_limit(l);

                updated = true;

                if(com()->l4_proto() == SOCK_DGRAM) {
                    // don't limit reads, packets are dropped in case of tension, so flow could be incorrect a bit (it will be fixed on read).
                    this->next_read_limit(0);
                }
                // TCP
                if(l >= (int)b.capacity()) {
                    _dia("AppHostCX::pre_read[%s]: pre_read at max. buffer capacity %d",c_type(),b.capacity());
                }
            }
        }

        if(updated) {
            _dia("AppHostCX::pre_read[%s]: side %c, flow path: %s",c_type(), 'r', flow().hr().c_str());

            // check first few exchanges to upgrade socket, but only if com is not SSL already
            if(flow().exchanges < config::max_starttls_exchanges and dynamic_cast<TCPCom*>(com()) and not dynamic_cast<SSLCom*>(com())) {

                if (detect(starttls_sensor())) {
                    upgrade_starttls = true;
                }
            }
            detect();
            inspect('r');
        }
    }
    _dum("AppHostCX::pre_read[%s]: === end",c_type());
}

bool AppHostCX::inside_detect_ranges() {

    auto bytes_total = meter_write_bytes + meter_read_bytes;
    bool inside_detect_range = bytes_total <= config::max_detect_bytes;

    bool exchanges_bytes_override = bytes_total <= config::min_detect_bytes;
    bool inside_detect_exchanges = flow().size() < config::max_exchanges or exchanges_bytes_override;

    return (inside_detect_range and inside_detect_exchanges);
}

bool AppHostCX::inside_detect_on_continue() {

    if(not inside_detect_ranges()) {
        if(mode() == mode_t::CONTINUOUS) {
            return true;
        } else {
            if(config::opt_switch_to_continuous) {

                _dia("continuous mode activated");

                // assign default continuous flow data (after which continuous mode would expire)
                acknowledge_continuous_mode(0L);
                mode(mode_t::CONTINUOUS);
                return true;
            }
        }
        return false;
    }
    return true;

}

void AppHostCX::pre_write() {

    // value-guard writebuf
    if(writebuf()->empty()) return;

    if (mode() == mode_t::PRE or mode() == mode_t::CONTINUOUS) {
        auto const* b = this->writebuf();

        if(inside_detect_on_continue()) {

            std::size_t  f_s = flow().flow_queue().size();
            std::size_t  f_last_data_size = 0;
            char f_last_data_side = '?';
            if(f_s > 0) {
                f_last_data_side = flow().flow_queue().back().source();
                f_last_data_size = flow().flow_queue().back().size();
            }
            
            _dia("AppHostCX::pre_write[%s]: peek_counter %d, written already %d, write buffer size %d, whole flow size %d, flow data side '%c' size %d",
                                            c_type(), peek_write_counter,
                                            meter_write_bytes,b->size(), f_s,f_last_data_side,f_last_data_size);

            // how many data I am missing?
            buffer::size_type delta  = (meter_write_bytes + b->size()) - peek_write_counter;
            
            if(delta > 0) {
                buffer delta_b = b->view(b->size()-delta,b->size());
                
                _dia("AppHostCX::pre_write[%s]: flow append new %d bytes",c_type(),delta_b.size());
                flow().append('w',delta_b);
                peek_write_counter += delta_b.size();

                if(mode() == mode_t::CONTINUOUS) {
                    continuous_mode_keeper(delta_b);
                }

                auto const& last_flow = flow().flow_queue().back().data();
                _dum("AppHostCX::pre_write:[%s]: Last flow entry is now: \r\n%s", c_type(),
                                                 hex_dump(last_flow->data(),last_flow->size(), 4, 0, true).c_str());
                _dia("AppHostCX::pre_write:[%s]: ...",c_type());
                _dia("AppHostCX::pre_write:[%s]: peek_counter is now %d",c_type(),peek_write_counter);
            } else {
                _dia("AppHostCX::pre_write:[%s]: data are already copied in the flow",c_type());
            }
            
            _deb("AppHostCX::pre_write[%s]: write buffer size %d",c_type(),b->size());

            _dia("AppHostCX::pre_write[%s]: side %c, flow path: %s",c_type(), 'w', flow().hr().c_str());

            // check first few exchanges to upgrade socket, but only if com is not SSL already
            if(flow().exchanges < config::max_starttls_exchanges and dynamic_cast<TCPCom*>(com()) and not dynamic_cast<SSLCom*>(com())) {

                if (detect(starttls_sensor())) {
                    upgrade_starttls = true;
                }
            }
            detect();
            inspect('w');
        }
    }
}



