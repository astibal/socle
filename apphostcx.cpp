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

AppHostCX::AppHostCX(baseCom* c, const char* h, const char* p) : baseHostCX(c,h,p), signatures_(2) {

    log = logan::attach(this, "inspect");

    if(c->l4_proto() != 0) {
        flow().domain(c->l4_proto());
    }
}
AppHostCX::AppHostCX(baseCom* c, unsigned int s) :baseHostCX(c,s), signatures_(2) {

    log = logan::attach(this, "inspect");

    if(c->l4_proto() != 0) {
        flow().domain(c->l4_proto());
    }
}

int AppHostCX::make_sig_states(sensorType& sig_states, std::vector<std::shared_ptr<duplexFlowMatch>>& source_signatures) {
    sig_states.clear();
    int r = 0;
    
    _deb("AppHostCX::zip_signatures: zipper start");
    for( auto& sh_ptr: source_signatures ) {
        
        if(! sh_ptr ) {
            _deb("AppHostCX::zip_signatures: attempt to zip nullptr signature");
            continue;
        }

        _deb("AppHostCX::zip_signatures: sensor 0x%x, adding %s at 0x%x",&sig_states, sh_ptr->name().c_str(), sh_ptr.get());
        
        std::pair<flowMatchState, std::shared_ptr<duplexFlowMatch>> a;
        a.first = flowMatchState();
        a.second = std::shared_ptr<duplexFlowMatch>(sh_ptr);



        sig_states.push_back(a);
        ++r;
    }

    _deb("AppHostCX::zip_signatures: loaded %d of %d",r, source_signatures.size());
    return r;
}

bool AppHostCX::detect(sensorType& cur_sensor,char side) {

    bool matched = false;
    
    if(cur_sensor.empty()) {
        _dia("AppHostCX::detect[%s]: Sensor %x is empty!",c_type(), &base_sensor());
    }
    
    for (auto& sig: cur_sensor) {
        
        // get zipped results with signature pointers
        std::shared_ptr<duplexFlowMatch> sig_sig = std::get<1>(sig);
        flowMatchState& sig_res = std::get<0>(sig);
        
        if (! sig_res.hit()) {
            _dia("AppHostCX::detect[%s]: Sensor %x, signature name %s", c_type(), &base_sensor(), sig_sig->name().c_str());
            
            bool r = sig_res.update(this->flowptr(),sig_sig);
            
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


void AppHostCX::post_read() {
    
    if ( mode() == MODE_POST) {
        if(this->meter_read_bytes <= max_detect_bytes()) {
            auto b = this->to_read();
            this->flow().append('r', b);


            _dia("AppHostCX::post_read[%s]: side %c, flow path: %s", c_type(), 'r', flow().hr().c_str());

            // we can't detect starttls in POST mode
            detect(base_sensor(), 'r');
            inspect('r');
        }
        else {
            _deb("AppHostCX::post_read[%s]: OUT OF INSPECT WINDOW: side %c, flow path: %s", c_type(), 'r', flow().hr().c_str());
        }
    }
    
    if (mode() == MODE_PRE) {
        // check if we need to upgrade this CX
    }
}

void AppHostCX::post_write() {
    
    if ( mode() == MODE_POST ) {
        
        if(this->meter_write_bytes <= max_detect_bytes()) {
            auto b = this->writebuf();

            int f_s = flow().flow().size();
            int f_last_data_size = flow().flow().back().second->size();

            _deb("AppHostCX::post_write[%s]: peek_counter %d, written to socket %d, write buffer size %d, flow size %d, flow data size %d",
                 c_type(), peek_write_counter, meter_write_bytes, b->size(), f_s, f_last_data_size);

            // how many data I am missing?
            int delta = (meter_write_bytes + b->size()) - peek_write_counter;
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
            detect(base_sensor(), 'w');
            inspect('w');
        }
        else {
            _deb("AppHostCX::post_write[%s]: OUT OF INSPECT WINDOW: side %c, flow path: %s", c_type(), 'w', flow().hr().c_str());
        }
    }
    
    // react on specific signatures 
    if (mode() == MODE_PRE) {
        if(upgrade_starttls) {
            
            //FIXME: check if all data were sent to client, otherwise block and wait till it's done
            
            upgrade_starttls = false;
            on_starttls(); // now it's safe to upgrade socket
        }
    }
}

void AppHostCX::pre_read() {

    _dum("AppHostCX::pre_read[%s]: === start",c_type());
    
    bool updated = false;
    
    bool __behind_read_warn = true;
    bool behind_read = false;
    
    if (mode() == MODE_PRE) {
        if(this->meter_read_bytes <= max_detect_bytes() && peek_read_counter <= this->meter_read_bytes  ) {

            if (peek_read_counter < this->meter_read_bytes) {
                behind_read = true;

                if (__behind_read_warn) {
                    _war("AppHostCX::pre_read[%s]: More data read than seen by peek: %d vs. %d", c_type(),
                         this->meter_read_bytes, peek_read_counter);
                } else {
                    _deb("AppHostCX::pre_read[%s]: More data read than seen by peek: %d vs. %d", c_type(),
                         this->meter_read_bytes, peek_read_counter);
                }
                _deb("AppHostCX::pre_read[%s]: METER_READ_COUNT=%d METER_READ_BYTES=%d PEEK_READ_BYTES=%d", c_type(),
                        meter_read_count, meter_read_bytes,peek_read_counter);

                unsigned int delta = this->meter_read_bytes - peek_read_counter;
                unsigned int w = this->readbuf()->size() - delta; // "+1" should be not there
                _deb("AppHostCX::pre_read[%s]: Creating readbuf view at <%d,%d>", c_type(), w, delta);
                buffer v = this->readbuf()->view(w, delta);
                _deb("AppHostCX::pre_read[%s]:  = readbuf: %d bytes (allocated buffer size %d): %s", c_type(),
                     this->readbuf()->size(), this->readbuf()->capacity(),
                     hex_dump(this->readbuf()->data(), this->readbuf()->size()).c_str());
                _deb("AppHostCX::pre_read[%s]:  = view of %d bytes (allocated buffer size %d): %s", c_type(), v.size(),
                     v.capacity(), hex_dump(v.data(), v.size()).c_str());


                if(v.size() > 0) {
                    this->flow().append('r', v);
                    _dia("AppHostCX::pre_read[%s]: detection pre-mode: salvaged %d bytes from readbuf", c_type(),
                           v.size());
                    _deb("AppHostCX::pre_read[%s]: Appended from readbuf to flow %d bytes (allocated buffer size %d): \n%s",
                         c_type(), v.size(), v.capacity(), hex_dump(v.data(), v.size()).c_str(), 4, '>');

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
        }

        if(meter_read_bytes < max_detect_bytes()) {
            buffer b(5000);
            b.size(0);
            int l = this->peek(b);

            if(behind_read && __behind_read_warn) {
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

                _deb("AppHostCX::pre_read[%s]: Appended to flow %d bytes (allocated buffer size %d): %s",c_type(),b.size(),b.capacity(),hex_dump(b.data(),b.size()).c_str());
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

            if (detect(starttls_sensor(),'r')) {
                upgrade_starttls = true;
            }
            detect(base_sensor(), 'r');
            inspect('r');
        }
    }
    _dum("AppHostCX::pre_read[%s]: === end",c_type());
}

void AppHostCX::pre_write() {
    
    if ( mode() == MODE_PRE ) {
        buffer* b = this->writebuf();
        
        if(this->meter_write_bytes <= max_detect_bytes() && b->size() > 0) {
            
            int  f_s = flow().flow().size();
            int  f_last_data_size = 0;
            char f_last_data_side = '?';
            if(f_s > 0) {
                f_last_data_side = flow().flow().back().first;
                f_last_data_size = flow().flow().back().second->size();
            }
            
            _dia("AppHostCX::pre_write[%s]: peek_counter %d, written already %d, "
                 "                          write buffer size %d, whole flow size %d, flow data side '%c' size %d",
                                            c_type(), peek_write_counter,
                                            meter_write_bytes,b->size(), f_s,f_last_data_side,f_last_data_size);

            // how many data I am missing?
            buffer::size_type delta  = (meter_write_bytes + b->size()) - peek_write_counter;
            
            if(delta > 0) {
                buffer delta_b = b->view(b->size()-delta,b->size());
                
                _dia("AppHostCX::pre_write[%s]: flow append new %d bytes",c_type(),delta_b.size());
                flow().append('w',delta_b);
                peek_write_counter += delta_b.size();

                buffer* last_flow = flow().flow().back().second;
                _dum("AppHostCX::pre_write:[%s]: Last flow entry is now: \n%s", c_type(),
                                                 hex_dump((unsigned char*)last_flow->data(),last_flow->size()).c_str());
                _dia("AppHostCX::pre_write:[%s]: ...",c_type());
                _dia("AppHostCX::pre_write:[%s]: peek_counter is now %d",c_type(),peek_write_counter);
            } else {
                _dia("AppHostCX::pre_write:[%s]: data are already copied in the flow",c_type());
            }
            
            _deb("AppHostCX::pre_write[%s]: write buffer size %d",c_type(),b->size());

            _dia("AppHostCX::pre_write[%s]: side %c, flow path: %s",c_type(), 'w', flow().hr().c_str());

            if(detect(starttls_sensor(),'w')) {
                upgrade_starttls = true;
            }
            detect(base_sensor(), 'w');
            inspect('w');
        }
    }
}



