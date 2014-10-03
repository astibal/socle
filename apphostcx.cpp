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

AppHostCX::AppHostCX(baseCom* c, const char* h, const char* p) :baseHostCX(c,h,p) {}
AppHostCX::AppHostCX(baseCom* c, unsigned int s) :baseHostCX(c,s) {}

int AppHostCX::zip_signatures(sensorType& s, std::vector<duplexFlowMatch*>& v) {
    s.clear();
    int r = 0;
    
    for( std::vector<duplexFlowMatch*>::iterator i = v.begin(); i < v.end(); ++i ) {
        
        if((*i) == nullptr ) {
            DEBS_("AppHostCX::zip_signatures: attempt to zip nullptr signature");
            continue;
        }
        
        std::pair<flowMatchState,duplexFlowMatch*> a;

        a.first = flowMatchState();
        a.second =(*i);

        s.push_back(a);
        ++r;
    }
    
    DEB_("AppHostCX::zip_signatures: loaded %d of %d",r,v.size());
    return r;
};

bool AppHostCX::detect(sensorType& cur_sensor) {

    bool matched = false;
    
    for (sensorType::iterator i = cur_sensor.begin(); i != cur_sensor.end(); ++i ) {
    
        std::pair<flowMatchState,duplexFlowMatch*>& sig = (*i);

        // get zipped results with signature pointers
        duplexFlowMatch* sig_sig = std::get<1>(sig);
        flowMatchState& sig_res = std::get<0>(sig);
        
        if (sig_res.hit() == false) {
            DEB_("AppHostCX::detect[%s]: Signature %s",c_name(), sig_sig->name().c_str());
            
            bool r = sig_res.update(this->flowptr(),sig_sig);
            
            vector_range& ret = sig_res.result();
            
            if (r) {
                sig_res.hit() = true;
                on_detect(sig_sig,sig_res,ret);
                
                matched = true;
                DIA_("AppHostCX::detect[%s]: Signature matched: %s",c_name(), vrangetos(ret).c_str());
                continue;
                
            } else {
                DEB_("AppHostCX::detect[%s]: Signature didn't match: %s",c_name(), vrangetos(ret).c_str());
            } 
        } else {
            DEB_("AppHostCX::detect[%s]: Signature %s already matched",c_name(), sig_sig->name().c_str());
        }
    }
    
    
    return matched;
}


void AppHostCX::post_read() {
    
    if ( mode() == MODE_POST) {
        if(this->meter_read_bytes <= DETECT_MAX_BYTES) {
            auto b = this->to_read();
            this->flow().append('r',b);
        }
        
        // we can't detect starttls in POST mode
        detect(sensor());
    }
    
    if (mode() == MODE_PRE) {
        // check if we need to upgrade this CX
    }
}

void AppHostCX::post_write() {
    
    if ( mode() == MODE_POST ) {
        
        if(this->meter_write_bytes <= DETECT_MAX_BYTES) {
            auto b = this->writebuf();
            this->flow().append('w',b);
        }
       
        // we can't detect starttls in POST mode
        detect(sensor());
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
    
    DUM_("AppHostCX::pre_read[%s]: === start",c_name());
    
    bool updated = false;
    
    bool __behind_read_warn = true;
    bool behind_read = false;
    
    if ( mode() == MODE_PRE) {
        if(this->meter_read_bytes <= DETECT_MAX_BYTES && peek_counter <= this->meter_read_bytes  ) {
            
            if(peek_counter < this->meter_read_bytes) {
                behind_read = true;

                if(__behind_read_warn) {
                    WAR_("AppHostCX::pre_read[%s]: More data read than seen by peek: %d vs. %d",c_name(), this->meter_read_bytes, peek_counter);
                } else {
                    DEB_("AppHostCX::pre_read[%s]: More data read than seen by peek: %d vs. %d",c_name(),this->meter_read_bytes, peek_counter);
                }
                
                unsigned int delta = this->meter_read_bytes - peek_counter;
                unsigned int w = this->readbuf()->size() - delta; // "+1" should be not there
                DEB_("AppHostCX::pre_read[%s]: Creating readbuf view at <%d,%d>",c_name(),w,delta);
                buffer v = this->readbuf()->view(w,delta);
                DEB_("AppHostCX::pre_read[%s]:  = Readbuf: %d bytes (allocated buffer size %d): %s",c_name(),this->readbuf()->size(),this->readbuf()->capacity(),hex_dump(this->readbuf()->data(),this->readbuf()->size()).c_str());
                DEB_("AppHostCX::pre_read[%s]:  = view of %d bytes (allocated buffer size %d): %s",c_name(),v.size(),v.capacity(),hex_dump(v.data(),v.size()).c_str());
                
                
                if(v.size() > 0) {
                    this->flow().append('r',v);
                    DIA_("AppHostCX::pre_read[%s]: detection pre-mode: salvaged %d bytes from readbuf",c_name(),v.size());
                    DEB_("AppHostCX::pre_read[%s]: Appended from readbuf to flow %d bytes (allocated buffer size %d): %s",c_name(),v.size(),v.capacity(),hex_dump(v.data(),v.size()).c_str());
                    
                    updated = true;
                    
                    // adapt peek_counter so we know we recovered data from readbuf
                    peek_counter += v.size();
                    
                } else {
                    WAR_("AppHostCX::pre_read[%s]: FIXME: peek counter behind read counter, but readbuf is empty!",c_name());
                    WAR_("AppHostCX::pre_read[%s]:   s attempt to create readbuf view at <%d,%d> ptr %p",c_name(),w,delta,readbuf()->data());
                    
                }
                
                
            }

            buffer b(1500);
            b.size(0);
            int l = this->peek(b);
            
            if(behind_read && __behind_read_warn) {
                WAR_("AppHostCX::pre_read[%s]: peek returns %d bytes",c_name(),l);
            } else {
                DEB_("AppHostCX::pre_read[%s]: peek returns %d bytes",c_name(),l);
            }
            
            if(l > 0) {
                peek_counter += l;
                this->flow().append('r',b);
                DEB_("AppHostCX::pre_read[%s]: Appended to flow %d bytes (allocated buffer size %d): %s",c_name(),b.size(),b.capacity(),hex_dump(b.data(),b.size()).c_str());
                this->next_read_limit(l); 
                
                updated = true;
            }
        }
        
        if(updated == true) {
            if (detect(starttls_sensor())) {
                upgrade_starttls = true;
            }
            detect(sensor());
        }
    }
    DUM_("AppHostCX::pre_read[%s]: === end",c_name());
}

void AppHostCX::pre_write() {
    
    if ( mode() == MODE_PRE ) {
        buffer* b = this->writebuf();
        
        if(this->meter_write_bytes <= DETECT_MAX_BYTES && b->size() > 0) {
            
            this->flow().append('w',b);
            DEB_("AppHostCX::pre_write[%s]: write buffer size %d",c_name(),b->size());
        
            if(detect(starttls_sensor())) {
                upgrade_starttls = true;
            }
            detect(sensor());
        }
    }
}


void AppHostCX::on_detect(duplexFlowMatch* sig_sig, flowMatchState& s, vector_range& r) {}

