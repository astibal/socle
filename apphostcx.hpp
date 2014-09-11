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

#ifndef __APPHOSTCX_HPP__
 # define __APPHOSTCX_HPP__

#include <vector>
 
#include <buffer.hpp>
 
#include <hostcx.hpp>
#include <signature.hpp>

typedef typename std::vector<std::pair<duplexStateSignature,bool>> sensorType;


class AppHostCX: public baseHostCX {
public:
    AppHostCX(baseCom* c, unsigned int s);
    AppHostCX(baseCom* c, const char* h, const char* p);
    
    static const int DETECT_MAX_BYTES = 20000;

    static const int MODE_NONE = 0;
    static const int MODE_PRE = 1;
    static const int MODE_POST = 2;
    int mode_ = MODE_POST;
    int mode() { return mode_; }
    void mode(int m) { mode_ = m; }
    
    sensorType& starttls_sensor() { return starttls_sensor_; };
    sensorType& sensor() { return sensor_; };
    
protected:
    unsigned int peek_counter = 0;
    duplexFlow appflow_;
    
    //FIXME: select more appropriate storage than vector. Pair will contain some "result-struct" instad of bool
    sensorType sensor_;
    sensorType starttls_sensor_;
    
    inline duplexFlow& flow() { return this->appflow_; }
    inline duplexFlow* flowptr() { return &this->appflow_; }

    // detection mode is done in "post" phase
    virtual void post_read();
    virtual void post_write();
    
    virtual void pre_read();
    virtual void pre_write();
    
    bool detect(sensorType&);
    
    virtual void on_detect(duplexSignature&, vector_range&);
    virtual void on_starttls() {};

protected:
    bool upgrade_starttls = false;

};

AppHostCX::AppHostCX(baseCom* c, const char* h, const char* p) :baseHostCX(c,h,p) {}
AppHostCX::AppHostCX(baseCom* c, unsigned int s) :baseHostCX(c,s) {}


bool AppHostCX::detect(sensorType& cur_sensor) {

    for (sensorType::iterator i = cur_sensor.begin(); i != cur_sensor.end(); ++i ) {
    
        std::pair<duplexStateSignature,bool>& sig = (*i);

        duplexStateSignature& sig_sig = std::get<0>(sig);
        bool& sig_res = std::get<1>(sig);
        
        if (sig_res == false) {
            DEB_("Signature %s", sig_sig.name.c_str());
            bool r = sig_sig.match(this->flowptr());
            
            vector_range& ret = sig_sig.result();
            
            if (r) {
                sig_res = true;
                on_detect(sig_sig,ret);
                
                DIA_("Signature matched: %s", vrangetos(ret).c_str());
                return true;
                
            } else {
                DEB_("Signature didn't match: %s", vrangetos(ret).c_str());
            } 
        } else {
            DEB_("Signature %s already matched", sig_sig.name.c_str());
        }
    }
    
    
    return false;
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
    
    bool updated = false;
    
    if ( mode() == MODE_PRE) {
        if(this->meter_read_bytes <= DETECT_MAX_BYTES && peek_counter <= this->meter_read_bytes  ) {
            
            if(peek_counter < this->meter_read_bytes) {

                WAR_("More data read than seen by peek: %d vs. %d",this->meter_read_bytes, peek_counter);
                unsigned int delta = this->meter_read_bytes - peek_counter;
                unsigned int w = this->readbuf()->size() - delta + 1;
                DEB_("Creating readbuf view at <%d,%d>",w,delta);
                buffer v = this->readbuf()->view(w,delta);
                DEB_(" = Readbuf: %d bytes (allocated buffer size %d): %s",this->readbuf()->size(),this->readbuf()->capacity(),hex_dump(this->readbuf()->data(),this->readbuf()->size()).c_str());
                DEB_(" = view of %d bytes (allocated buffer size %d): %s",v.size(),v.capacity(),hex_dump(v.data(),v.size()).c_str());
                
                
                if(v.size() > 0) {
                    this->flow().append('r',v);
                    DIA_("detection pre-mode: salvaged %d bytes from readbuf",v.size(0));
                    DEB_("Appended from readbuf to flow %d bytes (allocated buffer size %d): %s",v.size(),v.capacity(),hex_dump(v.data(),v.size()).c_str());
                    
                    updated = true;
                    
                } else {
                    DEB_("FIXME: Attempt to append readbuf to flow %d bytes (allocated buffer size %d): %s",v.size(),v.capacity(),hex_dump(v.data(),v.size()).c_str());
                }
                
                
            }

            buffer b(1500);
            b.size(0);
            int l = this->peek(b);
            
            DUM_("AppHostCX::pre_read: peek returns %d bytes",l);
            
            if(l > 0) {
                peek_counter += l;
                this->flow().append('r',b);
                DEB_("Appended to flow %d bytes (allocated buffer size %d): %s",b.size(),b.capacity(),hex_dump(b.data(),b.size()).c_str());
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
}

void AppHostCX::pre_write() {
    
    if ( mode() == MODE_PRE ) {
        auto b = this->writebuf();
        
        if(this->meter_write_bytes <= DETECT_MAX_BYTES && b->size() > 0) {
            
            this->flow().append('w',b);
            DEB_("AppHostCX::pre_write: write buffer size %d",b->size());
        
            if(detect(starttls_sensor())) {
                upgrade_starttls = true;
            }
            detect(sensor());
        }
    }
}


void AppHostCX::on_detect(duplexSignature& sig_sig, vector_range& r) {}



#endif //__APPHOSTCX_HPP__