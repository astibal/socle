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

typedef typename std::vector<std::pair<duplexSignature,bool>> sensorType;

template <class Com>
class AppHostCX: public baseHostCX<Com> {
public:
    AppHostCX(unsigned int s);
    AppHostCX(const char* h, const char* p);
    
    static const int DETECT_MAX_BYTES = 20000;
    sensorType& sensor() { return sensor_; };
    
protected:
    duplexFlow appflow_;
    
    //FIXME: select more appropriate storage than vector. Pair will contain some "result-struct" instad of bool
    sensorType sensor_;
    
    inline duplexFlow& flow() { return this->appflow_; }
    inline duplexFlow* flowptr() { return &this->appflow_; }

    // detection mode is done in "post" phase
    virtual void post_read();
    virtual void post_write();
    bool detect();
    
    virtual void on_detect(duplexSignature&, vector_range&);

};

template <class Com>
AppHostCX<Com>::AppHostCX(const char* h, const char* p) :
baseHostCX<Com>::baseHostCX(h,p) {}

template <class Com>
AppHostCX<Com>::AppHostCX(unsigned int s) :
baseHostCX<Com>::baseHostCX(s) {}

template <class Com>
bool AppHostCX<Com>::detect() {
    
    for (sensorType::iterator i = sensor().begin(); i != sensor().end(); i++ ) {
    
        std::pair<duplexSignature,bool>& sig = (*i);

        duplexSignature& sig_sig = std::get<0>(sig);
        bool& sig_res = std::get<1>(sig);
        
        if (sig_res == false) {
            vector_range r = sig_sig.match(this->flowptr());
            
            if (r.at(0) != NULLRANGE) {
                std::get<1>(sig) = true;
                on_detect(sig_sig,r);
                
                return true;
                
            } else {
                DEB_("Signature not matched: %s", vrangetos(r).c_str());
            } 
        }
    }
    
    
    return false;
}



template <class Com>
void AppHostCX<Com>::post_read() {
    if(this->meter_read_bytes <= DETECT_MAX_BYTES) {
        auto b = this->to_read();
        this->flow().append('r',b);
    }
    
    detect();
}

template <class Com>
void AppHostCX<Com>::post_write() {
    if(this->meter_write_bytes <= DETECT_MAX_BYTES) {
        auto b = this->writebuf();
        this->flow().append('w',b);
    }
    
    detect();
}

template <class Com>
void AppHostCX<Com>::on_detect(duplexSignature& sig_sig, vector_range& r) {}



#endif //__APPHOSTCX_HPP__