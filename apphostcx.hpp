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

typedef typename std::vector<std::pair<flowMatchState,duplexFlowMatch*>> sensorType;


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
    int zip_signatures(sensorType& s, std::vector<duplexFlowMatch*>& v); // create pairs of results and pointers to (somewhere, already created) signatures.
    
    virtual ~AppHostCX() {};
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
    
    virtual void on_detect(duplexFlowMatch*, flowMatchState&, vector_range&);
    virtual void on_starttls() {};

protected:
    bool upgrade_starttls = false;

};


#endif //__APPHOSTCX_HPP__