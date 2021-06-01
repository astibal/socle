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



class AppHostCX: public baseHostCX {
public:
    AppHostCX(baseCom* c, unsigned int s);
    AppHostCX(baseCom* c, const char* h, const char* p);

    static unsigned int& max_detect_bytes() {
        static unsigned int DETECT_MAX_BYTES = 20000;
        return DETECT_MAX_BYTES;
    }

    typedef enum { MODE_NONE = 0, MODE_PRE = 1, MODE_POST = 2 } mode_t;

    [[nodiscard]]
    mode_t mode() const { return mode_; }
    void mode(mode_t m) { mode_ = m; }
    
    sensorType& starttls_sensor() { return *signatures_.sensors_[0]; };
    sensorType& base_sensor() { return *signatures_.sensors_[1]; };

    // create pairs of results and pointers to (somewhere, already created) signatures.
    int make_sig_states(sensorType& sig_states, std::vector<std::shared_ptr<duplexFlowMatch>>& source_signatures);
    
    ~AppHostCX() override = default;

    inline duplexFlow& flow() { return appflow_; }
    inline duplexFlow* flowptr() { return &appflow_; }

    inline duplexFlow const & cflow() const { return appflow_; }
    inline  duplexFlow  const* cflowptr() const { return &appflow_; }

    [[nodiscard]] inline std::string to_string(int verbosity) const override {

        std::string ts = baseHostCX::to_string(verbosity);
        int sz = cflow().cflow().size();

        return string_format("AppHostCX: sz:%d [%s]", sz, ts.c_str());
    };
protected:

    // detection mode is done in "post" phase
    void post_read() override;
    void post_write() override;
    
    void pre_read() override;
    void pre_write() override;
    
    bool detect(sensorType&,char side); // signature detection engine
    bool detect(char side);
    virtual void inspect(char side) = 0; // to be overridden for ALG inspectors
    
    virtual void on_detect(std::shared_ptr<duplexFlowMatch>, flowMatchState&, vector_range&) = 0;
    virtual void on_starttls() = 0;


private:
    logan_attached<AppHostCX> log;

    duplexFlow appflow_;
    buffer::size_type peek_read_counter = 0;
    buffer::size_type peek_write_counter = 0;

    bool upgrade_starttls = false;

    SignatureTree signatures_;
    mode_t mode_ = MODE_NONE;

    TYPENAME_BASE("AppHostCX")
    DECLARE_LOGGING(to_string)
};


#endif //__APPHOSTCX_HPP__