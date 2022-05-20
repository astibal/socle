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

#ifndef APPHOSTCX_HPP
 # define APPHOSTCX_HPP

#include <vector>
 
#include <buffer.hpp>
 
#include <hostcx.hpp>
#include <signature.hpp>



class AppHostCX: public baseHostCX {
public:
    using sensorType = SignatureTree::sensorType;

    AppHostCX(baseCom* c, int s);
    AppHostCX(baseCom* c, const char* h, const char* p);
    ~AppHostCX() override = default;

    std::string to_string(int verbosity) const override;

    struct config {
        static inline unsigned int max_starttls_exchanges = 10;
        static inline unsigned int max_detect_bytes = 2048;

        static inline unsigned int min_detect_bytes = 1024;
        static inline unsigned int max_exchanges = 20;

        static inline size_t continuous_data_left_default = 100000;
        static inline bool opt_switch_to_continuous = true;
    };

    enum class mode_t { NONE = 0, PRE = 1, POST = 2, CONTINUOUS = 0xff };

    // acknowledge interest in capturing more flow data
    void acknowledge_continuous_mode(size_t to_read_bytes) {
        continuous_data_left = to_read_bytes == 0L ? config::continuous_data_left_default : to_read_bytes;
        _dia("acknowledged continuous mode for next %ldB", continuous_data_left);
    }

    // check data size and keep/unset continous mode
    void continuous_mode_keeper(buffer const& data);

    [[nodiscard]]
    mode_t mode() const { return mode_; }
    void mode(mode_t m) { mode_ = m; }
    
    auto starttls_sensor() { return signatures_.sensors_[0]; };
    auto base_sensor() { return signatures_.sensors_[1]; };
    auto get_sensor(unsigned int index) { return signatures_.sensors_[index]; }

    // create pairs of results and pointers to (somewhere, already created) signatures.
    static int make_sig_states(std::shared_ptr<sensorType> sig_states, std::shared_ptr<sensorType> source_signatures);
    
    inline duplexFlow& flow() { return appflow_; }
    inline duplexFlow const& flow() const { return appflow_; }

protected:

    bool inside_detect_ranges();
    bool inside_detect_on_continue();

    // detection mode is done in "post" phase
    void post_read() override;
    void post_write() override;
    
    void pre_read() override;
    void pre_write() override;
    
    bool detect (const std::shared_ptr<sensorType> &cur_sensor); // signature detection engine
    bool detect ();
    SignatureTree& signatures() { return signatures_; }

    virtual void inspect(char side) = 0; // to be overridden for ALG inspectors
    
    virtual void on_detect(std::shared_ptr<duplexFlowMatch>, flowMatchState&, vector_range&) = 0;
    virtual void on_starttls() = 0;


private:

    duplexFlow appflow_;
    buffer::size_type peek_read_counter = 0;
    buffer::size_type peek_write_counter = 0;

    bool upgrade_starttls = false;

    SignatureTree signatures_ {2};
    mode_t mode_ = mode_t::NONE;

    // how many continuous flow data should we capture in CONTINUOUS before switching to NONE
    size_t continuous_data_left = 0L;

    TYPENAME_BASE("AppHostCX")
    DECLARE_LOGGING(to_string)

    LOGAN_LITE("com.app");
};


#endif //APPHOSTCX_HPP