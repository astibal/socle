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

#include <sys/time.h>
#include <iostream>
#include <deque>

#include <vars.hpp>
#include <sobject.hpp>
#include <baseproxy.hpp>


#include <traflog/traflog.hpp>
#include <traflog/smcaplog.hpp>

namespace socle::traflog {

    SmcapLog::SmcapLog(baseProxy *p, const char* d_dir, const char* f_prefix, const char* f_suffix) :
            sobject(), proxy_(p), FS_(proxy_, d_dir, f_prefix, f_suffix, true) {
        ;

        if(!use_pool_writer) {
            writer_ = new fileWriter();
        } else {
            writer_ = threadedPoolFileWriter::instance();
        }
    }

    std::string SmcapLog::to_string(int verbosity) const {
        return string_format("trafLog: file=%s opened=%d", FS_.filename_full.c_str(), writer_->opened());
    }

    SmcapLog::~SmcapLog() {

        if(writer_) {
            if(! FS_.filename_full.empty()) {
                writer_->close(FS_.filename_full);
            }
        }

        if(! use_pool_writer)
            delete writer_;
    };



    void SmcapLog::write(side_t side, std::string const& s) {

        timeval now{};
        gettimeofday(&now, nullptr);
        char d[64];
        memset(d,0,64);
        ctime_r(&now.tv_sec,d);

        std::string k1;
        std::string k2;

        switch (side) {
            case side_t::RIGHT:
                k1 = FS_.writer_key_r_;
                k2 = FS_.writer_key_l_;
                break;
            case side_t::LEFT:
                k1 = FS_.writer_key_l_;
                k2 = FS_.writer_key_r_;
                break;
        }

        if(! writer_->opened() ) {
            if (writer_->open(FS_.filename_full)) {
                _dia("writer '%s' created",FS_.writer_key_l_.c_str());
            } else {
                _err("write '%s' failed to open dump file!",FS_.writer_key_l_.c_str());
            }
        }

        if (writer_->opened()) {

            std::stringstream ss;
            ss << d << "+" << now.tv_usec << ": "<< k1 << "(" << k2 << ")\n";
            ss << s << '\n';

            writer_->write(FS_.filename_full, ss.str());

        } else {
            _err("cannot write to stream, writer not opened.");
        }
    }

}