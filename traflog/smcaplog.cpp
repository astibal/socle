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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fstream>
#include <iostream>
#include <deque>
#include <queue>

#include <vars.hpp>
#include <sobject.hpp>
#include <baseproxy.hpp>


#include <traflog/traflog.hpp>
#include <traflog/smcaplog.hpp>

namespace socle::traflog {
    SmcapLog::SmcapLog(baseProxy *p, const char* d_dir, const char* f_prefix, const char* f_suffix) :
            sobject(),
            proxy_(p),
            data_dir(d_dir),
            file_prefix(f_prefix),
            file_suffix(f_suffix),
            writer_key_l_("???:???"),
            writer_key_r_("???:???") {
        create_writer_key();

        if(!use_pool_writer) {
            writer_ = new fileWriter();
        } else {
            writer_ = threadedPoolFileWriter::instance();
        }
    }

    std::string SmcapLog::to_string(int verbosity) const {
        return string_format("trafLog: file=%s opened=%d",writer_key_.c_str(),writer_->opened());
    }

    SmcapLog::~SmcapLog() {

        if(writer_) {
            if(! writer_key_.empty()) {
                writer_->close(writer_key_);
            }
        }

        if(! use_pool_writer)
            delete writer_;
    };



    std::string SmcapLog::create_writer_key() {

        host_l_ = traflog_dir_key(proxy_);
        writer_key_l_ = traflog_file_key(proxy_, 'L');
        writer_key_r_ = traflog_file_key(proxy_, 'R');

        if(writer_key_l_.empty() || writer_key_r_.empty()) {
            return "";
        }

        mkdir(data_dir.c_str(),0750);

        std::string hostdir = data_dir+"/"+host_l_+"/";
        mkdir(hostdir.c_str(),0750);

        time_t now = time(nullptr);
        tm loc{};

        localtime_r(&now,&loc);

        std::string datedir = string_format("%d-%02d-%02d/", loc.tm_year+1900, loc.tm_mon+1, loc.tm_mday);
        mkdir((hostdir+datedir).c_str(),0750);

        std::string file_datepart = string_format("%02d-%02d-%02d_", loc.tm_hour, loc.tm_min, loc.tm_sec);

        std::stringstream ss;

        ss << hostdir << datedir << file_prefix << file_datepart << writer_key_l_ << "." << file_suffix;
        writer_key_ = ss.str();

        return writer_key_;
    }


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
                k1 = writer_key_r_;
                k2 = writer_key_l_;
                break;
            case side_t::LEFT:
                k1 = writer_key_l_;
                k2 = writer_key_r_;
                break;
        }

        if(! writer_->opened() ) {
            if (writer_->open(writer_key_)) {
                _dia("writer '%s' created",writer_key_l_.c_str());
            } else {
                _err("write '%s' failed to open dump file!",writer_key_l_.c_str());
            }
        }

        if (writer_->opened()) {

            std::stringstream ss;
            ss << d << "+" << now.tv_usec << ": "<< k1 << "(" << k2 << ")\n";
            ss << s << '\n';

            writer_->write(writer_key_, ss.str());

        } else {
            _err("cannot write to stream, writer not opened.");
        }
    }

}