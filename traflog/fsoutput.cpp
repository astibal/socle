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
#include <sys/time.h>
#include <iostream>

#include <traflog/fsoutput.hpp>
#include <traflog/traflog.hpp>

namespace socle::traflog {
    std::string FsOutput::generate_filename(baseProxy* proxy_, bool create_dirs) {

        host_l_ = traflog_dir_key(proxy_);
        writer_key_l_ = traflog_file_key(proxy_, 'L');
        writer_key_r_ = traflog_file_key(proxy_, 'R');

        if(writer_key_l_.empty() || writer_key_r_.empty()) {
            return "";
        }

        if(create_dirs) mkdir(data_dir.c_str(),0750);

        std::string hostdir = data_dir+"/"+host_l_+"/";
        if(create_dirs) mkdir(hostdir.c_str(),0750);

        time_t now = time(nullptr);
        tm loc{};

        localtime_r(&now,&loc);

        std::string datedir = string_format("%d-%02d-%02d/", loc.tm_year+1900, loc.tm_mon+1, loc.tm_mday);
        if(create_dirs) mkdir((hostdir+datedir).c_str(),0750);

        std::string file_timepart = string_format("%02d-%02d-%02d_", loc.tm_hour, loc.tm_min, loc.tm_sec);

        std::stringstream ss;

        ss << hostdir << datedir << file_prefix << file_timepart << writer_key_l_ << "." << file_suffix;
        filename_full = ss.str();

        return filename_full;
    }

    std::string FsOutput::generate_filename_single(const char* filename, bool create_dirs) {

        if(create_dirs) mkdir(data_dir.c_str(),0750);

        time_t now = time(nullptr);
        tm loc{};

        localtime_r(&now,&loc);
        std::string file_datepart = string_format("%d-%02d-%02d", loc.tm_year + 1900, loc.tm_mon + 1, loc.tm_mday);
        std::string file_timepart = string_format("%02d-%02d-%02d", loc.tm_hour, loc.tm_min, loc.tm_sec);

        std::stringstream ss;

        ss << data_dir << "/" << file_prefix << filename << "-" << file_datepart << "--" << file_timepart << "." << file_suffix;
        filename_full = ss.str();

        return filename_full;
    }

}