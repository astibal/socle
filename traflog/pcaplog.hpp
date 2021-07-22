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

#ifndef PCAPLOG_HPP
#define PCAPLOG_HPP

#include <baseproxy.hpp>

#include <socketinfo.hpp>
#include <traflog/pcapapi.hpp>
#include <traflog/basetraflog.hpp>
#include <traflog/fsoutput.hpp>
#include <traflog/threadedpoolwriter.hpp>

#include <memory>

using namespace socle::pcap;

namespace socle::traflog {

    class PcapLog : public baseTrafficLogger {

        PcapLog() = default; // just for singleton, which is set up later
    public:
        explicit PcapLog (baseProxy *parent, const char* d_dir, const char* f_prefix, const char* f_suffix, bool create_dirs);
        ~PcapLog();

        void write(side_t side, const buffer &b) override;
        void write(side_t side, std::string const& s) override;

        baseProxy *parent;
        tcp_details details;

        static const bool use_pool_writer = true;
        baseFileWriter* writer_ = nullptr;
        void init_writer();

        FsOutput FS;

        bool single_only = false;             // write using single-file instance?
        bool pcap_header_written = false; // is PCAP file initialized (opened and preamble written)?
        bool tcp_start_written = false;   // if TCP, is SYNs written, so rest is just data?

        bool comment_frame(pcapng::pcapng_epb& frame);
        std::string comlog;

        static PcapLog& single_instance() {
            static PcapLog s;
            return s;
        }

        logan_lite log {"socle.pcaplog"};

    };
}

#endif //PCAPLOG_HPP
