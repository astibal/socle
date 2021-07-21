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

#include <memory>

using namespace socle::pcap;

namespace socle::traflog {

    class PcapLog : public baseTrafficLogger {
    public:
        explicit PcapLog (baseProxy *parent);

        void write(side_t side, const buffer &b) override;
        void write(side_t side, std::string const& s) override;

        baseProxy *parent;
        tcp_details details;
    };

}

#endif //PCAPLOG_HPP
