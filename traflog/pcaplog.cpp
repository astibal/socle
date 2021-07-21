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

#include <traflog/pcaplog.hpp>
#include <xorshift.hpp>

namespace socle::traflog {

    PcapLog::PcapLog (baseProxy *parent) : parent(parent) {

        if(not parent or not parent->com()) { parent = nullptr; return; }

        auto &ls = parent->ls().empty() ? parent->ls() : parent->lda();
        auto &rs = parent->rs().empty() ? parent->rs() : parent->rda();

        if (ls.empty() or rs.empty()) { parent = nullptr; return; }

        SocketInfo s;
        s.str_src_host = ls[0]->host();
        s.str_dst_host = rs[0]->host();
        s.sport = safe_val(ls[0]->port(), 0);
        s.dport = safe_val(rs[0]->port(), 0);
        s.pack_dst_ss();
        s.pack_src_ss();


        details.source = s.src_ss.value();
        details.destination = s.dst_ss.value();

        // this could become more complex in the (probably far) future
        parent->com()->l3_proto() == AF_INET6 ? details.ip_version = 6
                                              : details.ip_version = 4;

        parent->com()->l4_proto() == SOCK_STREAM ? details.next_proto = connection_details::TCP
                                                 : details.next_proto = connection_details::UDP;

        // some tcp specific values
        if(details.next_proto == connection_details::TCP) {
            details.seq_in = xorshift::rand();
            details.seq_out = xorshift::rand();
        }
    }

    void PcapLog::write (side_t side, const buffer &b) {}
    void PcapLog::write (side_t side, const std::string &s) {}
}