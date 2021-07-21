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

PcapLog::PcapLog(baseProxy* parent) : parent(parent) {

    auto& ls = parent->ls().empty() ? parent->ls() : parent->lda();
    auto& rs = parent->rs().empty() ? parent->rs() : parent->rda();

    if(ls.empty() or rs.empty()) {
        parent = nullptr;
        return;
    }

    SocketInfo s;
    s.str_src_host = ls[0]->host();
    s.str_dst_host = rs[0]->host();
    s.sport = safe_val(ls[0]->port(), 0);
    s.dport = safe_val(rs[0]->port(), 0);
    s.pack_dst_ss();
    s.pack_src_ss();

    details.seq_in = xorshift::rand();
    details.seq_out = xorshift::rand();
}


bool PcapLog::construct_details() {
    return true;
}
