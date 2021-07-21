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
#include <traflog/filewriter.hpp>
#include <xorshift.hpp>

namespace socle::traflog {

    PcapLog::PcapLog (baseProxy *parent, const char* d_dir, const char* f_prefix, const char* f_suffix) :
        parent(parent),
        FS(parent, d_dir, f_prefix, f_suffix) {

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

        init_writer();
    }

    void PcapLog::init_writer () {
        if(!use_pool_writer) {
            writer_ = new fileWriter();
        } else {
            writer_ = threadedPoolFileWriter::instance();
        }
    }

    void PcapLog::write (side_t side, const buffer &b) {
        PcapLog* self = this;
        if(single_only) self = &single_instance();

        if(not self->writer_) self->init_writer();

        auto* writer = self->writer_;
        auto const& fs = self->FS;


        if(not writer->opened() ) {
            if (writer->open(fs.filename_full)) {
                _dia("writer '%s' created", fs.filename_full.c_str());
            } else {
                _err("write '%s' failed to open dump file!", fs.filename_full.c_str());
            }
        }

        if(not writer->opened()) return;

        // PCAP HEADER

        if(not self->pcap_header_written) {
            buffer out;
            pcapng::append_PCAP_magic(out);

            // interface block
            pcapng::pcapng_ifb hdr;
            hdr.append(out);

            writer->write(fs.filename_full, out);
        }

        // TCP handshake

        if(not tcp_start_written and details.next_proto == 6) {
            buffer out;

            pcapng::pcapng_epb syn1;
            syn1.append_TCP(out, "", 0, 0, TCPFLAG_SYN, details);

            pcapng::pcapng_epb syn_ack;
            syn1.append_TCP(out, "", 0, 1, TCPFLAG_SYN|TCPFLAG_ACK, details);

            pcapng::pcapng_epb ack;
            syn1.append_TCP(out, "", 0, 0, TCPFLAG_ACK, details);

            writer->write(fs.filename_full, out);
        }


    }
    void PcapLog::write (side_t side, const std::string &s) {
    }
}