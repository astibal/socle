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

        if(not parent or not parent->com()) {
            _war("pcaplog::ctor: parent or parent com is nullptr");
            parent = nullptr; return;
        }

        auto &ls = parent->ls().empty() ? parent->lda() : parent->ls();
        auto &rs = parent->rs().empty() ? parent->rda() : parent->rs();

        if (ls.empty() or rs.empty()) {
            _war("pcaplog::ctor: ls or rs is empty");
            parent = nullptr; return;
        }

        SocketInfo s;
        s.str_src_host = ls[0]->host();
        s.str_dst_host = rs[0]->host();
        s.sport = safe_val(ls[0]->port(), 0);
        s.dport = safe_val(rs[0]->port(), 0);
        s.pack_dst_ss();
        s.pack_src_ss();

        if(not s.src_ss.has_value()) {
            _war("pcaplog::ctor: src info not created");
            return;
        } else {
            details.source = s.src_ss.value();
            _dia("pcaplog::ctor: src info: %s", s.src_ss_str().c_str());
        }



        if(not s.src_ss.has_value()) {
            _war("pcaplog::ctor: dst info not created");
            return;
        }
        else {
            _dia("pcaplog::ctor: dst info: %s", s.dst_ss_str().c_str());
            details.destination = s.dst_ss.value();
        }

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
        _dia("pcaplog::ctor OK");
    }

    PcapLog::~PcapLog() {
        if(writer_) {
            if(details.next_proto == connection_details::TCP) {
                if(tcp_start_written) {
                    buffer out;
                    pcapng::pcapng_epb f1;
                    f1.append_TCP(out, "", 0, 0, TCPFLAG_FIN|TCPFLAG_ACK, details);
                    pcapng::pcapng_epb f2;
                    f1.append_TCP(out, "", 0, 1, TCPFLAG_FIN|TCPFLAG_ACK, details);
                    writer_->write(FS.filename_full, out);
                }
            }
            writer_->flush(FS.filename_full);
            writer_->close(FS.filename_full);

            // do not delete threaded pool writer
            if(not use_pool_writer)
                delete writer_;
        }
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
            pcapng::pcapng_shb mag;
            mag.append(out);

            // interface block
            pcapng::pcapng_ifb hdr;
            hdr.append(out);

            _deb("pcaplog::write[%s]/magic+ifb : about to write %dB", fs.filename_full.c_str(), out.size());
            _deb("pcaplog::write[%s]/magic+ifb : \r\n%s", fs.filename_full.c_str(), hex_dump(out, 4, 0, true).c_str());
            auto wr = writer->write(fs.filename_full, out);
            _dia("pcaplog::write[%s]/magic+ifb : written %dB", fs.filename_full.c_str(), wr);

            self->pcap_header_written = true;
        }

        // TCP handshake

        if(details.next_proto == connection_details::TCP) {

            if (not tcp_start_written) {
                buffer out;

                pcapng::pcapng_epb syn1;
                syn1.append_TCP(out,"", 0, 0, TCPFLAG_SYN, details);

                pcapng::pcapng_epb syn_ack;
                syn_ack.append_TCP(out, "", 0, 1, TCPFLAG_SYN|TCPFLAG_ACK, details);

                pcapng::pcapng_epb ack;
                ack.append_TCP(out, "", 0, 0, TCPFLAG_ACK, details);

                _deb("pcaplog::write[%s]/tcp-hs : about to write %dB", fs.filename_full.c_str(), out.size());
                _deb("pcaplog::write[%s]/tcp-hs : \r\n%s", fs.filename_full.c_str(), hex_dump(out, 4, 0, true).c_str());

                auto wr = writer->write(fs.filename_full, out);
                writer->flush(fs.filename_full);

                _dia("pcaplog::write[%s]/tcp-hs : written %dB", fs.filename_full.c_str(), wr);

                tcp_start_written = true;
            }

            buffer out;
            pcapng::pcapng_epb data;
            data.append_TCP(out, (const char*)b.data(), b.size(), side == side_t::RIGHT, TCPFLAG_ACK, details);

            _deb("pcaplog::write[%s]/tcp-data : about to write %dB", fs.filename_full.c_str(), out.size());
            _deb("pcaplog::write[%s]/tcp-data : \r\n%s", fs.filename_full.c_str(), hex_dump(out, 4, 0, true).c_str());

            auto wr = writer->write(fs.filename_full, out);
            _dia("pcaplog::write[%s]/tcp-data : written %dB", fs.filename_full.c_str(), wr);
        }
        else {
            buffer out;

            pcapng::pcapng_epb u1;
            u1.append_UDP(out, (const char*)b.data(), b.size(), side == side_t::RIGHT, details);

            auto wr = writer->write(fs.filename_full, out);
            _dia("pcaplog::write[%s]/udp : written %dB", fs.filename_full.c_str(), wr);
        }

    }
    void PcapLog::write (side_t side, const std::string &s) {
    }
}