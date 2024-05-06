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

    using namespace socle::pcap;

    namespace log {
        static const logan_lite pcaplog {"socle.pcaplog"};
    }

    int raw_socket_gre(int family, int ttl, std::string const& iface) {
        auto const& log = log::pcaplog;

        int sock = socket(family, SOCK_RAW, IPPROTO_GRE);

        if(sock < 0) return sock;

        int none = 0;

        if(not iface.empty()) {
            if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface.c_str(), iface.length()) == -1) {
                _err("raw_socket_gre: failed to bind raw socket to interface '%s'", iface.c_str());
                close(sock);
                return -1;
            }
            else {
                _deb("raw_socket_gre: ok - bind raw socket to interface '%s'", iface.c_str());
            }
        }

        if (setsockopt (sock,
                        family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP,
                        family == AF_INET6 ? IPV6_HDRINCL : IP_HDRINCL,
                        &none, sizeof (none)) < 0) {
            _err("raw_socket_gre: cannot set HRDINCL");

            close(sock);
            return -1;
        }

        int n_ttl = ttl;

        if(setsockopt(sock, family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP,
                         family == AF_INET6 ? IPV6_HOPLIMIT : IP_TTL, &n_ttl, sizeof(n_ttl)) < 0) {

            _err("raw_socket_gre: cannot set TTL");
        }

        return sock;
    }

    PcapLog::PcapLog (baseProxy *parent, const char* d_dir, const char* f_prefix, const char* f_suffix, bool create_dirs) :
        parent(parent),
        FS(parent, d_dir, f_prefix, f_suffix, create_dirs) {

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
        s.src.str_host = ls[0]->host();
        s.dst.str_host = rs[0]->host();
        s.src.port = safe_val(ls[0]->port(), 0);
        s.dst.port = safe_val(rs[0]->port(), 0);
        s.src.family = ls.at(0)->com()->l3_proto();
        s.dst.family = rs.at(0)->com()->l3_proto();
        s.dst.pack();
        s.src.pack();

        if(not s.src) {
            _war("pcaplog::ctor: src info not created");
            return;
        } else {
            details.source = s.src.ss.value();
            _deb("pcaplog::ctor: src info: %s", s.src_ss_str().c_str());
        }



        if(not s.src) {
            _war("pcaplog::ctor: dst info not created");
            return;
        }
        else {
            _deb("pcaplog::ctor: dst info: %s", s.dst_ss_str().c_str());
            details.destination = s.dst.ss.value();
        }

        // this could become more complex in the (probably far) future
        ls.at(0)->com()->l3_proto() == AF_INET6 ? details.ip_version = 6
                                              : details.ip_version = 4;

        ls.at(0)->com()->l4_proto() == SOCK_STREAM ? details.next_proto = connection_details::TCP
                                                 : details.next_proto = connection_details::UDP;



        // some tcp specific values
        if(details.next_proto == connection_details::TCP) {
            details.seq_in = xorshift::rand();
            details.seq_out = xorshift::rand();
        }

        init_writer();
    }

    PcapLog::~PcapLog() {
        if(writer_) {

            // if no parent is set, there is nothing to write
            if(parent) {

                try {
                    if (details.next_proto == connection_details::TCP) {
                        if (tcp_start_written) {
                            PcapLog *self = this;
                            if (single_only) self = &single_instance();
                            auto *writer = self->writer_;
                            auto const &fs = self->FS;

                            buffer out;
                            pcapng::pcapng_epb f1;
                            if (self->ip_packet_hook) f1.ip_packet_hook = self->ip_packet_hook;

                            if (comment_frame(f1)) { _deb("comment inserted on close"); }

                            f1.append_TCP(out, "", 0, 0, TCPFLAG_FIN | TCPFLAG_ACK, details);
                            pcapng::pcapng_epb f2;
                            if (self->ip_packet_hook) f2.ip_packet_hook = self->ip_packet_hook;

                            f1.append_TCP(out, "", 0, 1, TCPFLAG_FIN | TCPFLAG_ACK, details);

                            if (not ip_packet_hook_only)
                                writer->write(fs.filename_full, out);
                        }
                    }
                    writer_->flush(FS.filename_full);
                    writer_->close(FS.filename_full);
                }
                catch (mempool_error const& e) {
                    _err("pcaplog-dtor: mempool alloc error: %s", e.what());
                }
                catch (std::invalid_argument const& e) {
                    _err("pcaplog-dtor: invalid argument error: %s", e.what());
                }
                catch (std::out_of_range& e) {
                    _err("pcaplog-dtor: out of range error: %s", e.what());
                }
            }
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


    bool PcapLog::prepare_file() {

        PcapLog *self = this;
        if (single_only) self = &single_instance();

        auto l_ = std::lock_guard(self->fs_lock_);
        auto *writer = self->writer_;
        auto const &fs = self->FS;

        // rotating logs is only possible for pcap_single mode
        if (single_only) {

            // don't allow rotating insanely low sizes (<10MiB). If 10MiB is too big for somebody, let me know.
            if (self->stat_bytes_quota > 0 and self->stat_bytes_quota <= 10000000LL) {
                self->stat_bytes_quota = 10000000LL;
            }


            if ((self->stat_bytes_quota > 0LL and self->stat_bytes_written >= self->stat_bytes_quota) or
                self->rotate_now) {

                _dia("pcaplog::write: rotating based on %s", self->rotate_now ? "request" : "quota limit");
                self->rotate_now = false;

                std::stringstream ss;
                ss << self->FS.data_dir << "/" << self->FS.file_prefix << "smithproxy.old." << self->FS.file_suffix;
                std::string renamed_fnm = ss.str();

                struct stat st{};
                int result = stat(renamed_fnm.c_str(), &st);
                auto file_exists = result == 0;

                _deb("pcaplog::write: old file %s exist", file_exists ? "does" : "doesn't");

                if (file_exists) {
                    auto ret = ::remove(renamed_fnm.c_str());
                    if (ret == 0) {
                        _deb("pcaplog::write: old file deleted");

                        bool closed = self->writer_->close(fs.filename_full);
                        _deb("pcaplog::write: current file closed: %s", closed ? "yes" : "no");

                        if (::rename(fs.filename_full.c_str(), renamed_fnm.c_str()) == 0) {
                            _dia("pcaplog::write: moving current file to backup: ok");
                            self->FS.filename_full = self->FS.generate_filename_single("smithproxy", true);
                            self->stat_bytes_written = 0LL;
                        } else {
                            _err("pcaplog::write: moving current file to backup: %s", string_error().c_str());
                        }
                    } else {
                        _err("pcaplog::write: old file not deleted: %s", string_error().c_str());
                    }
                } else {
                    bool closed = self->writer_->close(fs.filename_full);
                    _deb("pcaplog::write: current file closed: %s", closed ? "yes" : "no");

                    if (::rename(fs.filename_full.c_str(), renamed_fnm.c_str()) == 0) {
                        _dia("pcaplog::write: moving current file to backup: ok");
                        self->FS.filename_full = self->FS.generate_filename_single("smithproxy", true);
                        self->stat_bytes_written = 0LL;
                    } else {
                        _err("pcaplog::write: moving current file to backup: %s", string_error().c_str());
                    }
                }
            }
        }

        if(writer->recreate(fs.filename_full)) {
            auto fd = creat(fs.filename_full.c_str(),O_CREAT|O_WRONLY|O_TRUNC);

            if(fd >= 0) {
                if(chmod(fs.filename_full.c_str(), 0600) != 0) {
                    _err("chmod failed: %s", string_error().c_str());
                }
                _not("new file %s created", fs.filename_full.c_str());
                ::close(fd);
            }

            return true;
        }

        return false;
    }

    bool PcapLog::comment_frame(pcapng::pcapng_epb& frame) {
        if(not comlog.empty()) {
            frame.comment(comlog);
            comlog.clear();

            return true;
        }

        return false;
    }

    void PcapLog::write_pcap_header(bool is_recreated) {

        if (not pcap_header_written or is_recreated) {
            buffer out;
            pcapng::pcapng_shb mag;
            mag.append(out);

            // interface block
            pcapng::pcapng_ifb hdr;
            hdr.append(out);


            if(not ip_packet_hook_only) {
                _deb("pcaplog::write[%s]/magic+ifb : about to write %dB", FS.filename_full.c_str(), out.size());
                _dum("pcaplog::write[%s]/magic+ifb : \r\n%s", FS.filename_full.c_str(),
                     hex_dump(out, 4, 0, true).c_str());

                auto wr = writer_->write(FS.filename_full, out);
                _dia("pcaplog::write[%s]/magic+ifb : written %dB", FS.filename_full.c_str(), wr);
                stat_bytes_written += wr;
            }


            pcap_header_written = true;
        }
    };

    void PcapLog::write_tcp_start(tcp_details& real_details) {

        auto const& log = log_write;

        buffer out;

        pcapng::pcapng_epb syn1;
        if(ip_packet_hook) syn1.ip_packet_hook = ip_packet_hook;

        syn1.append_TCP(out, "", 0, 0, TCPFLAG_SYN, real_details);

        pcapng::pcapng_epb syn_ack;
        if(ip_packet_hook) syn_ack.ip_packet_hook = ip_packet_hook;

        syn_ack.append_TCP(out, "", 0, 1, TCPFLAG_SYN|TCPFLAG_ACK, real_details);

        pcapng::pcapng_epb ack;
        if(ip_packet_hook) ack.ip_packet_hook = ip_packet_hook;
        ack.append_TCP(out, "", 0, 0, TCPFLAG_ACK, real_details);


        if(not ip_packet_hook_only) {
            _deb("pcaplog::write[%s]/tcp-hs : about to write %dB", FS.filename_full.c_str(), out.size());
            _dum("pcaplog::write[%s]/tcp-hs : \r\n%s", FS.filename_full.c_str(), hex_dump(out, 4, 0, true).c_str());


            auto wr = writer_->write(FS.filename_full, out);
            writer_->flush(FS.filename_full);

            stat_bytes_written += wr;

            _dia("pcaplog::write[%s]/tcp-hs : written %dB", FS.filename_full.c_str(), wr);
        }
    }


    void PcapLog::write_tcp_data(side_t side, buffer const& b, tcp_details& real_details) {
        auto const& log = log_write;

        buffer out;
        pcapng::pcapng_epb data;
        if(ip_packet_hook) data.ip_packet_hook = ip_packet_hook;

        if(comment_frame(data)) { _dia("comment inserted into data"); };


        if(data.append_TCP(out, (const char*)b.data(), b.size(), side == side_t::RIGHT, TCPFLAG_ACK, real_details) > 0) {

            if(not ip_packet_hook_only) {
                _deb("pcaplog::write[%s]/tcp-data : about to write %dB", FS.filename_full.c_str(), out.size());
                _dum("pcaplog::write[%s]/tcp-data : \r\n%s", FS.filename_full.c_str(),
                     hex_dump(out, 4, 0, true).c_str());

                auto wr = writer_->write(FS.filename_full, out);
                _dia("pcaplog::write[%s]/tcp-data : written %dB", FS.filename_full.c_str(), wr);

                stat_bytes_written += wr;
            }
        } else {
            _err("pcaplog::write: error appending TCP data");
        }
    }

    void PcapLog::write_udp_data(side_t side, buffer const& b, tcp_details& real_details) {
        auto const& log = log_write;

        buffer out;

        pcapng::pcapng_epb u1;
        if(ip_packet_hook) u1.ip_packet_hook = ip_packet_hook;

        if(comment_frame(u1)) { _dia("comment inserted"); };
        if(u1.append_UDP(out, (const char*)b.data(), b.size(), side == side_t::RIGHT, real_details) > 0) {

            if(not ip_packet_hook_only) {
                _deb("pcaplog::write[%s]/udp : about to write %dB", FS.filename_full.c_str(), out.size());
                _dum("pcaplog::write[%s]/tcp : \r\n%s", FS.filename_full.c_str(), hex_dump(out, 4, 0, true).c_str());

                auto wr = writer_->write(FS.filename_full, out);
                _dia("pcaplog::write[%s]/udp : written %dB", FS.filename_full.c_str(), wr);

                stat_bytes_written += wr;
            }
        } else {
            _err("pcaplog::write: error appending UDP data");
        }
    }

    void PcapLog::write (side_t side, const buffer &b) {
        PcapLog *self = this;
        if (single_only) self = &single_instance();

        if (not self->writer_) self->init_writer();

        auto *writer = self->writer_;
        auto const &fs = self->FS;


        if (not writer->opened()) {
            if (writer->open(fs.filename_full)) {
                _dia("writer '%s' created", fs.filename_full.c_str());
            } else {
                _err("write '%s' failed to open dump file!", fs.filename_full.c_str());
            }
        }

        if(not ip_packet_hook_only) {

            if (not writer->opened()) return;

            bool is_recreated = prepare_file();

            // reset bytes written
            if(is_recreated) {
                _err("pcaplog::write: current file recreated");
                self->stat_bytes_written = 0LL;
            }

            // write header if needed
            self->write_pcap_header(is_recreated);
        }

        if(details.next_proto == connection_details::TCP) {

            if (not tcp_start_written) {
                self->write_tcp_start(details);
                tcp_start_written = true;
            }

            self->write_tcp_data(side, b, details);

            // Fins are written with PcapLog destruction
        }
        else if(details.next_proto == connection_details::UDP) {

            self->write_udp_data(side, b, details);
        }
        else {
            _err("pcaplog::write: unknown protocol to write: %d", details.next_proto);
        }

    }
    void PcapLog::write (side_t side, const std::string &s) {
        comlog.append(s);
    }
}