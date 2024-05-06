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


namespace socle::traflog {

    int raw_socket_gre(int family, int ttl, std::string const& iface);

    class PcapLog : public baseTrafficLogger {

        PcapLog() = default; // just for singleton, which is set up later
    public:
        explicit PcapLog (baseProxy *parent, const char* d_dir, const char* f_prefix, const char* f_suffix, bool create_dirs);
        ~PcapLog() override;

        bool prepare_file();

        // if ip_packet_hook is set and _only is set too, pcaplog will prepare IP packets, but won't write into files!
        static inline bool ip_packet_hook_only = false;
        std::shared_ptr<pcapng::IP_Hook> ip_packet_hook;

        void write_pcap_header(bool is_recreated);

        void write_tcp_start(pcap::tcp_details& real_details);
        void write_tcp_data(side_t side, buffer const& b, pcap::tcp_details& real_details);

        void write_udp_data(side_t side, buffer const& b, pcap::tcp_details& real_details);

        void write(side_t side, const buffer &b) override;
        void write(side_t side, std::string const& s) override;

        baseProxy *parent = nullptr;
        pcap::tcp_details details;

        static const bool use_pool_writer = true;
        baseFileWriter* writer_ = nullptr;
        void init_writer();

        FsOutput FS;
        mutable std::mutex fs_lock_;

        bool single_only = false;             // write using single-file instance?
        std::atomic_bool pcap_header_written = false; // is PCAP file initialized (opened and preamble written)?
        bool tcp_start_written = false;   // if TCP, is SYNs written, so rest is just data?

        long long stat_bytes_written = 0LL;
        long long stat_bytes_quota = 0LL;
        bool rotate_now = false;

        bool comment_frame(pcapng::pcapng_epb& frame);
        std::string comlog;

        static PcapLog& single_instance() {
            static PcapLog s;
            return s;
        }

        logan_lite log {"cap.pcap"};
        logan_lite log_write {"cap.pcap.write"};

    };



    struct GreExporter : public pcapng::IP_Hook {
        bool execute(pcap::connection_details const& det, buffer const& buf) override {

            if(sock < 0) {
                sock = traflog::raw_socket_gre(target.dst.family, tun_ttl, bind_interface);
            }

            if(not target.dst.ss) return false;
            if(sock < 0) return false;

            buffer send_data(buf.size() + sizeof(pcap::grehdr));
            pcapng::append_GRE_header(send_data, det);

            send_data.append(buf);

            auto r = sendto(sock, send_data.data(), send_data.size(), 0, (sockaddr*) target.dst.as_ss(), sizeof(sockaddr_storage));
            if(r <= 0) {
                return false;
            }

            return true;
        }

        GreExporter(int family, std::string_view host) {
            target.dst.family = family;
            target.dst.str_host = host;
            target.dst.pack();
        }
        GreExporter(GreExporter const& other) : target(other.target), sock(-1), tun_ttl(other.tun_ttl) {};
        GreExporter(GreExporter&& other) noexcept : target(std::move(other.target)), sock(other.sock), tun_ttl(other.tun_ttl) { other.sock = -1; };

        GreExporter& operator=(GreExporter const& other) {
            if(&other != this) {
                target = other.target;
                tun_ttl = other.tun_ttl;
                sock = -1;
            }

            return *this;
        };
        GreExporter& operator=(GreExporter&& other) noexcept {
            if(&other != this) {
                target = std::move(other.target);
                sock = other.sock;
                tun_ttl = other.tun_ttl;

                other.sock = -1;
            }

            return *this;
        };


        virtual ~GreExporter() { if(sock > 0) ::close(sock); }

        void ttl(uint8_t ttl) { tun_ttl = ttl; }
        void bind_if(std::string_view ifa) { bind_interface=ifa; }
    private:
        SocketInfo target{};
        int sock {-1};
        int tun_ttl {32};
        std::string bind_interface{};
    };

}

#endif //PCAPLOG_HPP
