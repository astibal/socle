/*
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.

    Linking Smithproxy statically or dynamically with other modules is
    making a combined work based on Smithproxy. Thus, the terms and
    conditions of the GNU General Public License cover the whole combination.

    In addition, as a special exception, the copyright holders of Smithproxy
    give you permission to combine Smithproxy with free software programs
    or libraries that are released under the GNU LGPL and with code
    included in the standard release of OpenSSL under the OpenSSL's license
    (or modified versions of such code, with unchanged license).
    You may copy and distribute such a system following the terms
    of the GNU GPL for Smithproxy and the licenses of the other code
    concerned, provided that you include the source code of that other code
    when and as the GNU GPL requires distribution of source code.

    Note that people who make modified versions of Smithproxy are not
    obligated to grant this special exception for their modified versions;
    it is their choice whether to do so. The GNU General Public License
    gives permission to release a modified version without this exception;
    this exception also makes it possible to release a modified version
    which carries forward this exception.
*/


#include <algorithm>

#include <traflog/pcapapi.hpp>
#include <unistd.h>

namespace socle::pcap {

    size_t append_PCAP_magic(buffer& out_buffer) {

        pcap_file_header header{};

        header.magic = 0xa1b2c3d4;
        header.version_major = 2;
        header.version_minor = 4;
        header.thiszone =0;
        header.sigfigs = 0;
        header.snaplen = 65535;
        header.linktype = 113;

        out_buffer.append(&header, sizeof(header));

        return sizeof(header);
    }

    size_t save_PCAP_magic(int fd) {
        buffer out(sizeof(pcap_file_header));
        out.size(0);

        append_PCAP_magic(out);
        save_payload(fd, out);

        return out.size();
    }


    uint16_t iphdr_cksum(void const* data, size_t len)
    {
        uint32_t sum=0;
        size_t i;
        for (i=0; i < len/2; ++i)
            sum += ntohs(((uint16_t*)data)[i]);
        while (sum & 0xFFFF0000)
            sum = (sum & 0xFFFFu)+(sum >> 16u);
        return ((uint16_t) ~sum);
    }


    uint16_t l4hdr_cksum(void* hdr, size_t hdr_sz, void *next, size_t next_sz, const char *payload, size_t payload_len) {

        unsigned int padd = payload_len & 1u;
        size_t buff_len = hdr_sz + next_sz + payload_len + padd;


        char* buff = static_cast<char*>(::alloca(buff_len));
        if(not buff) return 0;

        memcpy(buff,                                  hdr,     hdr_sz);
        memcpy(buff + hdr_sz,                         next,    next_sz);
        memcpy(buff + hdr_sz + next_sz,               payload, payload_len);
        if(padd > 0)
            buff[buff_len-1] = 0;

        uint16_t result = iphdr_cksum(buff, buff_len);

        return result;
    }

    void append_PCAP_header(buffer& out_buffer, connection_details const& details, size_t payload_size) {

        [[maybe_unused]] auto const& log = get_log();

        struct timeval time{};
        struct pcap_frame pcap_header{};


        /* we have to rather tediously fake a pcap header, linux cooked capture header, ip header and tcp header */
        /* pcap header */
        gettimeofday(&time, nullptr);

        pcap_header.tv_sec = time.tv_sec;
        pcap_header.tv_usec = time.tv_usec;

        auto l3_hdr_size = 0;
        if (details.ip_version == 4 or details.ip_version == 0) {
            l3_hdr_size = sizeof(struct iphdr);
        }
        if (details.ip_version == 6) {
            l3_hdr_size = sizeof(struct ip6_hdr);
        }

        auto l4_hdr_size = 0;
        if(details.next_proto == connection_details::TCP or details.next_proto == 0) {
            l4_hdr_size = sizeof(struct tcphdr);
        }
        else if(details.next_proto == connection_details::UDP) {
            l4_hdr_size = sizeof(struct udphdr);
        }

        pcap_header.caplen = sizeof(struct linux_cooked_capture) + l3_hdr_size + l4_hdr_size + payload_size;
        pcap_header.len =  sizeof(struct linux_cooked_capture) + l3_hdr_size + l4_hdr_size + payload_size;


        out_buffer.append(&pcap_header, sizeof(pcap_header));
    };


    void append_LCC_header(buffer& out_buffer, connection_details const& details, int in) {
        [[maybe_unused]] auto const& log = get_log();

        /* linux cooked capture header */
        struct linux_cooked_capture lcc_header{};
        lcc_header.type = htons(in ? 0 : 4); /* 0 sent is to us, 4 is sent by us */
        lcc_header.arphrd = htons(ARPHRD_ETHER);
        lcc_header.ll_addr_size = htons(6);

        std::memset(lcc_header.ll_hdr_data, 0, sizeof(lcc_header.ll_hdr_data));
        std::memset(lcc_header.ll_hdr_data, in ? 2 : 1, 6);

        if (details.ip_version == 4) {
            lcc_header.proto_type = htons(ETHERTYPE_IP);
        } else if (details.ip_version == 6) {
            lcc_header.proto_type = htons(ETHERTYPE_IPV6);
        }

        out_buffer.append(&lcc_header, sizeof(lcc_header));
    };


    void append_GRE_header(buffer& out_buffer, connection_details const& details) {
        grehdr hdr{0};

        if(details.ip_version == 6) {
            hdr.next_proto = htons(0x86DD);
        } else {
            hdr.next_proto = htons(0x0800);
        }
        out_buffer.append(&hdr, sizeof(hdr));
    }


    void encapulate_gre_v4(buffer& out_buffer, connection_details& details, int direction, size_t payload_size) {

        iphdr tun_hdr{};

        // create tunneled header
        create_IPv4_header(tun_hdr, details, direction + 2, payload_size);

        tun_hdr.protocol = IPPROTO_GRE;
        tun_hdr.ttl = details.tun_ttl;
        tun_hdr.saddr = {0};
        tun_hdr.daddr = {0};

        if(details.tun_details) {
            details.tun_details->pack();

            if(details.tun_details->src.family == AF_INET and details.tun_details->src) {
                auto ss = details.tun_details->src.ss.value();
                auto* ip = (sockaddr_in*)(&ss);
                tun_hdr.saddr = *(uint32_t*)&ip->sin_addr;
            }
            if(details.tun_details->dst.family == AF_INET and details.tun_details->dst) {
                auto ss = details.tun_details->dst.ss.value();
                auto* ip = (sockaddr_in*)(&ss);
                tun_hdr.daddr = *(uint32_t*)&ip->sin_addr;
            }
        }

        out_buffer.append(&tun_hdr,sizeof(tun_hdr));
        append_GRE_header(out_buffer, details);
    }

    void encapsulate_gre_v6(buffer& out_buffer, connection_details& details, int direction, size_t payload_size) {

        ip6_hdr tun_hdr{};

        create_IPv6_header(tun_hdr, details, direction + 2, payload_size);

        tun_hdr.ip6_nxt = IPPROTO_GRE;
        tun_hdr.ip6_hops = details.tun_ttl;
        tun_hdr.ip6_src = {};
        tun_hdr.ip6_dst = {};

        if(details.tun_details) {
            details.tun_details->pack();

            if (details.tun_details->src.family == AF_INET6 and details.tun_details->src.ss) {
                auto ss = details.tun_details->src.ss.value();
                auto const *ip = (sockaddr_in6 *) (&ss);
                tun_hdr.ip6_src = ip->sin6_addr;
            }
            if (details.tun_details->dst.family == AF_INET6 and details.tun_details->dst.ss) {
                auto ss = details.tun_details->dst.ss.value();
                auto const *ip = (sockaddr_in6 *) (&ss);
                tun_hdr.ip6_dst = ip->sin6_addr;
            }
        }

        out_buffer.append(&tun_hdr,sizeof(tun_hdr));
        append_GRE_header(out_buffer, details);
    }

    size_t l4_header_sz(connection_details const& details) {
        size_t l4_header_sz {0};
        if (details.next_proto == connection_details::TCP or details.next_proto == 0) {
            l4_header_sz = sizeof(struct tcphdr);
        }
        else if (details.next_proto == connection_details::UDP) {
            l4_header_sz = sizeof(struct udphdr);
        } else {
            auto msg = string_format("invalid tunnel inner l4 protocol: %d", details.next_proto);
            throw std::invalid_argument(msg.c_str());
        }

        return l4_header_sz;
    }


    size_t l3_header_sz(connection_details const& details) {
        size_t l3_header_sz {0};
        if (details.ip_version == 4 or details.ip_version == 0) {
            l3_header_sz = sizeof(struct iphdr);
        }
        else if (details.ip_version == 6) {
            l3_header_sz = sizeof(struct ip6_hdr);
        } else {
            auto msg = string_format("invalid IP version: %d", details.ip_version);
            throw std::invalid_argument(msg.c_str());
        }

        return l3_header_sz;
    }

    // parameter direction:
    //      even: - out
    //      odd:  - in
    //      > 1 - tunneled
    void create_IPv4_header(iphdr& ip_header, connection_details& details, int direction, size_t payload_size) {
        ip_header.version = IPVERSION;
        ip_header.ihl = sizeof(struct iphdr) / sizeof(uint32_t);
        ip_header.tos = IPTOS_TOS(0);

        auto l4_sz = l4_header_sz(details);

        if(direction <= 1) {
            ip_header.tot_len = htons(sizeof(struct iphdr) + l4_sz + payload_size);
            ip_header.protocol = details.next_proto;
        }
        else {

            auto l3_sz = l3_header_sz(details);

            if (details.tun_proto == connection_details::GRE) {
                ip_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct grehdr) + l3_sz + l4_sz + payload_size);
                ip_header.protocol = IPPROTO_GRE;
            } else {
                auto msg = string_format("invalid tunneling protocol: %d", details.next_proto);
                throw std::invalid_argument(msg.c_str());
            }
        }
        ip_header.id = direction % 2 ? details.ip_id_in++ : details.ip_id_out++;

        ip_header.frag_off = htons(0x4000); /* don't fragment */
        ip_header.ttl = details.ttl;

        auto const* target_sockaddr = reinterpret_cast<sockaddr_in const*>(&details.destination);
        auto const* client_sockaddr = reinterpret_cast<sockaddr_in const*>(&details.source);

        if (direction % 2) {

            if(direction > 1 and details.tun_details) {
                details.tun_details->pack();
                ip_header.saddr = details.tun_details->dst.as_v4()->sin_addr.s_addr;
                ip_header.daddr = details.tun_details->src.as_v4()->sin_addr.s_addr;
            } else {
                ip_header.saddr = target_sockaddr->sin_addr.s_addr;
                ip_header.daddr = client_sockaddr->sin_addr.s_addr;
            }
        } else {
            if(direction > 1 and details.tun_details) {
                ip_header.saddr = details.tun_details->src.as_v4()->sin_addr.s_addr;
                ip_header.daddr = details.tun_details->dst.as_v4()->sin_addr.s_addr;
            }
            else {
                ip_header.saddr = client_sockaddr->sin_addr.s_addr;
                ip_header.daddr = target_sockaddr->sin_addr.s_addr;
            }
        }
        ip_header.check = htons(iphdr_cksum(&ip_header, sizeof(struct iphdr)));
    }

    // parameter direction:
    //      even: - out
    //      odd:  - in
    //      > 1 - tunneled
    void create_IPv6_header(ip6_hdr& ip_header, connection_details& details, int direction, size_t payload_size) {

        ip_header.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
        ip_header.ip6_hops = details.ttl;

        auto l4_sz = l4_header_sz(details);

        if(direction <= 1) {
            ip_header.ip6_plen = htons(l4_sz + payload_size);
            ip_header.ip6_nxt = details.next_proto;
        }
        else {
            auto l3_sz = l3_header_sz(details);

            if (details.tun_proto == connection_details::GRE) {
                ip_header.ip6_plen = htons(sizeof(struct grehdr) + l3_sz + l4_sz + payload_size);
                ip_header.ip6_nxt = IPPROTO_GRE;
            } else {
                auto msg = string_format("invalid tunneling protocol: %d", details.next_proto);
                throw std::invalid_argument(msg.c_str());
            }
        }

        auto const* target_sockaddr = reinterpret_cast<sockaddr_in6 const*>(&details.destination);
        auto const* client_sockaddr = reinterpret_cast<sockaddr_in6 const*>(&details.source);

        if (direction % 2) {

            if(direction > 1 and details.tun_details) {
                details.tun_details->pack();
                ip_header.ip6_src = details.tun_details->dst.as_v6()->sin6_addr;
                ip_header.ip6_dst = details.tun_details->src.as_v6()->sin6_addr;
            } else {
                ip_header.ip6_src = target_sockaddr->sin6_addr;
                ip_header.ip6_dst = client_sockaddr->sin6_addr;
            }
        } else {
            if(direction > 1 and details.tun_details) {
                ip_header.ip6_src = details.tun_details->src.as_v6()->sin6_addr;
                ip_header.ip6_dst = details.tun_details->dst.as_v6()->sin6_addr;
            }
            else {
                ip_header.ip6_src = client_sockaddr->sin6_addr;
                ip_header.ip6_dst = target_sockaddr->sin6_addr;
            }
        }
    }


    void append_IPv4_header(buffer& out_buffer, connection_details& details, int direction, size_t payload_size) {
        [[maybe_unused]] auto const& log = get_log();

        struct iphdr ip_header{};
        create_IPv4_header(ip_header, details, direction, payload_size);

        if(details.tun_proto == connection_details::GRE) {

            if(details.tun_details and details.tun_details->src.family == AF_INET6)
                encapsulate_gre_v6(out_buffer, details, direction, payload_size);
            else
                encapulate_gre_v4(out_buffer, details, direction, payload_size);

        }

        out_buffer.append(&ip_header, sizeof(ip_header));
    };

    void append_IPv6_header(buffer& out_buffer, connection_details& details, int direction, size_t payload_size) {
        [[maybe_unused]] auto const& log = get_log();

        struct ip6_hdr ip_header{};

        create_IPv6_header(ip_header, details, direction, payload_size);

        if(details.tun_proto == connection_details::GRE) {

            if(details.tun_details and details.tun_details->src.family == AF_INET6)
                encapsulate_gre_v6(out_buffer, details, direction, payload_size);
            else
                encapulate_gre_v4(out_buffer, details, direction, payload_size);
        }

        out_buffer.append(&ip_header, sizeof(ip_header));
    };

    void append_IP_header(buffer& out_buffer, connection_details& details, int in, size_t payload_size) {
        if(details.ip_version == 4) {
            append_IPv4_header(out_buffer, details, in, payload_size);

        }
        else if(details.ip_version == 6) {
            append_IPv6_header(out_buffer, details, in, payload_size);
        }
    }

    void append_TCP_header (buffer &out_buffer, tcp_details &details, int in, const char *payload, size_t payload_size,
                            unsigned char tcpflags) {

        [[maybe_unused]] auto const& log = get_log();

        struct tcphdr tcp_header{};

        auto [ sport, dport ] = details.extract_ports();

        auto &tcp_seq_in = details.seq_in;
        auto &tcp_seq_out = details.seq_out;
        auto &tcp_lastack_in = details.tcp_lastack_in;
        auto &tcp_lastack_out = details.tcp_lastack_out;


        std::memset(&tcp_header, 0, sizeof(struct tcphdr));

        if (tcpflags & TCPFLAG_SYN)
            tcp_header.syn = 1;
        if (tcpflags & TCPFLAG_FIN)
            tcp_header.fin = 1;
        if (tcpflags & TCPFLAG_ACK)
            tcp_header.ack = 1;

        if (tcpflags == 0)
            tcp_header.ack = 1;

        if (in) {
            tcp_header.source = dport;
            tcp_header.dest = sport;
            /* seq counts data in the direction we're sending */
            tcp_header.seq = htonl(tcp_seq_in);

            tcp_seq_in += (tcp_header.syn or tcp_header.fin) ? 1 : payload_size;
            tcp_header.ack_seq = htonl(tcp_seq_out);

            /* ack-seq is the seq+size of the last packet we saw going the other way */
            if (tcp_seq_out != tcp_lastack_in) {
                tcp_lastack_in = tcp_seq_out;

                if (not(tcpflags & TCPFLAG_SYN)) {
                    tcp_header.ack = 1;
                }
            }
        } else {
            tcp_header.source = sport;
            tcp_header.dest = dport;
            tcp_header.seq = htonl(tcp_seq_out);

            tcp_seq_out += (tcp_header.syn or tcp_header.fin) ? 1 : payload_size;
            tcp_header.ack_seq = htonl(tcp_seq_in);

            if (tcp_seq_in != tcp_lastack_out) {
                tcp_lastack_out = tcp_seq_in;

                if (not(tcpflags & TCPFLAG_SYN)) {
                    tcp_header.ack = 1;
                }
            }
        }
        tcp_header.doff = 5; /* no options */
        tcp_header.window = htons(32768);
        tcp_header.check = 0;


        tcp_header.check = htons(L4_chksum<tcphdr>(details, in, &tcp_header, payload, payload_size));


        out_buffer.append(&tcp_header, sizeof(tcp_header));

    }

    void append_UDP_header(buffer& out_buffer, connection_details& details, int in, const char* payload, size_t payload_size) {

        [[maybe_unused]] auto const& log = get_log();

        struct udphdr udp_header{};
        auto [ sport, dport ] = details.extract_ports();

        if (in) {
            udp_header.source = dport;
            udp_header.dest = sport;
        }
        else {
            udp_header.source = sport;
            udp_header.dest = dport;
        }
        udp_header.len = htons(sizeof(udp_header) + payload_size);
        udp_header.check = htons(L4_chksum<udphdr>(details, in, &udp_header, payload, payload_size));

        out_buffer.append(&udp_header, sizeof(udp_header));
    }

    void save_payload(int fd, const char* data, size_t size) {

        auto & log = get_log();
        if (size && write(fd, data, size) != static_cast<ssize_t>(size)) {
            _err("cannot write all data to file");

            if (close(fd) < 0) {
                _err("cannot properly close the file");
            }
        }
    }

    void save_payload(int fd, buffer const& out) {
        save_payload(fd, (const char *) out.data(), out.size());
    }


    bool lock_fd(int fd) {
        auto const& log = get_log();

        if (flock(fd, LOCK_EX) < 0) {
            _err("cannot get exclusive lock");

            if (close(fd) < 0) {
                _err("cannot properly close the file");
            }

            return false;
        }

        return true;
    }

    bool unlock_fd(int fd) {
        if (flock(fd, LOCK_UN) < 0) {
            auto &log = get_log();
            _err("cannot unlock the file");

            return false;
        }

        return true;
    };

    size_t append_TCP_frame(buffer& out_buffer, const char* data, ssize_t size, int in, unsigned char tcpflags, tcp_details& details) {
        if(size < 0) {
            return -1;
        }

        append_PCAP_header(out_buffer, details, size);
        append_LCC_header(out_buffer, details, in);
        append_IP_header(out_buffer, details, in, size);
        append_TCP_header(out_buffer, details, in, data, size, tcpflags);
        out_buffer.append(data, size);

        return out_buffer.size();
    }

    size_t save_TCP_frame(int fd, const char* data, ssize_t size, int in, unsigned char tcpflags, tcp_details& details) {
        buffer out(
                 sizeof(pcap_frame) +
                 sizeof(linux_cooked_capture) +
                 std::max(sizeof(iphdr), sizeof(ip6_hdr)) +
                 sizeof(tcphdr) +
                 size
                 + 32); // add some extra bytes
        out.size(0);
        append_TCP_frame(out, data, size, in, tcpflags, details);
        save_payload(fd, out);

        return out.size();
    }


    size_t append_UDP_frame(buffer& out_buffer, const char* data, ssize_t size, int in, connection_details& details) {
        if(size < 0) {
            return -1;
        }

        append_PCAP_header(out_buffer, details, size);
        append_LCC_header(out_buffer, details, in);
        append_IP_header(out_buffer, details, in, size);
        append_UDP_header(out_buffer, details, in, data, size);
        out_buffer.append(data, size);

        return out_buffer.size();
    }

    size_t save_UDP_frame(int fd, const char* data, ssize_t size, int in, connection_details& details) {
        buffer out(
                sizeof(pcap_frame) +
                sizeof(linux_cooked_capture) +
                std::max(sizeof(iphdr), sizeof(ip6_hdr)) +
                sizeof(udphdr) +
                size
                + 32); // add some extra bytes
        out.size(0);
        append_UDP_frame(out, data, size, in, details);
        save_payload(fd, out);

        return out.size();
    }
}

namespace socle::pcapng {

    size_t padding_sz32(size_t s) {
        size_t padding_sz = 4 - (s + 4) % 4;
        if(padding_sz == 4) padding_sz = 0;

        return padding_sz;
    }

    size_t padding::append(buffer& out, size_t n, uint8_t c) {
        for (size_t i = 0; i < n; ++i) {
            out.append(c);
        }
        return n;
    }

    size_t pcapng_shb::size() const {
        constexpr size_t fixed_sz =
               sizeof(type) +
               sizeof(total_length) +
               sizeof(magic) +
               sizeof(version_maj) +
               sizeof(version_min) +
               sizeof(section_length) +
               sizeof(total_length);

        size_t sz = 0;
        if(options) sz += options->size();

        return sz + fixed_sz;

    }

    size_t pcapng_shb::append (buffer& out) {

        total_length = size();

        auto orig_size = out.size();

        out.append(type);
        out.append(total_length);
        out.append(magic);
        out.append(version_maj);
        out.append(version_min);
        out.append(section_length);
        if(options)
            out.append(options.get());
        out.append(total_length);

        return out.size() - orig_size;
    }


    size_t pcapng_ifb::size() const {
        constexpr size_t fixed_sz =
                sizeof(type) +
                sizeof(total_length) +
                sizeof(link_type) +
                sizeof(_reserved1) +
                sizeof(snaplen) +
                sizeof(total_length);

        size_t sz = 0;
        if(options) sz += options->size();

        return sz + fixed_sz;

    }

    size_t pcapng_ifb::append (buffer& out) {
        auto orig_size = out.size();

        total_length = size();

        out.append(type);
        out.append(total_length);
        out.append(link_type);
        out.append(_reserved1);
        out.append(snaplen);

        if(options)
            out.append(options.get());
        out.append(total_length);

        return out.size() - orig_size;
    }

    size_t pcapng_epb::size () const {

        size_t sz = 0;

        // packed data are padded to 32bits
        if(packet_data) {
            auto padding_sz = padding_sz32(packet_data->size());
            sz += ( padding_sz + packet_data->size() );
        }
        if(options) {
            sz += options->size();
        }

        return sz + fixed_sz;
    }

    size_t pcapng_epb::append (buffer& out) {
        auto orig_size = out.size();

        total_length = size();
        out.append(type);
        out.append(total_length);
        out.append(iface_id);

        // do timestamp automagic if not set yet
        if(timestamp_high == 0 and timestamp_low == 0) {
            timeval time{};
            gettimeofday(&time, nullptr);
            timestamp_high = time.tv_sec;
            timestamp_low = time.tv_usec;
        }

        out.append(timestamp_high);
        out.append(timestamp_low);

        if(packet_data)
            captured_len = packet_data->size();
        out.append(captured_len);

        original_len = captured_len;
        out.append(original_len);

        if(packet_data) {
            out.append(packet_data.get());

            // packet data are padded to 32bits
            auto padding_sz = padding_sz32(packet_data->size());

            for (unsigned int i = 0; i < padding_sz; ++i) {
                out.append('\xCC');
            }

        }

        if(options) {
            options->append(out);
        }
        out.append(total_length);

        return out.size() - orig_size;
    }

    void pcapng_epb::comment (const std::string &s) {
        if(not options)
            options = std::make_shared<pcapng_options>();

        pcapng_options::entry e = { pcapng_options::code_id::Comment, 0, std::make_shared<buffer>(s.data(), s.size()) };
        options->entries.emplace_back(e);
    }

    size_t save_NG_magic(int fd) {
        buffer out(sizeof(pcapng_shb));
        pcapng_shb hdr;
        out.capacity(hdr.size() + 16);
        out.size(0);

        hdr.append(out);

        save_payload(fd, out);
        return out.size();
    }

    size_t save_NG_ifb(int fd, pcapng_ifb& hdr) {
        buffer out(sizeof(pcapng_ifb));

        out.capacity(hdr.size() + 16);
        out.size(0);

        hdr.append(out);

        save_payload(fd, out);
        return out.size();
    }


    size_t pcapng_epb::append_TCP(buffer& out_buffer, const char* data, ssize_t data_size, int in, unsigned char tcpflags, tcp_details& details) {
        if(data_size < 0) {
            return -1;
        }

        ssize_t data_written = 0L;

        auto* cur_data = const_cast<char*>(data);
        auto to_write = details.max_data_size <= 0 ? data_size : std::min(details.max_data_size, data_size);

        do {

            auto cap_est = sizeof(linux_cooked_capture) +
                           std::max(sizeof(iphdr), sizeof(ip6_hdr)) +
                           sizeof(tcphdr) +
                           to_write
                           + 32;

            if(not packet_data)
                packet_data = std::make_shared<buffer>(cap_est);
            else
                packet_data->capacity(cap_est);

            if(packet_data->capacity() == 0 or not packet_data->data()) {
                return -1;
            }

            packet_data->size(0);

            append_LCC_header(*packet_data, details, in);

            auto ip_start = packet_data->size();

            append_IP_header(*packet_data, details, in, to_write);
            append_TCP_header(*packet_data, details, in, cur_data, to_write, tcpflags);
            packet_data->append(cur_data, to_write);

            if(auto ptr = ip_packet_hook.lock(); ptr ) {
                auto ip_end = packet_data->size() - ip_start;
                auto view = packet_data->view(ip_start, ip_end);
                if(ptr) ptr->execute(details, view);
            }

            append(out_buffer);

            data_written += to_write;
            cur_data += to_write;
            to_write = std::min(to_write, data_size - data_written);
        }
        while (data_written < data_size);

        return out_buffer.size();
    }

    size_t pcapng_epb::save_TCP(int fd, const char* data, ssize_t size, int in, unsigned char tcpflags, tcp_details& details) {
        buffer out(
                sizeof(pcapng_epb) +   // this is inaccurate, since there are non-trivial types, but is safe and sufficient
                sizeof(linux_cooked_capture) +
                std::max(sizeof(iphdr), sizeof(ip6_hdr)) +
                sizeof(tcphdr) +
                size
                + 32); // add some extra bytes
        out.size(0);
        append_TCP(out, data, size, in, tcpflags, details);
        save_payload(fd, out);

        return out.size();
    }


    size_t pcapng_epb::append_UDP(buffer& out_buffer, const char* data, ssize_t size, int in, connection_details& details) {
        if(size < 0) {
            return -1;
        }

        auto cap_est = sizeof(linux_cooked_capture) +
                       std::max(sizeof(iphdr), sizeof(ip6_hdr)) +
                       sizeof(udphdr) +
                       size
                       + 32;


        if(not packet_data)
            packet_data = std::make_shared<buffer>(cap_est);
        else
            packet_data->capacity(cap_est);

        if(packet_data->capacity() == 0 or not packet_data->data()) {
            return -1;
        }

        packet_data->size(0);

        append_LCC_header(*packet_data, details, in);
        auto ip_start = packet_data->size();

        append_IP_header(*packet_data, details, in, size);
        append_UDP_header(*packet_data, details, in, data, size);
        packet_data->append(data, size);

        if(auto ptr = ip_packet_hook.lock(); ptr) {
            auto ip_end = packet_data->size() - ip_start;
            auto view = packet_data->view(ip_start, ip_end);
            ptr->execute(details, view);
        }


        append(out_buffer);
        return out_buffer.size();
    }

    size_t pcapng_epb::save_UDP(int fd, const char* data, ssize_t size, int in, connection_details& details) {
        buffer out(
                sizeof(pcapng_epb) +   // this is inaccurate, since there are non-trivial types, but is safe and sufficient
                sizeof(linux_cooked_capture) +
                std::max(sizeof(iphdr), sizeof(ip6_hdr)) +
                sizeof(udphdr) +
                size
                + 32); // add some extra bytes
        out.size(0);
        append_UDP(out, data, size, in, details);
        save_payload(fd, out);

        return out.size();
    }

    size_t pcapng_options::entry::size() const {
        if(not data) return 0;
        if(data->size() == 0) return 0;

        auto padding_sz = padding_sz32(data->size());

        return sizeof(code) + sizeof(len) + data->size() + padding_sz + sizeof(footer);
    }

    size_t pcapng_options::entry::append (buffer &out) {
        if(size() == 0) return 0;

        auto orig_sz = out.size();

        out.append(code);

        len = data->size();
        out.append(len);
        out.append(*data);
        padding::append(out, padding_sz32(data->size()));

        return out.size() - orig_sz;
    }

    size_t pcapng_options::size () const {
        size_t sz = 0;
        std::for_each(entries.begin(), entries.end(), [&sz](auto e) { sz += e.size(); });

        return sz;
    }

    size_t pcapng_options::append (buffer &out) {

        size_t wrt = 0;

        std::for_each(entries.begin(), entries.end(), [&wrt, &out](auto e) { if(e.size() > 0) wrt += e.append(out); });

        if(wrt > 0) {
            out.append(footer);
        }

        return wrt;
    }
}