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


    uint16_t iphdr_cksum(void *data, size_t len)
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


        char* buff = static_cast<char*>(::malloc(buff_len));
        if(not buff) return 0;

        memcpy(buff,                                  hdr,     hdr_sz);
        memcpy(buff + hdr_sz,                         next,    next_sz);
        memcpy(buff + hdr_sz + next_sz,               payload, payload_len);
        if(padd > 0)
            buff[buff_len-1] = 0;

        uint16_t result = iphdr_cksum(buff, buff_len);

        ::free(buff);

        return result;
    }

    void append_PCAP_header(buffer& out_buffer, connection_details const& details, size_t payload_size) {

        [[maybe_unused]] auto& log = get_log();

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
        [[maybe_unused]] auto& log = get_log();

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

    void append_IPv4_header(buffer& out_buffer, connection_details& details, int in, size_t payload_size) {
        [[maybe_unused]] auto& log = get_log();

        auto const* target_sockaddr = reinterpret_cast<sockaddr_in const*>(&details.destination);
        auto const* client_sockaddr = reinterpret_cast<sockaddr_in const*>(&details.source);



        struct iphdr ip_header{};
        auto& ip_id_in = details.ip_id_in;
        auto& ip_id_out = details.ip_id_out;

        ip_header.version = IPVERSION;
        ip_header.ihl = sizeof(struct iphdr) / sizeof(uint32_t);
        ip_header.tos = IPTOS_TOS(0);

        if(details.next_proto == connection_details::TCP or details.next_proto == 0) {
            ip_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size);
            ip_header.protocol = IPPROTO_TCP;
        }
        else if(details.next_proto == connection_details::UDP) {
            ip_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size);
            ip_header.protocol = IPPROTO_UDP;
        }
        ip_header.id = in ? ip_id_in++ : ip_id_out++;

        ip_header.frag_off = htons(0x4000); /* don't fragment */
        ip_header.ttl = 128;

        if (in) {
            ip_header.saddr = target_sockaddr->sin_addr.s_addr;
            ip_header.daddr = client_sockaddr->sin_addr.s_addr;
        } else {
            ip_header.saddr = client_sockaddr->sin_addr.s_addr;
            ip_header.daddr = target_sockaddr->sin_addr.s_addr;
        }
        ip_header.check = htons(iphdr_cksum(&ip_header, sizeof(struct iphdr)));

        out_buffer.append(&ip_header, sizeof(ip_header));
    };

    void append_IPv6_header(buffer& out_buffer, connection_details& details, int in, size_t payload_size) {
        [[maybe_unused]] auto& log = get_log();

        struct ip6_hdr ip_header{};

        auto* target_sockaddr = reinterpret_cast<sockaddr_in6 const*>(&details.destination);
        auto* client_sockaddr = reinterpret_cast<sockaddr_in6 const*>(&details.source);

        if (in) {
            ip_header.ip6_src = target_sockaddr->sin6_addr;
            ip_header.ip6_dst = client_sockaddr->sin6_addr;
        } else {
            ip_header.ip6_src = client_sockaddr->sin6_addr;
            ip_header.ip6_dst = target_sockaddr->sin6_addr;
        }
        ip_header.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
        ip_header.ip6_hops = 128;

        if(details.next_proto == connection_details::TCP or details.next_proto == 0) {
            ip_header.ip6_plen = htons(sizeof(tcphdr) + payload_size);
            ip_header.ip6_nxt = connection_details::TCP;
        }
        else if(details.next_proto == connection_details::UDP) {
            ip_header.ip6_plen = htons(sizeof(udphdr) + payload_size);
            ip_header.ip6_nxt = connection_details::UDP;

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

        [[maybe_unused]] auto& log = get_log();

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

        [[maybe_unused]] auto& log = get_log();

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
        auto& log = get_log();

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


    size_t pcapng_epb::append_TCP(buffer& out_buffer, const char* data, ssize_t size, int in, unsigned char tcpflags, tcp_details& details) {
        if(size < 0) {
            return -1;
        }


        auto cap_est = sizeof(linux_cooked_capture) +
                       std::max(sizeof(iphdr), sizeof(ip6_hdr)) +
                       sizeof(tcphdr) +
                       size
                       + 32;
        auto temp_buffer = std::make_shared<buffer>(cap_est);
        temp_buffer->size(0);

        append_LCC_header(*temp_buffer, details, in);
        append_IP_header(*temp_buffer, details, in, size);
        append_TCP_header(*temp_buffer, details, in, data, size, tcpflags);
        temp_buffer->append(data, size);

        packet_data = temp_buffer;

        append(out_buffer);
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
        auto temp_buffer = std::make_shared<buffer>(cap_est);
        temp_buffer->size(0);

        append_LCC_header(*temp_buffer, details, in);
        append_IP_header(*temp_buffer, details, in, size);
        append_UDP_header(*temp_buffer, details, in, data, size);
        temp_buffer->append(data, size);

        packet_data = temp_buffer;

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