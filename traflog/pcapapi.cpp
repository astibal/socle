#include <traflog/pcapapi.hpp>
#include <unistd.h>

namespace socle::pcap {

    int write_pcap_header(int fd) {

        pcap_file_header header{};

        header.magic = 0xa1b2c3d4;
        header.version_major = 2;
        header.version_minor = 4;
        header.thiszone =0;
        header.sigfigs = 0;
        header.snaplen = 65535;
        header.linktype = 113;

        auto written = ::write(fd, &header, sizeof(header));

        if( written != sizeof(header)) {
            return -1;
        }

        return 0;
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

    uint16_t tcphdr_cksum(struct iphdr *ip, struct tcphdr *tcp, const char *payload, size_t payload_len) {

        uint16_t result;
        struct {
            uint32_t saddr;
            uint32_t daddr;
            unsigned char reserved;
            unsigned char proto;
            uint16_t tcp_len;
        } pseudoheader;

        unsigned int padd = payload_len & 1u;
        uint16_t tcp_len = payload_len + sizeof(struct tcphdr);
        size_t buff_len = sizeof(pseudoheader) + tcp_len + padd;

#ifndef USE_MEMPOOL
        char* buff = static_cast<char*>(malloc(buff_len));
#else
        char* buff = static_cast<char*>(mempool_alloc(buff_len));
#endif
        pseudoheader.saddr = ip->saddr;
        pseudoheader.daddr = ip->daddr;
        pseudoheader.reserved = 0;
        pseudoheader.proto = ip->protocol;
        pseudoheader.tcp_len = htons(tcp_len);


        memcpy(buff,                                           &pseudoheader, sizeof(pseudoheader));
        memcpy(buff+sizeof(pseudoheader),                       tcp,          sizeof(struct tcphdr));
        memcpy(buff+sizeof(pseudoheader)+sizeof(struct tcphdr), payload,      payload_len);
        if(padd)
            buff[buff_len-1] = 0;

        result = iphdr_cksum(buff, buff_len);

#ifndef USE_MEMPOOL
        free(buff);
#else
        mempool_free(buff);
#endif

        return result;
    }

    int write_pcap_frame(int fd, const char* data, ssize_t size, int in, unsigned char tcpflags, tcp_details& details) {
        if(size < 0) {
            return -1;
        }

        struct timeval time{};
        struct pcap_frame pcap_header{};
        struct linux_cooked_capture lcc_header{};
        struct iphdr ip_header{};
        struct tcphdr tcp_header{};

        auto* target_sockaddr = reinterpret_cast<sockaddr_in*>(&details.destination);
        auto* client_sockaddr = reinterpret_cast<sockaddr_in*>(&details.source);

        auto& tcp_seq_in = details.seq_in;
        auto& tcp_seq_out = details.seq_out;
        auto& ip_id_in = details.ip_id_in;
        auto& ip_id_out = details.ip_id_out;
        auto& tcp_lastack_in = details.tcp_lastack_in;
        auto& tcp_lastack_out = details.tcp_lastack_out;

        /* in=1 means REDIR_IN means from target to client */

        auto& log = get_log();

        if(flock(fd, LOCK_EX) < 0) {
            _err("cannot get exclusive lock");

            if(close(fd) < 0) {
                _err("cannot properly close the file");
            }

            return -1;
        }

        /* we have to rather tediously fake a pcap header, linux cooked capture haeder, ip header and tcp header */
        /* pcap header */
        gettimeofday(&time, nullptr);

        pcap_header.tv_sec = time.tv_sec;
        pcap_header.tv_usec = time.tv_usec;
        pcap_header.caplen = sizeof(struct linux_cooked_capture) + sizeof(struct iphdr) + sizeof(struct tcphdr) + size;
        pcap_header.len = sizeof(struct linux_cooked_capture) + sizeof(struct iphdr) + sizeof(struct tcphdr) + size;
        if(write(fd, &pcap_header, sizeof(pcap_header)) != sizeof(pcap_header)) {
            _err("cannot write all data to file");

            if(close(fd) < 0) {
                _err("cannot properly close the file");
            }
        }

        /* linux cooked capture header */
        lcc_header.type = htons(in?0:4); /* 0 sent is to us, 4 is sent by us */
        lcc_header.arphrd = htons(ARPHRD_ETHER);
        lcc_header.ll_addr_size = htons(6);

        std::memset(lcc_header.ll_hdr_data, 0, sizeof(lcc_header.ll_hdr_data));
        std::memset(lcc_header.ll_hdr_data, in ? 2 : 1, 6);


        lcc_header.proto_type = htons(ETHERTYPE_IP);
        if(write(fd, &lcc_header, sizeof(lcc_header)) != sizeof(lcc_header)) {
            _err("cannot write all data to file");

            if(close(fd) < 0) {
                _err("cannot properly close the file");
            }
        }

        /* ip header */
        ip_header.version = IPVERSION;
        ip_header.ihl = sizeof(struct iphdr)/sizeof(uint32_t);
        ip_header.tos = IPTOS_TOS(0);
        ip_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + size);
        ip_header.id = in ? ip_id_in++ : ip_id_out++;

        ip_header.frag_off = htons(0x4000); /* don't fragment */
        ip_header.ttl = 64; /* arbitrary */
        ip_header.protocol = IPPROTO_TCP;
        if(in) {
            ip_header.saddr = target_sockaddr->sin_addr.s_addr;
            ip_header.daddr = client_sockaddr->sin_addr.s_addr;
        } else {
            ip_header.saddr = client_sockaddr->sin_addr.s_addr;
            ip_header.daddr = target_sockaddr->sin_addr.s_addr;
        }
        ip_header.check = 0;
        ip_header.check = htons(iphdr_cksum(&ip_header, sizeof(struct iphdr)));
        if(write(fd, &ip_header, sizeof(ip_header)) != sizeof(ip_header)) {
            _err("cannot write all data to file");

            if(close(fd) < 0) {
                _err("cannot properly close the file");
            }
        }

        std::memset(&tcp_header, 0, sizeof(struct tcphdr));

        if(tcpflags & TCPFLAG_SYN)
            tcp_header.syn = 1;
        if(tcpflags & TCPFLAG_FIN)
            tcp_header.fin = 1;
        if(tcpflags & TCPFLAG_ACK)
            tcp_header.ack = 1;

        if(tcpflags == 0)
            tcp_header.ack = 1;

        if(in) {
            tcp_header.source = target_sockaddr->sin_port;
            tcp_header.dest = client_sockaddr->sin_port;
            /* seq counts data in the direction we're sending */
            tcp_header.seq = htonl(tcp_seq_in);

            tcp_seq_in += (tcp_header.syn or tcp_header.fin) ? 1 : size;

            /* ack-seq is the seq+size of the last packet we saw going the other way */
            if(tcp_seq_out != tcp_lastack_in) {
                tcp_header.ack_seq = 0L;
                tcp_lastack_in = tcp_seq_out;

                if(not (tcpflags & TCPFLAG_SYN)) {
                    tcp_header.ack_seq = htonl(tcp_seq_out);
                    tcp_header.ack = 1;
                }
            }
        } else {
            tcp_header.source = client_sockaddr->sin_port;
            tcp_header.dest = target_sockaddr->sin_port;
            tcp_header.seq = htonl(tcp_seq_out);

            tcp_seq_out += (tcp_header.syn or tcp_header.fin) ? 1 : size;

            if(tcp_seq_in != tcp_lastack_out) {
                tcp_header.ack_seq = 0L;
                tcp_lastack_out = tcp_seq_in;

                if(not (tcpflags & TCPFLAG_SYN)) {
                    tcp_header.ack_seq = htonl(tcp_seq_in);
                    tcp_header.ack = 1;
                }
            }
        }
        tcp_header.doff = 5; /* no options */
        tcp_header.window = htons(32768);
        tcp_header.check = htons(tcphdr_cksum(&ip_header, &tcp_header, data, size));

        if(write(fd, &tcp_header, sizeof(tcp_header)) != sizeof(tcp_header)) {
            _err("cannot write all data to file");

            if(close(fd) < 0) {
                _err("cannot properly close the file");
            }
        }

        if(size && write(fd, data, size) != size) {
            _err("cannot write all data to file");

            if(close(fd) < 0) {
                _err("cannot properly close the file");
            }
        }

        if(flock(fd, LOCK_UN) < 0) {
            _err("cannot unlock the file");
        }

        return 0;
    }


}