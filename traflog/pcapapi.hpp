//
// Created by astib on 11.07.21.
//

#ifndef PCAPAPI_HPP
#define PCAPAPI_HPP

#include <cstdint>
#include <cstdio>
#include <sys/time.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sys/file.h>

// #define USE_MEMPOOL

#ifdef USE_MEMPOOL
#include <mempool/mempool.hpp>
#else
#include <malloc.h>
#endif

#include <log/logan.hpp>

namespace socle::pcap {

    struct connection_details {
        sockaddr_storage source;
        sockaddr_storage destination;
        uint16_t ip_id_in;
        uint16_t ip_id_out;
    };

    struct tcp_details : public connection_details {
        uint32_t seq_in;
        uint32_t seq_out;
        uint32_t tcp_lastack_in;
        uint32_t tcp_lastack_out;
    };


    [[maybe_unused]] static logan_lite& get_log() {
        static logan_lite l_("pcapapi");
        return l_;
    }


    constexpr const uint8_t NO_TCPFLAGS = 0x0;
    constexpr const uint8_t TCPFLAG_SYN = 0x1;
    constexpr const uint8_t TCPFLAG_FIN = 0x2;
    constexpr const uint8_t TCPFLAG_ACK = 0x4;

    struct pcap_file_header {
        	uint32_t magic;
        	uint16_t version_major;
        	uint16_t version_minor;
        	int32_t thiszone; /* gmt to local correction */
        	uint32_t sigfigs;    /* accuracy of timestamps */
        	uint32_t snaplen;    /* max length saved portion of each pkt */
        	uint32_t linktype;   /* data link type (LINKTYPE_*) */
        };
    
    struct pcap_frame {
        	int32_t   tv_sec;
        	int32_t   tv_usec;
        	uint32_t caplen;     /* length of portion present */
        	uint32_t len;        /* length this packet (off wire) */
        };
    
    struct linux_cooked_capture {
        	uint16_t type;
            uint16_t arphrd;
            uint16_t ll_addr_size;
        	uint8_t ll_hdr_data[8];
        	uint16_t proto_type;
        };    
    
    int write_pcap_header(int fd);

    uint16_t iphdr_cksum(void *data, size_t len);

    uint16_t tcphdr_cksum(struct iphdr *ip, struct tcphdr *tcp, const char *payload, size_t payload_len);

    int write_pcap_frame(int fd, const char* data, ssize_t size, int in, unsigned char tcpflags, tcp_details& details);

}
#endif //PCAPAPI_HPP
