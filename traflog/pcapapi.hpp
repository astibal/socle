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
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <sys/file.h>

#include <vector>

// mempool
#define USE_MEMPOOL

#ifdef USE_MEMPOOL
#include <mempool/mempool.hpp>
#else
#include <malloc.h>
#endif

#include <buffer.hpp>
#include <log/logan.hpp>

namespace socle::pcap {

    template<typename V, typename P>
    struct chksum_pseudoheader {
        V saddr{};
        V daddr{};
        unsigned char reserved;
        unsigned char proto;
        uint16_t next_len;

        static chksum_pseudoheader construct(V src, V dst, uint8_t proto, size_t payload_size ) {
            chksum_pseudoheader hdr{};

            hdr.saddr = src;
            hdr.daddr = dst;
            hdr.reserved = 0;
            hdr.proto = proto;
            hdr.next_len = htons(payload_size + sizeof(P));

            return hdr;
        }
    };

    using chksum_tcp_v4 = chksum_pseudoheader<in_addr, tcphdr>;
    using chksum_tcp_v6 = chksum_pseudoheader<in6_addr, tcphdr>;

    using chksum_udp_v4 = chksum_pseudoheader<in_addr, udphdr>;
    using chksum_udp_v6 = chksum_pseudoheader<in6_addr, tcphdr>;


    struct connection_details {
        sockaddr_storage source{};
        sockaddr_storage destination{};
        uint16_t ip_id_in;
        uint16_t ip_id_out;
        uint8_t ip_version{4};
        uint16_t next_proto{6};

        enum proto { TCP=6, UDP=17 };


        [[nodiscard]] in_addr source_in() const {
            return ((sockaddr_in *)&source)->sin_addr;
        }
        [[nodiscard]] in6_addr source_in6() const {
            return ((sockaddr_in6 *)&source)->sin6_addr;
        }
        [[nodiscard]] in_addr destination_in() const {
            return ((sockaddr_in *)&destination)->sin_addr;
        }
        [[nodiscard]] in6_addr destination_in6() const {
            return ((sockaddr_in6 *)&destination)->sin6_addr;
        }

        std::pair<unsigned short, unsigned short> extract_ports() {

            unsigned short sport = 0;
            unsigned short dport = 0;

            if (ip_version == 4) {
                auto *target_sockaddr = reinterpret_cast<sockaddr_in const *>(&destination);
                auto *client_sockaddr = reinterpret_cast<sockaddr_in const *>(&source);

                dport = target_sockaddr->sin_port;
                sport = client_sockaddr->sin_port;
            } else if (ip_version == 6) {
                auto *target_sockaddr = reinterpret_cast<sockaddr_in6 const *>(&destination);
                auto *client_sockaddr = reinterpret_cast<sockaddr_in6 const *>(&source);
                dport = target_sockaddr->sin6_port;
                sport = client_sockaddr->sin6_port;
            }

            return { sport, dport };
        }
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
    
    size_t append_PCAP_magic(buffer& out_buffer);

    [[maybe_unused]] uint16_t iphdr_cksum(void *data, size_t len);
    [[maybe_unused]] uint16_t l4hdr_cksum(void* hdr, size_t hdr_sz, void *next, size_t next_sz, const char *payload, size_t payload_len);

    template<typename L4type>
    uint16_t L4_chksum (connection_details const &details, int in, L4type *next_header, const char *payload,
                        size_t payload_size);

    void append_PCAP_header(buffer& out_buffer, connection_details const& details, size_t payload_size);
    void append_LCC_header(buffer& out_buffer, connection_details const& details, int in);

    void append_IP_header(buffer& out_buffer, connection_details& details, int in, size_t payload_size);
        void append_IPv4_header(buffer& out_buffer, connection_details& details, int in, size_t payload_size);
        void append_IPv6_header(buffer& out_buffer, connection_details& details, int in, size_t payload_size);

    void append_TCP_header (buffer &out_buffer, tcp_details &details, int in, const char *payload, size_t payload_size,
                            unsigned char tcpflags);
    void append_UDP_header(buffer& out_buffer, connection_details& details, int in, const char* payload, size_t payload_size);

    size_t append_TCP_frame(buffer& out_buffer, const char* data, ssize_t size, int in, unsigned char tcpflags, tcp_details& details);
    size_t append_UDP_frame(buffer& out_buffer, const char* data, ssize_t size, int in, connection_details& details);

    void save_payload(int fd, const char* data, size_t size);
    void save_payload(int fd, buffer const& out);

    size_t save_PCAP_magic(int fd);
    size_t save_TCP_frame(int fd, const char* data, ssize_t size, int in, unsigned char tcpflags, tcp_details& details);
    size_t save_UDP_frame(int fd, const char* data, ssize_t size, int in, connection_details& details);



template<typename NextHeader>
uint16_t L4_chksum (connection_details const &details, int in, NextHeader *next_header, const char *payload,
                    size_t payload_size) {

    uint16_t to_ret = 0;

    if (details.ip_version == 4 or details.ip_version == 0) {
        in_addr src{};
        in_addr dst{};

        if (in) {
            src = details.destination_in();
            dst = details.source_in();
        } else {
            dst = details.destination_in();
            src = details.source_in();
        }

        auto hdr = chksum_pseudoheader<in_addr, NextHeader>::construct(src, dst, details.next_proto, payload_size);
        to_ret = l4hdr_cksum(&hdr, sizeof(hdr), next_header, sizeof(NextHeader), payload,payload_size);
    } else if (details.ip_version == 6) {
        in6_addr src{};
        in6_addr dst{};

        if (in) {
            src = details.destination_in6();
            dst = details.source_in6();
        } else {
            dst = details.destination_in6();
            src = details.source_in6();
        }

        auto hdr = chksum_pseudoheader<in6_addr, NextHeader>::construct(src, dst, details.next_proto, payload_size);
        to_ret = l4hdr_cksum(&hdr, sizeof(hdr), next_header, sizeof(NextHeader), payload, payload_size);
    }

    return to_ret;
};

}

namespace socle::pcapng {
    using namespace socle::pcap;

    // section header block
    struct pcapng_shb {
        uint32_t  type = 0x0A0D0D0AL;
        uint32_t total_length = 0;
        uint32_t magic = 0x1A2B3C4DL;
        uint16_t version_maj = 1;
        uint16_t version_min = 0;
        uint64_t section_length = 0xFFFFFFFFFFFFFFFFL;

        std::shared_ptr<buffer> options;

        size_t size() const;
        size_t append(buffer& out);
    };

    // section header block
    struct pcapng_ifb {
        uint32_t  type = 0x00000001L;
        uint32_t total_length = 0;
        uint16_t link_type = 113;
        uint16_t _reserved1 = 0;
        uint32_t snaplen = 20000;
        std::shared_ptr<buffer> options;

        size_t size() const;
        size_t append(buffer& out);
    };

    struct pcapng_options;

    struct pcapng_epb {
        uint32_t  type = 0x00000006L;
        uint32_t total_length = 0;
        uint32_t iface_id = 0;
        uint32_t timestamp_high = 0;
        uint32_t timestamp_low = 0;
        uint32_t captured_len = 0;
        uint32_t original_len = 0;
        std::shared_ptr<buffer> packet_data;
        std::shared_ptr<pcapng_options> options;

        static constexpr size_t fixed_sz =
                sizeof(type) +
                sizeof(total_length) +
                sizeof(iface_id) +
                sizeof(timestamp_high) +
                sizeof(timestamp_low) +
                sizeof(captured_len) +
                sizeof(original_len) +
                sizeof(total_length);

        void comment(std::string const& s);

        size_t size() const;
        size_t append(buffer& out);
        size_t append_TCP(buffer& out_buffer, const char* data, ssize_t size, int in, unsigned char tcpflags, tcp_details& details);
        size_t save_TCP(int fd, const char* data, ssize_t size, int in, unsigned char tcpflags, tcp_details& details);

        size_t append_UDP(buffer& out_buffer, const char* data, ssize_t size, int in, connection_details& details);
        size_t save_UDP(int fd, const char* data, ssize_t size, int in, connection_details& details);
    };
    using pcapng_frame = pcapng_epb;

    struct pcapng_options {

        struct entry {
            uint16_t code = 0;
            uint16_t len = 0;
            std::shared_ptr<buffer> data;

            size_t size() const;
            size_t append(buffer& out);
        };
        std::vector<entry> entries;

        enum code_id { Comment=1 };

        size_t append(buffer& out);
        size_t size() const;

        constexpr static uint32_t footer = 0L;
    };


    struct padding {
        static size_t append(buffer& out, size_t n, uint8_t c = 0xCC);
    };

    size_t padding_sz32(size_t s);
    size_t save_NG_magic(int fd);
    size_t save_NG_ifb(int fd, pcapng_ifb& hdr);
}

#endif //PCAPAPI_HPP
