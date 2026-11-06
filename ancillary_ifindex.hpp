#pragma once

#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>

namespace socle {
// Parse both families independently of original-destination cmsg ordering.
// A truncated control buffer is not authoritative metadata.
inline unsigned ancillary_ifindex(const msghdr& message) noexcept {
    if(message.msg_flags & MSG_CTRUNC) return 0;
    auto msg = message;
    for(auto* item = CMSG_FIRSTHDR(&msg); item; item = CMSG_NXTHDR(&msg, item)) {
        const auto* end = static_cast<const unsigned char*>(msg.msg_control) + msg.msg_controllen;
        if(item->cmsg_len < CMSG_LEN(0) ||
           item->cmsg_len > static_cast<std::size_t>(end - reinterpret_cast<const unsigned char*>(item))) return 0;
        if(item->cmsg_level == IPPROTO_IP && item->cmsg_type == IP_PKTINFO &&
           item->cmsg_len >= CMSG_LEN(sizeof(in_pktinfo))) {
            in_pktinfo info{};
            std::memcpy(&info, CMSG_DATA(item), sizeof(info));
            return info.ipi_ifindex > 0 ? static_cast<unsigned>(info.ipi_ifindex) : 0;
        }
        if(item->cmsg_level == IPPROTO_IPV6 && item->cmsg_type == IPV6_PKTINFO &&
           item->cmsg_len >= CMSG_LEN(sizeof(in6_pktinfo))) {
            in6_pktinfo info{};
            std::memcpy(&info, CMSG_DATA(item), sizeof(info));
            return info.ipi6_ifindex;
        }
    }
    return 0;
}
}
