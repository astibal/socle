#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/in6.h>

#include <cstddef>
#include <cstring>

namespace socle_detail {

inline bool copy_socket_address(sockaddr_storage& destination,
                                const void* source,
                                socklen_t source_length) {
    if(source == nullptr || source_length < sizeof(sa_family_t)) return false;

    sa_family_t family = AF_UNSPEC;
    std::memcpy(&family, source, sizeof(family));

    std::size_t required = 0;
    switch(family) {
        case AF_INET: required = sizeof(sockaddr_in); break;
        case AF_INET6: required = sizeof(sockaddr_in6); break;
        default: return false;
    }
    if(source_length < required) return false;

    destination = {};
    std::memcpy(&destination, source, required);
    return true;
}

inline bool copy_original_destination(sockaddr_storage& destination,
                                      const cmsghdr* control) {
    if(control == nullptr) return false;

    std::size_t required = 0;
    if(control->cmsg_level == SOL_IP &&
       control->cmsg_type == IP_RECVORIGDSTADDR) {
        required = sizeof(sockaddr_in);
    } else if(control->cmsg_level == SOL_IPV6 &&
              control->cmsg_type == IPV6_RECVORIGDSTADDR) {
        required = sizeof(sockaddr_in6);
    } else {
        return false;
    }

    if(control->cmsg_len < CMSG_LEN(required)) return false;
    return copy_socket_address(destination, CMSG_DATA(control), required);
}

} // namespace socle_detail
