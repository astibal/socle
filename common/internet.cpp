#include <internet.hpp>
#include <log/logger.hpp>
#include <epoll.hpp>

namespace inet {

    std::vector<std::string> dns_lookup (const std::string &host_name, int ipv)
    {
        std::vector<std::string> output;

        auto& log = Factory::log();

        addrinfo hints{};
        addrinfo* res = nullptr;

        int status, ai_family;
        char ip_address[INET6_ADDRSTRLEN];

        ai_family = ipv == 6 ? AF_INET6 : AF_INET; //v4 vs v6?
        ai_family = ipv == 0 ? AF_UNSPEC : ai_family; // AF_UNSPEC (any), or chosen
        memset(&hints, 0, sizeof hints);
        hints.ai_family = ai_family;
        hints.ai_socktype = SOCK_STREAM;

        if ((status = getaddrinfo(host_name.c_str(), nullptr, &hints, &res)) != 0) {
            _err("inet::dns_lookup: getaddrinfo: %s", gai_strerror(status));
            return output;
        }

        _deb("inet::dns_lookup: %s ipv: %d", host_name.c_str(), ipv);

        for (auto* p = res; p != nullptr; p = p->ai_next) {
            void *addr;
            if (p->ai_family == AF_INET) { // IPv4
                auto* ipv4 = reinterpret_cast<sockaddr_in*>(p->ai_addr);
                addr = &(ipv4->sin_addr);
            } else { // IPv6
                auto* ipv6 = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
                addr = &(ipv6->sin6_addr);
            }

            // convert the IP to a std::string
            inet_ntop(p->ai_family, addr, ip_address, sizeof ip_address);
            _deb("inet::dns_lookup: ->%s", ip_address);

            output.emplace_back(ip_address);
        }

        freeaddrinfo(res); // free the linked list

        return output;
    }

    bool is_ipv6_address (const std::string &str) {
        sockaddr_in6 sa{};
        return inet_pton(AF_INET6, str.c_str(), &(sa.sin6_addr)) != 0;
    }

    bool is_ipv4_address (const std::string &str) {
        sockaddr_in sa{};
        return inet_pton(AF_INET, str.c_str(), &(sa.sin_addr)) != 0;
    }

    int socket_connect (std::string const& ip_address, int port) {

        auto& log = Factory::log();

        _dia("inet::socket_connect: connecting to %s:%d", ip_address.c_str(), port);

        sockaddr_storage final_sa{};
        int family = AF_UNSPEC;

        if(is_ipv4_address(ip_address)) {
            auto* sa = to_sockaddr_in(&final_sa);
            inet_pton(AF_INET, ip_address.c_str(), &(sa->sin_addr));
            sa->sin_family = AF_INET;
            family = AF_INET;
            sa->sin_port = htons(port);
        }
        else if(is_ipv6_address(ip_address)) {
            auto* sa = to_sockaddr_in6(&final_sa);
            inet_pton(AF_INET6, ip_address.c_str(), &(sa->sin6_addr));
            sa->sin6_family = AF_INET6;
            family = AF_INET6;
            sa->sin6_port = htons(port);
        }
        else  {
            return -1;
        }

        int sd = ::socket(family, SOCK_STREAM, 0);
        if (sd >= 0) {
            auto connect_err = ::connect(sd, (struct sockaddr *) &final_sa, sizeof(final_sa));

            if (connect_err == 0) {
                // success - connected
                _dia("inet::socket_connect: socket[%d] OK", sd );
                return sd;
            } else {
                _err("inet::socket_connect: socket[%d] failed to connect: %s", sd, string_error().c_str());
                ::close(sd); // coverity: 1407966

                return -2;
            }
        } else {
            _err("inet::socket_connect: invalid socket %d", sd);
            return -1;
        }
    }

    int download (const std::string &url, buffer &buf, int timeout, int ipv) {

        auto& log = Factory::log();
        _dia("inet::download: getting file %s", url.c_str());

        int ret = 0;

        unsigned short port;
        std::string protocol, domain, path, query, url_port;
        std::vector<std::string> ip_addresses;

        int offset = 0;
        size_t pos1, pos2, pos3, pos4;
        offset = url.compare(0, 8, "https://") == 0 ? 8 : offset;
        offset = offset == 0 && url.compare(0, 7, "http://") == 0 ? 7 : offset;

        pos1 = url.find_first_of('/', offset + 1);

        path = pos1 == std::string::npos ? "" : url.substr(pos1);
        domain = std::string(url.begin() + offset, pos1 != std::string::npos ? url.begin() + pos1 : url.end());

        path = (pos2 = path.find('#')) != std::string::npos ? path.substr(0, pos2) : path;
        url_port = (pos3 = domain.find(':')) != std::string::npos ? domain.substr(pos3 + 1) : "80";
        domain = domain.substr(0, pos3 != std::string::npos ? pos3 : domain.length());

        protocol = offset > 0 ? url.substr(0, offset - 3) : "";
        query = (pos4 = path.find('?')) != std::string::npos ? path.substr(pos4 + 1) : "";
        path = pos4 != std::string::npos ? path.substr(0, pos4) : path;

        if(path.empty()) {
            path = "/";
        }

        if (query.length() > 0) {
            path.reserve(path.length() + 1 + query.length());
            path.append("?").append(query);
        }
        if(protocol.length() > 0) {
            if(protocol == "http") {
                url_port = "80";
            }
            else if(protocol == "https") {
                url_port = "443";
            }
        }
        _deb("inet:download: using %s on port %s", protocol.c_str(), url_port.c_str());


        if (domain.length()) {
            if (is_ipv4_address(domain)) {
                ip_addresses.push_back(domain);

            }
            else if(is_ipv6_address(domain)) {
                ip_addresses.push_back(domain);
            }
            else
            {
                ip_addresses = dns_lookup(domain, ipv);
            }
        }
        _deb("inet:download: domain %s", domain.c_str());
        for(auto const& s: ip_addresses) {
            _deb("inet::download: IP: %s", s.c_str());
        }

        if (not ip_addresses.empty()) {
            port = std::stoi(url_port);

            std::string request = "GET " + path + " HTTP/1.0\r\n";
            request += "Host: " + domain + "\r\n\r\n";

            for (int i = 0, r = 0, ix = ip_addresses.size(); i < ix && r == 0; i++) {
                _deb("inet::download: GETting %s at IP:%s PORT: %d, timeout %d", request.c_str(), ip_addresses[i].c_str(), port, timeout);
                r = http_get(request, ip_addresses[i], port, buf, timeout);
                _dia("inet::download: finished");
                ret = r;
                if (ret > 0) {
                    _dia("inet::download: finished, %dB transferred", buf.size());

                    _dum("inet::download: dump:\n%s", hex_dump(buf, 4).c_str());

                    break;
                } else {
                    _err("inet::download: download failed");
                }
            }
        }
        else {
            _err("internet::download: no address to connect to");
        }

        _deb("internet::download: returning %d", ret);

        return ret;
    }

    std::string header_value (const std::string &full_header, const std::string &header_name) {
        size_t pos = full_header.find(header_name);//case sensitive but probably shouldn't be
        std::string r;
        if (pos != std::string::npos) {
            size_t begin = full_header.find_first_not_of(": ", pos + header_name.length());
            size_t until = full_header.find_first_of("\r\n\t ", begin + 1);
            if (begin != std::string::npos && until != std::string::npos) {
                r = full_header.substr(begin, until - begin);
            }
        }
        return r;
    }

    int http_get (const std::string &request, const std::string &ip_address, int port, buffer &buf, int timeout) {


        auto& log = Factory::log();

        auto send_request = [&request](auto sd) -> int{
            unsigned attempts = 10;
            buffer send_buf(request.length());
            send_buf.size(0);
            std::memcpy(send_buf.data(), request.c_str(), request.length());

            std::size_t sent = 0;
            do {
                auto str_send = request.substr(sent);
                auto ret = ::send(sd, str_send.c_str(), str_send.length(), 0);
                if (ret > 0) {
                    sent += ret;
                } else {
                    return -1;
                }
            } while (sent < request.length() and attempts > 0);

            return request.length();
        };


        auto receive_response = [&log, &request](auto sd, auto timeout, auto& buf) -> int{

            epoll e;
            e.init();
            e.add(sd, EPOLLIN);


            std::string header;
            char constexpr delim[] = "\r\n\r\n";
            char recv_buffer[16384];

            int bytes_received = -1;
            int bytes_sofar = 0;
            int bytes_expected = -1;
            int bytes_total = 0;
            int state = 0;

            time_t start_time = time(nullptr);

            while (bytes_sofar != bytes_expected) {

                int nfds = e.wait(1000);

                if (nfds > 0 and e.in_read_set(sd)) {
                    /* Don't rely on the value of tv now! */
                    bytes_received = ::recv(sd, recv_buffer, sizeof(recv_buffer), 0);
                    bytes_total += bytes_received;

                    _deb("internet::http_get(%s): received %dB, %dB total", request.c_str(), bytes_received,
                         bytes_total);

                } else {
                    if (nfds <= 0) {
                        _err("internet::http_get(%s): %s", request.c_str(),
                             nfds < 0 ?
                             string_format("error %d: %s", errno, string_error().c_str()).c_str() : "timeout");
                    }

                    if (time(nullptr) > start_time + timeout) {
                        bytes_sofar = -1;
                        break;
                    }

                    continue;
                }

                if (time(nullptr) > start_time + timeout) {
                    bytes_sofar = -1;
                    break;
                }


                if (bytes_received <= 0) {
                    break;
                }

                int body_index = 0;
                if (state + 1 < (signed int) sizeof(delim))//read header
                {
                    int i = 0;
                    for (; i < bytes_received && state + 1 < (signed int) sizeof(delim); i++) {
                        header += recv_buffer[i];
                        state = recv_buffer[i] == delim[state] ? state + 1 : 0;
                    }

                    if (state == sizeof(delim) - 1) {
                        bytes_received -= i;
                        body_index = i;
                    }
                }
                if (bytes_expected == -1 && state == sizeof(delim) - 1) //parse header
                {
                    bytes_expected = -2;
                    std::stringstream(header_value(header, "Content-Length")) >> bytes_expected;
                }
                if (state == sizeof(delim) - 1)//read body
                {
                    bytes_sofar += bytes_received;
                    buf.append(recv_buffer + body_index, bytes_received);
                }
            }

            return bytes_sofar;

        };


        int response_size = 0;
        int sd = socket_connect(ip_address, port);
        if (sd >= 0) {

            if(send_request(sd) < static_cast<int>(request.length())) {
                _err("internet::http_get: failed to send request: %s", request.c_str());
                ::close(sd);
                return -1;
            }

            response_size = receive_response(sd, timeout, buf);

            ::close(sd);
        } else {
            _err("inet::http_get: socket_connect failed: %d", sd);
        }
        return response_size;
    }

}