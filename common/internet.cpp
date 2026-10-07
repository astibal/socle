#include <internet.hpp>
#include <privileged_socket.hpp>
#include <log/logger.hpp>
#include <epoll.hpp>

#include <cctype>
#include <charconv>
#include <chrono>
#include <climits>
#include <fcntl.h>
#include <poll.h>
#include <string_view>

namespace inet {

    namespace {
        class operation_deadline {
        public:
            explicit operation_deadline(int timeout_seconds):
                end_(std::chrono::steady_clock::now() +
                     std::chrono::seconds(std::max(timeout_seconds, 0))) {}

            int remaining_ms() const {
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                    end_ - std::chrono::steady_clock::now()).count();
                if(remaining <= 0)
                    return 0;
                return static_cast<int>(std::min<long long>(remaining, INT_MAX));
            }

        private:
            std::chrono::steady_clock::time_point end_;
        };

        int wait_for_socket(int sd, short events, operation_deadline& deadline) {
            pollfd descriptor{sd, events, 0};
            while(true) {
                const int remaining = deadline.remaining_ms();
                if(remaining <= 0)
                    return 0;
                const int result = ::poll(&descriptor, 1, remaining);
                if(result < 0 && errno == EINTR)
                    continue;
                return result;
            }
        }

        int socket_connect_until(const std::string& ip_address,
                                 unsigned short port,
                                 operation_deadline& deadline) {
            auto const& log = Factory::log();
            sockaddr_storage final_sa{};
            int family = AF_UNSPEC;

            if(is_ipv4_address(ip_address)) {
                auto* sa = to_sockaddr_in(&final_sa);
                inet_pton(AF_INET, ip_address.c_str(), &(sa->sin_addr));
                sa->sin_family = AF_INET;
                sa->sin_port = htons(port);
                family = AF_INET;
            }
            else if(is_ipv6_address(ip_address)) {
                auto* sa = to_sockaddr_in6(&final_sa);
                inet_pton(AF_INET6, ip_address.c_str(), &(sa->sin6_addr));
                sa->sin6_family = AF_INET6;
                sa->sin6_port = htons(port);
                family = AF_INET6;
            }
            else {
                return -1;
            }

            const int sd = socle::socket(family, SOCK_STREAM, 0);
            if(sd < 0)
                return -1;

            const int flags = ::fcntl(sd, F_GETFL, 0);
            if(flags < 0 || ::fcntl(sd, F_SETFL, flags | O_NONBLOCK) < 0) {
                ::close(sd);
                return -1;
            }

            const socklen_t address_size = family == AF_INET
                ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
            if(::connect(sd, reinterpret_cast<sockaddr*>(&final_sa), address_size) == 0)
                return sd;
            if(errno != EINPROGRESS) {
                ::close(sd);
                return -2;
            }

            if(wait_for_socket(sd, POLLOUT, deadline) <= 0) {
                _err("inet::socket_connect: connection deadline expired for %s:%d",
                     ip_address.c_str(), port);
                ::close(sd);
                return -2;
            }

            int socket_error = 0;
            socklen_t error_size = sizeof(socket_error);
            if(::getsockopt(sd, SOL_SOCKET, SO_ERROR,
                            &socket_error, &error_size) != 0 || socket_error != 0) {
                if(socket_error != 0)
                    errno = socket_error;
                ::close(sd);
                return -2;
            }
            return sd;
        }

        int http_get_until(const std::string& request,
                           const std::string& ip_address, int port,
                           buffer& buf, operation_deadline& deadline,
                           transfer_limits limits);
    }

    std::vector<std::string> dns_lookup (const std::string &host_name, int ipv)
    {
        std::vector<std::string> output;

        auto const& log = Factory::log();

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

    int socket_connect (std::string const& ip_address, unsigned short port) {
        sockaddr_storage final_sa{};
        int family = AF_UNSPEC;
        if(is_ipv4_address(ip_address)) {
            auto* sa = to_sockaddr_in(&final_sa);
            inet_pton(AF_INET, ip_address.c_str(), &(sa->sin_addr));
            sa->sin_family = AF_INET;
            sa->sin_port = htons(port);
            family = AF_INET;
        }
        else if(is_ipv6_address(ip_address)) {
            auto* sa = to_sockaddr_in6(&final_sa);
            inet_pton(AF_INET6, ip_address.c_str(), &(sa->sin6_addr));
            sa->sin6_family = AF_INET6;
            sa->sin6_port = htons(port);
            family = AF_INET6;
        }
        else {
            return -1;
        }

        const int sd = socle::socket(family, SOCK_STREAM, 0);
        if(sd < 0)
            return -1;
        const socklen_t address_size = family == AF_INET
            ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
        if(::connect(sd, reinterpret_cast<sockaddr*>(&final_sa), address_size) == 0)
            return sd;
        ::close(sd);
        return -2;
    }

    int download (const std::string &url, buffer &buf, int timeout, int ipv) {
        return download(url, buf, timeout, transfer_limits{}, ipv);
    }

    int download (const std::string &url, buffer &buf, int timeout,
                  transfer_limits limits, int ipv) {

        auto const& log = Factory::log();
        _dia("inet::download: getting file %s", url.c_str());

        int ret = 0;
        operation_deadline deadline(timeout);

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
        bool explicit_port = false;
        url_port = "80";
        if (!domain.empty() && domain.front() == '[') {
            const auto bracket = domain.find(']');
            if (bracket == std::string::npos)
                return 0;
            if (bracket + 1 < domain.size()) {
                if (domain[bracket + 1] != ':' || bracket + 2 >= domain.size())
                    return 0;
                url_port = domain.substr(bracket + 2);
                explicit_port = true;
            }
            domain = domain.substr(1, bracket - 1);
        } else {
            pos3 = domain.find(':');
            // A single colon separates host and port. Multiple colons are an
            // unbracketed IPv6 literal and therefore carry no explicit port.
            if (pos3 != std::string::npos && domain.find(':', pos3 + 1) == std::string::npos) {
                url_port = domain.substr(pos3 + 1);
                domain.resize(pos3);
                explicit_port = true;
            }
        }

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
        if(protocol.length() > 0 && !explicit_port) {
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
            try {
                std::size_t parsed_chars = 0;
                const auto parsed_port = std::stoul(url_port, &parsed_chars);
                if (parsed_chars != url_port.size() || parsed_port == 0 || parsed_port > 65535)
                    return 0;
                port = static_cast<unsigned short>(parsed_port);
            } catch (const std::exception&) {
                return 0;
            }

            std::string host_header = is_ipv6_address(domain)
                ? "[" + domain + "]" : domain;
            const std::string default_port = protocol == "https" ? "443" : "80";
            if(explicit_port && url_port != default_port)
                host_header += ":" + url_port;

            std::string request = "GET " + path + " HTTP/1.0\r\n";
            request += "Host: " + host_header + "\r\n\r\n";

            for (int i = 0, r = 0, ix = ip_addresses.size(); i < ix && r == 0; i++) {
                _deb("inet::download: GETting %s at IP:%s PORT: %d, timeout %d", request.c_str(), ip_addresses[i].c_str(), port, timeout);
                r = http_get_until(
                    request, ip_addresses[i], port, buf, deadline, limits);
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

    namespace {
    std::vector<std::string> header_values(const std::string& full_header,
                                           const std::string& header_name) {
        auto equal_name = [](std::string_view left, std::string_view right) {
            if(left.size() != right.size())
                return false;
            for(std::size_t i = 0; i < left.size(); ++i) {
                const auto l = static_cast<unsigned char>(left[i]);
                const auto r = static_cast<unsigned char>(right[i]);
                if(std::tolower(l) != std::tolower(r))
                    return false;
            }
            return true;
        };

        std::vector<std::string> values;
        std::size_t line_start = 0;
        while(line_start < full_header.size()) {
            const std::size_t line_end = full_header.find("\r\n", line_start);
            const std::size_t end = line_end == std::string::npos
                ? full_header.size() : line_end;
            const std::size_t colon = full_header.find(':', line_start);
            if(colon < end && equal_name(
                    std::string_view(full_header).substr(
                        line_start, colon - line_start), header_name)) {
                std::size_t value_start = colon + 1;
                while(value_start < end &&
                      (full_header[value_start] == ' ' ||
                       full_header[value_start] == '\t'))
                    ++value_start;
                std::size_t value_end = end;
                while(value_end > value_start &&
                      (full_header[value_end - 1] == ' ' ||
                       full_header[value_end - 1] == '\t'))
                    --value_end;
                values.emplace_back(full_header.substr(
                    value_start, value_end - value_start));
            }
            if(line_end == std::string::npos)
                break;
            line_start = line_end + 2;
        }
        return values;
    }

    bool successful_http_response(const std::string& header) {
        const auto line_end = header.find("\r\n");
        if(line_end == std::string::npos)
            return false;
        std::istringstream status_line(header.substr(0, line_end));
        std::string version;
        int status = 0;
        status_line >> version >> status;
        return (version == "HTTP/1.0" || version == "HTTP/1.1") &&
               status >= 200 && status < 300;
    }
    }

    std::string header_value (const std::string &full_header, const std::string &header_name) {
        const auto values = header_values(full_header, header_name);
        return values.empty() ? std::string{} : values.front();
    }

    int http_get (const std::string &request, const std::string &ip_address,
                  int port, buffer &buf, int timeout) {
        return http_get(request, ip_address, port, buf, timeout, transfer_limits{});
    }

    int http_get (const std::string &request, const std::string &ip_address,
                  int port, buffer &buf, int timeout, transfer_limits limits) {
        operation_deadline deadline(timeout);
        return http_get_until(request, ip_address, port, buf, deadline, limits);
    }

    namespace {
    int http_get_until(const std::string &request,
                       const std::string &ip_address, int port, buffer &buf,
                       operation_deadline& deadline, transfer_limits limits) {

        auto const& log = Factory::log();

        auto send_request = [&request, &deadline](auto sd) -> int{
            std::size_t sent = 0;
            do {
                auto ret = ::send(sd, request.data() + sent, request.length() - sent, MSG_NOSIGNAL);
                if (ret > 0) {
                    sent += ret;
                }
                else if(ret < 0 && errno == EINTR) {
                    continue;
                }
                else if(ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if(wait_for_socket(sd, POLLOUT, deadline) > 0)
                        continue;
                    return -1;
                }
                else {
                    return -1;
                }
            } while (sent < request.length());

            return request.length();
        };


        auto receive_response = [&log, &request, &deadline, limits](auto sd, auto& buf) -> int{

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

            while (bytes_sofar != bytes_expected) {
                const int remaining = deadline.remaining_ms();
                if(remaining <= 0) {
                    bytes_sofar = -1;
                    break;
                }
                int nfds = e.wait(std::min(remaining, 1000));

                if (nfds > 0 and e.in_read_set(sd)) {
                    /* Don't rely on the value of tv now! */
                    bytes_received = ::recv(sd, recv_buffer, sizeof(recv_buffer), 0);
                    if (bytes_received > 0)
                        bytes_total += bytes_received;

                    _deb("internet::http_get(%s): received %dB, %dB total", request.c_str(), bytes_received,
                         bytes_total);

                } else {
                    if (nfds <= 0) {
                        _err("internet::http_get(%s): %s", request.c_str(),
                             nfds < 0 ?
                             string_format("error %d: %s", errno, string_error().c_str()).c_str() : "timeout");
                    }

                    if (deadline.remaining_ms() <= 0) {
                        bytes_sofar = -1;
                        break;
                    }

                    continue;
                }

                if (deadline.remaining_ms() <= 0) {
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
                        if(header.size() >= limits.max_header_bytes) {
                            _err("internet::http_get(%s): response header exceeds %zuB limit",
                                 request.c_str(), limits.max_header_bytes);
                            return -1;
                        }
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
                    if(!successful_http_response(header)) {
                        _err("internet::http_get(%s): non-successful or malformed HTTP status",
                             request.c_str());
                        return -1;
                    }
                    if(!header_values(header, "Transfer-Encoding").empty()) {
                        _err("internet::http_get(%s): unsupported Transfer-Encoding",
                             request.c_str());
                        return -1;
                    }
                    const auto lengths = header_values(header, "Content-Length");
                    if(lengths.size() > 1) {
                        _err("internet::http_get(%s): duplicate Content-Length",
                             request.c_str());
                        return -1;
                    }
                    if(!lengths.empty()) {
                        unsigned long long parsed_length = 0;
                        const auto parsed = std::from_chars(
                            lengths.front().data(),
                            lengths.front().data() + lengths.front().size(),
                            parsed_length);
                        if(parsed.ec != std::errc{} ||
                           parsed.ptr != lengths.front().data() + lengths.front().size() ||
                           parsed_length > static_cast<unsigned long long>(INT_MAX)) {
                            _err("internet::http_get(%s): invalid Content-Length",
                                 request.c_str());
                            return -1;
                        }
                        bytes_expected = static_cast<int>(parsed_length);
                    }
                    if(bytes_expected >= 0 &&
                       static_cast<std::size_t>(bytes_expected) > limits.max_body_bytes) {
                        _err("internet::http_get(%s): Content-Length exceeds %zuB limit",
                             request.c_str(), limits.max_body_bytes);
                        return -1;
                    }
                }
                if (state == sizeof(delim) - 1)//read body
                {
                    if (bytes_expected >= 0)
                        bytes_received = std::min(bytes_received, bytes_expected - bytes_sofar);
                    if(bytes_received > 0 &&
                       static_cast<std::size_t>(bytes_sofar) +
                           static_cast<std::size_t>(bytes_received) > limits.max_body_bytes) {
                        _err("internet::http_get(%s): response body exceeds %zuB limit",
                             request.c_str(), limits.max_body_bytes);
                        return -1;
                    }
                    bytes_sofar += bytes_received;
                    buf.append(recv_buffer + body_index, bytes_received);
                }
            }

            if (bytes_expected >= 0 && bytes_sofar != bytes_expected)
                return -1;
            return bytes_sofar;

        };


        int response_size = 0;
        int sd = socket_connect_until(ip_address, port, deadline);
        if (sd >= 0) {

            if(send_request(sd) < static_cast<int>(request.length())) {
                _err("internet::http_get: failed to send request: %s", request.c_str());
                ::close(sd);
                return -1;
            }

            response_size = receive_response(sd, buf);

            ::close(sd);
        } else {
            _err("inet::http_get: socket_connect failed: %d", sd);
        }
        return response_size;
    }
    }

}
