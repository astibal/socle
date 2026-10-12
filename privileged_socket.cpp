/*
 * Socle - Socket Library Ecosystem
 * Copyright (c) 2026, Ales Stibal <astib@mag0.net>
 */

#include "privileged_socket.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

constexpr std::array<std::byte, 2> request_magic{std::byte{'S'}, std::byte{'C'}};
constexpr std::uint8_t protocol_version = 1;
constexpr std::size_t request_header_size = 16;
constexpr std::size_t response_header_size = 4;
constexpr std::size_t max_payload_size = 64U * 1024U;
constexpr std::size_t stats_field_count = 13;

std::mutex installed_client_mutex;
std::shared_ptr<socle::privsep::Client> installed_client;
std::mutex helper_process_mutex;
pid_t helper_process_pid = -1;

void put_u32(std::byte* destination, std::uint32_t value) {
    const auto encoded = htonl(value);
    std::memcpy(destination, &encoded, sizeof(encoded));
}

std::uint32_t get_u32(const std::byte* source) {
    std::uint32_t encoded = 0;
    std::memcpy(&encoded, source, sizeof(encoded));
    return ntohl(encoded);
}

void put_u64(std::byte* destination, std::uint64_t value) {
    put_u32(destination, static_cast<std::uint32_t>(value >> 32U));
    put_u32(destination + 4, static_cast<std::uint32_t>(value));
}

std::uint64_t get_u64(const std::byte* source) {
    return (static_cast<std::uint64_t>(get_u32(source)) << 32U) | get_u32(source + 4);
}

std::vector<std::byte> make_request(socle::privsep::Opcode opcode, int argument0 = 0,
                                    int argument1 = 0, const void* payload = nullptr,
                                    std::size_t payload_size = 0) {
    std::vector<std::byte> request(request_header_size + payload_size);
    request[0] = request_magic[0];
    request[1] = request_magic[1];
    request[2] = std::byte{protocol_version};
    request[3] = std::byte{static_cast<std::uint8_t>(opcode)};
    put_u32(request.data() + 4, static_cast<std::uint32_t>(argument0));
    put_u32(request.data() + 8, static_cast<std::uint32_t>(argument1));
    put_u32(request.data() + 12, static_cast<std::uint32_t>(payload_size));
    if(payload_size != 0) std::memcpy(request.data() + request_header_size, payload, payload_size);
    return request;
}

bool valid_request_header(const std::vector<std::byte>& request) {
    if(request.size() < request_header_size) return false;
    if(request[0] != request_magic[0] || request[1] != request_magic[1]) return false;
    if(request[2] != std::byte{protocol_version}) return false;
    const auto payload_size = get_u32(request.data() + 12);
    return payload_size <= max_payload_size && request.size() == request_header_size + payload_size;
}

std::shared_ptr<socle::privsep::Client> current_client() {
    std::lock_guard<std::mutex> guard(installed_client_mutex);
    return installed_client;
}

[[noreturn]] void local_helper_process_entry(int channel_fd) {
    // The helper is owned through its channel.  Give it a separate process
    // group so an orderly group shutdown of the parent does not race closing
    // that channel.  Parent-death signalling covers an unexpected owner exit.
    if(::setpgid(0, 0) != 0) ::_exit(EXIT_FAILURE);
    const pid_t parent = ::getppid();
    if(::prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || ::getppid() != parent) {
        ::_exit(EXIT_FAILURE);
    }

    socle::privsep::Server server(channel_fd);
    ::close(channel_fd);
    const int result = server.run();
    ::_exit(result == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

} // namespace

namespace socle::privsep {

SeqPacketChannel::SeqPacketChannel(int fd) {
    if(fd < 0) {
        errno = EBADF;
        return;
    }
    fd_ = ::fcntl(fd, F_DUPFD_CLOEXEC, 0);
}

SeqPacketChannel::~SeqPacketChannel() { close(); }

SeqPacketChannel::SeqPacketChannel(SeqPacketChannel&& other) noexcept: fd_(other.fd_) {
    other.fd_ = -1;
}

SeqPacketChannel& SeqPacketChannel::operator=(SeqPacketChannel&& other) noexcept {
    if(this != &other) {
        close();
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

void SeqPacketChannel::close() noexcept {
    if(fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

int SeqPacketChannel::send(const std::byte* data, std::size_t size, int passed_fd) const {
    if(fd_ < 0) {
        errno = EBADF;
        return -1;
    }
    if(data == nullptr || size == 0 || size > request_header_size + max_payload_size) {
        errno = EINVAL;
        return -1;
    }

    iovec iov{const_cast<std::byte*>(data), size};
    std::array<std::byte, CMSG_SPACE(sizeof(int))> control{};
    msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    if(passed_fd >= 0) {
        message.msg_control = control.data();
        message.msg_controllen = control.size();
        auto* cmsg = CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        std::memcpy(CMSG_DATA(cmsg), &passed_fd, sizeof(passed_fd));
    }

    ssize_t sent = -1;
    do {
        sent = ::sendmsg(fd_, &message, MSG_NOSIGNAL);
    } while(sent < 0 && errno == EINTR);
    if(sent < 0) return -1;
    if(static_cast<std::size_t>(sent) != size) {
        errno = EIO;
        return -1;
    }
    return 0;
}

int SeqPacketChannel::receive(Message& output, int flags) const {
    output.data.clear();
    output.fd = -1;
    if(fd_ < 0) {
        errno = EBADF;
        return -1;
    }

    std::vector<std::byte> buffer(request_header_size + max_payload_size);
    std::array<std::byte, CMSG_SPACE(sizeof(int))> control{};
    iovec iov{buffer.data(), buffer.size()};
    msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();

    ssize_t received = -1;
    do {
        received = ::recvmsg(fd_, &message, MSG_CMSG_CLOEXEC | flags);
    } while(received < 0 && errno == EINTR);
    if(received == 0) {
        errno = ECONNRESET;
        return 0;
    }
    if(received < 0) return -1;

    int received_fd = -1;
    bool invalid_control = false;
    for(auto* cmsg = CMSG_FIRSTHDR(&message); cmsg != nullptr; cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if(cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS
           && cmsg->cmsg_len == CMSG_LEN(sizeof(int)) && received_fd < 0 && !invalid_control) {
            std::memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(received_fd));
        } else {
            invalid_control = true;
            if(cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS
               && cmsg->cmsg_len >= CMSG_LEN(0)) {
                const auto descriptor_count =
                    (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                auto* descriptors = reinterpret_cast<int*>(CMSG_DATA(cmsg));
                for(std::size_t i = 0; i < descriptor_count; ++i) ::close(descriptors[i]);
            }
        }
    }
    if((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
        if(received_fd >= 0) ::close(received_fd);
        errno = EMSGSIZE;
        return -1;
    }
    if(invalid_control) {
        if(received_fd >= 0) ::close(received_fd);
        errno = EPROTO;
        return -1;
    }

    buffer.resize(static_cast<std::size_t>(received));
    output.data = std::move(buffer);
    output.fd = received_fd;
    return 1;
}

Client::Client(int fd, std::chrono::milliseconds timeout): channel_(fd), timeout_(timeout) {
    if(timeout_.count() < 0) timeout_ = std::chrono::milliseconds{0};
}

int Client::wait_readable() const {
    const auto deadline = std::chrono::steady_clock::now() + timeout_;
    for(;;) {
        const auto now = std::chrono::steady_clock::now();
        if(now >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const auto timeout = static_cast<int>(std::min<std::int64_t>(remaining.count(), INT_MAX));
        pollfd descriptor{channel_.fd(), POLLIN, 0};
        const int result = ::poll(&descriptor, 1, timeout);
        if(result < 0 && errno == EINTR) continue;
        if(result < 0) return -1;
        if(result == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if((descriptor.revents & POLLIN) != 0) return 0;
        errno = ECONNRESET;
        return -1;
    }
}

void Client::break_channel() noexcept {
    broken_ = true;
    channel_.close();
}

int Client::transact(const std::vector<std::byte>& request, int passed_fd, Message& response) {
    std::lock_guard<std::mutex> guard(mutex_);
    if(broken_ || channel_.fd() < 0) {
        errno = ECONNRESET;
        return -1;
    }
    if(channel_.send(request, passed_fd) != 0 || wait_readable() != 0) {
        break_channel();
        return -1;
    }
    if(channel_.receive(response) != 1) {
        if(errno == 0) errno = ECONNRESET;
        break_channel();
        return -1;
    }
    if(response.data.size() < response_header_size) {
        if(response.fd >= 0) ::close(response.fd);
        response.fd = -1;
        errno = EPROTO;
        break_channel();
        return -1;
    }

    std::uint16_t encoded_error = 0;
    std::memcpy(&encoded_error, response.data.data() + 2, sizeof(encoded_error));
    const int error = ntohs(encoded_error);
    if(response.data[0] == std::byte{'O'} && response.data[1] == std::byte{'K'} && error == 0) return 0;
    if(response.data[0] == std::byte{'E'} && response.data[1] == std::byte{'R'}
       && error != 0 && response.data.size() == response_header_size && response.fd < 0) {
        errno = error;
        return -1;
    }

    if(response.fd >= 0) ::close(response.fd);
    response.fd = -1;
    errno = EPROTO;
    break_channel();
    return -1;
}

int Client::ping() {
    Message response;
    if(transact(make_request(Opcode::Ping), -1, response) != 0) return -1;
    if(response.data.size() != response_header_size || response.fd >= 0) {
        if(response.fd >= 0) ::close(response.fd);
        errno = EPROTO;
        return -1;
    }
    return 0;
}

int Client::socket(int domain, int type, int protocol) {
    const std::uint32_t encoded_protocol = htonl(static_cast<std::uint32_t>(protocol));
    Message response;
    if(transact(make_request(Opcode::Socket, domain, type, &encoded_protocol,
                             sizeof(encoded_protocol)), -1, response) != 0) return -1;
    if(response.data.size() != response_header_size || response.fd < 0) {
        if(response.fd >= 0) ::close(response.fd);
        errno = EPROTO;
        return -1;
    }
    if((type & SOCK_CLOEXEC) == 0) {
        const int flags = ::fcntl(response.fd, F_GETFD, 0);
        if(flags < 0 || ::fcntl(response.fd, F_SETFD, flags & ~FD_CLOEXEC) != 0) {
            const int saved_errno = errno;
            ::close(response.fd);
            errno = saved_errno;
            return -1;
        }
    }
    return response.fd;
}

int Client::setsockopt(int socket_fd, int level, int option_name,
                       const void* option_value, socklen_t option_len) {
    if(socket_fd < 0 || (option_len != 0 && option_value == nullptr)
       || static_cast<std::size_t>(option_len) > max_payload_size) {
        errno = EINVAL;
        return -1;
    }
    Message response;
    if(transact(make_request(Opcode::SetSockOpt, level, option_name,
                             option_value, option_len), socket_fd, response) != 0) return -1;
    if(response.data.size() != response_header_size || response.fd >= 0) {
        if(response.fd >= 0) ::close(response.fd);
        errno = EPROTO;
        return -1;
    }
    return 0;
}

int Client::bind(int socket_fd, const sockaddr* address, socklen_t address_len) {
    if(socket_fd < 0 || address == nullptr || address_len == 0
       || static_cast<std::size_t>(address_len) > sizeof(sockaddr_storage)) {
        errno = EINVAL;
        return -1;
    }
    Message response;
    if(transact(make_request(Opcode::Bind, 0, 0, address, address_len),
                socket_fd, response) != 0) return -1;
    if(response.data.size() != response_header_size || response.fd >= 0) {
        if(response.fd >= 0) ::close(response.fd);
        errno = EPROTO;
        return -1;
    }
    return 0;
}

int Client::listen(int socket_fd, int backlog) {
    if(socket_fd < 0) {
        errno = EBADF;
        return -1;
    }
    Message response;
    if(transact(make_request(Opcode::Listen, backlog), socket_fd, response) != 0) return -1;
    if(response.data.size() != response_header_size || response.fd >= 0) {
        if(response.fd >= 0) ::close(response.fd);
        errno = EPROTO;
        return -1;
    }
    return 0;
}

int Client::stats(Stats& output) {
    Message response;
    if(transact(make_request(Opcode::Stats), -1, response) != 0) return -1;
    constexpr std::size_t payload_size = stats_field_count * sizeof(std::uint64_t);
    if(response.data.size() != response_header_size + payload_size || response.fd >= 0) {
        if(response.fd >= 0) ::close(response.fd);
        errno = EPROTO;
        return -1;
    }
    const auto* data = response.data.data() + response_header_size;
    std::uint64_t* fields[] = {
        &output.ping, &output.socket, &output.setsockopt, &output.bind, &output.listen,
        &output.stats, &output.unknown_opcode, &output.errors, &output.operation_errors,
        &output.protocol_errors, &output.transport_errors, &output.drains,
        &output.max_ops_per_drain
    };
    for(std::size_t i = 0; i < stats_field_count; ++i) *fields[i] = get_u64(data + i * 8);
    return 0;
}

Server::Server(int fd): channel_(fd) {}

int Server::respond_ok(const std::byte* payload, std::size_t payload_size, int passed_fd) {
    std::vector<std::byte> response(response_header_size + payload_size);
    response[0] = std::byte{'O'};
    response[1] = std::byte{'K'};
    if(payload_size != 0) std::memcpy(response.data() + response_header_size, payload, payload_size);
    const int result = channel_.send(response, passed_fd);
    if(result != 0) record_error(ErrorKind::Transport);
    return result;
}

int Server::respond_error(int error) {
    if(error <= 0 || error > std::numeric_limits<std::uint16_t>::max()) error = EIO;
    const auto encoded_error = htons(static_cast<std::uint16_t>(error));
    std::array<std::byte, response_header_size> response{std::byte{'E'}, std::byte{'R'}};
    std::memcpy(response.data() + 2, &encoded_error, sizeof(encoded_error));
    const int result = channel_.send(response.data(), response.size());
    if(result != 0) record_error(ErrorKind::Transport);
    return result;
}

int Server::handle_socket(const Message& request) {
    if(request.fd >= 0 || get_u32(request.data.data() + 12) != sizeof(std::uint32_t)) {
        record_error(ErrorKind::Protocol);
        return respond_error(EINVAL);
    }
    const int domain = static_cast<int>(get_u32(request.data.data() + 4));
    const int type = static_cast<int>(get_u32(request.data.data() + 8));
    const int protocol = static_cast<int>(get_u32(request.data.data() + request_header_size));
    const int socket_fd = ::socket(domain, type, protocol);
    if(socket_fd < 0) {
        record_error(ErrorKind::Operation);
        return respond_error(errno);
    }
    const int result = respond_ok(nullptr, 0, socket_fd);
    ::close(socket_fd);
    return result;
}

int Server::handle_setsockopt(const Message& request) {
    if(request.fd < 0) {
        record_error(ErrorKind::Protocol);
        return respond_error(EBADF);
    }
    const int level = static_cast<int>(get_u32(request.data.data() + 4));
    const int option_name = static_cast<int>(get_u32(request.data.data() + 8));
    const auto option_len = get_u32(request.data.data() + 12);
    const void* option_value = option_len == 0 ? nullptr : request.data.data() + request_header_size;
    if(::setsockopt(request.fd, level, option_name, option_value,
                    static_cast<socklen_t>(option_len)) != 0) {
        record_error(ErrorKind::Operation);
        return respond_error(errno);
    }
    return respond_ok();
}

int Server::handle_bind(const Message& request) {
    const auto address_len = get_u32(request.data.data() + 12);
    if(request.fd < 0 || address_len < sizeof(sa_family_t)
       || address_len > sizeof(sockaddr_storage)) {
        record_error(ErrorKind::Protocol);
        return respond_error(EINVAL);
    }
    const auto* address = reinterpret_cast<const sockaddr*>(request.data.data() + request_header_size);
    if(::bind(request.fd, address, static_cast<socklen_t>(address_len)) != 0) {
        record_error(ErrorKind::Operation);
        return respond_error(errno);
    }
    return respond_ok();
}

int Server::handle_listen(const Message& request) {
    if(request.fd < 0 || get_u32(request.data.data() + 12) != 0) {
        record_error(ErrorKind::Protocol);
        return respond_error(EINVAL);
    }
    const int backlog = static_cast<int>(get_u32(request.data.data() + 4));
    if(::listen(request.fd, backlog) != 0) {
        record_error(ErrorKind::Operation);
        return respond_error(errno);
    }
    return respond_ok();
}

int Server::handle_stats(const Message& request) {
    if(request.fd >= 0 || get_u32(request.data.data() + 12) != 0) {
        record_error(ErrorKind::Protocol);
        return respond_error(EINVAL);
    }
    const auto snapshot = stats();
    const std::uint64_t fields[] = {
        snapshot.ping, snapshot.socket, snapshot.setsockopt, snapshot.bind, snapshot.listen,
        snapshot.stats, snapshot.unknown_opcode, snapshot.errors, snapshot.operation_errors,
        snapshot.protocol_errors, snapshot.transport_errors, snapshot.drains,
        snapshot.max_ops_per_drain
    };
    std::array<std::byte, stats_field_count * sizeof(std::uint64_t)> payload{};
    for(std::size_t i = 0; i < stats_field_count; ++i) put_u64(payload.data() + i * 8, fields[i]);
    return respond_ok(payload.data(), payload.size());
}

int Server::dispatch(Message& request) {
    if(!valid_request_header(request.data)) {
        record_error(ErrorKind::Protocol);
        return respond_error(EPROTO);
    }
    const auto opcode = static_cast<Opcode>(std::to_integer<std::uint8_t>(request.data[3]));
    switch(opcode) {
        case Opcode::Ping:
            record_opcode(opcode);
            if(request.fd >= 0 || get_u32(request.data.data() + 12) != 0) {
                record_error(ErrorKind::Protocol);
                return respond_error(EINVAL);
            }
            return respond_ok();
        case Opcode::Socket:
            record_opcode(opcode);
            return handle_socket(request);
        case Opcode::SetSockOpt:
            record_opcode(opcode);
            return handle_setsockopt(request);
        case Opcode::Bind:
            record_opcode(opcode);
            return handle_bind(request);
        case Opcode::Listen:
            record_opcode(opcode);
            return handle_listen(request);
        case Opcode::Stats:
            record_opcode(opcode);
            return handle_stats(request);
        default:
            record_unknown_opcode();
            record_error(ErrorKind::Protocol);
            return respond_error(EOPNOTSUPP);
    }
}

int Server::serve_once() { return serve_once(0); }

int Server::serve_once(int flags) {
    Message request;
    const int received = channel_.receive(request, flags);
    if(received < 0 && (errno == EMSGSIZE || errno == EPROTO)) {
        record_error(ErrorKind::Protocol);
        return 1;
    }
    if(received <= 0) {
        if(received < 0 && errno != EAGAIN && errno != EWOULDBLOCK) record_error(ErrorKind::Transport);
        return received;
    }
    const int result = dispatch(request);
    if(request.fd >= 0) ::close(request.fd);
    return result == 0 ? 1 : -1;
}

int Server::run() {
    for(;;) {
        std::uint64_t operations = 0;
        int result = serve_once(0);
        if(result <= 0) return result;
        ++operations;
        for(;;) {
            result = serve_once(MSG_DONTWAIT);
            if(result > 0) {
                ++operations;
                continue;
            }
            if(result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            record_drain(operations);
            return result;
        }
        record_drain(operations);
    }
}

void Server::record_opcode(Opcode opcode) noexcept {
    std::lock_guard<std::mutex> guard(stats_mutex_);
    switch(opcode) {
        case Opcode::Ping: ++stats_.ping; break;
        case Opcode::Socket: ++stats_.socket; break;
        case Opcode::SetSockOpt: ++stats_.setsockopt; break;
        case Opcode::Bind: ++stats_.bind; break;
        case Opcode::Listen: ++stats_.listen; break;
        case Opcode::Stats: ++stats_.stats; break;
    }
}

void Server::record_unknown_opcode() noexcept {
    std::lock_guard<std::mutex> guard(stats_mutex_);
    ++stats_.unknown_opcode;
}

void Server::record_error(ErrorKind kind) noexcept {
    std::lock_guard<std::mutex> guard(stats_mutex_);
    ++stats_.errors;
    switch(kind) {
        case ErrorKind::Operation: ++stats_.operation_errors; break;
        case ErrorKind::Protocol: ++stats_.protocol_errors; break;
        case ErrorKind::Transport: ++stats_.transport_errors; break;
    }
}

void Server::record_drain(std::uint64_t operations) noexcept {
    std::lock_guard<std::mutex> guard(stats_mutex_);
    ++stats_.drains;
    stats_.max_ops_per_drain = std::max(stats_.max_ops_per_drain, operations);
}

Stats Server::stats() const noexcept {
    std::lock_guard<std::mutex> guard(stats_mutex_);
    return stats_;
}

void install_client(std::shared_ptr<Client> client) {
    std::lock_guard<std::mutex> guard(installed_client_mutex);
    installed_client = std::move(client);
}

void clear_client() { install_client(nullptr); }

int make_channel_pair(int sockets[2]) {
    if(sockets == nullptr) {
        errno = EINVAL;
        return -1;
    }
    return ::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets);
}

int start_local_helper() {
    std::lock_guard<std::mutex> guard(helper_process_mutex);
    if(helper_process_pid > 0 || current_client()) {
        errno = EALREADY;
        return -1;
    }

    int channels[2] = {-1, -1};
    if(make_channel_pair(channels) != 0) return -1;

    const pid_t child = ::fork();
    if(child < 0) {
        const int saved_errno = errno;
        ::close(channels[0]);
        ::close(channels[1]);
        errno = saved_errno;
        return -1;
    }
    if(child == 0) {
        ::close(channels[0]);
        local_helper_process_entry(channels[1]);
    }

    ::close(channels[1]);
    auto client = std::make_shared<Client>(channels[0]);
    ::close(channels[0]);
    if(client->ping() != 0) {
        const int saved_errno = errno;
        ::kill(child, SIGTERM);
        while(::waitpid(child, nullptr, 0) < 0 && errno == EINTR) {}
        errno = saved_errno;
        return -1;
    }
    helper_process_pid = child;
    install_client(std::move(client));
    return 0;
}

int stop_local_helper() {
    std::lock_guard<std::mutex> guard(helper_process_mutex);
    if(helper_process_pid <= 0) {
        clear_client();
        return 0;
    }

    clear_client();
    int status = 0;
    pid_t result = -1;
    do {
        result = ::waitpid(helper_process_pid, &status, 0);
    } while(result < 0 && errno == EINTR);
    helper_process_pid = -1;
    // Daemon mode may install SIG_IGN/SA_NOCLDWAIT for SIGCHLD.  In that
    // configuration the kernel reaps the helper automatically after closing
    // the last client channel, so there is deliberately no child left to
    // collect here.
    if(result < 0 && errno == ECHILD) return 0;
    if(result < 0) return -1;
    if(!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
        errno = ECHILD;
        return -1;
    }
    return 0;
}

} // namespace socle::privsep

namespace socle {

int socket(int domain, int type, int protocol) {
    if(auto client = current_client()) return client->socket(domain, type, protocol);
    return ::socket(domain, type, protocol);
}

int setsockopt(int socket_fd, int level, int option_name,
               const void* option_value, socklen_t option_len) {
    if(auto client = current_client()) {
        return client->setsockopt(socket_fd, level, option_name, option_value, option_len);
    }
    return ::setsockopt(socket_fd, level, option_name, option_value, option_len);
}

int bind(int socket_fd, const sockaddr* address, socklen_t address_len) {
    if(auto client = current_client()) return client->bind(socket_fd, address, address_len);
    return ::bind(socket_fd, address, address_len);
}

int listen(int socket_fd, int backlog) {
    if(auto client = current_client()) return client->listen(socket_fd, backlog);
    return ::listen(socket_fd, backlog);
}

int privileged_stats(privsep::Stats& output) {
    if(auto client = current_client()) return client->stats(output);
    errno = ENOTCONN;
    return -1;
}

} // namespace socle
