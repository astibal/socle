/*
 * Socle - Socket Library Ecosystem
 * Copyright (c) 2026, Ales Stibal <astib@mag0.net>
 */

#ifndef SOCLE_PRIVILEGED_SOCKET_HPP
#define SOCLE_PRIVILEGED_SOCKET_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include <sys/socket.h>

namespace socle::privsep {

enum class Opcode : std::uint8_t {
    Ping = 1,
    Socket = 2,
    SetSockOpt = 3,
    Bind = 4,
    Listen = 5,
    Stats = 6,
};

struct Stats {
    std::uint64_t ping = 0;
    std::uint64_t socket = 0;
    std::uint64_t setsockopt = 0;
    std::uint64_t bind = 0;
    std::uint64_t listen = 0;
    std::uint64_t stats = 0;
    std::uint64_t unknown_opcode = 0;
    std::uint64_t errors = 0;
    std::uint64_t operation_errors = 0;
    std::uint64_t protocol_errors = 0;
    std::uint64_t transport_errors = 0;
    std::uint64_t drains = 0;
    std::uint64_t max_ops_per_drain = 0;
};

struct Message {
    std::vector<std::byte> data;
    int fd = -1;
};

class SeqPacketChannel {
public:
    explicit SeqPacketChannel(int fd);
    ~SeqPacketChannel();

    SeqPacketChannel(const SeqPacketChannel&) = delete;
    SeqPacketChannel& operator=(const SeqPacketChannel&) = delete;
    SeqPacketChannel(SeqPacketChannel&& other) noexcept;
    SeqPacketChannel& operator=(SeqPacketChannel&& other) noexcept;

    [[nodiscard]] int fd() const noexcept { return fd_; }
    void close() noexcept;

    int send(const std::byte* data, std::size_t size, int passed_fd = -1) const;
    int send(const std::vector<std::byte>& data, int passed_fd = -1) const {
        return send(data.data(), data.size(), passed_fd);
    }
    int receive(Message& message, int flags = 0) const;

private:
    int fd_ = -1;
};

class Client {
public:
    explicit Client(int fd, std::chrono::milliseconds timeout = std::chrono::seconds(90));

    int ping();
    int socket(int domain, int type, int protocol);
    int setsockopt(int socket, int level, int option_name,
                   const void* option_value, socklen_t option_len);
    int bind(int socket, const sockaddr* address, socklen_t address_len);
    int listen(int socket, int backlog);
    int stats(Stats& output);

private:
    int transact(const std::vector<std::byte>& request, int passed_fd, Message& response);
    int wait_readable() const;
    void break_channel() noexcept;

    SeqPacketChannel channel_;
    std::chrono::milliseconds timeout_;
    std::mutex mutex_;
    bool broken_ = false;
};

class Server {
public:
    explicit Server(int fd);

    int run();
    int serve_once();
    [[nodiscard]] Stats stats() const noexcept;

private:
    enum class ErrorKind { Operation, Protocol, Transport };

    int serve_once(int flags);
    int dispatch(Message& request);
    int handle_socket(const Message& request);
    int handle_setsockopt(const Message& request);
    int handle_bind(const Message& request);
    int handle_listen(const Message& request);
    int handle_stats(const Message& request);
    int respond_ok(const std::byte* payload = nullptr, std::size_t payload_size = 0,
                   int passed_fd = -1);
    int respond_error(int error);
    void record_opcode(Opcode opcode) noexcept;
    void record_unknown_opcode() noexcept;
    void record_error(ErrorKind kind) noexcept;
    void record_drain(std::uint64_t operations) noexcept;

    SeqPacketChannel channel_;
    mutable std::mutex stats_mutex_;
    Stats stats_;
};

void install_client(std::shared_ptr<Client> client);
void clear_client();
int make_channel_pair(int sockets[2]);

// Standalone prototype: fork an in-process helper and install its client.
// Must be called before worker threads are created.
int start_local_helper();
int stop_local_helper();

} // namespace socle::privsep

namespace socle {

int socket(int domain, int type, int protocol);
int setsockopt(int socket, int level, int option_name,
               const void* option_value, socklen_t option_len);
int bind(int socket, const sockaddr* address, socklen_t address_len);
int listen(int socket, int backlog);
int privileged_stats(privsep::Stats& output);

} // namespace socle

#endif // SOCLE_PRIVILEGED_SOCKET_HPP
