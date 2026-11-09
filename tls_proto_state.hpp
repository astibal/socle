#pragma once

#include <array>
#include <cstdint>
#include <optional>

namespace socle {

// Local TLS role, independent of which side of a proxy owns the COM object.
enum class TlsProtoRole : std::uint8_t {
    client,
    server,
};

// Observations, not ordered milestones or instructions to the transport.
// A snapshot can skip intermediate states; it is not an event history.
enum class TlsProtoState : std::uint8_t {
    idle,
    waiting_peer_hello,       // Outbound TLS waits for its counterpart's hello.
    peer_hello_ready,         // Prerequisite met or deliberately skipped.
    waiting_client_hello,     // Client-facing TLS has not received a full hello.
    client_hello_received,    // A complete ClientHello was actually parsed.
    initializing,
    prepared,
    listening,               // DTLS cookie exchange, before SSL_accept.
    handshaking,
    handshake_want_read,
    handshake_want_write,
    checking_peer,           // Wire handshake succeeded; local checks remain.
    established,             // Handshake and local checks accepted.
    bypassed,
    peer_closed,             // close_notify; the write half may still be usable.
    closed,                  // Local shutdown or cleanup, not a confirmed exchange.
    failed,                  // Retained through cleanup during shutdown and cleanup.
};

// Pending observations, owned and consumed by the COM object's thread.
// A full buffer retains its prefix and reports the gap instead of overwriting it.
struct TlsProtoHistory {
    std::array<TlsProtoState, 32> states {};
    std::uint8_t size { 0 };
    bool overflowed { false };

    // Queries inspect retained entries only, including after an overflow.
    std::optional<TlsProtoState> last() const {

        if(size == 0) {
            return std::nullopt;
        }

        return states[size - 1];
    }

    bool contains(TlsProtoState state) const {

        for(std::uint8_t index = 0; index < size; ++index) {
            if(states[index] == state) {
                return true;
            }
        }

        return false;
    }

    void append(TlsProtoState state) {

        if(size != 0 && states[size - 1] == state) {
            return;
        }

        if(size == states.size()) {
            overflowed = true;
            return;
        }

        states[size++] = state;
    }
};

} // namespace socle
