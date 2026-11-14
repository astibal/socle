#pragma once

#include <cstdint>
#include <string_view>

namespace socle {

enum class trace_side : uint8_t { proxy, left, right };
enum class trace_component : uint8_t {
    proxy, tcp, tls, quic, stream, policy, routing, load_balancer
};
enum class trace_scope : uint8_t { session, connection, stream };
enum class trace_event : uint8_t {
    created, accepted, connect_started, connected, handshake_started,
    handshake_ready, handshake_failed, timed_out, opened, first_data,
    closed, decision, selected, matched
};
enum class trace_status : uint8_t { info, pending, ok, failed, timeout };

struct protocol_trace_event {
    trace_side side = trace_side::proxy;
    trace_component component = trace_component::proxy;
    trace_scope scope = trace_scope::session;
    uint64_t subject_id = 0;
    bool has_subject_id = false;
    trace_event event = trace_event::created;
    trace_status status = trace_status::info;
    std::string_view detail;
};

class ProtocolTracer {
public:
    virtual ~ProtocolTracer() = default;
    virtual void trace(protocol_trace_event const& event) noexcept = 0;
};

constexpr std::string_view to_string(trace_side value) noexcept {
    switch(value) {
        case trace_side::left: return "L";
        case trace_side::right: return "R";
        default: return "P";
    }
}
constexpr std::string_view to_string(trace_component value) noexcept {
    switch(value) {
        case trace_component::tcp: return "tcp";
        case trace_component::tls: return "tls";
        case trace_component::quic: return "quic";
        case trace_component::stream: return "stream";
        case trace_component::policy: return "policy";
        case trace_component::routing: return "routing";
        case trace_component::load_balancer: return "load_balancer";
        default: return "proxy";
    }
}
constexpr std::string_view to_string(trace_scope value) noexcept {
    switch(value) {
        case trace_scope::connection: return "connection";
        case trace_scope::stream: return "stream";
        default: return "session";
    }
}
constexpr std::string_view to_string(trace_event value) noexcept {
    switch(value) {
        case trace_event::accepted: return "ACCEPTED";
        case trace_event::connect_started: return "CONNECT_STARTED";
        case trace_event::connected: return "CONNECTED";
        case trace_event::handshake_started: return "HANDSHAKE_STARTED";
        case trace_event::handshake_ready: return "HANDSHAKE_READY";
        case trace_event::handshake_failed: return "HANDSHAKE_FAILED";
        case trace_event::timed_out: return "TIMED_OUT";
        case trace_event::opened: return "OPENED";
        case trace_event::first_data: return "FIRST_DATA";
        case trace_event::closed: return "CLOSED";
        case trace_event::decision: return "DECISION";
        case trace_event::selected: return "SELECTED";
        case trace_event::matched: return "MATCHED";
        default: return "CREATED";
    }
}
constexpr std::string_view to_string(trace_status value) noexcept {
    switch(value) {
        case trace_status::pending: return "pending";
        case trace_status::ok: return "ok";
        case trace_status::failed: return "failed";
        case trace_status::timeout: return "timeout";
        default: return "info";
    }
}

} // namespace socle
