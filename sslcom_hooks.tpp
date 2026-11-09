#pragma once

// Synchronous application hooks, kept separate from the transport flow.
// Call sites retain responsibility for returning after a rejected handshake.
template <class L4Proto>
socle::ProtocolHookResult baseSSLCom<L4Proto>::dispatch_tls_hook(
    typename TlsHookState::Invocation& invocation,
    socle::ProtocolHooks::Callback callback, const char* name) {

    if(invocation.called) {
        return invocation.result;
    }

    // Claim even disabled boundaries: a resumed handshake is too late to
    // subscribe. Only TCP TLS currently dispatches application callbacks.
    invocation.called = true;
    if(!this->protocol_hooks_enabled() || l4_proto() != SOCK_STREAM) {
        return socle::ProtocolHookResult::Continue;
    }

    invocation.result = callback ? callback(*this) : socle::ProtocolHookResult::Continue;
    if(invocation.result == socle::ProtocolHookResult::Terminate) {
        _war("TLS handshake terminated by callback: hook=%s socket=%d com=%p",
             name, this->socket(), static_cast<void*>(this));
    }

    return invocation.result;
}

template <class L4Proto>
socle::ProtocolHookResult baseSSLCom<L4Proto>::hook_tls_start() {

    // Missing SSL must not consume the start boundary.
    if(!sslcom_ssl) {
        return socle::ProtocolHookResult::Continue;
    }

    const auto& hooks = socle::ProtocolHooks::registry();
    const bool client = tls_proto_role_ == socle::TlsProtoRole::client;
    const auto callback = client ? hooks.tls_client_start : hooks.tls_server_start;
    const auto* name = client ? "client-start" : "server-start";

    const auto result = dispatch_tls_hook(tls_hooks_.start, callback, name);
    if(result == socle::ProtocolHookResult::Terminate) {
        reject_tls_handshake();
    }

    return result;
}

template <class L4Proto>
socle::ProtocolHookResult baseSSLCom<L4Proto>::hook_client_hello(baseSSLCom& client) {

    const auto callback = socle::ProtocolHooks::registry().tls_client_hello;
    const auto result = dispatch_tls_hook(tls_hooks_.client_hello, callback, "client-hello");

    // The parsed hello belongs to the client-facing peer; reject both legs.
    if(result == socle::ProtocolHookResult::Terminate) {
        client.reject_tls_handshake();
        reject_tls_handshake();
    }

    return result;
}

template <class L4Proto>
void baseSSLCom<L4Proto>::reject_tls_handshake() {

    record_tls_state(socle::TlsProtoState::failed);
    error(ERROR_UNSPEC);
}
