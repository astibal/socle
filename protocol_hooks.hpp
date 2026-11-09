#pragma once

class baseCom;

namespace socle {

enum class ProtocolHookResult {
    Continue,
    Terminate
};

// One process-wide registry, shared by all transport implementations.
// Register before starting workers; change it only after all workers stop.
// Callbacks run synchronously on the owning thread and may run concurrently
// for different connections. References must not escape the call. Callbacks
// must not destroy or replace the transport, reenter I/O, or throw.
struct ProtocolHooks {
    using Callback = ProtocolHookResult (*)(baseCom&) noexcept;

    // The outbound COM parses the peer's complete ClientHello. Its peer()
    // remains the client-facing transport; no SSL object is required yet.
    Callback tls_client_hello = nullptr;

    // Names describe the local TLS role, not the proxy's left/right side.
    Callback tls_client_start = nullptr;
    Callback tls_server_start = nullptr;

    static ProtocolHooks& registry() {
        static ProtocolHooks hooks;
        return hooks;
    }
};

} // namespace socle
