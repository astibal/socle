#pragma once

#include <cstddef>

namespace socle::build_profile {

#ifdef MEM_CONSTRAINED
inline constexpr bool mem_constrained = true;
#else
inline constexpr bool mem_constrained = false;
#endif

inline constexpr std::size_t tls_certificate_cache_entries = 64U;
inline constexpr std::size_t tls_verify_cache_entries = 64U;
inline constexpr std::size_t tls_session_cache_entries = 32U;
inline constexpr std::size_t tls_crl_cache_entries = 16U;

constexpr std::size_t configured_cache_entries(
        std::size_t configured, std::size_t constrained) noexcept {
    if constexpr (mem_constrained) {
        return constrained;
    }
    return configured;
}

} // namespace socle::build_profile
