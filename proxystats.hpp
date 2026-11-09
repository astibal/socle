#ifndef SOCLE_PROXYSTATS_HPP
#define SOCLE_PROXYSTATS_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>

#include <common/meter.hpp>

class ProxyStats {
public:
    struct poll {
        std::size_t handled_count = 0L;
        std::size_t generic_count = 0L;
        std::size_t hint_count = 0L;
        std::size_t null_count = 0L;

        poll operator+(poll const&) = delete;
        void operator+=(poll const& other) {
            handled_count += other.handled_count;
            generic_count += other.generic_count;
            hint_count += other.hint_count;
            null_count += other.null_count;
        }
    };

    int last_read = 0;
    int last_write = 0;
    poll polls;
    bool do_rate_meter = true;
    socle::meter mtr_down;
    socle::meter mtr_up;

    void count_session_opened() noexcept {
        sessions_total_.fetch_add(1, std::memory_order_relaxed);
        sessions_active_.fetch_add(1, std::memory_order_relaxed);
    }

    void count_session_closed() noexcept {
        sessions_active_.fetch_sub(1, std::memory_order_relaxed);
    }

    void count_bytes_up(std::uint64_t bytes) noexcept {
        bytes_up_.fetch_add(bytes, std::memory_order_relaxed);
    }

    void count_bytes_down(std::uint64_t bytes) noexcept {
        bytes_down_.fetch_add(bytes, std::memory_order_relaxed);
    }

    [[nodiscard]] std::uint64_t sessions_total() const noexcept {
        return sessions_total_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t sessions_active() const noexcept {
        return sessions_active_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t bytes_up() const noexcept {
        return bytes_up_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t bytes_down() const noexcept {
        return bytes_down_.load(std::memory_order_relaxed);
    }

private:
    std::atomic_uint64_t sessions_total_ {0};
    std::atomic_uint64_t sessions_active_ {0};
    std::atomic_uint64_t bytes_up_ {0};
    std::atomic_uint64_t bytes_down_ {0};
};

#endif // SOCLE_PROXYSTATS_HPP
