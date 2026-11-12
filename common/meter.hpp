#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>

namespace socle {

/** Thread-safe byte rate over four intervals, including the current interval.
 * Rates use elapsed intervals (at least one) during startup, then the full
 * window. Reads age the samples even without another write. Expiry is rounded
 * to interval boundaries; total() is cumulative and never ages out.
 */
struct meter {
    using clock = std::chrono::steady_clock;

    explicit meter(unsigned int interval = 1) : meter(interval, clock::now()) {}
    meter(unsigned int interval, clock::time_point start)
        : start_(start), interval_(interval ? interval : 1) {}

    // Returns the bytes in the preceding interval, as before (not a rate).
    unsigned long update(unsigned long val);
    [[nodiscard]] unsigned long get() const;
    [[nodiscard]] unsigned long total() const { return total_.load(std::memory_order_relaxed); }

    // Explicit timestamps allow deterministic sampling and tests. Updates with
    // stale timestamps are clamped to the latest observed write interval.
    unsigned long update(unsigned long val, clock::time_point now);
    [[nodiscard]] unsigned long get(clock::time_point now) const;

private:
    static constexpr std::size_t window_size = 4;
    struct sample {
        std::uint64_t tick = 0;
        unsigned long bytes = 0;
    };
    std::uint64_t tick_at(clock::time_point now) const;
    unsigned long update_locked(unsigned long val, clock::time_point now);
    unsigned long get_locked(clock::time_point now) const;

    std::atomic_ulong total_ {};
    std::array<sample, window_size> samples_ {};
    const clock::time_point start_;
    const unsigned int interval_;
    std::uint64_t latest_tick_ = 0;
    mutable std::mutex lock_;
};

} // namespace socle
