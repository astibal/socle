#include <common/meter.hpp>

#include <algorithm>

namespace socle {

std::uint64_t meter::tick_at(clock::time_point now) const {
    if (now <= start_) return latest_tick_;
    auto const elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_).count();
    return std::max(latest_tick_, static_cast<std::uint64_t>(elapsed) / interval_);
}

unsigned long meter::update(unsigned long val) {
    auto lock = std::lock_guard(lock_);
    return update_locked(val, clock::now());
}

unsigned long meter::update(unsigned long val, clock::time_point now) {
    auto lock = std::lock_guard(lock_);
    return update_locked(val, now);
}

unsigned long meter::update_locked(unsigned long val, clock::time_point now) {
    auto const tick = tick_at(now);
    latest_tick_ = tick;

    auto& current = samples_[tick % window_size];
    if (current.tick != tick) {
        current = {tick, 0};
    }
    current.bytes += val;
    total_.fetch_add(val, std::memory_order_relaxed);

    if (tick == 0) {
        return 0;
    }

    auto const previous_tick = tick - 1;
    auto const& previous = samples_[previous_tick % window_size];
    return previous.tick == previous_tick ? previous.bytes : 0;
}

unsigned long meter::get() const {
    auto lock = std::lock_guard(lock_);
    return get_locked(clock::now());
}

unsigned long meter::get(clock::time_point now) const {
    auto lock = std::lock_guard(lock_);
    return get_locked(now);
}

unsigned long meter::get_locked(clock::time_point now) const {
    auto const tick = tick_at(now);
    unsigned long bytes = 0;
    for (auto const& sample : samples_) {
        if (tick >= sample.tick && tick - sample.tick < window_size) bytes += sample.bytes;
    }
    auto const intervals = std::min<std::uint64_t>(tick, window_size - 1) + 1;
    return bytes / (intervals * interval_);
}

} // namespace socle
