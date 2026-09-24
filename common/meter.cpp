#include <common/meter.hpp>

#include <mutex>

namespace socle {

unsigned long meter::update(unsigned long val) {
    auto now = std::chrono::system_clock::now();
    total_ += val;
    cnt_updates++;

    std::chrono::system_clock::time_point last_update_copy;
    {
        auto lock = std::shared_lock(chrono_lock_);
        last_update_copy = last_update;
    }
    if (now - last_update_copy >= std::chrono::seconds(interval_)) {
        if (now - last_update_copy >= std::chrono::seconds(2 * interval_)) {
            auto missed = (now - last_update_copy) / std::chrono::seconds(interval_) - 1;
            if (missed > scoreboard_sz) missed = scoreboard_sz;
            for (unsigned int i = 0; i < missed; ++i) push_score(0);
        }
        {
            auto lock = std::unique_lock(chrono_lock_);
            last_update = now;
        }
        push_score(prev_counter_);
        prev_counter_ = curr_counter_.load();
        curr_counter_ = val;
    } else {
        curr_counter_ += val;
    }
    return prev_counter_;
}

unsigned long meter::get() const {
    auto now = std::chrono::system_clock::now();
    {
        auto lock = std::shared_lock(chrono_lock_);
        if (now > last_update + (1 + scoreboard_sz) * std::chrono::seconds(interval_)) return 0;
    }
    unsigned long divisor = (1 + scoreboard_sz) * interval_;
    if (cnt_updates < 1 + scoreboard_sz) divisor = cnt_updates.load() * interval_;
    if (!divisor) divisor = 1;
    return (prev_counter_ + sum_score()) / divisor;
}

} // namespace socle
