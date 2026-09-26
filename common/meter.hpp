#pragma once

#include <atomic>
#include <chrono>
#include <shared_mutex>

namespace socle {

struct meter {
private:
    std::atomic_ulong total_{};
    std::atomic_ulong prev_counter_{};
    std::atomic_ulong curr_counter_{};
    static constexpr unsigned int scoreboard_sz = 3;
    std::atomic_ulong scoreboard[scoreboard_sz] = {0};
    std::chrono::system_clock::time_point last_update{};
    std::atomic_uint interval_{1};
    std::atomic_uint cnt_updates = 0;
    mutable std::shared_mutex chrono_lock_;

public:
    explicit meter(unsigned int interval = 1)
        : last_update(std::chrono::system_clock::now()), interval_(interval) {}
    unsigned long update(unsigned long val);
    [[nodiscard]] unsigned long get() const;
    [[nodiscard]] unsigned long total() const { return total_; }

    void push_score(unsigned long val) {
        for (int i = scoreboard_sz - 1; i > 0; --i) scoreboard[i] = scoreboard[i - 1].load();
        scoreboard[0] = val;
    }
    [[nodiscard]] unsigned long sum_score() const {
        unsigned long ret = 0;
        unsigned int max_it = cnt_updates;
        unsigned int cur_it = 0;
        for (int i = scoreboard_sz - 1; i >= 0; --i) {
            if (++cur_it > max_it) break;
            ret += scoreboard[i];
        }
        return ret;
    }
};

} // namespace socle
