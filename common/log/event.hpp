#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// Structured, opt-in observations. Independent of logging thresholds and sinks.
namespace logan_events {
using Clock = std::chrono::steady_clock;
enum class EventLevel : std::uint8_t { detail, notice, warning, error };
enum class EventKind : std::uint8_t { individual, repeatable };
struct Event {
    std::string message{};
    std::string context{};
    EventLevel level = EventLevel::notice;
    EventKind kind = EventKind::repeatable;
};
struct EventContext {
    // Optional human-readable diagnostics, supplied at scope completion.
    std::string detail;
    void set_detail(std::string value) {
        value.resize(std::min(value.size(), std::size_t{16384}));
        detail = std::move(value);
    }
    std::vector<std::pair<std::string, std::string>> fields;
    void add(std::string key, std::string value) {
        key.resize(std::min(key.size(), std::size_t{128}));
        value.resize(std::min(value.size(), std::size_t{1024}));
        for (auto& field : fields) {
            if (field.first == key) { field.second = std::move(value); return; }
        }
        if (fields.size() < 16) fields.emplace_back(std::move(key), std::move(value));
    }
};
struct Observation {
    Event event;
    Clock::time_point first_seen = Clock::now();
    Clock::time_point last_seen = first_seen;
    std::uint64_t count = 1;
};
struct EventBatch {
    EventContext context;
    std::vector<Observation> events;
    std::uint64_t lost = 0;
};

class EventTrail {
public:
    static constexpr std::size_t capacity = 64;
    static constexpr std::size_t text_limit = 1024;
    void append(Event event) noexcept {
        event.message.resize(std::min(event.message.size(), text_limit));
        event.context.resize(std::min(event.context.size(), text_limit));
        const auto slot = (begin_ + size_) % capacity;
        entries_[slot] = Observation{std::move(event)};
        if (size_ == capacity) { begin_ = (begin_ + 1) % capacity; ++lost_; }
        else ++size_;
    }
    EventBatch take() {
        EventBatch batch;
        batch.events.reserve(size_);
        for (std::size_t i = 0; i < size_; ++i) {
            auto& entry = entries_[(begin_ + i) % capacity];
            batch.events.push_back(std::move(*entry));
            entry.reset();
        }
        batch.lost = lost_;
        begin_ = size_ = lost_ = 0;
        return batch;
    }
    bool empty() const noexcept { return size_ == 0; }
private:
    std::array<std::optional<Observation>, capacity> entries_;
    std::size_t begin_ = 0, size_ = 0;
    std::uint64_t lost_ = 0;
};
inline thread_local EventTrail* active_trail = nullptr;
inline bool emit(Event event) noexcept {
    if (!active_trail) return false;
    active_trail->append(std::move(event));
    return true;
}

// Owned by one event-loop thread. No transport, proxy or JSON dependencies.
class EventCollector {
public:
    static constexpr std::size_t capacity = 1024;
    void collect(EventBatch batch) {
        lost_ += batch.lost;
        for (auto& observation : batch.events) {
            bool merged = false;
            if (observation.event.kind == EventKind::repeatable) {
                for (auto& pending : pending_) {
                    auto& existing = pending.events.front();
                    const auto& a = existing.event;
                    const auto& b = observation.event;
                    if (pending.context.fields == batch.context.fields &&
                        a.kind == b.kind && a.level == b.level &&
                        a.message == b.message && a.context == b.context) {
                        existing.count += observation.count;
                        existing.last_seen = observation.last_seen;
                        pending.context.detail = batch.context.detail;
                        merged = true;
                        break;
                    }
                }
            }
            if (merged) continue;
            if (pending_.size() == capacity) { lost_ += observation.count; continue; }
            pending_.push_back(EventBatch{batch.context, {std::move(observation)}, 0});
        }
    }
    struct Delivery {
        std::vector<EventBatch> batches;
        std::uint64_t lost = 0;
    };
    bool has_pending() const noexcept { return !pending_.empty() || lost_ != 0; }
    Delivery take() noexcept {
        Delivery result{std::move(pending_), std::exchange(lost_, 0)};
        pending_.clear();
        return result;
    }
    std::optional<Delivery> take_due(Clock::time_point now = Clock::now()) {
        if (!has_pending() || now < next_flush_) return std::nullopt;
        next_flush_ = now + std::chrono::seconds(5);
        return take();
    }
    void record_loss() noexcept { ++lost_; }
private:
    std::vector<EventBatch> pending_;
    std::uint64_t lost_ = 0;
    Clock::time_point next_flush_ = Clock::now() + std::chrono::seconds(5);
};

// Enricher receives the final batch and can capture operation-specific state.
// Captures and collector must outlive this scope. Scopes must nest in LIFO order.
template<class Enricher>
class EventScope {
public:
    EventScope(EventCollector& collector, Enricher enrich)
        : collector_(collector), enrich_(std::move(enrich)), previous_(active_trail) {
        active_trail = &trail_;
    }
    EventScope(const EventScope&) = delete;
    EventScope& operator=(const EventScope&) = delete;
    ~EventScope() noexcept {
        // Enrichment must not leak its own observations into this or the parent trail.
        active_trail = nullptr;
        if (!trail_.empty()) {
            try {
                auto batch = trail_.take();
                enrich_(batch.context, std::as_const(batch));
                collector_.collect(std::move(batch));
            } catch (...) { collector_.record_loss(); }
        }
        active_trail = previous_;
    }
private:
    EventCollector& collector_;
    Enricher enrich_;
    EventTrail* previous_;
    EventTrail trail_;
};
} // namespace logan_events
