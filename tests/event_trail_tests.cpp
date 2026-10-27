#include <log/event.hpp>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <stdexcept>
#include <thread>

using namespace logan_events;
int main() {
    auto enrich = [](EventContext& context, const EventBatch&) { context.add("connection", "a"); };
    EventCollector collector;
    emit({"outside"});
    assert(!collector.has_pending());
    int final_state = 0;
    {
        EventScope scope(collector, [&](EventContext& ctx, const EventBatch& batch) {
            assert(batch.events.size() == 2);
            ctx.add("state", std::to_string(final_state));
            emit({"must not leak"});
        });
        emit({"repeat"}); emit({"repeat"}); final_state = 42;
    }
    auto delivery = collector.take();
    assert(delivery.batches.size() == 1);
    assert(delivery.batches[0].events[0].count == 2);
    assert(delivery.batches[0].context.fields[0].second == "42");
    assert(active_trail == nullptr);
    [&] {
        EventScope scope(collector, enrich);
        emit({"early return"});
        return;
    }();
    assert(collector.take().batches.size() == 1);
    {
        EventScope scope(collector, enrich);
        emit({std::string(4096, 'a'), std::string(4096, 'b')});
    }
    delivery = collector.take();
    assert(delivery.batches[0].events[0].event.message.size() == 1024);
    assert(delivery.batches[0].events[0].event.context.size() == 1024);
    {
        EventScope outer(collector, enrich);
        emit({"outer before"});
        {
            EventScope inner(collector, enrich);
            emit({"inner"});
        }
        emit({"outer after"});
    }
    delivery = collector.take();
    assert(delivery.batches.size() == 3);
    try {
        EventScope scope(collector, enrich);
        emit({"unwound"});
        throw std::runtime_error("test");
    } catch (const std::runtime_error&) {}
    assert(collector.take().batches.size() == 1);
    {
        EventScope scope(collector, [](EventContext&, const EventBatch&) { throw 1; });
        emit({"failed enrichment"});
    }
    assert(collector.take().lost == 1);
    assert(active_trail == nullptr);
    {
        EventScope scope(collector, enrich);
        for (int i = 0; i < 70; ++i) emit({std::to_string(i)});
    }
    delivery = collector.take();
    assert(delivery.lost == 6 && delivery.batches.size() == 64);
    assert(delivery.batches.front().events.front().event.message == "6");
    {
        EventScope scope(collector, enrich);
        std::thread worker([&] {
            assert(active_trail == nullptr);
            EventCollector local;
            { EventScope s(local, enrich); emit({"other thread"}); }
            assert(local.take().batches.size() == 1);
        });
        emit({"this thread"});
        worker.join();
    }
    assert(collector.take().batches.size() == 1);
    for (int i = 0; i < 2; ++i) {
        EventScope scope(collector, enrich);
        emit({"repeat across scopes"});
        emit({"individual", "", EventLevel::notice, EventKind::individual});
    }
    assert(!collector.take_due(Clock::time_point{}));
    auto due = collector.take_due(Clock::now() + std::chrono::seconds(6));
    assert(due && due->batches.size() == 3);
    assert(due->batches.front().events.front().count == 2);
    assert(!collector.take_due(Clock::now() + std::chrono::seconds(20)));
    for (int i = 0; i < 1100; ++i) {
        EventScope scope(collector, enrich);
        emit({"individual", "", EventLevel::notice, EventKind::individual});
    }
    delivery = collector.take();
    assert(delivery.batches.size() == 1024 && delivery.lost == 76);
}
