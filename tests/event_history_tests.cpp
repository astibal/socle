#include <log/logan.hpp>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <thread>

int main() {
    using namespace logan_events;
    Log::init();
    auto& history = Log::get()->events();
    history.clear();
    logan_lite logger("test.events");
    const auto legacy_id = logger.event(INF, "legacy %s", "configuration");
    logger.event_detail(legacy_id, "%s", "legacy details");
    EventCollector collector;
    for (int i = 0; i < 3; ++i) {
        EventScope scope(collector, [](EventContext& context, const EventBatch&) {
            context.add("connection", "123");
            context.add("proxy", "client -> upstream");
            context.set_detail("certificate diagnostic details");
        });
        assert(logan::event({"TLS fatal alert", "received: unknown CA", EventLevel::error}));
    }
    assert(history.entries().size() == 1); // collection must not publish prematurely
    {
        auto legacy_block = logger.event_block();
        history.publish(collector.take());
        assert(history.entries().back().first != legacy_block.eid);
    }
    assert(history.entries().size() == 2); // not one history entry per occurrence
    const auto new_id = history.entries().back().first;
    assert(new_id != legacy_id);
    assert(history.entries().back().second.find("[x3]") != std::string::npos);
    assert(history.event_details().at(new_id).find("client -> upstream") != std::string::npos);
    assert(history.event_details().at(new_id).find("certificate diagnostic details") != std::string::npos);
    assert(history.event_details().at(legacy_id) == "legacy details");
    assert(!logan::event({"outside scope"}));
    // Legacy writers and the scoped sink share the history and ID allocator.
    std::thread writer([&] { for (int i = 0; i < 100; ++i) logger.event(INF, "legacy %d", i); });
    for (int i = 0; i < 100; ++i) {
        { EventScope scope(collector, [](auto&, const auto&) {}); logan::event({"scoped"}); }
        history.publish(collector.take());
    }
    writer.join();
    std::set<uint64_t> ids;
    for (const auto& entry : history.entries()) assert(ids.insert(entry.first).second);
    const auto old_limit = Events::events_max_;
    Events::events_max_ = 2;
    history.publish(EventCollector::Delivery{{}, 4});
    assert(history.entries().size() == 2);
    assert(history.entries().back().second.find("loss: 4") != std::string::npos);
    assert(history.event_details().find(legacy_id) == history.event_details().end());
    Events::events_max_ = old_limit;
    history.clear();
    assert(history.entries().empty() && history.event_details().empty());
    logger.event(INF, "legacy still works");
    assert(history.entries().size() == 1);
}
