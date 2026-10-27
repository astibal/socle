#include <sslcom.hpp>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>

int main() {
    using namespace logan_events;
    Log::init();
    auto& history = Log::get()->events();
    SSLCom connection;
    EventCollector collector;
    const unsigned char unknown_ca[] {SSL3_AL_FATAL, SSL_AD_UNKNOWN_CA};
    const unsigned char close_notify[] {SSL3_AL_WARNING, SSL_AD_CLOSE_NOTIFY};
    auto alert = [&](const unsigned char* bytes, int direction = 0) {
        SSLCom::ssl_msg_callback(direction, TLS1_2_VERSION, SSL3_RT_ALERT,
                                bytes, 2, nullptr, &connection);
    };
    auto enrich = [](EventContext& ctx, const EventBatch&) { ctx.add("proxy", "test proxy"); };
    {
        EventScope scope(collector, enrich);
        alert(unknown_ca);
        assert(connection.error());
        assert(history.entries().empty()); // no synchronous legacy duplicate
    }
    auto delivery = collector.take();
    assert(delivery.batches.size() == 1);
    assert(delivery.batches[0].events[0].event.context.find("received:") == 0);
    history.publish(delivery);
    assert(history.entries().size() == 1);
    assert(history.event_details().at(history.entries().back().first).find("test proxy") != std::string::npos);
    history.clear();
    connection.opt.alerts.suppress_all = true;
    { EventScope scope(collector, enrich); alert(unknown_ca); }
    assert(!collector.has_pending() && history.entries().empty());
    connection.opt.alerts.suppress_all = false;
    const unsigned char decode_error[] {SSL3_AL_FATAL, TLS1_AD_DECODE_ERROR};
    connection.sslcom_op_state = SSLCom::sslcom_op_state_t::READY;
    connection.opt.alerts.decode_error_in_operational = false;
    { EventScope scope(collector, enrich); alert(decode_error); }
    assert(!collector.has_pending() && history.entries().empty());
    connection.sslcom_op_state = SSLCom::sslcom_op_state_t::UNKNOWN;
    { EventScope scope(collector, enrich); alert(close_notify); }
    assert(!collector.has_pending() && history.entries().empty());
    { EventScope scope(collector, enrich); alert(unknown_ca, 1); }
    assert(collector.take().batches[0].events[0].event.context.find("sent:") == 0);
    alert(unknown_ca); // unscoped callers retain legacy reporting
    assert(history.entries().size() == 1);
}
