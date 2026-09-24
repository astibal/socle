/*
    Socle - Socket Library Ecosystem
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    This library  is free  software;  you can redistribute  it and/or
    modify  it  under   the  terms of the  GNU Lesser  General Public
    License  as published by  the   Free Software Foundation;  either
    version 3.0 of the License, or (at your option) any later version.
    This library is  distributed  in the hope that  it will be useful,
    but WITHOUT ANY WARRANTY;  without  even  the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
    
    See the GNU Lesser General Public License for more details.
    
    You  should have received a copy of the GNU Lesser General Public
    License along with this library.
*/


#ifndef MASTERPROXY_H
#define MASTERPROXY_H

#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>

#include <baseproxy.hpp>

class MasterProxy : public baseProxy {

public:
    enum class pressure_level : std::uint8_t {
        nominal,
        elevated,
        critical,
        emergency
    };

    template<class T>
    using vector_type = mp::vector<T>;
    template<class T>
    using set_type = mp::set<T>;
    using proxy_entry = std::pair<std::unique_ptr<baseProxy>,std::unique_ptr<std::thread>>;

    struct deferred_entry {
        proxy_entry proxy;
        std::chrono::steady_clock::time_point deferred_at;
    };
    using deferred_queue = std::deque<deferred_entry>;

    using mutex_t = std::mutex;
    mutex_t& proxy_lock() const { return proxies_lock_; }

private:
    vector_type <proxy_entry> proxies_;
    deferred_queue deferred_;
    mutable mutex_t proxies_lock_;
    mutable mutex_t deferred_lock_;
    std::size_t deferred_reap_tick_ = 0;

    static bool thread_finish(std::unique_ptr<std::thread>& thread_ptr);
    // Caller holds proxies_lock_. The _ul suffix follows the existing
    // convention for operations which expect their lock to be held already.
    void defer_proxy_ul(proxy_entry&& entry);
    void reap_deferred(std::size_t count_budget,
                       std::optional<std::chrono::milliseconds> time_budget,
                       std::size_t target_size = 0);
protected:
    // Called from the socket polling cycle. Overrides must keep this
    // calculation cheap and non-blocking so they do not burden that cycle.
    [[nodiscard]] virtual pressure_level get_pressure_level() const;
public:
    static inline unsigned int subproxy_reserve = 10;
    static inline unsigned int subproxy_thread_spray_min = 5;
    static inline unsigned int subproxy_thread_spray_bytes_min = 1400;
    static inline std::chrono::milliseconds deferred_grace {1000};
    static inline std::size_t deferred_reap_every = 16;
    static inline std::size_t deferred_pressure_threshold = 128;
    static inline std::size_t deferred_pressure_batch = 32;
    static inline std::chrono::milliseconds deferred_reap_time_budget {2};
    static inline std::size_t deferred_critical_threshold = 512;
    static inline std::size_t deferred_critical_batch = 128;
    static inline std::chrono::milliseconds deferred_critical_time_budget {10};
    static inline std::size_t deferred_emergency_threshold = 1024;
    static inline std::size_t deferred_emergency_batch = 512;
    static inline std::chrono::milliseconds deferred_emergency_time_budget {25};
    static inline std::size_t deferred_emergency_low_watermark = 512;

    explicit MasterProxy(baseCom* c): baseProxy(c) {
        proxies_.reserve(subproxy_reserve);
    }
    ~MasterProxy() override {
        // shutdown active sessions, join in_progress ones
        MasterProxy::shutdown();
    }

    vector_type <proxy_entry>& proxies() { return proxies_; };
    vector_type <proxy_entry> const& proxies() const { return proxies_; };
    deferred_queue& deferred() { return deferred_; };
    deferred_queue const& deferred() const { return deferred_; };

    void add_proxy(baseProxy* p) {
        auto lc_ = std::scoped_lock(proxies_lock_);
        proxies_.emplace_back(p, nullptr);
    }
    void add_proxy(std::unique_ptr<baseProxy> upx) {
        auto lc_ = std::scoped_lock(proxies_lock_);
        proxies_.emplace_back(std::move(upx), nullptr);
    }

    int prepare_sockets(baseCom*) override;
	int handle_sockets_once(baseCom*) override;
	void shutdown() override;
    
    bool run_timers() override;

	std::string hr();

private:
    logan_lite log {"proxy.master"};
};

#endif // MASTERPROXY_H
