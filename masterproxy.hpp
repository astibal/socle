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

#include <baseproxy.hpp>

class MasterProxy : public baseProxy {

public:
    template<class T>
    using vector_type = mp::vector<T>;
    template<class T>
    using set_type = mp::set<T>;
    using proxy_entry = std::pair<std::unique_ptr<baseProxy>,std::unique_ptr<std::thread>>;

    using mutex_t = std::mutex;
    mutex_t& proxy_lock() const { return proxies_lock_; }

private:
    vector_type <proxy_entry> proxies_;
    mutable mutex_t proxies_lock_;

    static bool thread_finish(std::unique_ptr<std::thread>& thread_ptr);
public:
    static inline unsigned int subproxy_reserve = 10;
    static inline unsigned int subproxy_thread_spray_min = 5;
    static inline unsigned int subproxy_thread_spray_bytes_min = 1400;

    explicit MasterProxy(baseCom* c): baseProxy(c) {
        proxies_.reserve(subproxy_reserve);
    }
    ~MasterProxy() override {
        // shutdown active sessions, join in_progress ones
        MasterProxy::shutdown();
    }

    vector_type <proxy_entry>& proxies() { return proxies_; };
    vector_type <proxy_entry> const& proxies() const { return proxies_; };

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
