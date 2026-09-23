/*
    Socle Library Ecosystem
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

#include <vector>

#include "masterproxy.hpp"
#include "baseproxy.hpp"
#include "log/logger.hpp"


int MasterProxy::prepare_sockets(baseCom* xcom)
{
    int r = 0;
    
    r += baseProxy::prepare_sockets(xcom);

    auto lc_ = std::scoped_lock(proxies_lock_);
    for(auto& [ p, thr ]: proxies()) {

        if(p && not p->state().dead() && not p->state().in_progress()) {
            r += p->prepare_sockets(xcom); // fill my fd_sets!
        }
    }    
    
    return r;
}

bool MasterProxy::run_timers()
{
    if(baseProxy::run_timers()) {

        {
            auto l_ = std::scoped_lock(proxies_lock_);
            for(auto i = proxies().begin(); i != proxies().end(); ) {

                auto const& p = i->first;

                if(not p) {
                    _inf("null sub-proxy!!");
                    i = proxies().erase(i);
                    continue;
                }

                if(p->state().in_progress()) {
                    ++i;
                    continue;
                }

                if(not p->state().dead()) {
                    auto lcx = logan_context(p->to_string(iNOT));
                    p->run_timers();
                }
                else {
                    defer_proxy_ul(std::move(*i));
                    i = proxies().erase(i);
                    continue;
                }

                ++i;
            }
        }

        return true;
    }

    return false;
}


bool MasterProxy::thread_finish(std::unique_ptr<std::thread>& thread_ptr) {
    bool ret = false;

    if(thread_ptr) {
        if(thread_ptr->joinable()) {
            thread_ptr->join();
        }

        thread_ptr.reset();
        ret = true;
    }

    return ret;
}

void MasterProxy::defer_proxy_ul(proxy_entry&& entry) {
    {
        auto l_ = std::scoped_lock(deferred_lock_);
        deferred().push_back({std::move(entry), std::chrono::steady_clock::now()});
        _deb("MasterProxy::defer_proxy_ul: queued, deferred=%zd", deferred().size());
    }
}

bool MasterProxy::deferred_under_pressure() const {
    auto lock = std::scoped_lock(deferred_lock_);
    return deferred().size() >= deferred_pressure_threshold;
}

void MasterProxy::reap_deferred(std::size_t budget) {
    auto const started_at = std::chrono::steady_clock::now();
    std::size_t reaped = 0;
    std::size_t deferred_left = 0;
    while(reaped < budget) {
        proxy_entry entry;
        {
            auto lock = std::scoped_lock(deferred_lock_);
            if(deferred().empty()) break;
            if(deferred().front().deferred_at + deferred_grace > std::chrono::steady_clock::now()) break;
            entry = std::move(deferred().front().proxy);
            deferred().pop_front();
            deferred_left = deferred().size();
        }

        // HostCX and Com teardown has worker-thread affinity. Keep destruction
        // on the MasterProxy worker, but outside both queue locks.
        auto& [proxy, thread] = entry;
        thread_finish(thread);
        proxy.reset();

        ++reaped;
        if(std::chrono::steady_clock::now() - started_at >= deferred_reap_time_budget) break;
    }
    if(reaped > 0) {
        _deb("MasterProxy::reap_deferred: reaped=%zd, deferred=%zd", reaped, deferred_left);
    }
}

int MasterProxy::handle_sockets_once(baseCom* xcom) {

    auto const deferred_pressure = deferred_under_pressure();
    if(deferred_pressure or ++deferred_reap_tick_ >= deferred_reap_every) {
        deferred_reap_tick_ = 0;
        reap_deferred(deferred_pressure ? deferred_pressure_batch : 1);
    }

    int my_handle_returned = 0;

    try {
        my_handle_returned = baseProxy::handle_sockets_once(xcom);
        _ext("handling own sockets: returned %d", my_handle_returned);
    }
    catch(socle::com_error const& e) {
        _err("master proxy exception: %s", e.what());
        return 0;
    }

    int r = 0;
    int proxies_handled  = 0;
    int proxies_shutdown = 0;
    int proxies_deleted  = 0;


    auto l_ = std::scoped_lock(proxies_lock_);

    if(proxies().empty()) return 0;
    auto proxies_sz = proxies().size();


    for(auto& [ proxy, thr ] : proxies()) {

        if(state().dead()) {
            proxy->state().dead(true);
        }

        // don't mess with running threaded proxy
        if(proxy->state().in_progress()) continue;

        // we know it's not in progress from condition at the start of the loop
        // therefore joining it would not block
        if(thr and thread_finish(thr)) {
            _deb("MasterProxy::handle_sockets_once: run-phase finished handle thread");
        }

        if (not proxy->state().dead()) {

            auto run_proxy = [this, xcom](baseProxy* p) {
                if(p->state().in_progress().fetch_add(1) == 0) {
                    auto lcx = logan_context(p->to_string(iNOT));

                    try {
                        p->handle_sockets_once(xcom);
                    }
                    catch (socle::com_error const &e) {
                        _err("slave proxy exception: %s", e.what());
                        p->state().dead(true);
                    }
                    catch (std::exception const &e) {
                        _err("slave proxy exception: %s", e.what());
                        p->state().dead(true);
                    }

                    p->state().in_progress().store(0);
                }
            };

            r++;

            // if threading is allowed, thread all proxies unless we are alone
            auto const spray_possible = (subproxy_thread_spray_min > 0 and proxies_sz >= subproxy_thread_spray_min and proxies_sz > 1);


            // spray on existing connections with some data already exchanged
            if(spray_possible
                and proxy->stats().mtr_down.total() > subproxy_thread_spray_bytes_min
                and proxy->stats().mtr_up.total() > subproxy_thread_spray_bytes_min) {

                _deb("proxy spray for: %s", proxy->to_string(iINF).c_str());
                thr = std::make_unique<std::thread>(run_proxy, proxy.get());

            } else {

                auto pref = logan_lite::context();
                run_proxy(proxy.get());
                logan_lite::context(pref);
            }
        }
    }

    for(auto i = proxies().begin(); i != proxies().end(); ) {

        auto const& proxy = i->first;
        auto& thr = i->second;

        if(not proxy) {
            i = proxies().erase(i);
            proxies_deleted++;
            continue;
        }

        // assert in_progress state
        if(proxy->state().in_progress()) {
            ++i;
            continue;
        }

        // we know it's not in progress anymore
        if(thr and thread_finish(thr)) {
            _deb("MasterProxy::handle_sockets_once: cleanup-phase finished handle thread");
        }

        if (proxy->state().dead()) {

            auto lcx = logan_context(proxy->to_string(iNOT));
            defer_proxy_ul(std::move(*i));
            i = proxies().erase(i);

            proxies_shutdown++;
            proxies_deleted++;
            continue;
        }

        ++i;
    }
    
    _ext("MasterProxy::handle_sockets_once: returning %d, sub-proxies: handled=%d, shutdown=%d, deleted=%d",r,proxies_handled,proxies_shutdown,proxies_deleted);
    return r;
}


void MasterProxy::shutdown() {
	
	_inf("MasterProxy::shutdown");
	
	int i = 0;

	vector_type<proxy_entry> shutdown_entries;
	{
		// anyone getting proxies from list would get a valid pointer until it is
		// atomically moved to the local shutdown list.
		auto l_ = std::scoped_lock(proxies_lock_);
		shutdown_entries.reserve(proxies().size());
		for(auto& entry : proxies()) shutdown_entries.emplace_back(std::move(entry));
		proxies().clear();
	}

	{
		auto l_ = std::scoped_lock(deferred_lock_);
		shutdown_entries.reserve(shutdown_entries.size() + deferred().size());
		while(not deferred().empty()) {
			shutdown_entries.emplace_back(std::move(deferred().front().proxy));
			deferred().pop_front();
		}
	}

	for(auto& [ proxy, thr ] : shutdown_entries) {
		_inf("MasterProxy::shutdown: slave[%d]",i);

        if(thr and thr->joinable()) {
            _deb("MasterProxy::shutdown: slave[%d]: joining handler thread",i);
            thr->join();
            thr.reset();
            _dia("MasterProxy::shutdown: slave[%d]: joined",i);
        }

        if(proxy) {
            proxy->shutdown();
        }
        i++;
    }
}


std::string MasterProxy::hr() {

	std::stringstream ss;
	
	ss << "Masterproxy:\n";
    ss << baseProxy::hr();

    auto lc_ = std::scoped_lock(proxies_lock_);
	if(not proxies().empty()) {
        ss << "Slaves:\n";
		
		int i = 0;
		for(auto const& [ proxy, thr ]: proxies()) {
			
            ss << "slave-" + std::to_string(i) + ":\n";
            ss << proxy->hr();
            ss << "\n";
		}
	}
	else {
        ss << "Slaves: <empty>";
	}
	
	return ss.str();
}
