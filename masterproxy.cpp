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
    for(auto& [ p, thr ]: proxies()) {
        if(p && not p->state().dead()) {
            r += p->prepare_sockets(xcom); // fill my fd_sets!
        }
    }    
    
    return r;
}

bool MasterProxy::run_timers()
{
    if(baseProxy::run_timers()) {

        auto delit_list = std::vector<baseProxy*>();

        for(auto i = proxies().begin(); i != proxies().end(); ) {

            auto const& p = i->first;

            if(not p) {
                _inf("null sub-proxy!!");
                continue;
            }

            if(p->state().dead() and not p->state().in_progress()) {
                {
                    auto l_ = std::scoped_lock(proxies_lock_);
                    auto& thr = i->second;

                    if(thread_finish(thr)) {
                        _deb("MasterProxy::run_timers: finished handle thread");
                    }

                    auto lcx = logan_context(p->to_string(iNOT));
                    i = proxies().erase(i);
                }
                continue;
            } else {
                auto lcx = logan_context(p->to_string(iNOT));
                p->run_timers();
            }

            ++i;
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

int MasterProxy::handle_sockets_once(baseCom* xcom) {

    int my_handle_returned = 0;

    try {
        my_handle_returned = baseProxy::handle_sockets_once(xcom);
        _ext("handling own sockets: returned %d", my_handle_returned);
    }
    catch(socle::com_error const& e) {
        _err("master proxy exception: %s", e.what());
        return 0;
    }

    if(proxies().empty()) return 0;

    int r = 0;
    int proxies_handled= 0;
    int proxies_shutdown=0;
    int proxies_deleted=0;

    auto proxies_sz = proxies().size();

    std::size_t proxy_idx = 0;
    for(auto& [ proxy, thr ] : proxies()) {

        if(state().dead()) {
            proxy->state().dead(true);
        }

        // don't mess with running threaded proxy
        if(proxy->state().in_progress()) continue;

        // we know it's not in progress from condition at the start of the loop
        if(thr and thread_finish(thr)) {
            _deb("MasterProxy::handle_sockets_once: run-phase finished handle thread");
        }

        if (not proxy->state().dead()) {

            auto run_proxy = [this, xcom](baseProxy* p) {
                auto lcx = logan_context(p->to_string(iNOT));

                try {
                    if(p->state().in_progress().fetch_add(1) == 0) {
                        p->handle_sockets_once(xcom);

                        p->state().in_progress().store(0);
                    }
                }
                catch (socle::com_error const &e) {
                    _err("slave proxy exception: %s", e.what());
                    p->state().dead(true);
                }
                catch (std::exception const &e) {
                    _err("slave proxy exception: %s", e.what());
                    p->state().dead(true);
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

        ++proxy_idx;
    }

    for(auto i = proxies().begin(); i != proxies().end(); ) {

        auto const& proxy = i->first;
        auto& thr = i->second;

        if(not proxy) {
            i = proxies().erase(i);
            continue;
        }

        // assert in_progress state
        if(proxy->state().in_progress()) continue;

        // we know it's not in progress anymore
        if(thread_finish(thr)) {
            _deb("MasterProxy::handle_sockets_once: cleanup-phase finished handle thread");
        }


        if (proxy->state().dead()) {

            {
                auto l_ = std::scoped_lock(proxies_lock_);
                proxies_shutdown++;

                auto lcx = logan_context(proxy->to_string(iNOT));
                i = proxies().erase(i);
            }

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

	// anyone getting proxies from list would get valid pointer
	auto l_ = std::scoped_lock(proxies_lock_);

	for(auto& [ proxy, thr ] : proxies()) {
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
	proxies().clear();
}


std::string MasterProxy::hr() {

	std::stringstream ss;
	
	ss << "Masterproxy:\n";
    ss << baseProxy::hr();

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
