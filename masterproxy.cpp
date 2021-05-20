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
#include "baseproxy.hpp"
#include "log/logger.hpp"


int MasterProxy::prepare_sockets(baseCom* xcom)
{
    int r = 0;
    
    r += baseProxy::prepare_sockets(xcom);
    for(auto p: proxies()) {
        if(p && !p->state().dead()) {
            r += p->prepare_sockets(xcom); // fill my fd_sets!
        }
    }    
    
    return r;
}

bool MasterProxy::run_timers()
{
    if(baseProxy::run_timers()) {

        auto delit_list = std::vector<baseProxy*>();

        for(auto i = proxies().cbegin(); i != proxies().end(); ) {

            auto p = *i;

            if(!p) {
                _inf("null sub-proxy!!");
                continue;
            }

            if(p->state().dead()) {
                delit_list.push_back(*i);
                {
                    auto l_ = std::scoped_lock(proxies_lock_);
                    i = proxies().erase(i);
                }
                continue;
            } else {
                p->run_timers();
            }

            ++i;
        }

        // delete proxies after their removal from the list - avoid data races iterating proxies list
        std::for_each(delit_list.begin(), delit_list.end(), [](auto dead_beef) { delete dead_beef; });

        return true;
    }

    return false;
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
    
    int r = 0;
    int proxies_handled= 0;
    int proxies_shutdown=0;
    int proxies_deleted=0;
    
    for(auto p: proxies()) {
                
        if (p->state().dead()) {
            p->shutdown();
            proxies_shutdown++;
        } else {

            try {
                r += p->handle_sockets_once(xcom);
            }
            catch(socle::com_error const& e) {
                _err("slave proxy exception: %s", e.what());
                p->state().dead(true);
            }


            proxies_handled++;
        }
    }
    
    for(auto i = proxies().cbegin(); i != proxies().end(); ) {

        auto p = *i;
        if (p->state().dead()) {

            {
                auto l_ = std::scoped_lock(proxies_lock_);
                i = proxies().erase(i);
            }

            delete(p);
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

	for(auto ii: proxies()) {
		_inf("MasterProxy::shutdown: slave[%d]",i);
		ii->shutdown();
		i++;
		delete ii;
	}
	proxies().clear();
}


std::string MasterProxy::hr() {

	std::stringstream ss;
	
	ss << "Masterproxy:\n";
    ss << baseProxy::hr();

	if(proxies().size() > 0) {
        ss << "Slaves:\n";
		
		int i = 0;
		for(auto ii: proxies()) {
			
			baseProxy* p = ii;

            ss << "slave-" + std::to_string(i) + ":\n";
            ss << p->hr();
            ss << "\n";
		}
	}
	else {
        ss << "Slaves: <empty>";
	}
	
	return ss.str();
}
