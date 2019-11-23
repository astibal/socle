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

bool MasterProxy::run_timers (void)
{
    if(baseProxy::run_timers()) {

        for(baseProxy* p: proxies()) {

            if(!p) {
                _inf("null sub-proxy!!");
                continue;
            }

            if(p->state().dead()) {
                delete p;
                proxies().erase(p);
            } else {
                p->run_timers();
            }
        }

        return true;
    }

    return false;
}



int MasterProxy::handle_sockets_once(baseCom* xcom) {

    int my_handle_returned = baseProxy::handle_sockets_once(xcom);
    _ext("handling own sockets: returned %d", my_handle_returned);
    
    int r = 0;
    int proxies_handled= 0;
    int proxies_shutdown=0;
    int proxies_deleted=0;
    
    for(auto p: proxies()) {
                
        if (p->state().dead()) {
            p->shutdown();
            proxies_shutdown++;
        } else {
            r += p->handle_sockets_once(xcom);
            proxies_handled++;
        }
    }
    
    for(auto p: proxies()) {
        
        if (p->state().dead()) {
            delete(p);
            proxies().erase(p); 
                        
            proxies_deleted++;
            break;
        }
    }
    
    _ext("MasterProxy::handle_sockets_once: returning %d, sub-proxies: handled=%d, shutdown=%d, deleted=%d",r,proxies_handled,proxies_shutdown,proxies_deleted);
    return r;
}


void MasterProxy::shutdown() {
	
	_inf("MasterProxy::shutdown");
	baseProxy::shutdown();
	
	int i = 0;
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
