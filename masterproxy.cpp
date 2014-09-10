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
#include "logger.hpp"


int MasterProxy::run_once(void) {
	
    int r = baseProxy::run_once();
	
	for(typename std::vector<baseProxy*>::iterator ii = proxies().begin(); ii != proxies().end(); ii++) {
		
		baseProxy *p = (*ii); 
		
		if (p->dead()) { 
			p->shutdown();
		} else {
			r += p->run_once();
		}
	}
	
	for(typename std::vector<baseProxy*>::iterator ii = proxies().begin(); ii != proxies().end(); ii++) {
		
		baseProxy *p = (*ii); 
		
		if (p->dead()) { 
			delete(p);
			proxies().erase(ii);			
			break;
		}
	}
	
	DUM_("MasterProxy::run_once: returning %d",r);
	return r;
}


void MasterProxy::shutdown() {
	
	INFS_("MasterProxy::shutdown");
	baseProxy::shutdown();
	
	int i = 0;
	for(typename std::vector<baseProxy*>::iterator ii = proxies().begin(); ii != proxies().end(); ii++) {
		INF_("MasterProxy::shutdown: slave[%d]",i);
		(*ii)->shutdown();
		i++;
		delete (*ii);
	}
	proxies().clear();
}


std::string MasterProxy::hr() {

	std::string ret;
	
	ret += "Masterproxy:\n";
	ret += baseProxy::hr();

	if(proxies().size() > 0) {
		ret += "Slaves:\n";
		
		int i = 0;
		for(typename std::vector<baseProxy*>::iterator ii = proxies().begin(); ii != proxies().end(); ii++,i++) {
			
			baseProxy *p = (*ii); 
			
			ret+= "slave-" + std::to_string(i) + ":\n";
			ret+= p->hr();
			ret+= "\n";
		}
	}
	else {
		ret += "Slaves: <empty>";
	}
	
	return ret;
}
