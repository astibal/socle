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

    using mutex_t = std::mutex;
    mutex_t& proxy_lock() const { return proxies_lock_; }

protected:
    vector_type <baseProxy*> proxies_;
    mutable mutex_t proxies_lock_;

public:
    static inline unsigned int subproxy_reserve = 10;

    explicit MasterProxy(baseCom* c): baseProxy(c) {
        proxies_.reserve(subproxy_reserve);
    }
    vector_type <baseProxy*>& proxies() { return proxies_; };
	
    int prepare_sockets(baseCom*) override;
	int handle_sockets_once(baseCom*) override;
	void shutdown() override;
    
    bool run_timers() override;

	std::string hr();
};

#endif // MASTERPROXY_H
