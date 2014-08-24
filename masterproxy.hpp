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


template <class Com>
class MasterProxy : public baseProxy<Com> {

protected:
	std::vector<baseProxy<Com>*> proxies_;
public:
	std::vector<baseProxy<Com>*>& proxies() { return proxies_; };
	
	virtual int run_once(void);	
	virtual void shutdown();
	
	std::string hr();
};

#include <masterproxy.impl>

#endif // MASTERPROXY_H