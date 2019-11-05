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

#ifndef LRPROXY_HPP
#define LRPROXY_HPP

#include <hostcx.hpp>
#include <basecom.hpp>
#include <baseproxy.hpp>
#include <buffer.hpp>


class SimpleLRProxy: public baseProxy {
	public:
		explicit SimpleLRProxy(baseCom* c);
		
		void on_left_bytes(baseHostCX*) override;
		void on_right_bytes(baseHostCX*) override;
};

#endif