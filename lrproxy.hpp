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

#include <baseproxy.hpp>
#include <buffer.hpp>

class LRProxy: public TCPProxy {
	protected:
		void write_left_right();
		void write_right_left();
		
	public: 
		LRProxy();
		
		virtual void on_left_bytes(tcpHostCX*);
		virtual void on_right_bytes(tcpHostCX*);
};

#endif