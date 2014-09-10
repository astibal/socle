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
#include <iostream>
#include <vector>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

#include <baseproxy.hpp>
#include <lrproxy.hpp>

LRProxy::LRProxy(baseCom* c) : baseProxy(c) {
}

void LRProxy::on_left_bytes(baseHostCX* left) {
	DEB_("LRProxy::on_left_bytes[%d]",left->socket());

	
	for(std::vector<baseHostCX*>::iterator j = right_sockets.begin(); j != right_sockets.end(); ++j) {
		//move from left read buffer -> right write buffer
		DEB_("LRProxy::on_left_bytes[%d]: copying into socket %d, size %d",left->socket(),(*j)->socket(),left->readbuf()->size());
		(*j)->to_write(left->to_read());
	}
	for(std::vector<baseHostCX*>::iterator j = right_pc_cx.begin(); j != right_pc_cx.end(); ++j) {
		DEB_("LRProxy::on_left_bytes[%d]: copying into pc socket %d, size %d",left->socket(),(*j)->socket(),left->readbuf()->size());
		//move from left read buffer -> right write buffer
		(*j)->to_write(left->to_read());
	}	
	
	// move away copied data from left read buffer -> they were processed and now even copied to another side
	left->finish();
};

void LRProxy::on_right_bytes(baseHostCX* right) {
	DEB_("LRProxy::on_right_bytes[%d]",right->socket());
	for(std::vector<baseHostCX*>::iterator j = left_sockets.begin(); j != left_sockets.end(); ++j) {
		// move from right read buffer -> left write buffer
		DEB_("LRProxy::on_right_bytes[%d]: copying into socket %d, size %d",right->socket(),(*j)->socket(),right->readbuf()->size());
		(*j)->to_write(right->to_read());
	}
	for(std::vector<baseHostCX*>::iterator j = left_pc_cx.begin(); j != left_pc_cx.end(); ++j) {
		// move from right read buffer -> left write buffer
		DEB_("LRProxy::on_right_bytes[%d]: copying into pc socket %d, size %d",right->socket(),(*j)->socket(),right->readbuf()->size());
		(*j)->to_write(right->to_read());
	}
	
	// move away copied data from left read buffer -> they were processed and now even copied to another side
	right->finish();
};

