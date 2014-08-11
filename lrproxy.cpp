/*
    Copyright (c) 2013, Ales Stibal <astibal@gmail.com>
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:
        * Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.
        * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.
        * Neither the name of the Fortinet  nor the
        names of its contributors may be used to endorse or promote products
        derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY Ales Stibal <astibal@gmail.com> ''AS IS'' AND ANY
    EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL Ales Stibal <astibal@gmail.com> BE LIABLE FOR ANY
    DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <iostream>
#include <vector>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

#include <lrproxy.hpp>

LRProxy::LRProxy() {
	TCPProxy();

}

void LRProxy::on_left_bytes(tcpHostCX* left) {
	DEB_("LRProxy::on_left_bytes[%d]",left->socket());

	
	for(std::vector<tcpHostCX*>::iterator j = right_sockets.begin(); j != right_sockets.end(); j++) {
		//move from left read buffer -> right write buffer
		DEB_("LRProxy::on_left_bytes[%d]: copying into socket %d, size %d",left->socket(),(*j)->socket(),left->readbuf()->size());
		(*j)->to_write(left->to_read());
	}
	for(std::vector<tcpHostCX*>::iterator j = right_pc_cx.begin(); j != right_pc_cx.end(); j++) {
		DEB_("LRProxy::on_left_bytes[%d]: copying into pc socket %d, size %d",left->socket(),(*j)->socket(),left->readbuf()->size());
		//move from left read buffer -> right write buffer
		(*j)->to_write(left->to_read());
	}	
	
	// move away copied data from left read buffer -> they were processed and now even copied to another side
	left->finish();
};

void LRProxy::on_right_bytes(tcpHostCX* right) {
	DEB_("LRProxy::on_right_bytes[%d]",right->socket());
	for(std::vector<tcpHostCX*>::iterator j = left_sockets.begin(); j != left_sockets.end(); j++) {
		// move from right read buffer -> left write buffer
		DEB_("LRProxy::on_right_bytes[%d]: copying into socket %d, size %d",right->socket(),(*j)->socket(),right->readbuf()->size());
		(*j)->to_write(right->to_read());
	}
	for(std::vector<tcpHostCX*>::iterator j = left_pc_cx.begin(); j != left_pc_cx.end(); j++) {
		// move from right read buffer -> left write buffer
		DEB_("LRProxy::on_right_bytes[%d]: copying into pc socket %d, size %d",right->socket(),(*j)->socket(),right->readbuf()->size());
		(*j)->to_write(right->to_read());
	}
	
	// move away copied data from left read buffer -> they were processed and now even copied to another side
	right->finish();
};

