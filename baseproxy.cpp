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

#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <functional>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <baseproxy.hpp>
#include <hostcx.hpp>

#include <display.hpp>
#include <log/logger.hpp>
#include "udpcom.hpp"

DEFINE_LOGGING(baseProxy);

baseProxy::baseProxy(baseCom* c) :
new_raw_(false),
parent_(nullptr),
sleep_time_(1000),
handle_last_status(0)
{
    com_ = c;
    log = logan_attached(this, "proxy");
};


baseProxy::~baseProxy() {
	shutdown(); 
    
    if (com_ != nullptr) {
        _dum("Proxy: deleting com");
        delete com_;
    }
};



void baseProxy::ladd(baseHostCX* cs) {
    cs->unblock();
    
    //int s = cs->com()->translate_socket(cs->socket());
    int s = cs->socket();
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);
    left_sockets.push_back(cs);
    cs->parent_proxy(this, 'L');
    _dia("baseProxy::ladd: added socket: %s",cs->c_name());
};


void baseProxy::radd(baseHostCX* cs) {
    cs->unblock();
    
    //int s = cs->com()->translate_socket(cs->socket());
    int s = cs->socket();
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);
    right_sockets.push_back(cs);
    cs->parent_proxy(this, 'R');
    _dia("baseProxy::radd: added socket: %s",cs->c_name());
};


void baseProxy::lbadd(baseHostCX* cs) {
    
    int s = cs->com()->translate_socket(cs->socket());
    
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);
    left_bind_sockets.push_back(cs);
    cs->parent_proxy(this, 'L');
	_dia("baseProxy::lbadd: added bound socket: %s",cs->c_name());
};


void baseProxy::rbadd(baseHostCX* cs) {
    
    int s = cs->com()->translate_socket(cs->socket());
    
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);
    right_bind_sockets.push_back(cs);
    cs->parent_proxy(this, 'R');
	_dia("baseProxy::rbadd: added bound socket: %s",cs->c_name());
};


void baseProxy::lpcadd(baseHostCX* cx) {
    cx->permanent(true);
    int s = cx->com()->translate_socket(cx->socket());
    
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);
    left_pc_cx.push_back(cx);
    cx->parent_proxy(this, 'L');
    _dia("baseProxy::lpcadd: added perma socket: %s", cx->c_name());
};


void baseProxy::rpcadd(baseHostCX* cx) {
    cx->permanent(true);
    int s = cx->com()->translate_socket(cx->socket());
    
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);
    
    right_pc_cx.push_back(cx);
    cx->parent_proxy(this,'R');
    _dia("baseProxy::rpcadd: added perma socket %s", cx->c_name());
};


void baseProxy::ldaadd(baseHostCX* cs) {
    cs->unblock();
    int s = cs->com()->translate_socket(cs->socket());
    
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);

    left_delayed_accepts.push_back(cs);
    cs->parent_proxy(this,'l');
    _dia("baseProxy::ldaadd: added delayed socket: %s",cs->c_name());
};


void baseProxy::rdaadd(baseHostCX* cs) {
    cs->unblock();
    int s = cs->com()->translate_socket(cs->socket());
    
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);
    
    right_delayed_accepts.push_back(cs);
    cs->parent_proxy(this,'r');
    _dia("baseProxy::rdaadd: added delayed socket: %s",cs->c_name());
};



void baseProxy::left_shutdown() {
	int lb = left_bind_sockets.size();
	int ls = left_sockets.size();
	int lp = left_pc_cx.size();
	
	int ld = left_delayed_accepts.size();
	
	for(auto* ii: left_bind_sockets) { ii->shutdown(); };
	for(auto* ii: left_sockets)       { ii->shutdown(); };
	for(auto* ii: left_pc_cx)          { ii->shutdown(); };
    for(auto* ii: left_delayed_accepts) { ii->shutdown(); };


    for(auto* ii: left_bind_sockets) { delete ii; };
    left_bind_sockets.clear();

    for(auto* ii: left_sockets) {  delete ii; };
    left_sockets.clear();

    for(auto* ii: left_pc_cx) {  delete ii; };
    left_pc_cx.clear();

    for(auto* ii: left_delayed_accepts) { delete ii; };
    left_delayed_accepts.clear();       
    
 	_deb("baseProxy::left_shutdown: bind=%d(delayed=%d), sock=%d, perm=%d",lb,ld,ls,lp);
}


void baseProxy::right_shutdown() {
	int rb = right_bind_sockets.size();
	int rs = right_sockets.size();
	int rp = right_pc_cx.size();
    
    int rd = right_delayed_accepts.size();
	
	for(auto ii: right_bind_sockets) { ii->shutdown(); };
	for(auto ii: right_sockets)       { ii->shutdown(); };
	for(auto ii: right_pc_cx)          { ii->shutdown(); };
    for(auto ii: right_delayed_accepts) { ii->shutdown(); };


    for(auto ii: right_bind_sockets) {  delete ii; };
    right_bind_sockets.clear();

    for(auto ii: right_sockets) {  delete ii; };
    right_sockets.clear();

    for(auto ii: right_pc_cx) { delete ii; };
    right_pc_cx.clear();

    for(auto ii: right_delayed_accepts) {  delete ii; };
    right_delayed_accepts.clear();      
    
    
	_deb("baseProxy::right_shutdown: bind=%d(delayed=%d), sock=%d, perm=%d",rb,rd,rs,rp);
}


void baseProxy::shutdown() {
    _dia("baseProxy::shutdown");
	left_shutdown();
	right_shutdown();
    _deb("baseProxy::shutdown finished");
}



int baseProxy::lsize() {
	return (left_sockets.size()+left_bind_sockets.size()+left_pc_cx.size()+left_delayed_accepts.size());
}


int baseProxy::rsize() {
	return (right_sockets.size()+right_bind_sockets.size()+right_pc_cx.size()+right_delayed_accepts.size());
}


bool baseProxy::on_cx_timer(baseHostCX* cx) {

		cx->on_timer();
		return true;

	return false;
}


// return true if clicked, false otherwise.

bool baseProxy::clicker::reset_timer() {

    time(&clock_);

	if( clock_ - last_tick_ > timer_interval) {
		time(&last_tick_);

		return true;
	}

	return false;
}


// (re)set socket set and calculate max socket no

bool baseProxy::run_timers () {

    if(clicker_.reset_timer()) {

        for (auto i: left_sockets) {
            on_cx_timer(i);
        }
        for (auto ii: left_bind_sockets) {
            on_cx_timer(ii);
        }

        for (auto j: right_sockets) {
            on_cx_timer(j);
        }
        for (auto jj: right_bind_sockets) {
            on_cx_timer(jj);
        }

        for (auto k: left_pc_cx) {
            on_cx_timer(k);
        }
        for (auto l: right_pc_cx) {
            on_cx_timer(l);
        }

        for (auto k: left_delayed_accepts) {
            on_cx_timer(k);
        }
        for (auto l: right_delayed_accepts) {
            on_cx_timer(l);
        }

        return true;
    }

    return false;
};

// (re)set socket set and calculate max socket no

int baseProxy::prepare_sockets(baseCom* fdset_owner) {
     int max = 1;


     return max;
};


bool baseProxy::handle_cx_events(unsigned char side, baseHostCX* cx) {
        // treat non-blocking still opening sockets 
        if( cx->opening_timeout() ) {
            _dia("baseProxy::handle_cx_events[%d]: opening timeout!",cx->socket());
            
            if     (side == 'l')  { on_left_error(cx);  }
            else if(side == 'r')  { on_right_error(cx); }
            else if(side == 'x')  { on_left_pc_error(cx); }
            else if(side == 'y')  { on_right_pc_error(cx); }

            cx->shutdown();
            return false;
        }
        if( cx->idle_timeout() ) {
            _dia("baseProxy::handle_cx_events[%d]: idle timeout!",cx->socket());

            if     (side == 'l')  { on_left_error(cx);  }
            else if(side == 'r')  { on_right_error(cx); }
            else if(side == 'x')  { on_left_pc_error(cx); }
            else if(side == 'y')  { on_right_pc_error(cx); }

            cx->shutdown();
            return false;
        }
        if( cx->error() ) {
            _dia("baseProxy::handle_cx_events[%d]: error!",cx->socket());

            if     (side == 'l')  { on_left_error(cx);  }
            else if(side == 'r')  { on_right_error(cx); }
            else if(side == 'x')  { on_left_pc_error(cx); }
            else if(side == 'y')  { on_right_pc_error(cx); }

            cx->shutdown();
            return false;
        }
        
        //process new messages before waiting_for_peercom check
        if( cx->new_message() ) {
            _dia("baseProxy::handle_cx_events[%d]: new message!",cx->socket());
            if     (side == 'l') {  on_left_message(cx); }
            else if(side == 'r') { on_right_message(cx); }
            else if(side == 'x')  { on_left_message(cx); }
            else if(side == 'y')  { on_right_message(cx); }
            return false;
        }    
        
        return true;
}

bool baseProxy::handle_cx_read(unsigned char side, baseHostCX* cx) {
    
    _ext("%c in R fdset: %d", side, cx->socket());
    
    bool proceed = cx->readable();
    if(cx->com()->forced_read_on_write_reset()) {
        _dia("baseProxy::handle_cx_read[%c]: read overriden on write socket event",side);
        proceed = true;
    }
    
    if (proceed) {
        _ext("%c in R fdset and readable: %d", side, cx->socket());
        int red = cx->read();
        
        if (red == 0) {
            cx->shutdown();
            //left_sockets.erase(i);
            handle_last_status |= HANDLE_LEFT_ERROR;
            
            state().error_on_read = true;
            if     (side == 'l') { on_left_error(cx); }
            else if(side == 'r') { on_right_error(cx); }
            else if(side == 'x')  { on_left_pc_error(cx); }
            else if(side == 'y')  { on_right_pc_error(cx); }
           
            _dia("baseProxy::handle_cx_read[%c]: error processed",side);
           
            return false;
        }
        
        if (red > 0) {
            meters.last_read += red;
            if     (side == 'l') { on_left_bytes(cx); }
            else if(side == 'r') { on_right_bytes(cx); }
            else if(side == 'x')  { on_left_bytes(cx); }
            else if(side == 'y')  { on_right_bytes(cx); }
            
            _dia("baseProxy::handle_cx_read[%c]: %d bytes processed",side,red);
        }
    }
    
    return true;
}

bool baseProxy::handle_cx_write(unsigned char side, baseHostCX* cx) {
    
    _ext("baseProxy::handle_cx_write[%c]: in write fdset: %d",side, cx->socket());
    
    bool proceed = cx->writable();
    if(cx->com()->forced_write_on_read_reset()) {
        _dia("baseProxy::handle_cx_read[%c]: write overriden on read socket event",side);
        proceed = true;
    }
    
    if (proceed) {
        _ext("baseProxy::handle_cx_write[%c]: writable: %d",side, cx->socket());
        int wrt = cx->write();
        if (wrt < 0) {
            cx->shutdown();
            //left_sockets.erase(i);
            handle_last_status |= HANDLE_LEFT_ERROR;
            
            state().error_on_write = true;
            if     (side == 'l') { on_left_error(cx); }
            else if(side == 'r') { on_right_error(cx); }
            else if(side == 'x') { on_left_pc_error(cx); }
            else if(side == 'y') { on_right_pc_error(cx); }
            
            _dia("baseProxy::handle_cx_write[%c]: error processed",side); 
            
            return false;
        } else {
            meters.last_write += wrt;
            if(wrt > 0) {
                _dia("baseProxy::handle_cx_write[%c]: %d bytes processed",side,wrt);
            }
        }
    }

    return true;
}

bool baseProxy::handle_cx_read_once(unsigned char side, baseCom* xcom, baseHostCX* cx) {

    bool ret = true;
    bool dont_read = false;

    _ext("%c: %d",side, cx->socket());
    if(cx->socket() == 0) {
        _dia("baseProxy::handle_cx_read_once[%c]: monitored socket changed to zero - terminating.",side);
        cx->error(true);
        ret = false;
        goto failure;
    }


    if ((side == 'l' || side == 'x') && state().write_right_bottleneck()) dont_read = true;
    else {
        if ((side == 'r' || side == 'y') && state().write_left_bottleneck()) dont_read = true;
    }

    if(dont_read){
        _dia("baseProxy::handle_cx_read_once[%c]: bottleneck, not reading", side);
    }


    // waiting_for_peercom cx is subject to timeout only, no r/w is done on it ( it would return -1/0 anyway, so spare some cycles)
    if( (!cx->read_waiting_for_peercom()) && (!dont_read) ) {
        bool forced_read = cx->com()->forced_read_reset();
        bool in_read_set = xcom->in_readset(cx->socket());

        if(in_read_set || forced_read) {

            if(forced_read) {
                if(! in_read_set) {
                    _dia("baseProxy::handle_cx_read_once[%c]: forced read, NOT in read set",side);
                } else {
                    _deb("baseProxy::handle_cx_read_once[%c]: forced read, but in read set too",side);
                }
            }
            
            if(! handle_cx_read(side,cx)) {
                ret = false;
                goto failure;
            }
            
            if(cx->com()->forced_write_on_read()) {
                _dia("baseProxy::handle_cx_read_once[%c]: write on read enforced on socket %d",side,cx->socket());
                if(! handle_cx_write(side,cx)) {
                    ret = false;
                    goto failure;
                }
            }
        }
    } else {
        _dia("baseProxy::handle_cx_read_once[%c]: waiting_for_peercom read in cx with socket %d, in read_set: %s",side, cx->socket(),
                                                                 xcom->in_readset(cx->socket()) ? "yes" : "no");
    }

    // on failure, skip all operations and go here
    failure:
    
    // errors are proucts of operations above. Act on them.
    if(! handle_cx_events(side,cx))
        ret = false;    
    
    return ret;
};


// Iterate vector and set monitoring for each cx->socket() according to ifread (read monitor), and ifwrite (write monitor).
// Tricky one:
// paused_* arguments: 0 - don't change anything pausing
//                     greater than 0 - pause read or write
//                     lesser than 0 - unpause read or write

unsigned int baseProxy::change_monitor_for_cx_vec(std::vector<baseHostCX*>* cx_vec, bool ifread, bool ifwrite, int pause_read, int pause_write) {

    unsigned int sockets_changed = 0;

    // do reference
    if(cx_vec) {
        std::vector<baseHostCX *>& nnn = *cx_vec;
        for(auto cx: nnn) {
            if(ifread && ifwrite) {
                cx->com()->change_monitor(cx->socket(),EPOLLIN|EPOLLOUT);
            } else {
                if (ifread) {
                    cx->com()->change_monitor(cx->socket(), EPOLLIN);
                } else if (ifwrite) {
                    cx->com()->change_monitor(cx->socket(), EPOLLOUT);
                } else {
                    cx->com()->unset_monitor(cx->socket());
                }
            }

            if(pause_read != 0) {
                cx->read_waiting_for_peercom(pause_read > 0);
            }
            if(pause_write != 0) {
                cx->write_waiting_for_peercom(pause_write > 0);
            }

            sockets_changed++;
        }
    }

    return sockets_changed;
}

unsigned int baseProxy::change_side_monitoring(char side, bool ifread, bool ifwrite, int pause_read, int pause_write) {

    std::string str_side = "unknown";
    std::vector<baseHostCX*>* normal = nullptr;
    std::vector<baseHostCX*>* bound  = nullptr;


    if (side == 'l' || side == 'x') {
        str_side = "left";
        normal = &ls();
        bound = &lbs();
    }
    if (side == 'r' || side == 'y') {
        str_side = "right";
        normal = &rs();
        bound = &rbs();
    }


    unsigned int sockets_changed = 0;

    if(normal) {
        sockets_changed += change_monitor_for_cx_vec(normal,ifread,ifwrite, pause_read, pause_write);
    }
    if(bound) {
        sockets_changed += change_monitor_for_cx_vec(bound,ifread,ifwrite, pause_read, pause_write);
    }
    _inf("side-wide monitor change for side %c|%s [r %d:w %d - pr %d: pw %d]: %d sockets changed.",
                                              side,str_side.c_str(),
                                                 ifread, ifwrite,
                                                                 pause_read, pause_write, sockets_changed);

    return sockets_changed;
}


bool baseProxy::handle_cx_write_once(unsigned char side, baseCom* xcom, baseHostCX* cx) {

    bool ret = true;
    
    if(cx->socket() == 0) {
        _dia("baseProxy::handle_cx_write_once[%c]: monitored socket changed to zero - terminating.",side);
        cx->error(true);
        ret = false;
        goto failure;
    }    

    if(!cx->write_waiting_for_peercom()) {
        if( xcom->in_writeset(cx->socket()) || cx->com()->forced_write_reset() || ( !cx->writebuf()->empty() ) ) {

            ssize_t  orig_writebuf_size = cx->writebuf()->size();
            ssize_t  cur_writebuf_size = orig_writebuf_size;

            if(! handle_cx_write(side,cx)) {
                ret = false;
                goto failure;
            }
            cur_writebuf_size = cx->writebuf()->size();


            if(cx->com()->forced_read_on_write()) {
                _dia("baseProxy::handle_cx_write_once[%c]: read on write enforced on socket %d",side,cx->socket());
                if(! handle_cx_read(side,cx)) {
                    ret = false;
                    goto failure;
                }
            }

            // if we wanted to write something, but after write we have some left-overs
            if (orig_writebuf_size > 0 && cur_writebuf_size > 0) {

                // on bottleneck, we monitor write on this socket to flush buffered data
                cx->com()->set_write_monitor(cx->socket());

                if (side == 'l' || side == 'L' || side == 'x' || side == 'X') {
                    _inf("left write bottleneck %s!", state().write_left_bottleneck() ? "continuing" : "start");
                    state().write_left_bottleneck(true);
                    change_side_monitoring('r', false, false, 1, 0);

                }
                else
                if(side == 'r' || side == 'R' || side == 'y' || side == 'Y') {
                    _inf("right write bottleneck %s!", state().write_right_bottleneck() ? "continuing" : "start");
                    state().write_right_bottleneck(true);
                    change_side_monitoring('l', false, false, 1, 0);
                }
            } else
            if(orig_writebuf_size > 0 && cur_writebuf_size <= 0){

                // we emptied write buffer!

                if(state().write_left_bottleneck() && (side == 'l' || side == 'L' || side == 'x' || side == 'X')) {
                    _inf("left write bottleneck stop!");
                    state().write_left_bottleneck(false);
                    change_side_monitoring('r',true,false, -1, 0); //FIXME: write monitor enable?
                } else
                if( state().write_right_bottleneck() && (side == 'r' || side == 'R' || side == 'y' || side == 'Y')) {
                    _inf("right write bottleneck stop!");
                    state().write_right_bottleneck(false);
                    change_side_monitoring('l',true,false, -1, 0); //FIXME: write monitor enable?

                }
            } else {
                // orig_writebuf_size == 0
                // not interesting - nothing to write
            }
        }
    }
    
    // on failure, skip all operations and go here
    failure:
    
    // errors are proucts of operations above. Act on them.
    if(! handle_cx_events(side,cx))
        ret = false;    
    
    return ret;
}


bool baseProxy::handle_cx_new(unsigned char side, baseCom* xcom, baseHostCX* thiscx) {
    
    sockaddr_in clientInfo{0};
    socklen_t addrlen = sizeof(clientInfo);

    int client = com()->accept(thiscx->socket(), (sockaddr*)&clientInfo, &addrlen);
    
    if(client < 0) {
        _dia("baseProxy::handle_cx_new[%c]: bound socket accept failed: %s",side,strerror(errno));
        return true; // still, it's not the error which should break socket list iteration
    }
    
    if(new_raw()) {
        _deb("baseProxy::handle_cx_new[%c]: raw processing on %d",side,client);
        if     (side == 'l') { on_left_new_raw(client); }
        else if(side == 'r') { on_right_new_raw(client); }
    }
    else {
        auto* cx = new_cx(client);
        
        // propagate nonlocal setting
        // FIXME: this call is a bit strange, is it?
        // cx->com()->nonlocal_dst(cx->com()->nonlocal_dst());
        
        if(!cx->read_waiting_for_peercom()) {
            _dia("baseProxy::handle_cx_new[%c]: new unpaused socket %d -> accepting",side,client);
            
            cx->on_accept_socket(client);
            //  DON'T: you don't know if this proxy does have child proxy, or wants to handle situation different way.
            //        if(side == 'l') { ladd(cx); }
            //   else if(side == 'r') { radd(cx); }
            
        } else {
            _dia("baseProxy::handle_cx_new[%c]: new waiting_for_peercom socket %d -> delaying",side,client);
            
            cx->on_delay_socket(client);
            //  DON'T: you don't know if this proxy does have child proxy, or wants to handle situation different way.
            //      if(side == 'l') { ldaadd(cx); }
            // else if(side == 'r') { rdaadd(cx); }
        }
        
        if     (side == 'l') { on_left_new(cx); }
        else if(side == 'r') { on_right_new(cx); }
    }
    
    handle_last_status |= HANDLE_LEFT_NEW;
    
    return true;
};


int baseProxy::handle_sockets_once(baseCom* xcom) {

	run_timers();
	
	meters.last_read = 0;
	meters.last_write = 0;

	state().error_on_read = false;
	state().error_on_write = false;
	
    if ( xcom->poll_result >= 0) {


        // READS
		if(! left_sockets.empty() ) {
            for (auto i: left_sockets) {
                if (!handle_cx_read_once('l', xcom, i)) {
                    break;
                }
            }
        }

		if(! right_sockets.empty() ) {
            for (auto i: right_sockets) {
                if (!handle_cx_read_once('r', xcom, i)) {
                    break;
                }
            }
        }

		//WRITES
        if( ! left_sockets.empty() ) {
            for (auto i: left_sockets) {
                if (!handle_cx_write_once('l', xcom, i)) {
                    break;
                }
            }
        }
        if( ! right_sockets.empty() ) {
            for(auto i: right_sockets) {
                if(! handle_cx_write_once('r',xcom, i)) {
                    break;
                }
            }
        }

        // now operate permanent-connect sockets to create accepted sockets
        
        if(! left_pc_cx.empty() ) {
            for (auto i: left_pc_cx) {

                //READS

                // if socket is already in error, don't read, instead just raise again error, if we should reconnect
                if (i->error() and i->should_reconnect_now()) {
                    on_left_pc_error(i);
                    break;
                } else if (i->error()) {
                    break;
                }

                if (!handle_cx_read_once('x', xcom, i)) {
                    handle_last_status |= HANDLE_LEFT_PC_ERROR;

                    state().error_on_read = true;
                    on_left_pc_error(i);
                    break;
                } else {
                    bool opening_status = i->opening();
                    if (opening_status) {
                        on_left_pc_restore(i);
                    }
                }

               //WRITES

                // if socket is already in error, don't read, instead just raise again error, if we should reconnect
                if (i->error() and i->should_reconnect_now()) {
                    on_left_pc_error(i);
                    break;
                } else if (i->error()) {
                    break;
                }

                if (!handle_cx_write_once('x', xcom, i)) {
                    handle_last_status |= HANDLE_LEFT_PC_ERROR;

                    state().error_on_write = true;
                    on_left_pc_error(i);
                    break;
                } else {

                    if (i->opening()) {
                        on_left_pc_restore(i);
                    }
                }
            }
        }
        
        if(! right_pc_cx.empty() ) {
            for (auto i: right_pc_cx) {

                // READS

                // if socket is already in error, don't read, instead just raise again error, if we should reconnect
                if (i->error() and i->should_reconnect_now()) {
                    on_right_pc_error(i);
                    break;
                } else if (i->error()) {
                    break;
                }

                if (!handle_cx_read_once('y', xcom, i)) {
                    handle_last_status |= HANDLE_RIGHT_PC_ERROR;

                    state().error_on_read = true;
                    on_right_pc_error(i);
                    break;
                } else {
                    if (i->opening()) {
                        on_right_pc_restore(i);
                    }
                }


//              // WRITES

                // if socket is already in error, don't read, instead just raise again error, if we should reconnect
                if (i->error() and i->should_reconnect_now()) {
                    on_right_pc_error(i);
                    break;
                } else if (i->error()) {
                    break;
                }

                if (!handle_cx_write_once('y', xcom, i)) {
                    handle_last_status |= HANDLE_RIGHT_PC_ERROR;

                    state().error_on_write = true;
                    on_right_pc_error(i);
                    break;
                } else {

                    if (i->opening()) {
                        on_right_pc_restore(i);
                    }
                }
            }
        }
        
		// no socket is really ready to be processed; while it make sense to check 'connecting' sockets, it makes
		// no sense to loop through bound sockets.
		
		if (xcom->poll_result > 0) {
            // now operate bound sockets to create accepted sockets
            
            if( ! left_bind_sockets.empty() ) {
                for (auto i: left_bind_sockets) {
                    int s = i->socket();
                    if (xcom->in_readset(s)) {
                        handle_cx_new('l', xcom, (i));
                    }
                }
            }
            
            
            // iterate and if unpaused, run the accept_socket and release (add them to regular socket list)
            // we will try to remove them all to not have delays
            
            while(true) {
                bool no_suc = true;
                
                if(! left_delayed_accepts.empty() ) {
                    for (auto i = left_delayed_accepts.begin(); i != left_delayed_accepts.end() ; ++i) {

                        baseHostCX* p = *i;
                        if (! p->read_waiting_for_peercom() ) {
                            p->on_accept_socket(p->socket());

                            ladd(p);
                            left_delayed_accepts.erase(i);

                            _dia("baseProxy::run_once: %s removed from delayed", p->c_name());
                            // restart iterator
                            no_suc = false;
                            break;
                        }
                    }
                }
                
                if(no_suc) break;
            }
            
            if(! right_bind_sockets.empty() ) {
                for (auto i: right_bind_sockets) {
                    int s = i->socket();
                    if (xcom->in_readset(s)) {
                        sockaddr_in clientInfo{0};
                        socklen_t addrlen = sizeof(clientInfo);

                        int client = com()->accept(s, (sockaddr *) &clientInfo, &addrlen);

                        if (new_raw()) {
                            on_right_new_raw(client);
                        } else {
                            baseHostCX *cx = new_cx(client);

                            // propagate nonlocal setting
                            cx->com()->nonlocal_dst(i->com()->nonlocal_dst());

                            if (!cx->read_waiting_for_peercom()) {
                                cx->on_accept_socket(client);
                            } else {
                                cx->on_delay_socket(client);
                                // dealayed accept in effect -- carrier is accepted, but we will postpone higher level accept_socket
                                _deb("baseProxy::handle_sockets_once[%d]: adding to right delayed sockets", client);
                                rdaadd(cx);
                            }
                            on_right_new(cx);
                        }

                        handle_last_status |= HANDLE_RIGHT_NEW;
                    }
                }
            }

            // iterate and if unpaused, run the accept_socket and release (add them to regular socket list)
            // we will try to remove them all to not have delays
            
            while(true) {
                bool no_suc = true;
                
                if(! right_delayed_accepts.empty() ) {
                    for (auto i = right_delayed_accepts.begin(); i != right_delayed_accepts.end() ; ++i ) {

                        baseHostCX* p = *i;
                        if (! p->read_waiting_for_peercom() ) {
                            p->on_accept_socket(p->socket());
                            radd(p);
                            right_delayed_accepts.erase(i);

                            // restart iterator
                            no_suc = false;
                            break;
                        }
                    }
                }

                if(no_suc) break;
            }		
        }

		
// 		_dia("_");

        // handle the case when we are running this cycle due to n_tv timeout. In such a case return 0 to sleep accordingly.
        if (xcom->poll_result ==  0) {
            return 0;
        } else {
            return  meters.last_read + meters.last_write;
        }
    }
    return 0;
};



void baseProxy::on_left_bytes(baseHostCX* cx) {
	_deb("Left context bytes: %s, bytes in buffer: %d", cx->c_name(), cx->readbuf()->size());
};


void baseProxy::on_right_bytes(baseHostCX* cx) {
	_deb("Right context bytes: %s, bytes in buffer: %d", cx->c_name(), cx->readbuf()->size());
};


void baseProxy::on_left_error(baseHostCX* cx) {
	if (cx->opening()) {
		_err("Left socket connection timeout %s:",cx->c_name());
	} else {
		_not("Left socket error: %s", cx->c_name());
	}
};


void baseProxy::on_right_error(baseHostCX* cx) {
	if (cx->opening()) {
		_err("Right socket connection timeout %s:",cx->c_name());
	} else {	
		_not("Right socket error: %s", cx->c_name());
	}
};


void baseProxy::on_left_pc_error(baseHostCX* cx) {
	_dum("Left permanent-connect socket error: %s",cx->c_name());
	
	if (cx->opening()) {
		_err("Left permanent socket connection timeout %s:",cx->c_name());	
	}
	else if ( cx->reconnect()) {
		_inf("reconnecting");
	} 
	else {
		_dum("reconnection postponed");
	}
};


void baseProxy::on_right_pc_error(baseHostCX* cx) {
	_dum("Right permanent-connect socket error: %s",cx->c_name());

	if (cx->opening()) {
		_dia("Right permanent socket connection timeout %s:",cx->c_name());	
	}
	
	if ( cx->reconnect()) {
		_dia("Reconnecting %s",cx->c_name());
	} 
	else {
		_dum("reconnection postponed");
	}
};


void baseProxy::on_left_pc_restore(baseHostCX* cx) {
    _dia("Left permanent connection restored: %s",cx->c_name());
    cx->opening(false);
    com()->set_monitor(cx->socket());
    com()->set_poll_handler(cx->socket(),this);
}


void baseProxy::on_right_pc_restore(baseHostCX* cx) {
    _dia("Right permanent connection restored: %s",cx->c_name());
    cx->opening(false);
    com()->set_monitor(cx->socket());
    com()->set_poll_handler(cx->socket(),this);    
}


void baseProxy::on_left_new(baseHostCX* cx) {
	ladd(cx);
};


void baseProxy::on_right_new(baseHostCX* cx) {
	radd(cx);
};


// Infinite loop ... 

int baseProxy::run() {
    
    while(! state().dead() ) {
        
        if(pollroot()) {
            
            _ext("baseProxy::run: preparing sockets");
            int s_max = prepare_sockets(com());
            _ext("baseProxy::run: sockets prepared");
            if (s_max) {
                com()->poll();
            }
            
            int counter_proxy_handler = 0;
            int counter_generic_handler = 0;
            int counter_back_handler = 0;
            int counter_hint_handler = 0;

            int counter_fence_fail = 0;

            std::vector<int> back_in_set;
            
            // std::set<int>& sets[] = { com()->poller.poller->in_set, com()->poller.poller->out_set };
            std::vector<epoll::set_type*> sets;
            sets.push_back(&com()->poller.poller->in_set);
            sets.push_back(&com()->poller.poller->out_set);
            sets.push_back(&com()->poller.poller->idle_set);
            
            std::vector<std::string> setname = { "inset","outset", "idleset" };
            int name_iter = 0;

            bool virt_global_hack = false;
            epoll::set_type udp_in_set;
            
            auto* uc = dynamic_cast<UDPCom*>(com()->master());
            if(uc) {
                
                //_inf("adding virtual sockets");
                {
                    std::scoped_lock<std::recursive_mutex> m(UDPCom::lock);
                    udp_in_set = UDPCom::in_virt_set;
                }
                
                sets.push_back(&udp_in_set);
                setname.emplace_back("inset_virt");
            }
            
            for (epoll::set_type * current_set: sets) {
                 
                for (auto s: *current_set) {
                    //FIXME
                    _deb("baseProxy::run: %s socket %d ",setname.at(name_iter).c_str(),s);
                    epoll_handler* p_handler = com()->poller.get_handler(s);
                    
                    if(p_handler != nullptr) {

                        auto seg = p_handler->fence__;
                        _ext("baseProxy::run: socket %d has registered handler 0x%x (fence %x)",s,p_handler,seg);
                        
                        if(seg != HANDLER_FENCE) {
                            _err("baseProxy::run: socket %d magic fence doesn't match!!",s);
                            counter_fence_fail++;

                        } else {

                            // Try if handler is a proxy object. If so, call different method.
                            // This design is intentional, to separate meaning of "handling socket"
                            // by proxy (which might be killed and terminated)
                            // and generic "event handler".

                            auto* proxy = dynamic_cast<baseProxy*>(p_handler);
                            if(proxy != nullptr) {
                                _ext("baseProxy::run: socket %d has baseProxy handler!!",s);
                                
                                // call poller-carried proxy handler!
                                proxy->handle_sockets_once(com());
                                if(proxy->state().dead()) {
                                    proxy->shutdown();
                                    _dia("Proxy 0x%x has been shutdown.", proxy);
                                }
                                
                                counter_proxy_handler++;
                                
                            } else {

                                _ext("baseProxy::run: socket %d has generic handler",s);
                                p_handler->handle_event(com());
                                counter_generic_handler++;
                            }
                        }
                        
                    } else {
                        
                        //FIXME: report virtual sockets too, in the future
                        
                        _deb("baseProxy::run: socket %d has NO handler!!",s);

                        // all real sockets without ANY handler should be re-inserted
                        if(s > 0) {
                            back_in_set.push_back(s);
                        }
                        
                        if (com()->poller.poller) {
                            if(s != com()->poller.poller->hint_socket()) {
                                if(s < 0) {
                                    _ext("virtual socket %d has null handler",s);
                                    virt_global_hack = true;
                                }else {
                                    _err("baseProxy::run: socket %d has registered NULL handler, removing",s);
                                    com()->poller.poller->del(s);
                                }
                            } else {
                                // hint file descriptor don't have handler
                                _deb("baseProxy::run: socket %d is hint socket, running proxy socket handler",s);
                                handle_sockets_once(com());
                                counter_hint_handler++;
                            }
                        } else {
                            _err("com()->poller.poller is null!");                        
                        }
                    }
                }
                
                name_iter++;
            }
            
            // clear in_set, so already handled sockets are excluded
            com()->poller.poller->in_set.clear();
            
            // add back sockets which don't have handler - generally it should be just few sockets!

            if(!back_in_set.empty())  _deb("%d sockets in back_in_set re-added to in_set", back_in_set.size());

            for(int a: back_in_set) {
                counter_back_handler++;
                
                com()->poller.poller->in_set.insert(a);
            }
            
            run_timers();
            
            if(virt_global_hack) {
                handle_sockets_once(com());
            }
            
            if(counter_proxy_handler || counter_generic_handler || counter_back_handler) {
                _dia("baseProxy::run: called handlers - proxy: %d, gen: %d, back-ins: %d, hint: %d",counter_proxy_handler,
                        counter_generic_handler, counter_back_handler, counter_hint_handler);
            }
            if (virt_global_hack && !udp_in_set.empty())  _deb("baseProxy::run: virtual hack, virtuals: %d", udp_in_set.size());
            if (counter_fence_fail) _err("baseProxy::run: fence failures: %d", counter_fence_fail);
        }

        on_run_round();
    }

    return 0;
};

void baseProxy::sleep() {
  
	unsigned int x_time = sleep_time();
  
	if(sleep_factor_ > 0 && sleep_factor_ < 10) {

	  // do some progressive slowdown
	  x_time = sleep_time() * sleep_factor_;
	}
  
	usleep(x_time);
	sleep_factor_++;
}



int baseProxy::bind(unsigned short port, unsigned char side) {
	
	int s = com()->bind(port);
	
	// this function will always return value of 'port' parameter (but <=0 will not be added)
	
	auto *cx = new baseHostCX(com()->replicate(), s);
        cx->host() = string_format("listening_%d",port);
	cx->com()->nonlocal_dst(com()->nonlocal_dst());
	
	if ( s > 0 ) {
		if ( side == 'L' || side == 'l') lbadd(cx);
		else rbadd(cx);
	}

	return s;
};


int baseProxy::bind(std::string const& path, unsigned char side) {
    
    int s = com()->bind(path.c_str());
    
    // this function will always return value of 'port' parameter (but <=0 will not be added)
    
    auto* cx = new baseHostCX(com()->replicate(), s);
    cx->host() = string_format("listening_%s",path);
    cx->com()->nonlocal_dst(com()->nonlocal_dst());
    
    if ( s > 0 ) {
        if ( side == 'L') lbadd(cx);
        else rbadd(cx);
    }

    return s;
};



baseHostCX* baseProxy::new_cx(int s) {
	return new baseHostCX(com()->replicate(),s);
}


baseHostCX* baseProxy::new_cx(const char* host, const char* port) {
	return new baseHostCX(com()->replicate(),host,port);
}



int baseProxy::connect ( const char* host, const char* port, char side,bool blocking) {
	if (side == 'L') {
		return left_connect(host,port,blocking);
	}
	return right_connect(host,port,blocking);
}


int baseProxy::left_connect ( const char* host, const char* port, bool blocking)
{
	baseHostCX* cx = new_cx(host,port);
	
	int sock = cx->connect();
        if(sock > 0) {
            _dia("baseProxy::left_connect: successfully created socket %d", sock);
            lpcadd(cx);
        } else {
            _err("baseProxy::left_connect: socket not created, returned %s", sock);
        } 
        
        return sock;
};


int baseProxy::right_connect ( const char* host, const char* port, bool blocking)
{
	baseHostCX* cx = new_cx(host,port);
        int sock = cx->connect();
        if(sock > 0) {
            _dia("baseProxy::left_connect: successfully created socket %d", sock);
            rpcadd(cx);
        } else {
            _err("baseProxy::left_connect: socket not created, returned %s", sock);
        } 
        
        return sock;
};



std::string baseProxy::to_string(int verbosity) const {

    std::string ret;
    ret.append(" ");

	int lb = left_bind_sockets.size();
	int ls = left_sockets.size();
    int la = left_delayed_accepts.size();
	int lp = left_pc_cx.size();
	int rb = right_bind_sockets.size();
    int ra = right_delayed_accepts.size();
	int rs = right_sockets.size();
	int rp = right_pc_cx.size();

	bool empty = true;
	
	if(lb > 0) {
		for(auto ii: left_bind_sockets) { ret += ("a: " + ii->to_string(verbosity) + " "); };
		empty = false;
	}
	if(ls > 0) {
		for(auto ii: left_sockets) { ret += ("l:" + ii->to_string(verbosity) + " "); };
		empty = false;	
	}
    if(la > 0) {
        for(auto ii: left_delayed_accepts) { ret += ("l:" + ii->to_string(verbosity) + " "); };
        empty = false;  
    }
	if(lp > 0) {
		for(auto ii: left_pc_cx) { ret += ("x:" + ii->to_string(verbosity) + " "); };
		empty = false;	
	}
	
	ret += "<+> ";
	
	if(rb > 0) {
		for(auto ii: right_bind_sockets) { ret += ("b:" + ii->to_string(verbosity) + " "); };
		empty = false;	
	}
	if(rs > 0) {
		for(auto ii: right_sockets) { ret += ("r:" + ii->to_string(verbosity) + " "); };
		empty = false;	
	}
    if(ra > 0) {
        for(auto ii: right_delayed_accepts) { ret += ("r:" + ii->to_string(verbosity) + " "); };
        empty = false;  
    }
	if(rp > 0) {
		for(auto ii: right_pc_cx) { ret += ("y:" + ii->to_string(verbosity) + " "); };
		empty = false;	
	}
	
	if(verbosity > DIA) {
        ret += "\n";
        ret += string_format("    parent id: 0x%x, poll_root: %d", parent(),pollroot());
    }
	
	if (empty) {
		ret += "<empty> ";
	}
	return ret;
}
