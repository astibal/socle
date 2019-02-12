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
#include <logger.hpp>
#include "udpcom.hpp"

#define BUFSIZE 9216

extern int errno;

DEFINE_LOGGING(baseProxy);

baseProxy::baseProxy(baseCom* c) :
dead_(false),
new_raw_(false),
parent_(NULL),
error_on_read(false),
error_on_write(false),
meter_last_read(0),
meter_last_write(0),
handle_last_status(0)
{
    com_ = c;
	set_sleeptime(1000);
	time(&last_tick_);
};


baseProxy::~baseProxy() {
	shutdown(); 
    
    if (com_ != nullptr) {
        DUMS___("Proxy: deleting com");
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
    DIA___("baseProxy::ladd: added socket: %s",cs->c_name());
};


void baseProxy::radd(baseHostCX* cs) {
    cs->unblock();
    
    //int s = cs->com()->translate_socket(cs->socket());
    int s = cs->socket();
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);
    right_sockets.push_back(cs);
    DIA___("baseProxy::radd: added socket: %s",cs->c_name());
};


void baseProxy::lbadd(baseHostCX* cs) {
    
    int s = cs->com()->translate_socket(cs->socket());
    
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);
    left_bind_sockets.push_back(cs);
	DIA___("baseProxy::lbadd: added bound socket: %s",cs->c_name());
};


void baseProxy::rbadd(baseHostCX* cs) {
    
    int s = cs->com()->translate_socket(cs->socket());
    
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);
    right_bind_sockets.push_back(cs);
	DIA___("baseProxy::rbadd: added bound socket: %s",cs->c_name());
};


void baseProxy::lpcadd(baseHostCX* cx) {
    cx->permanent(true);
    int s = cx->com()->translate_socket(cx->socket());
    
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);
    left_pc_cx.push_back(cx);
    DIA___("baseProxy::lpcadd: added perma socket: %s", cx->c_name());
};


void baseProxy::rpcadd(baseHostCX* cx) {
    cx->permanent(true);
    int s = cx->com()->translate_socket(cx->socket());
    
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);
    
    right_pc_cx.push_back(cx);
    DIA___("baseProxy::rpcadd: added perma socket %s", cx->c_name());
};


void baseProxy::ldaadd(baseHostCX* cs) {
    
    int s = cs->com()->translate_socket(cs->socket());
    
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);

    left_delayed_accepts.push_back(cs);
    DIA___("baseProxy::ldaadd: added delayed socket: %s",cs->c_name());
};


void baseProxy::rdaadd(baseHostCX* cs) {
    int s = cs->com()->translate_socket(cs->socket());
    
    com()->set_monitor(s);
    com()->set_poll_handler(s,this);
    
    right_delayed_accepts.push_back(cs);
    DIA___("baseProxy::rdaadd: added delayed socket: %s",cs->c_name());
};



void baseProxy::left_shutdown() {
	int lb = left_bind_sockets.size();
	int ls = left_sockets.size();
	int lp = left_pc_cx.size();
	
	int ld = left_delayed_accepts.size();
	
	for(typename std::vector<baseHostCX*>::iterator ii = left_bind_sockets.begin(); ii != left_bind_sockets.end(); ++ii) { (*ii)->shutdown(); };
	for(typename std::vector<baseHostCX*>::iterator ii = left_sockets.begin(); ii != left_sockets.end(); ++ii) { (*ii)->shutdown();  };
	for(typename std::vector<baseHostCX*>::iterator ii = left_pc_cx.begin(); ii != left_pc_cx.end(); ++ii) { (*ii)->shutdown(); };
    for(typename std::vector<baseHostCX*>::iterator ii = left_delayed_accepts.begin(); ii != left_delayed_accepts.end(); ++ii) { (*ii)->shutdown(); };

    
    for(typename std::vector<baseHostCX*>::iterator ii = left_bind_sockets.begin(); ii != left_bind_sockets.end(); ++ii) { delete(*ii); };
    left_bind_sockets.clear();
    for(typename std::vector<baseHostCX*>::iterator ii = left_sockets.begin(); ii != left_sockets.end(); ++ii) {  delete(*ii); };
    left_sockets.clear();
    for(typename std::vector<baseHostCX*>::iterator ii = left_pc_cx.begin(); ii != left_pc_cx.end(); ++ii) {  delete(*ii); };
    left_pc_cx.clear();
    for(typename std::vector<baseHostCX*>::iterator ii = left_delayed_accepts.begin(); ii != left_delayed_accepts.end(); ++ii) { delete(*ii); };
    left_delayed_accepts.clear();       
    
 	DEB___("baseProxy::left_shutdown: bind=%d(delayed=%d), sock=%d, perm=%d",lb,ld,ls,lp);
}


void baseProxy::right_shutdown() {
	int rb = right_bind_sockets.size();
	int rs = right_sockets.size();
	int rp = right_pc_cx.size();
    
    int rd = right_delayed_accepts.size();
	
	for(typename std::vector<baseHostCX*>::iterator ii = right_bind_sockets.begin(); ii != right_bind_sockets.end(); ++ii) { (*ii)->shutdown(); };
	for(typename std::vector<baseHostCX*>::iterator ii = right_sockets.begin(); ii != right_sockets.end(); ++ii) { (*ii)->shutdown(); };
	for(typename std::vector<baseHostCX*>::iterator ii = right_pc_cx.begin(); ii != right_pc_cx.end(); ++ii) { (*ii)->shutdown();  };
    for(typename std::vector<baseHostCX*>::iterator ii = right_delayed_accepts.begin(); ii != right_delayed_accepts.end(); ++ii) { (*ii)->shutdown(); };

    
    for(typename std::vector<baseHostCX*>::iterator ii = right_bind_sockets.begin(); ii != right_bind_sockets.end(); ++ii) {  delete(*ii); };
    right_bind_sockets.clear();
    for(typename std::vector<baseHostCX*>::iterator ii = right_sockets.begin(); ii != right_sockets.end(); ++ii) {  delete(*ii); };
    right_sockets.clear();
    for(typename std::vector<baseHostCX*>::iterator ii = right_pc_cx.begin(); ii != right_pc_cx.end(); ++ii) { delete(*ii); };
    right_pc_cx.clear();
    for(typename std::vector<baseHostCX*>::iterator ii = right_delayed_accepts.begin(); ii != right_delayed_accepts.end(); ++ii) {  delete(*ii); };
    right_delayed_accepts.clear();      
    
    
	DEB___("baseProxy::right_shutdown: bind=%d(delayed=%d), sock=%d, perm=%d",rb,rd,rs,rp);
}


void baseProxy::shutdown() {
    DIAS___("baseProxy::shutdown");
	left_shutdown();
	right_shutdown();
    DEBS___("baseProxy::shutdown finished");
}



int baseProxy::lsize() {
	return (left_sockets.size()+left_bind_sockets.size()+left_pc_cx.size()+left_delayed_accepts.size());
}


int baseProxy::rsize() {
	return (right_sockets.size()+right_bind_sockets.size()+right_pc_cx.size()+right_delayed_accepts.size());
}


void baseProxy::set_clock() {
	time(&clock_);
}


bool baseProxy::run_timer(baseHostCX* cx) {
	
	if( clock_ - last_tick_ > timer_interval) {
		cx->on_timer();
		return true;
	}
	
	return false;
}


void baseProxy::reset_timer() {

	if( clock_ - last_tick_ > timer_interval) {	
		time(&last_tick_);
	}
}


// (re)set socket set and calculate max socket no

void baseProxy::run_timers(void) {

	set_clock();

	for(typename std::vector<baseHostCX*>::iterator i = left_sockets.begin(); i != left_sockets.end(); ++i) {
		run_timer(*i);
    }
	for(typename std::vector<baseHostCX*>::iterator ii = left_bind_sockets.begin(); ii != left_bind_sockets.end(); ++ii) {
		run_timer(*ii);
    }

    for(typename std::vector<baseHostCX*>::iterator j = right_sockets.begin(); j != right_sockets.end(); ++j) {
		run_timer(*j);
    }
	for(typename std::vector<baseHostCX*>::iterator jj = right_bind_sockets.begin(); jj != right_bind_sockets.end(); ++jj) {
		run_timer(*jj);
    }    
    
	for(typename std::vector<baseHostCX*>::iterator k = left_pc_cx.begin(); k != left_pc_cx.end(); ++k) {
		run_timer(*k);
	}
	for(typename std::vector<baseHostCX*>::iterator l = right_pc_cx.begin(); l != right_pc_cx.end(); ++l) {    
		run_timer(*l);		
	}

    for(typename std::vector<baseHostCX*>::iterator k = left_delayed_accepts.begin(); k != left_delayed_accepts.end(); ++k) {
        run_timer(*k);
    }
    for(typename std::vector<baseHostCX*>::iterator l = right_delayed_accepts.begin(); l != right_delayed_accepts.end(); ++l) {    
        run_timer(*l);      
    }	
	
	reset_timer();
};

// (re)set socket set and calculate max socket no

int baseProxy::prepare_sockets(baseCom* fdset_owner) {
     int max = 1;


     return max;
};


bool baseProxy::handle_cx_events(unsigned char side, baseHostCX* cx) {
        // treat non-blocking still opening sockets 
        if( cx->opening_timeout() ) {
            DIA___("baseProxy::handle_cx_events[%d]: opening timeout!",cx->socket());
            
                 if(side == 'l')  { on_left_error(cx);  }
            else if(side == 'r')  { on_right_error(cx); }
            else if(side == 'x')  { on_left_pc_error(cx); }
            else if(side == 'y')  { on_right_pc_error(cx); }

            cx->shutdown();
            return false;
        }
        if( cx->idle_timeout() ) {
            DIA___("baseProxy::handle_cx_events[%d]: idle timeout!",cx->socket());

                 if(side == 'l')  { on_left_error(cx);  }
            else if(side == 'r')  { on_right_error(cx); }
            else if(side == 'x')  { on_left_pc_error(cx); }
            else if(side == 'y')  { on_right_pc_error(cx); }

            cx->shutdown();
            return false;
        }
        if( cx->error() ) {
            DIA___("baseProxy::handle_cx_events[%d]: error!",cx->socket());

                 if(side == 'l')  { on_left_error(cx);  }
            else if(side == 'r')  { on_right_error(cx); }
            else if(side == 'x')  { on_left_pc_error(cx); }
            else if(side == 'y')  { on_right_pc_error(cx); }

            cx->shutdown();
            return false;
        }
        
        //process new messages before waiting_for_peercom check
        if( cx->new_message() ) {
            DIA___("baseProxy::handle_cx_events[%d]: new message!",cx->socket());
                 if(side == 'l') {  on_left_message(cx); }
            else if(side == 'r') { on_right_message(cx); }
            else if(side == 'x')  { on_left_message(cx); }
            else if(side == 'y')  { on_right_message(cx); }
            return false;
        }    
        
        return true;
}

bool baseProxy::handle_cx_read(unsigned char side, baseHostCX* cx) {
    
    EXT___("%c in R fdset: %d", side, cx->socket());
    
    bool proceed = cx->readable();
    if(cx->com()->forced_read_on_write_reset()) {
        DIA___("baseProxy::handle_cx_read[%c]: read overriden on write socket event",side);
        proceed = true;
    }
    
    if (proceed) {
        EXT___("%c in R fdset and readable: %d", side, cx->socket())
        int red = cx->read();
        
        if (red == 0) {
            cx->shutdown();
            //left_sockets.erase(i);
            handle_last_status |= HANDLE_LEFT_ERROR;
            
            error_on_read = true;
                 if(side == 'l') { on_left_error(cx); }
            else if(side == 'r') { on_right_error(cx); }
            else if(side == 'x')  { on_left_pc_error(cx); }
            else if(side == 'y')  { on_right_pc_error(cx); }
           
            DIA___("baseProxy::handle_cx_read[%c]: error processed",side);
           
            return false;
        }
        
        if (red > 0) {
            meter_last_read += red;
                 if(side == 'l') { on_left_bytes(cx); }
            else if(side == 'r') { on_right_bytes(cx); }
            else if(side == 'x')  { on_left_bytes(cx); }
            else if(side == 'y')  { on_right_bytes(cx); }
            
            DIA___("baseProxy::handle_cx_read[%c]: %d bytes processed",side,red);
        }
    }
    
    return true;
}

bool baseProxy::handle_cx_write(unsigned char side, baseHostCX* cx) {
    
    EXT___("baseProxy::handle_cx_write[%c]: in write fdset: %d",side, cx->socket());
    
    bool proceed = cx->writable();
    if(cx->com()->forced_write_on_read_reset()) {
        DIA___("baseProxy::handle_cx_read[%c]: write overriden on read socket event",side)
        proceed = true;
    }
    
    if (proceed) {
        EXT___("baseProxy::handle_cx_write[%c]: writable: %d",side, cx->socket())
        int wrt = cx->write();
        if (wrt < 0) {
            cx->shutdown();
            //left_sockets.erase(i);
            handle_last_status |= HANDLE_LEFT_ERROR;
            
            error_on_write = true;
                 if(side == 'l') { on_left_error(cx); }
            else if(side == 'r') { on_right_error(cx); }
            else if(side == 'x') { on_left_pc_error(cx); }
            else if(side == 'y') { on_right_pc_error(cx); }
            
            DIA___("baseProxy::handle_cx_write[%c]: error processed",side); 
            
            return false;
        } else {
            meter_last_write += wrt;
            if(wrt > 0) {
                DIA___("baseProxy::handle_cx_write[%c]: %d bytes processed",side,wrt);
            }
        }
    }

    return true;
}

bool baseProxy::handle_cx_read_once(unsigned char side, baseCom* xcom, baseHostCX* cx) {

    bool ret = true;
    bool dont_read = false;

    EXT___("%c: %d",side, cx->socket());
    if(cx->socket() == 0) {
        DIA___("baseProxy::handle_cx_read_once[%c]: monitored socket changed to zero - terminating.",side);
        cx->error(true);
        ret = false;
        goto failure;
    }


    if ((side == 'l' || side == 'x') && write_right_bottleneck()) dont_read = true;
    else
    if ((side == 'r' || side == 'y') && write_left_bottleneck()) dont_read = true;

    if(dont_read){
        DIA___("baseProxy::handle_cx_read_once[%c]: bottleneck, not reading",side);
    }


    // waiting_for_peercom cx is subject to timeout only, no r/w is done on it ( it would return -1/0 anyway, so spare some cycles)
    if( (!cx->read_waiting_for_peercom()) && (!dont_read) ) {
        bool forced_read = cx->com()->forced_read_reset();
        bool in_read_set = xcom->in_readset(cx->socket());

        if(in_read_set || forced_read) {

            if(forced_read) {
                if(! in_read_set) {
                    DIA___("baseProxy::handle_cx_read_once[%c]: forced read, NOT in read set",side);
                } else {
                    DEB___("baseProxy::handle_cx_read_once[%c]: forced read, but in read set too",side);
                }
            }
            
            if(! handle_cx_read(side,cx)) {
                ret = false;
                goto failure;
            }
            
            if(cx->com()->forced_write_on_read()) {
                DIA___("baseProxy::handle_cx_read_once[%c]: write on read enforced on socket %d",side,cx->socket());
                if(! handle_cx_write(side,cx)) {
                    ret = false;
                    goto failure;
                }
            }
        }
    } else {
        DIA___("baseProxy::handle_cx_read_once[%c]: waiting_for_peercom read in cx with socket %d, in read_set: %s",side, cx->socket(),
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
            } else
            if(ifread) {
                cx->com()->change_monitor(cx->socket(),EPOLLIN);
            } else
            if(ifwrite){
                cx->com()->change_monitor(cx->socket(),EPOLLOUT);
            } else {
                cx->com()->unset_monitor(cx->socket());
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
    INF___("side-wide monitor change for side %c|%s [r %d:w %d - pr %d: pw %d]: %d sockets changed.",
                                              side,str_side.c_str(),
                                                 ifread, ifwrite,
                                                                 pause_read, pause_write, sockets_changed);

    return sockets_changed;
}


bool baseProxy::handle_cx_write_once(unsigned char side, baseCom* xcom, baseHostCX* cx) {

    bool ret = true;
    
    if(cx->socket() == 0) {
        DIA___("baseProxy::handle_cx_write_once[%c]: monitored socket changed to zero - terminating.",side);
        cx->error(true);
        ret = false;
        goto failure;
    }    

    if(!cx->write_waiting_for_peercom()) {
        if(xcom->in_writeset(cx->socket()) || cx->com()->forced_write_reset() || cx->writebuf()->size() > 0) {

            ssize_t  orig_writebuf_size = cx->writebuf()->size();
            ssize_t  cur_writebuf_size = orig_writebuf_size;

            if(! handle_cx_write(side,cx)) {
                ret = false;
                goto failure;
            }
            cur_writebuf_size = cx->writebuf()->size();


            if(cx->com()->forced_read_on_write()) {
                DIA___("baseProxy::handle_cx_write_once[%c]: read on write enforced on socket %d",side,cx->socket());
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
                    INF___("left write bottleneck %s!", write_left_bottleneck() ? "continuing" : "start");
                    write_left_bottleneck(true);
                    change_side_monitoring('r', false, false, 1, 0);

                }
                else
                if(side == 'r' || side == 'R' || side == 'y' || side == 'Y') {
                    INF___("right write bottleneck %s!", write_right_bottleneck() ? "continuing" : "start");
                    write_right_bottleneck(true);
                    change_side_monitoring('l', false, false, 1, 0);
                }
            } else
            if(orig_writebuf_size > 0 && cur_writebuf_size <= 0){

                // we emptied write buffer!

                if(write_left_bottleneck() && (side == 'l' || side == 'L' || side == 'x' || side == 'X')) {
                    INFS___("left write bottleneck stop!");
                    write_left_bottleneck(false);
                    change_side_monitoring('r',true,false, -1, 0); //FIXME: write monitor enable?
                } else
                if(write_right_bottleneck() && (side == 'r' || side == 'R' || side == 'y' || side == 'Y')) {
                    INFS___("right write bottleneck stop!");
                    write_right_bottleneck(false);
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


bool baseProxy::handle_cx_new(unsigned char side, baseCom* xcom, baseHostCX* cx) {
    
    sockaddr_in clientInfo;
    socklen_t addrlen = sizeof(clientInfo);

    int client = com()->accept(cx->socket(), (sockaddr*)&clientInfo, &addrlen);
    
    if(client < 0) {
        DIA___("baseProxy::handle_cx_new[%c]: bound socket accept failed: %s",side,strerror(errno));
        return true; // still, it's not the error which should break socket list iteration
    }
    
    if(new_raw()) {
        DEB___("baseProxy::handle_cx_new[%c]: raw processing on %d",side,client);
             if(side == 'l') { on_left_new_raw(client); }
        else if(side == 'r') { on_right_new_raw(client); }
    }
    else {
        baseHostCX* cx = new_cx(client);
        
        // propagate nonlocal setting
        // FIXME: this call is a bit strange, is it?
        // cx->com()->nonlocal_dst(cx->com()->nonlocal_dst());
        
        if(!cx->read_waiting_for_peercom()) {
            DIA___("baseProxy::handle_cx_new[%c]: new unpaused socket %d -> accepting",side,client);
            
            cx->on_accept_socket(client);
            //  DON'T: you don't know if this proxy does have child proxy, or wants to handle situation different way.
            //        if(side == 'l') { ladd(cx); }
            //   else if(side == 'r') { radd(cx); }
            
        } else {
            DIA___("baseProxy::handle_cx_new[%c]: new waiting_for_peercom socket %d -> delaying",side,client);
            
            cx->on_delay_socket(client);
            //  DON'T: you don't know if this proxy does have child proxy, or wants to handle situation different way.
            //      if(side == 'l') { ldaadd(cx); }
            // else if(side == 'r') { rdaadd(cx); }
        }
        
             if(side == 'l') { on_left_new(cx); }
        else if(side == 'r') { on_right_new(cx); }
    }
    
    handle_last_status |= HANDLE_LEFT_NEW;
    
    return true;
};


int baseProxy::handle_sockets_once(baseCom* xcom) {

	run_timers();
	
	meter_last_read = 0;
	meter_last_write = 0;
	error_on_read = false;
	error_on_write = false;
	
    if ( xcom->poll_result >= 0) {


        // READS
		if(left_sockets.size() > 0)
		for(typename std::vector<baseHostCX*>::iterator i = left_sockets.begin(); i != left_sockets.end(); ++i) {
			if(! handle_cx_read_once('l',xcom,*i)) {
                break;
            }
		}
		if(right_sockets.size() > 0)
		for(typename std::vector<baseHostCX*>::iterator j = right_sockets.begin(); j != right_sockets.end(); ++j) {
            if(! handle_cx_read_once('r',xcom,*j)) {
                break;
            }
		}

		//WRITES
        if(left_sockets.size() > 0)
        for(typename std::vector<baseHostCX*>::iterator i = left_sockets.begin(); i != left_sockets.end(); ++i) {
            if(! handle_cx_write_once('l',xcom,*i)) {
                break;
            }
        }
        if(right_sockets.size() > 0)
        for(typename std::vector<baseHostCX*>::iterator j = right_sockets.begin(); j != right_sockets.end(); ++j) {
            if(! handle_cx_write_once('r',xcom,*j)) {
                break;
            }
        }

        // now operate permanent-connect sockets to create accepted sockets
        
        if(left_pc_cx.size() > 0)
        for(typename std::vector<baseHostCX*>::iterator k = left_pc_cx.begin(); k != left_pc_cx.end(); ++k) {

            
            //READS
            
            // if socket is already in error, don't read, instead just raise again error, if we should reconnect
            if ((*k)->error() and (*k)->should_reconnect_now()) {
                on_left_pc_error(*k);
                break;
            } else if ((*k)->error()) {
                break;
            }

            if (!handle_cx_read_once('x',xcom, *k)) {
                handle_last_status |= HANDLE_LEFT_PC_ERROR;
                
                error_on_read = true;
                on_left_pc_error(*k);
                break;
            } else {
                bool opening_status = (*k)->opening();
                if (opening_status) {
                    on_left_pc_restore(*k);
                }
            }
            

            //WRITES

            // if socket is already in error, don't read, instead just raise again error, if we should reconnect
            if ((*k)->error() and (*k)->should_reconnect_now()) {
                on_left_pc_error(*k);
                break;
            } else if ((*k)->error()) {
                break;
            }
                        
            if(!handle_cx_write_once('x',xcom,*k)) {
                        handle_last_status |= HANDLE_LEFT_PC_ERROR;
                        
                        error_on_write = true;
                        on_left_pc_error(*k);
                        break;
            } 
            else {
                
                if ((*k)->opening()) {
                    on_left_pc_restore(*k);
                }
            }       
        }
        
        if(right_pc_cx.size() > 0)
        for(typename std::vector<baseHostCX*>::iterator l = right_pc_cx.begin(); l != right_pc_cx.end(); ++l) {

        
            // if socket is already in error, don't read, instead just raise again error, if we should reconnect
            if ((*l)->error() and (*l)->should_reconnect_now()) {
                on_right_pc_error(*l);
                break;
            } else if ((*l)->error()) {
                break;
            }
            
            if (!handle_cx_read_once('y',xcom,*l)) {
                handle_last_status |= HANDLE_RIGHT_PC_ERROR;
                
                error_on_read = true;
                on_right_pc_error(*l);
                break;
            } else {
                if ((*l)->opening()) {
                    on_right_pc_restore(*l);
                }
            }

        
            // if socket is already in error, don't read, instead just raise again error, if we should reconnect
            if ((*l)->error() and (*l)->should_reconnect_now()) {
                on_right_pc_error(*l);
                break;
            } else if ((*l)->error()) {
                break;
            }            


            if (!handle_cx_write_once('y',xcom,*l)) {
                handle_last_status |= HANDLE_RIGHT_PC_ERROR;
                
                error_on_write = true;
                on_right_pc_error(*l);
                break;
            } 
            else {
                
                if ((*l)->opening()) {
                    on_right_pc_restore(*l);
                }
            }       
        } 
        
        
		// no socket is really ready to be processed; while it make sense to check 'connecting' sockets, it makes
		// no sense to loop through bound sockets.
		
		if (xcom->poll_result > 0) {
            // now operate bound sockets to create accepted sockets
            
            if(left_bind_sockets.size() > 0)
            for(typename std::vector<baseHostCX*>::iterator ii = left_bind_sockets.begin(); ii != left_bind_sockets.end(); ++ii) {
                int s = (*ii)->socket();
                if (xcom->in_readset(s)) {
                        handle_cx_new('l',xcom,(*ii));
                }
            }
            
            
            // iterate and if unpaused, run the accept_socket and release (add them to regular socket list)
            // we will try to remove them all to not have delays
            
            while(true) {
                bool no_suc = true;
                
                if(left_delayed_accepts.size())
                for(typename std::vector<baseHostCX*>::iterator k = left_delayed_accepts.begin(); k != left_delayed_accepts.end(); ++k) {
                    
                    baseHostCX *p = *k;
                    if(!(*k)->read_waiting_for_peercom()) {
                        p->on_accept_socket(p->socket());
                        ladd(p);
                        left_delayed_accepts.erase(k);
                        
                        DIA___("baseProxy::run_once: %s removed from delayed",p->c_name());
                        // restart iterator
                        no_suc = false;
                        break;
                    }
                }
                
                if(no_suc) break;
            }
            
            if(right_bind_sockets.size() > 0)
            for(typename std::vector<baseHostCX*>::iterator jj = right_bind_sockets.begin(); jj != right_bind_sockets.end(); ++jj) {
                int s = (*jj)->socket();
                if (xcom->in_readset(s)) {
                    sockaddr_in clientInfo;
                    socklen_t addrlen = sizeof(clientInfo);

                    int client = com()->accept(s, (sockaddr*)&clientInfo, &addrlen);
                    
                    if(new_raw()) {
                        on_right_new_raw(client);
                    } 
                    else {
                        baseHostCX* cx = new_cx(client);

                        // propagate nonlocal setting
                        cx->com()->nonlocal_dst((*jj)->com()->nonlocal_dst());

                        if(!cx->read_waiting_for_peercom()) {
                            cx->on_accept_socket(client);
                        } else {
                            cx->on_delay_socket(client);
                            // dealayed accept in effect -- carrier is accepted, but we will postpone higher level accept_socket
                            DEB___("baseProxy::handle_sockets_once[%d]: adding to right delayed sockets",client);
                            rdaadd(cx);
                        } 
                        on_right_new(cx);
                    }
                    
                    handle_last_status |= HANDLE_RIGHT_NEW;
                }
            }

            // iterate and if unpaused, run the accept_socket and release (add them to regular socket list)
            // we will try to remove them all to not have delays
            
            while(true) {
                bool no_suc = true;
                
                if(right_delayed_accepts.size())
                for(typename std::vector<baseHostCX*>::iterator k = right_delayed_accepts.begin(); k != right_delayed_accepts.end(); ++k) {
                    
                    baseHostCX *p = *k;
                    if(!(*k)->read_waiting_for_peercom()) {
                        p->on_accept_socket(p->socket());
                        radd(p);
                        right_delayed_accepts.erase(k);
                        
                        // restart iterator
                        no_suc = false;
                        break;
                    }
                }
                
                if(no_suc) break;
            }		
        }

		
// 		DIAS___("_");

        // handle the case when we are running this cycle due to n_tv timeout. In such a case return 0 to sleep accordingly.
        if (xcom->poll_result ==  0) {
            return 0;
        } else {
            return  meter_last_read + meter_last_write;
        }
    }
    return 0;
};



void baseProxy::on_left_bytes(baseHostCX* cx) {
	DEB___("Left context bytes: %s, bytes in buffer: %d", cx->c_name(), cx->readbuf()->size());
};


void baseProxy::on_right_bytes(baseHostCX* cx) {
	DEB___("Right context bytes: %s, bytes in buffer: %d", cx->c_name(), cx->readbuf()->size());
};


void baseProxy::on_left_error(baseHostCX* cx) {
	if (cx->opening()) {
		ERR___("Left socket connection timeout %s:",cx->c_name());
	} else {
		NOT___("Left socket error: %s", cx->c_name());
	}
};


void baseProxy::on_right_error(baseHostCX* cx) {
	if (cx->opening()) {
		ERR___("Right socket connection timeout %s:",cx->c_name());
	} else {	
		NOT___("Right socket error: %s", cx->c_name());
	}
};


void baseProxy::on_left_pc_error(baseHostCX* cx) {
	DUM___("Left permanent-connect socket error: %s",cx->c_name());
	
	if (cx->opening()) {
		ERR___("Left permanent socket connection timeout %s:",cx->c_name());	
	}
	else if ( cx->reconnect()) {
		INFS___("reconnecting");
	} 
	else {
		DUMS___("reconnection postponed");
	}
};


void baseProxy::on_right_pc_error(baseHostCX* cx) {
	DUM___("Right permanent-connect socket error: %s",cx->c_name());

	if (cx->opening()) {
		DIA___("Right permanent socket connection timeout %s:",cx->c_name());	
	}
	
	if ( cx->reconnect()) {
		DIA___("Reconnecting %s",cx->c_name());
	} 
	else {
		DUMS___("reconnection postponed");
	}
};


void baseProxy::on_left_pc_restore(baseHostCX* cx) {
    DIA___("Left permanent connection restored: %s",cx->c_name());
    cx->opening(false);
    com()->set_monitor(cx->socket());
    com()->set_poll_handler(cx->socket(),this);
}


void baseProxy::on_right_pc_restore(baseHostCX* cx) {
    DIA___("Right permanent connection restored: %s",cx->c_name());
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

int baseProxy::run(void) {
    
    while(! dead() ) {
        
        if(pollroot()) {
            
            EXTS___("baseProxy::run: preparing sockets");
            int s_max = prepare_sockets(com());
            EXTS___("baseProxy::run: sockets prepared");
            if (s_max) {
                com()->poll();
            }
            
            int counter_proxy_handler = 0;
            int counter_generic_handler = 0;
            int counter_back_handler = 0;
            std::vector<int> back_in_set;
            
            // std::set<int>& sets[] = { com()->poller.poller->in_set, com()->poller.poller->out_set };
            std::vector<std::set<int>*> sets;
            sets.push_back(&com()->poller.poller->in_set);
            sets.push_back(&com()->poller.poller->out_set);
            
            std::vector<std::string> setname = { "inset","outset" };
            int name_iter = 0;

            bool virt_global_hack = false;
            std::set<int> udp_in_set;
            
            UDPCom* uc = dynamic_cast<UDPCom*>(com()->master());
            if(uc) {
                
                //INFS___("adding virtual sockets");
                {
                std::lock_guard<std::recursive_mutex>(uc->lock);
                udp_in_set = uc->in_virt_set;
                }
                
                sets.push_back(&udp_in_set);
                setname.push_back("inset_virt");
            }
            
            for (std::set<int>* current_set: sets) {
                 
                for (auto s: *current_set) {
                    //FIXME
                    /*if(s>0) */DIA___("baseProxy::run: %s socket %d ",setname.at(name_iter).c_str(),s);
                    epoll_handler* ptr = com()->poller.get_handler(s);
                    
                    if(ptr != nullptr) {
                        auto seg = ptr->fence__;
                        EXT___("baseProxy::run: socket %d has registered handler 0x%x (fence %x)",s,ptr,seg);
                        
                        if(seg != HANDLER_FENCE) {
                            ERR___("baseProxy::run: socket %d magic fence doesn't match!!",s);
                        } else {
                            baseProxy* proxy = dynamic_cast<baseProxy*>(ptr);
                            if(proxy != nullptr) {
                                EXT___("baseProxy::run: socket %d has baseProxy handler!!",s);
                                
                                // call poller-carried proxy handler!
                                proxy->handle_sockets_once(com());
                                if(proxy->dead()) {
                                    proxy->shutdown();
                                }
                                
                                counter_proxy_handler++;
                                
                            } else {

                                DIA___("baseProxy::run: socket %d has generic handler",s);
                                ptr->handle_event(com());
                                counter_generic_handler++;


                                if(s > 0) {
                                    back_in_set.push_back(s);
                                }
                            }
                        }
                        
                    } else {
                        
                        //FIXME: report virtual sockets too, in the future
                        
                        DEB___("baseProxy::run: socket %d has NO handler!!",s);
                        
                        // all real sockets without ANY handler should be re-inserted
                        if(s > 0) {
                            back_in_set.push_back(s);
                        }
                        
                        if (com()->poller.poller != nullptr) {
                            if(s != com()->poller.poller->hint_socket()) {
                                if(s < 0) {
                                    EXT___("FIXME: calling global handle_sockets_once due to virtual socket %d",s);
                                    virt_global_hack = true;
                                }else {
                                    ERR___("baseProxy::run: socket %d has registered NULL handler, removing",s);
                                    com()->poller.poller->del(s);
                                }
                            } else {
                                // hint filedescriptor don't have handler
                                DEB___("baseProxy::run: socket %d is hint socket, running proxy socket handler",s);
                                handle_sockets_once(com());
                            }
                        } else {
                            ERRS___("com()->poller.poller is null!");                        
                        }
                    }
                }
                
                name_iter++;
            }
            
            // clear in_set, so alrady handled sockets are excluded 
            com()->poller.poller->in_set.clear();
            
            // add back sockets which don't have handler - generally it should be just few sockets!
            for(int a: back_in_set) {
                counter_back_handler++;
                
                com()->poller.poller->in_set.insert(a);
            }
            
//             // add back sockets to rescan
//             if(com()->poller.poller->should_rescan_now()) {
//                 for(int a: com()->poller.poller->rescan_set_in) {
//                     counter_back_handler++;
//                     
//                     DIA___("baseProxy::run: adding back to poller to rescan IN socket %d",a);
//                     com()->poller.poller->in_set.insert(a);
//                     com()->poller.poller->add(a);
//                 }
//                 com()->poller.poller->rescan_set_in.clear();
//                 
//                 
//                 for(int a: com()->poller.poller->rescan_set_out) {
//                     counter_back_handler++;
//                     
//                     DIA___("baseProxy::run: adding back to poller to rescan OUT socket %d",a);
//                     com()->poller.poller->out_set.insert(a);
//                     com()->poller.poller->add(a);
//                 }
//                 com()->poller.poller->rescan_set_out.clear();
//                 
//             }
            
            // run REST of all sockets. in_read_set and out_read_set is called, so if it's cleared handled (and not re-inserted back)
            // proxies will not be processed, unless they are forced.
            // 
            // now you say why we can't call this at the beginning and avoid all that smart stuff
            // above. 
            // Reason: we want to have a code prepared for fully handler-based approach,
            // which means traversing all proxies will not be needed, and only proxies which asked beforehand 
            // will be handled if they won't receive any data.
            
            // FIXME: this should be removed
            // handle_sockets_once(com());
            
            //instead of wholesale proxying, run timers
            run_timers();
            
            if(virt_global_hack) {
                handle_sockets_once(com());
            }
            
            if(counter_proxy_handler > 0) {
                EXT___("baseProxy::run: proxy handlers: %d, back-inserted: %d",counter_proxy_handler,counter_back_handler);
            }
        }
    }

    return 0;
};

void baseProxy::sleep(void) {
  
	unsigned int x_time = sleep_time;
  
	if(sleep_factor_ > 0 && sleep_factor_ < 10) {
	  // do some progressive slowdown
	  x_time = sleep_time*sleep_factor_;
	}
  
	usleep(x_time);
	sleep_factor_++;
}



int baseProxy::bind(unsigned short port, unsigned char side) {
	
	int s = com()->bind(port);
	
	// this function will always return value of 'port' parameter (but <=0 will not be added)
	
	baseHostCX *cx = new baseHostCX(com()->replicate(), s);
        cx->host() = string_format("listening_%d",port);
	cx->com()->nonlocal_dst(com()->nonlocal_dst());
	
	if ( s > 0 ) {
		if ( side == 'L' || side == 'l') lbadd(cx);
		else rbadd(cx);
	}

	return s;
};


int baseProxy::bind(const char* path, unsigned char side) {
    
    int s = com()->bind(path);
    
    // this function will always return value of 'port' parameter (but <=0 will not be added)
    
    baseHostCX *cx = new baseHostCX(com()->replicate(), s);
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
	
	int sock = cx->connect(blocking);
        if(sock > 0) {
            DIA___("baseProxy::left_connect: successfully created socket %d", sock);
            lpcadd(cx);
        } else {
            ERR___("baseProxy::left_connect: socket not created, returned %s", sock);
        } 
        
        return sock;
};


int baseProxy::right_connect ( const char* host, const char* port, bool blocking)
{
	baseHostCX* cx = new_cx(host,port);
        int sock = cx->connect(blocking);
        if(sock > 0) {
            DIA___("baseProxy::left_connect: successfully created socket %d", sock);
            rpcadd(cx);
        } else {
            ERR___("baseProxy::left_connect: socket not created, returned %s", sock);
        } 
        
        return sock;
};



std::string baseProxy::to_string(int verbosity) {

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
		for(typename std::vector<baseHostCX*>::iterator ii = left_bind_sockets.begin(); ii != left_bind_sockets.end(); ++ii) { ret += ("a: " + (*ii)->to_string(verbosity) + " "); };
		empty = false;
	}
	if(ls > 0) {
		for(typename std::vector<baseHostCX*>::iterator ii = left_sockets.begin(); ii != left_sockets.end(); ++ii) { ret += ("l:" + (*ii)->to_string(verbosity) + " "); };
		empty = false;	
	}
    if(la > 0) {
        for(typename std::vector<baseHostCX*>::iterator ii = left_delayed_accepts.begin(); ii != left_delayed_accepts.end(); ++ii) { ret += ("l:" + (*ii)->to_string(verbosity) + " "); };
        empty = false;  
    }
	if(lp > 0) {
		for(typename std::vector<baseHostCX*>::iterator ii = left_pc_cx.begin(); ii != left_pc_cx.end(); ++ii) { ret += ("x:" + (*ii)->to_string(verbosity) + " "); };
		empty = false;	
	}
	
	ret += "<+> ";
	
	if(rb > 0) {
		for(typename std::vector<baseHostCX*>::iterator ii = right_bind_sockets.begin(); ii != right_bind_sockets.end(); ++ii) { ret += ("b:" + (*ii)->to_string(verbosity) + " "); };
		empty = false;	
	}
	if(rs > 0) {
		for(typename std::vector<baseHostCX*>::iterator ii = right_sockets.begin(); ii != right_sockets.end(); ++ii) { ret += ("r:" + (*ii)->to_string(verbosity) + " "); };
		empty = false;	
	}
    if(ra > 0) {
        for(typename std::vector<baseHostCX*>::iterator ii = right_delayed_accepts.begin(); ii != right_delayed_accepts.end(); ++ii) { ret += ("r:" + (*ii)->to_string(verbosity) + " "); };
        empty = false;  
    }
	if(rp > 0) {
		for(typename std::vector<baseHostCX*>::iterator ii = right_pc_cx.begin(); ii != right_pc_cx.end(); ++ii) { ret += ("y:" + (*ii)->to_string(verbosity) + " "); };
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
