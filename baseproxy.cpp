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

#define BUFSIZE 9216

extern int errno;
extern ::logger lout;

int baseProxy::log_level = NON;

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
    com()->set_monitor(cs->socket());
    com()->set_poll_handler(cs->socket(),this);
    left_sockets.push_back(cs);
	DIA___("baseProxy::ladd: added socket: %s",cs->c_name());
};


void baseProxy::radd(baseHostCX* cs) {
	cs->unblock();
//     INF___("baseProxy::radd: master com: %x",com()->master());
//     INF___("baseProxy::radd: poller: %x",com()->master()->poller.poller);
//     INF___("baseProxy::radd: socket to monitor: %d",cs->socket());
    com()->set_monitor(cs->socket());
    com()->set_poll_handler(cs->socket(),this);
    right_sockets.push_back(cs);
	DIA___("baseProxy::radd: added socket: %s",cs->c_name());
};


void baseProxy::lbadd(baseHostCX* cs) {
    com()->set_monitor(cs->socket());
    com()->set_poll_handler(cs->socket(),this);
    left_bind_sockets.push_back(cs);
	DIA___("baseProxy::lbadd: added bound socket: %s",cs->c_name());
};


void baseProxy::rbadd(baseHostCX* cs) {
    com()->set_monitor(cs->socket());
    com()->set_poll_handler(cs->socket(),this);
    right_bind_sockets.push_back(cs);
	DIA___("baseProxy::rbadd: added bound socket: %s",cs->c_name());
};


void baseProxy::lpcadd(baseHostCX* cx) {
	cx->permanent(true);
    left_pc_cx.push_back(cx);
    com()->set_monitor(cx->socket());
    com()->set_poll_handler(cx->socket(),this);
	DIA___("baseProxy::lpcadd: added perma socket: %s", cx->c_name());
};


void baseProxy::rpcadd(baseHostCX* cx) {
	cx->permanent(true);
    right_pc_cx.push_back(cx);
    com()->set_monitor(cx->socket());
    com()->set_poll_handler(cx->socket(),this);
	DIA___("baseProxy::rpcadd: added perma socket %s", cx->c_name());
};


void baseProxy::ldaadd(baseHostCX* cs) {
    left_delayed_accepts.push_back(cs);
    com()->set_monitor(cs->socket());
    com()->set_poll_handler(cs->socket(),this);
    DIA___("baseProxy::ldaadd: added delayed socket: %s",cs->c_name());
};


void baseProxy::rdaadd(baseHostCX* cs) {
    right_delayed_accepts.push_back(cs);
    com()->set_monitor(cs->socket());
    com()->set_poll_handler(cs->socket(),this);
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
    DIAS_("baseProxy::shutdown");
	left_shutdown();
	right_shutdown();
    DEBS_("baseProxy::shutdown finished");
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
	
	if( clock_ - last_tick_ > 1) {
		cx->on_timer();
		return true;
	}
	
	return false;
}


void baseProxy::reset_timer() {

	if( clock_ - last_tick_ > 1) {	
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

    
//     DUM___("baseProxy::prepare_sockets: preparing my sockets for Com: %x",fdset_owner);
//     
//     if(left_sockets.size() > 0)
// 	for(typename std::vector<baseHostCX*>::iterator i = left_sockets.begin(); i != left_sockets.end(); ++i) {
// 		int s = (*i)->socket();
//         fdset_owner->set_monitor(s);
// 		EXT___("baseProxy::prepare_sockets: left -> preparing %d",s);
// 
//         if (s > max) {
//             max = s;
//         }
//     }
// 
//     if(left_delayed_accepts.size() > 0)
//     for(typename std::vector<baseHostCX*>::iterator i = left_delayed_accepts.begin(); i != left_delayed_accepts.end(); ++i) {
//         int s = (*i)->socket();
//         fdset_owner->set_monitor(s);
//         EXT___("baseProxy::prepare_sockets: left -> preparing %d",s);
// 
//         if (s > max) {
//             max = s;
//         }
//     }    
//     
//     if (left_bind_sockets.size() > 0)
// 	for(typename std::vector<baseHostCX*>::iterator ii = left_bind_sockets.begin(); ii != left_bind_sockets.end(); ++ii) {
// 		int s = (*ii)->socket();
//         fdset_owner->set_monitor(s);
// 		EXT___("baseProxy::prepare_sockets: left, bound -> preparing %d",s);
// 		
//         if (s > max) {
//             max = s;
//         }
//     }
// 
//     if(right_sockets.size() > 0)
//     for(typename std::vector<baseHostCX*>::iterator j = right_sockets.begin(); j != right_sockets.end(); ++j) {
// 		int s = (*j)->socket();
//         fdset_owner->set_monitor(s);
// 		EXT___("baseProxy::prepare_sockets: right -> preparing %d",s);
// 
//         if (s > max) {
//             max = s;
//         }
//     }
//     
//     if(right_delayed_accepts.size() > 0)
//     for(typename std::vector<baseHostCX*>::iterator j = right_delayed_accepts.begin(); j != right_delayed_accepts.end(); ++j) {
//         int s = (*j)->socket();
//         fdset_owner->set_monitor(s);
//         EXT___("baseProxy::prepare_sockets: right -> preparing %d",s);
// 
//         if (s > max) {
//             max = s;
//         }
//     }    
//     
//     if(right_bind_sockets.size() > 0)
// 	for(typename std::vector<baseHostCX*>::iterator jj = right_bind_sockets.begin(); jj != right_bind_sockets.end(); ++jj) {
// 		int s = (*jj)->socket();
//         fdset_owner->set_monitor(s);
// 		EXT___("baseProxy::prepare_sockets: right, bound -> preparing %d",s);
// 		
//         if (s > max) {
//             max = s;
//         }
//     }
//     
//     if(left_pc_cx.size() > 0)
// 	for(typename std::vector<baseHostCX*>::iterator k = left_pc_cx.begin(); k != left_pc_cx.end(); ++k) {
// 		int k_s = (*k)->socket();
// 		if (k_s <= 0) { continue; };
//         fdset_owner->set_monitor(k_s);
// 		
// 		EXT___("baseProxy::prepare_sockets: left, perma -> preparing %d",k_s);
// 		if (k_s > max) {
//             max = k_s;
//         }
// 	}
// 	
// 	if(right_pc_cx.size() > 0)
// 	for(typename std::vector<baseHostCX*>::iterator l = right_pc_cx.begin(); l != right_pc_cx.end(); ++l) {    
// 		int l_s = (*l)->socket();
// 		if (l_s <= 0) { continue; };
//         fdset_owner->set_monitor(l_s);
// 		
// 		EXT___("baseProxy::prepare_sockets: right, perma -> preparing %d",l_s);
// 		if (l_s > max) {
//             max = l_s;
//         }
// 	}
// 	
// 	// Note: delayed accepts are not subject to be read/written, they are not yet fully accepted by higher level CX
// 		
     return max;
};


bool baseProxy::handle_cx_events(unsigned char side, baseHostCX* cx) {
        // treat non-blocking still opening sockets 
        if( cx->opening_timeout() ) {
            DIA___("baseProxy::handle_cx_events[%d]: opening timeout!",cx->socket());
            cx->shutdown();
            
                 if(side == 'l')  { on_left_error(cx);  }
            else if(side == 'r')  { on_right_error(cx); }
            else if(side == 'x')  { on_left_pc_error(cx); }
            else if(side == 'y')  { on_right_pc_error(cx); }
            return false;
        }
        if( cx->idle_timeout() ) {
            DIA___("baseProxy::handle_cx_events[%d]: idle timeout!",cx->socket());
            cx->shutdown();

                 if(side == 'l')  { on_left_error(cx);  }
            else if(side == 'r')  { on_right_error(cx); }
            else if(side == 'x')  { on_left_pc_error(cx); }
            else if(side == 'y')  { on_right_pc_error(cx); }
            return false;
        }
        if( cx->error() ) {
            DIA___("baseProxy::handle_cx_events[%d]: error!",cx->socket());
            cx->shutdown();

                 if(side == 'l')  { on_left_error(cx);  }
            else if(side == 'r')  { on_right_error(cx); }
            else if(side == 'x')  { on_left_pc_error(cx); }
            else if(side == 'y')  { on_right_pc_error(cx); }
            return false;
        }
        
        //process new messages before paused check
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

bool baseProxy::handle_cx_once(unsigned char side, baseCom* xcom, baseHostCX* cx) {

    bool ret = true;

    EXT___("%c: %d",side, cx->socket());
    
    // paused cx is subject to timeout only, no r/w is done on it ( it would return -1/0 anyway, so spare some cycles)
    if(! cx->paused_read()) {
        if(xcom->in_readset(cx->socket()) || cx->com()->forced_read_reset()) {

            if(! handle_cx_read(side,cx)) {
                ret = false;
                goto failure;
            }
            
            if(cx->com()->forced_write_on_read()) {
                DIA___("baseProxy::handle_cx_once[%c]: write on read enforced on socket %d",side,cx->socket());
                if(! handle_cx_write(side,cx)) {
                    ret = false;
                    goto failure;
                }
            }
        }
    }
    if(! cx->paused_write()) {
        if(xcom->in_writeset(cx->socket()) || cx->com()->forced_write_reset()) {
            if(! handle_cx_write(side,cx)) {
                ret = false;
                goto failure;
            }

            if(cx->com()->forced_read_on_write()) {
                DIA___("baseProxy::handle_cx_once[%c]: read on write enforced on socket %d",side,cx->socket());
                if(! handle_cx_read(side,cx)) {
                    ret = false;
                    goto failure;
                }
            }
            
        }
    }

    // on failure, skip all operations and go here
    failure:
    
    // errors are proucts of operations above. Act on them.
    if(! handle_cx_events(side,cx))
        ret = false;    
    
    return ret;
};

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
        
        if(!cx->paused_read()) {
            DIA___("baseProxy::handle_cx_new[%c]: new unpaused socket %d -> accepting",side,client);
            
            cx->on_accept_socket(client);
            //  DON'T: you don't know if this proxy does have child proxy, or wants to handle situation different way.
            //        if(side == 'l') { ladd(cx); }
            //   else if(side == 'r') { radd(cx); }
            
        } else {
            DIA___("baseProxy::handle_cx_new[%c]: new paused socket %d -> delaying",side,client);
            
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
        
		if(left_sockets.size() > 0)
		for(typename std::vector<baseHostCX*>::iterator i = left_sockets.begin(); i != left_sockets.end(); ++i) {
			if(! handle_cx_once('l',xcom,*i)) {
                break;
            }
		}
		
		if(right_sockets.size() > 0)
		for(typename std::vector<baseHostCX*>::iterator j = right_sockets.begin(); j != right_sockets.end(); ++j) {
            if(! handle_cx_once('r',xcom,*j)) {
                break;
            }
		}


        // now operate permanent-connect sockets to create accepted sockets
        
        if(left_pc_cx.size() > 0)
        for(typename std::vector<baseHostCX*>::iterator k = left_pc_cx.begin(); k != left_pc_cx.end(); ++k) {

            handle_cx_events('x',*k);

            
                
            int k_s = (*k)->socket();            
                
            // paused cx is subject to timeout only, no r/w is done on it ( it would return -1/0 anyway, so spare some cycles)
            if( ! (*k)->paused_read()) {

                // if socket is already in error, don't read, instead just raise again error, if we should reconnect
                if ((*k)->error() and (*k)->should_reconnect_now()) {
                    on_left_pc_error(*k);
                    break;
                } else if ((*k)->error()) {
                    break;
                }
                
                if(xcom->in_readset(k_s) || (*k)->com()->forced_read_reset()) {
                    if ((*k)->readable()) {
                        int red = (*k)->read();
                        if (red == 0) {
                            handle_last_status |= HANDLE_LEFT_PC_ERROR;
                            
                            error_on_read = true;
                            on_left_pc_error(*k);
                            break;
                        } else {
                            bool opening_status = (*k)->opening();
                            if (opening_status) {
                                on_left_pc_restore(*k);
                            }
                            if (red > 0) {
                                meter_last_read += red;
                                on_left_bytes(*k);
                            }
                        }
                    }
                }
            }
            
            if( ! (*k)->paused_write()) {

                // if socket is already in error, don't read, instead just raise again error, if we should reconnect
                if ((*k)->error() and (*k)->should_reconnect_now()) {
                    on_left_pc_error(*k);
                    break;
                } else if ((*k)->error()) {
                    break;
                }
                            
                if(xcom->in_writeset(k_s) || (*k)->com()->forced_write_reset()) {
                    if ((*k)->writable()) {
                        int wrt = (*k)->write();
                        if (wrt < 0) {
                            handle_last_status |= HANDLE_LEFT_PC_ERROR;
                            
                            error_on_write = true;
                            on_left_pc_error(*k);
                            break;
                        } 
                        else {
                            
                            meter_last_write += wrt;
                            
                            if ((*k)->opening()) {
                                on_left_pc_restore(*k);
                            }
                        }       
                    }
                }               
            }
        }
        
        if(right_pc_cx.size() > 0)
        for(typename std::vector<baseHostCX*>::iterator l = right_pc_cx.begin(); l != right_pc_cx.end(); ++l) {

            handle_cx_events('y',*l);

            
            int l_s = (*l)->socket();            
            // paused cx is subject to timeout only, no r/w is done on it ( it would return -1/0 anyway, so spare some cycles)
            if((*l)->paused_read()) {

                // if socket is already in error, don't read, instead just raise again error, if we should reconnect
                if ((*l)->error() and (*l)->should_reconnect_now()) {
                    on_right_pc_error(*l);
                    break;
                } else if ((*l)->error()) {
                    break;
                }
                
                if(xcom->in_readset(l_s)  || (*l)->com()->forced_read_reset()) {
                    if ((*l)->readable()) {
                        int red = (*l)->read();
                        if (red == 0) {
                            //(*l)->close();
                            //right_pc_cx.erase(l);
                            handle_last_status |= HANDLE_RIGHT_PC_ERROR;
                            
                            error_on_read = true;
                            on_right_pc_error(*l);
                            break;
                        } else {
                            if ((*l)->opening() && red > 0) {
                                on_right_pc_restore(*l);
                            }
                            if (red > 0) {
                                meter_last_read += red;
                                on_right_bytes(*l);
                            }
                        }
                    }
                }
            }
            
            if((*l)->paused_read()) {

                // if socket is already in error, don't read, instead just raise again error, if we should reconnect
                if ((*l)->error() and (*l)->should_reconnect_now()) {
                    on_right_pc_error(*l);
                    break;
                } else if ((*l)->error()) {
                    break;
                }            

                if(xcom->in_writeset(l_s)  || (*l)->com()->forced_write_reset()) {
                    if ((*l)->writable()) {
                        int wrt = (*l)->write();
                        if (wrt < 0) {
        //                  (*l)->close();
        //                  right_pc_cx.erase(l);
                            handle_last_status |= HANDLE_RIGHT_PC_ERROR;
                            
                            error_on_write = true;
                            on_right_pc_error(*l);
                            break;
                        } 
                        else {
                            
                            meter_last_write += wrt;
                            
                            if ((*l)->opening() && wrt > 0) {
                                on_right_pc_restore(*l);
                            }
                        }       
                    }   
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
                    if(!(*k)->paused_read()) {
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

                        if(!cx->paused_read()) {
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
                    if(!(*k)->paused_read()) {
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
}


void baseProxy::on_right_pc_restore(baseHostCX* cx) {
	DIA___("Right permanent connection restored: %s",cx->c_name());
}


void baseProxy::on_left_new(baseHostCX* cx) {
	ladd(cx);
};


void baseProxy::on_right_new(baseHostCX* cx) {
	radd(cx);
};


// Infinite loop ... 

int baseProxy::run(void) {
    
    timespec sl;
    sl.tv_sec = 0;
    sl.tv_nsec = get_sleeptime();
    

    while(! dead() ) {
        
        if(pollroot()) {
            
//             com()->zeroize_exset();
//             com()->zeroize_readset();
//             com()->zeroize_writeset();            
            
            EXTS___("baseProxy::run: preparing sockets");
            int s_max = prepare_sockets(com());
            EXTS___("baseProxy::run: sockets prepared");
            if (s_max) {
                com()->poll();
            }
            
            for (auto s: com()->poller.poller->in_set) {
                auto ptr = com()->poller.get_handler(s);
                
                if(ptr != nullptr) {
                    auto seg = ptr->fence__;
                    DIA_("baseProxy::run: socket %d has registered handler 0x%x (fence %d)",s,ptr,seg);
                } else {
                    ERR_("baseProxy::run: socket %d has registered NULL handler",s);
                }
            }
        }
        
        int r = handle_sockets_once(com());
        EXT___("baseProxy::handle_sockets_once: %d",r);

        if (r == 0) {
            EXT___("Proxy going to sleep for %dus",sl.tv_nsec );
            //nanosleep(&sl, NULL);
	    sleep();
        } else {
            DEB___("Proxy transferred %d bytes",r);
	    sleep_factor_ = 0;
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
	lpcadd(cx);
	
	return cx->connect(blocking);
};


int baseProxy::right_connect ( const char* host, const char* port, bool blocking)
{
	baseHostCX* cx = new_cx(host,port);
	rpcadd(cx);
	
	return cx->connect(blocking);
};



const char* baseProxy::hr() {

	hr_.clear();
    hr_.append(" ");

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
		for(typename std::vector<baseHostCX*>::iterator ii = left_bind_sockets.begin(); ii != left_bind_sockets.end(); ++ii) { hr_ += ("a: " + (*ii)->hr() + " "); };
		empty = false;
	}
	if(ls > 0) {
		for(typename std::vector<baseHostCX*>::iterator ii = left_sockets.begin(); ii != left_sockets.end(); ++ii) { hr_ += ("l:" + (*ii)->hr() + " "); };
		empty = false;	
	}
    if(la > 0) {
        for(typename std::vector<baseHostCX*>::iterator ii = left_delayed_accepts.begin(); ii != left_delayed_accepts.end(); ++ii) { hr_ += ("*l:" + (*ii)->hr() + " "); };
        empty = false;  
    }
	if(lp > 0) {
		for(typename std::vector<baseHostCX*>::iterator ii = left_pc_cx.begin(); ii != left_pc_cx.end(); ++ii) { hr_ += ("x:" + (*ii)->hr() + " "); };
		empty = false;	
	}
	if(rb > 0) {
		for(typename std::vector<baseHostCX*>::iterator ii = right_bind_sockets.begin(); ii != right_bind_sockets.end(); ++ii) { hr_ += ("b:" + (*ii)->hr() + " "); };
		empty = false;	
	}
	if(rs > 0) {
		for(typename std::vector<baseHostCX*>::iterator ii = right_sockets.begin(); ii != right_sockets.end(); ++ii) { hr_ += ("r:" + (*ii)->hr() + " "); };
		empty = false;	
	}
    if(ra > 0) {
        for(typename std::vector<baseHostCX*>::iterator ii = right_delayed_accepts.begin(); ii != right_delayed_accepts.end(); ++ii) { hr_ += ("*r:" + (*ii)->hr() + " "); };
        empty = false;  
    }
	if(rp > 0) {
		for(typename std::vector<baseHostCX*>::iterator ii = right_pc_cx.begin(); ii != right_pc_cx.end(); ++ii) { hr_ += ("y:" + (*ii)->hr() + " "); };
		empty = false;	
	}
	
	if (empty) {
		hr_ += "<empty> ";
	}
	return hr_.c_str();
}
