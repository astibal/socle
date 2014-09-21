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
	set_polltime(0,350);
	set_sleeptime(400000);
	time(&last_tick_);
};


baseProxy::~baseProxy() {
	left_shutdown(); 
	right_shutdown(); 
    
    DUMS_("Proxy: deleting com");
    
    if (com_ != nullptr) {
        delete com_;
    }
    
 	DIAS_("Proxy has been destroyed"); 
};



void baseProxy::set_polltime(unsigned int sec, unsigned int usec)
{
	tv.tv_sec = sec;
    tv.tv_usec = usec;
};


void baseProxy::ladd(baseHostCX* cs) {
	cs->unblock();
    left_sockets.push_back(cs);
	DEB_("Left client socket added: %s",cs->c_name());
};


void baseProxy::radd(baseHostCX* cs) {
	cs->unblock();
    right_sockets.push_back(cs);
	DEB_("Right client socket added: %s",cs->c_name());
};


void baseProxy::lbadd(baseHostCX* cs) {
	DEB_("Left bound socket added: %s",cs->c_name());
    left_bind_sockets.push_back(cs);
};


void baseProxy::rbadd(baseHostCX* cs) {
	DEB_("Right bound socket added: %s",cs->c_name());
    right_bind_sockets.push_back(cs);
};


void baseProxy::lpcadd(baseHostCX* cx) {
	DEB_("Left permanent connection context added %s", cx->c_name());
	cx->permanent(true);
    left_pc_cx.push_back(cx);
};


void baseProxy::rpcadd(baseHostCX* cx) {
	DEB_("Right permanent connection context added %s", cx->c_name());
	cx->permanent(true);
    right_pc_cx.push_back(cx);
};


void baseProxy::ldaadd(baseHostCX* cs) {
    DEB_("Left delayed socket added: %s",cs->c_name());
    left_delayed_accepts.push_back(cs);
};


void baseProxy::rdaadd(baseHostCX* cs) {
    DEB_("Right delayed socket added: %s",cs->c_name());
    right_delayed_accepts.push_back(cs);
};



void baseProxy::left_shutdown() {
	int lb = left_bind_sockets.size();
	int ls = left_sockets.size();
	int lp = left_pc_cx.size();
	
	int ld = left_delayed_accepts.size();
	
	for(typename std::vector<baseHostCX*>::iterator ii = left_bind_sockets.begin(); ii != left_bind_sockets.end(); ++ii) { (*ii)->close(); delete(*ii); };
	left_bind_sockets.clear();
	for(typename std::vector<baseHostCX*>::iterator ii = left_sockets.begin(); ii != left_sockets.end(); ++ii) { (*ii)->close(); delete(*ii); };
	left_sockets.clear();
	for(typename std::vector<baseHostCX*>::iterator ii = left_pc_cx.begin(); ii != left_pc_cx.end(); ++ii) { (*ii)->close(); delete(*ii); };
	left_pc_cx.clear();

    for(typename std::vector<baseHostCX*>::iterator ii = left_delayed_accepts.begin(); ii != left_delayed_accepts.end(); ++ii) { (*ii)->close(); delete(*ii); };
    left_delayed_accepts.clear();	
	
	DEB_("Left shutdown: bind=%d(delayed=%d), sock=%d, pc=%d",lb,ld,ls,lp);
}


void baseProxy::right_shutdown() {
	int rb = right_bind_sockets.size();
	int rs = right_sockets.size();
	int rp = right_pc_cx.size();
    
    int rd = right_delayed_accepts.size();
	
	for(typename std::vector<baseHostCX*>::iterator ii = right_bind_sockets.begin(); ii != right_bind_sockets.end(); ++ii) { (*ii)->close(); delete(*ii); };
	right_bind_sockets.clear();
	for(typename std::vector<baseHostCX*>::iterator ii = right_sockets.begin(); ii != right_sockets.end(); ++ii) { (*ii)->close(); delete(*ii); };
	right_sockets.clear();
	for(typename std::vector<baseHostCX*>::iterator ii = right_pc_cx.begin(); ii != right_pc_cx.end(); ++ii) { (*ii)->close(); delete(*ii); };
	right_pc_cx.clear();

    for(typename std::vector<baseHostCX*>::iterator ii = right_delayed_accepts.begin(); ii != right_delayed_accepts.end(); ++ii) { (*ii)->close(); delete(*ii); };
    right_delayed_accepts.clear();   	
	
	DEB_("Right shutdown: bind=%d(delayed=%d), sock=%d, pc=%d",rb,rd,rs,rp);
}


void baseProxy::shutdown() {
	left_shutdown();
	right_shutdown();
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

int baseProxy::prepare_sockets(void) {
    int max = 0;

	com()->zeroize_writeset();
	com()->zeroize_readset();

    if(left_sockets.size() > 0)
	for(typename std::vector<baseHostCX*>::iterator i = left_sockets.begin(); i != left_sockets.end(); ++i) {
		int s = (*i)->socket();
        com()->set_readset(s);
		com()->set_writeset(s);
		EXT_("left -> preparing %d",s);

        if (s > max) {
            max = s;
        }
    }
    
    if (left_bind_sockets.size() > 0)
	for(typename std::vector<baseHostCX*>::iterator ii = left_bind_sockets.begin(); ii != left_bind_sockets.end(); ++ii) {
		int s = (*ii)->socket();
        com()->set_readset(s);
		com()->set_writeset(s);
		EXT_("left, bound -> preparing %d",s);
		
        if (s > max) {
            max = s;
        }
    }

    if(right_sockets.size() > 0)
    for(typename std::vector<baseHostCX*>::iterator j = right_sockets.begin(); j != right_sockets.end(); ++j) {
		int s = (*j)->socket();
        com()->set_readset(s);
		com()->set_writeset(s);
		EXT_("right -> preparing %d",s);

        if (s > max) {
            max = s;
        }
    }
    
    if(right_bind_sockets.size() > 0)
	for(typename std::vector<baseHostCX*>::iterator jj = right_bind_sockets.begin(); jj != right_bind_sockets.end(); ++jj) {
		int s = (*jj)->socket();
        com()->set_readset(s);
		com()->set_writeset(s);
		EXT_("right, bound -> preparing %d",s);
		
        if (s > max) {
            max = s;
        }
    }
    
    if(left_pc_cx.size() > 0)
	for(typename std::vector<baseHostCX*>::iterator k = left_pc_cx.begin(); k != left_pc_cx.end(); ++k) {
		int k_s = (*k)->socket();
		if (k_s <= 0) { continue; };
        com()->set_readset(k_s);
		com()->set_writeset(k_s);
		
		EXT_("left, perma-conn -> preparing %d",k_s);
		if (k_s > max) {
            max = k_s;
        }
	}
	
	if(right_pc_cx.size() > 0)
	for(typename std::vector<baseHostCX*>::iterator l = right_pc_cx.begin(); l != right_pc_cx.end(); ++l) {    
		int l_s = (*l)->socket();
		if (l_s <= 0) { continue; };
        com()->set_readset(l_s);
		com()->set_writeset(l_s);

		
		EXT_("right, perma-conn -> preparing %d",l_s);
		if (l_s > max) {
            max = l_s;
        }
	}
	
	// Note: delayed accepts are not subject to be read/written, they are not yet fully accepted by higher level CX
		
    return max;
};


int baseProxy::handle_sockets_once() {
	EXTS_("CALL: handle_sockets_once");
	
	run_timers();
    int m = prepare_sockets();
    EXTS_("handle_sockets_once: sockets prepared");
	
	meter_last_read = 0;
	meter_last_write = 0;
	error_on_read = false;
	error_on_write = false;
	
	auto n_tv = tv;
	
	int ret_sel = select(m + 1, &(com()->read_socketSet), &(com()->write_socketSet), NULL, &n_tv);
	
    EXT_("select max: %d",m);
    
    if ( ret_sel >= 0) {
        
//         DIAS_(".");
		
		if(left_sockets.size() > 0)
		for(typename std::vector<baseHostCX*>::iterator i = left_sockets.begin(); i != left_sockets.end(); ++i) {
			
			// treat non-blocking still opening sockets 
			if( (*i)->opening_timeout() ) {
				DIA_("baseProxy::handle_sockets_once[%d]: opening timeout!",(*i)->socket());
				(*i)->close();
				on_left_error(*i);
				break;
			}
			
			// paused cx is subject to timeout only, no r/w is done on it ( it would return -1/0 anyway, so spare some cycles)
			if((*i)->paused()) {
				continue;
			}
			
			int s = (*i)->socket();
			
            EXT_("L: %d",s);
            
            if(com()->in_readset(s) || (*i)->com()->forced_read_reset()) {
                EXT_("L in R fdset: %d",s);
                if ((*i)->readable()) {
                    EXT_("L in R fdset and readable: %d",s)
                    int red = (*i)->read();
                    
                    if (red == 0) {
                        (*i)->close();
                        //left_sockets.erase(i);
                        handle_last_status |= HANDLE_LEFT_ERROR;
                        
                        error_on_read = true;
                        on_left_error(*i);
                        break;
                    }
                    
                    if (red > 0) {
                        meter_last_read += red;
                        on_left_bytes(*i);
                    }
                }
            }
			if(com()->in_writeset(s) || (*i)->com()->forced_write_reset()) {
                EXT_("L in W fdset: %d",s);
                if ((*i)->writable()) {
                    EXT_("L in W fdset and writable: %d",s)
                    int wrt = (*i)->write();
                    if (wrt < 0) {
                        (*i)->close();
                        //left_sockets.erase(i);
                        handle_last_status |= HANDLE_LEFT_ERROR;
                        
                        error_on_write = true;
                        on_left_error(*i);
                        break;
                    } else {
                        meter_last_write += wrt;
                    }
                }
            }
		}
		
		if(right_sockets.size() > 0)
		for(typename std::vector<baseHostCX*>::iterator j = right_sockets.begin(); j != right_sockets.end(); ++j) {

			// treat non-blocking still opening sockets 
			if( (*j)->opening_timeout() ) {
				DIA_("baseProxy::handle_sockets_once[%d]: opening timeout!",(*j)->socket());
				(*j)->close();
				on_right_error(*j);
				break;
			}			

			// paused cx is subject to timeout only, no r/w is done on it ( it would return -1/0 anyway, so spare some cycles)
			if((*j)->paused()) {
				continue;
			}
			
			int s = (*j)->socket();
			
            EXT_("R: %d",s);
            
            if(com()->in_readset(s) || (*j)->com()->forced_read_reset()) {
                EXT_("R in R fdset: %d",s);
                if ((*j)->readable()) {
                    EXT_("R in R fdset and readable: %d",s);
                    int red = (*j)->read();
                    if (red == 0) {
                        (*j)->close();
                        //right_sockets.erase(j);
                        handle_last_status |= HANDLE_RIGHT_ERROR;
                        
                        error_on_read = true;
                        on_right_error(*j);
                        break;
                    }
                    if (red > 0) {
                        meter_last_read += red;
                        on_right_bytes(*j);
                    }
                }
            }
			if(com()->in_writeset(s) || (*j)->com()->forced_write_reset()) {
                EXT_("R in W fdset: %d",s);
                if ((*j)->writable()) {
                    EXT_("R in W fdset and writable: %d",s);
                    int wrt = (*j)->write();
                    if (wrt < 0) {
                        (*j)->close();
                        //right_sockets.erase(j);
                        handle_last_status |= HANDLE_RIGHT_ERROR;
                        
                        error_on_write = true;
                        on_right_error(*j);
                        break;
                    } else {
                        meter_last_write += wrt;
                    }					
                }	
            }
		}


        // now operate permanent-connect sockets to create accepted sockets
        
        if(left_pc_cx.size() > 0)
        for(typename std::vector<baseHostCX*>::iterator k = left_pc_cx.begin(); k != left_pc_cx.end(); ++k) {

            bool opening_status = (*k)->opening();
            
            // treat non-blocking still opening sockets 
            if( (*k)->opening_timeout() ) {
                (*k)->close();
                on_left_pc_error(*k);
                break;
            }           

            // paused cx is subject to timeout only, no r/w is done on it ( it would return -1/0 anyway, so spare some cycles)
            if((*k)->paused()) {
                continue;
            }
            
            
            int k_s = (*k)->socket();
            
            // if socket is already in error, don't read, instead just raise again error, if we should reconnect
            if ((*k)->error() and (*k)->should_reconnect_now()) {
                on_left_pc_error(*k);
                break;
            } else if ((*k)->error()) {
                break;
            }
            
            if(com()->in_readset(k_s) || (*k)->com()->forced_read_reset()) {
                if ((*k)->readable()) {
                    int red = (*k)->read();
                    if (red == 0) {
                        //(*k)->close();
                        //left_pc_cx.erase(k);
                        handle_last_status |= HANDLE_LEFT_PC_ERROR;
                        
                        error_on_read = true;
                        on_left_pc_error(*k);
                        break;
                    } else {
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
            
            if(com()->in_writeset(k_s) || (*k)->com()->forced_write_reset()) {
                if ((*k)->writable()) {
                    int wrt = (*k)->write();
                    if (wrt < 0) {
    //                  (*k)->close();
    //                  left_pc_cx.erase(k);
                        handle_last_status |= HANDLE_LEFT_PC_ERROR;
                        
                        error_on_write = true;
                        on_left_pc_error(*k);
                        break;
                    } 
                    else {
                        
                        meter_last_write += wrt;
                        
                        if (opening_status) {
                            on_left_pc_restore(*k);
                        }
                    }       
                }
            }               
        }
        
        if(right_pc_cx.size() > 0)
        for(typename std::vector<baseHostCX*>::iterator l = right_pc_cx.begin(); l != right_pc_cx.end(); ++l) {
 
            bool opening_status = (*l)->opening();          
            
            // treat non-blocking still opening sockets 
            if( (*l)->opening_timeout() ) {
                (*l)->close();
                on_right_pc_error(*l);
                break;
            }           

            // paused cx is subject to timeout only, no r/w is done on it ( it would return -1/0 anyway, so spare some cycles)
            if((*l)->paused()) {
                continue;
            }
            
            int l_s = (*l)->socket();

            // if socket is already in error, don't read, instead just raise again error, if we should reconnect
            if ((*l)->error() and (*l)->should_reconnect_now()) {
                on_right_pc_error(*l);
                break;
            } else if ((*l)->error()) {
                break;
            }
            
            if(com()->in_readset(l_s)  || (*l)->com()->forced_read_reset()) {
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
                        if (opening_status && red > 0) {
                            on_right_pc_restore(*l);
                        }
                        if (red > 0) {
                            meter_last_read += red;
                            on_right_bytes(*l);
                        }
                    }
                }
            }
            if(com()->in_writeset(l_s)  || (*l)->com()->forced_write_reset()) {
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
                        
                        if (opening_status && wrt > 0) {
                            on_right_pc_restore(*l);
                        }
                    }       
                }   
            }
        } 
        
        
		// no socket is really ready to be processed; while it make sense to check 'connecting' sockets, it makes
		// no sense to loop through bound sockets.
		
		if (ret_sel > 0) {
            // now operate bound sockets to create accepted sockets
            
            if(left_bind_sockets.size() > 0)
            for(typename std::vector<baseHostCX*>::iterator ii = left_bind_sockets.begin(); ii != left_bind_sockets.end(); ++ii) {
                int s = (*ii)->socket();
                if (com()->in_readset(s)) {
                    sockaddr_in clientInfo;
                    socklen_t addrlen = sizeof(clientInfo);

                    int client = com()->accept(s, (sockaddr*)&clientInfo, &addrlen);
                    
                    if(new_raw()) {
                        on_left_new_raw(client);
                    }
                    else {
                        baseHostCX* cx = new_cx(client);
                        
                        // propagate nonlocal setting
                        cx->com()->nonlocal((*ii)->com()->nonlocal());
                        
                        if(!cx->paused()) {
                            cx->accept_socket(client);
                        } else {
                            DEB_("baseProxy::handle_sockets_once[%d]: adding to delayed sockets",client);
                            // dealayed accept in effect -- carrier is accepted, but we will postpone higher level accept_socket
                            ldaadd(cx);
                            
                        }
                        on_left_new(cx);
                    }
                    
                    handle_last_status |= HANDLE_LEFT_NEW;
                }
            }
            
            
            // iterate and if unpaused, run the accept_socket and release (add them to regular socket list)
            // we will try to remove them all to not have delays
            
            while(true) {
                bool no_suc = true;
                
                if(left_delayed_accepts.size())
                for(typename std::vector<baseHostCX*>::iterator k = left_delayed_accepts.begin(); k != left_delayed_accepts.end(); ++k) {
                    
                    baseHostCX *p = *k;
                    if(!(*k)->paused()) {
                        p->accept_socket(p->socket());
                        ladd(p);
                        left_delayed_accepts.erase(k);
                        
                        DIA_("baseProxy::run_once: %s removed from delayed",p->c_name());
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
                if (com()->in_readset(s)) {
                    sockaddr_in clientInfo;
                    socklen_t addrlen = sizeof(clientInfo);

                    int client = com()->accept(s, (sockaddr*)&clientInfo, &addrlen);
                    
                    if(new_raw()) {
                        on_right_new_raw(client);
                    } 
                    else {
                        baseHostCX* cx = new_cx(client);

                        // propagate nonlocal setting
                        cx->com()->nonlocal((*jj)->com()->nonlocal());

                        if(!cx->paused()) {
                            cx->accept_socket(client);
                        } else {
                            // dealayed accept in effect -- carrier is accepted, but we will postpone higher level accept_socket
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
                    if(!(*k)->paused()) {
                        p->accept_socket(p->socket());
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

		
// 		DIAS_("_");

        // handle the case when we are running this cycle due to n_tv timeout. In such a case return 0 to sleep accordingly.
        if (ret_sel ==  0) {
            return 0;
        } else {
            return handle_last_status + meter_last_read + meter_last_write;
        }
    }
    return 0;
};



void baseProxy::on_left_bytes(baseHostCX* cx) {
	DEB_("Left context bytes: %s, bytes in buffer: %d", cx->c_name(), cx->readbuf()->size());
};


void baseProxy::on_right_bytes(baseHostCX* cx) {
	DEB_("Right context bytes: %s, bytes in buffer: %d", cx->c_name(), cx->readbuf()->size());
};


void baseProxy::on_left_error(baseHostCX* cx) {
	if (cx->opening()) {
		ERR_("Left socket connection timeout %s:",cx->c_name());
	} else {
		NOT_("Left socket error: %s", cx->c_name());
	}
};


void baseProxy::on_right_error(baseHostCX* cx) {
	if (cx->opening()) {
		ERR_("Right socket connection timeout %s:",cx->c_name());
	} else {	
		NOT_("Right socket error: %s", cx->c_name());
	}
};


void baseProxy::on_left_pc_error(baseHostCX* cx) {
	DUM_("Left permanent-connect socket error: %s",cx->c_name());
	
	if (cx->opening()) {
		ERR_("Left permanent socket connection timeout %s:",cx->c_name());	
	}
	else if ( cx->reconnect()) {
		INFS_("reconnecting");
	} 
	else {
		DUMS_("reconnection postponed");
	}
};


void baseProxy::on_right_pc_error(baseHostCX* cx) {
	DUM_("Right permanent-connect socket error: %s",cx->c_name());

	if (cx->opening()) {
		DIA_("Right permanent socket connection timeout %s:",cx->c_name());	
	}
	
	if ( cx->reconnect()) {
		DIA_("Reconnecting %s",cx->c_name());
	} 
	else {
		DUMS_("reconnection postponed");
	}
};


void baseProxy::on_left_pc_restore(baseHostCX* cx) {
	DIA_("Left permanent connection restored: %s",cx->c_name());
}


void baseProxy::on_right_pc_restore(baseHostCX* cx) {
	DIA_("Right permanent connection restored: %s",cx->c_name());
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
        int r = run_once();
		if (r == 0) {
			EXT_("Proxy going to sleep for %dus",sl.tv_nsec );
			nanosleep(&sl, NULL);
		} else {
            DEB_("Proxy transferred %d bytes",r);
        }
	}

	return 0;
};


int baseProxy::run_once(void) {
	return handle_sockets_once();
}


void baseProxy::sleep(void) {
	usleep(sleep_time);
}



int baseProxy::bind(unsigned short port, unsigned char side) {
	
	int s = com()->bind(port);
	
	// this function will always return value of 'port' parameter (but <=0 will not be added)
	
	baseHostCX *cx = new baseHostCX(com()->replicate(), s);
	cx->com()->nonlocal(com()->nonlocal());
	
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



std::string baseProxy::hr() {

	std::string ret;
	ret += string_format("%p: \n",this);

	int lb = left_bind_sockets.size();
	int ls = left_sockets.size();
	int lp = left_pc_cx.size();
	int rb = right_bind_sockets.size();
	int rs = right_sockets.size();
	int rp = right_pc_cx.size();

	bool empty = true;
	
	if(lb > 0) {
		empty = false;
		for(typename std::vector<baseHostCX*>::iterator ii = left_bind_sockets.begin(); ii != left_bind_sockets.end(); ++ii) { ret += ("L(bound): " + (*ii)->hr() + "\n"); };
	}
	if(ls > 0) {
		empty = false;	
		for(typename std::vector<baseHostCX*>::iterator ii = left_sockets.begin(); ii != left_sockets.end(); ++ii) { ret += ("L: " + (*ii)->hr() + "\n"); };
	}
	if(lp > 0) {
		empty = false;	
		for(typename std::vector<baseHostCX*>::iterator ii = left_pc_cx.begin(); ii != left_pc_cx.end(); ++ii) { ret += ("L(persistent): " + (*ii)->hr() + "\n"); };
	}
	if(rb > 0) {
		empty = false;	
		for(typename std::vector<baseHostCX*>::iterator ii = right_bind_sockets.begin(); ii != right_bind_sockets.end(); ++ii) { ret += ("R(bound): " + (*ii)->hr() + "\n"); };
	}
	if(rs > 0) {
		empty = false;	
		for(typename std::vector<baseHostCX*>::iterator ii = right_sockets.begin(); ii != right_sockets.end(); ++ii) { ret += ("R: " + (*ii)->hr() + "\n"); };
	}
	if(rp > 0) {
		empty = false;	
		for(typename std::vector<baseHostCX*>::iterator ii = right_pc_cx.begin(); ii != right_pc_cx.end(); ++ii) { ret += ("R(persistent): " + (*ii)->hr() + "\n"); };
	}
	
	if (! empty) {
		ret+="Last R/W: " + std::to_string(meter_last_read) + "/" + std::to_string(meter_last_write) + "\n";
	} 
	else {
		ret += "<empty>\n";
	}
	
	return ret;
}
