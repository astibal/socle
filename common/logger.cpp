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
#include <sstream>
#include <string>

#include <cstring>
#include <cstdarg>
#include <cstdio>
#include <ctime>

#include <mutex>

#include "display.hpp"
#include "logger.hpp"

#include <sys/time.h>
#include <sys/socket.h>

logger* lout_ = nullptr;

static  std::string level_table[] = {"None    ","Fatal   ","Critical","Error   ","Warning ","Notify  ","Informat","Diagnose","Debug   ","Dumpit  ","Extreme "};



logger* get_logger() { 
    if(lout_ == nullptr) { lout_ = create_default_logger(); }
    return lout_; 
}; 

logger* create_default_logger() {
    return new logger();
}

void set_logger(logger* l) {
    if (lout_ != nullptr) {
        delete lout_;
    }
    
    lout_ = l;
}


std::string ESC_(std::string s) {
    std::string t = s;
    std::replace( t.begin(), t.end(), '%', '^');
    return t;
}

logger_profile::~logger_profile() { 
    for(std::list<std::ostream*>::iterator i = targets_.begin(); i != targets_.end(); ++i) {  
        if(*i != nullptr) { 
                (*i)->flush(); 
                delete *i; 
            
        } 
    }
}

bool logger::periodic_start(unsigned int s) {
	time_t now = time(NULL);
	
	if (now > last_period + s) {
		last_period_status = true;
	} else {
		last_period_status = false;
	}
	
	return last_period_status;
}


bool logger::periodic_end() {
	if (last_period_status) {
		time_t now = time(NULL);
		last_period = now;
		
		return true;
	}
	
	return false;
}


int logger::write_log(unsigned int level, std::string& sss) {

    bool really_dup = dup2_cout();
    
    for(std::list<std::ostream*>::iterator i = targets().begin(); i != targets().end(); ++i) {
        if(target_profiles().find((uint64_t)*i) != target_profiles().end()) 
            if(target_profiles()[(uint64_t)*i]->level_ < level && ! forced_) 
                continue;
            if(forced_ && target_profiles()[(uint64_t)*i]->level_ < INF)
                continue;
            
        *(*i) << sss << std::endl;
        //if(target_profiles()[(uint64_t)*i]->dup_to_cout_) really_dup = true;
    }

    for(std::list<int>::iterator i = remote_targets().begin(); i != remote_targets().end(); ++i) {
        
        if(target_profiles().find((uint64_t)*i) != target_profiles().end()) 
            if(target_profiles()[(uint64_t)*i]->level_ < level && ! forced_ ) 
                continue;
            if(forced_ && target_profiles()[(uint64_t)*i]->level_ == NON)
                continue;
            
        std::stringstream  s;
        s << sss <<  "\r\n";
        std::string a = s.str();
        
        if(::send(*i,a.c_str(),a.size(),0) < 0) {
            std::cerr << string_format("logger::write_log: cannot write remote socket: %d",*i);
        }
        
        //if(target_profiles()[(uint64_t)*i]->dup_to_cout_) really_dup = true;
    }
    
    // if set, log extra to stdout/stderr
    if(really_dup) {
        std::ostream* o = &std::cout;

        if( level <= ERR) {
            o = &std::cerr;
        }
        *o << sss << std::endl;
    }
    
    forced_ = false;

    return sss.size();
}

void logger::log(unsigned int l, const std::string& fmt, ...) {

    std::lock_guard<std::recursive_mutex> lck(mtx_lout);

    if (l > level() && ! forced_) return;

    struct timeval tv;
    struct timezone tz;

    gettimeofday(&tv,&tz);

    time_t *now = &tv.tv_sec;
    time(now);
    struct tm *tmp;
    tmp = localtime(now);	
    char date[64];


    int date_len = std::strftime(date,sizeof(date),"%y-%m-%d %H:%M:%S",tmp);

    std::string str;    
    PROCESS_VALIST(str,fmt);
    
    
    std::string desc = std::string(level_table[0]);
    if (l > sizeof(level_table)-1) {
		desc = string_format("%d",l);
	} else {
		desc = level_table[l];
	}    
    
    
    std::stringstream ss;
    ss << std::string(date,date_len) << "." << string_format("%06d",tv.tv_usec) << " <" << std::hex << std::this_thread::get_id() << "> " << desc << " - " << str;
    std::string sss = ss.str();
    
    write_log(l,sss);
};



void logger::log2(unsigned int l, const char* src, int line, const std::string& fmt, ...) {
  
    std::lock_guard<std::recursive_mutex> lck(mtx_lout);
  
    std::string src_info = string_format("%20s:%-4d: ",src,line);

    std::string str;

    PROCESS_VALIST(str,fmt);
    
    log(l,src_info + str);
}


void logger::log_w_name(unsigned int l, std::string name, const std::string& fmt, ...) {

    std::lock_guard<std::recursive_mutex> lck(mtx_lout);
  
    std::string  str;
    PROCESS_VALIST(str,fmt);
    log_w_name(l, name.c_str(), str);
}

void logger::log_w_name(unsigned int l, const char* name, const std::string& fmt, ...) {

    std::lock_guard<std::recursive_mutex> lck(mtx_lout);
  
    const char* n = "(null)";
    if (name != nullptr) {
        n = name;
    }
    
    std::string  str;
    PROCESS_VALIST(str,fmt);
    log(l,string_format("[%s]: ",n)+str);
}

void logger::log2_w_name(unsigned int l, const char* f, int li, std::string n, const std::string& fmt, ...) {
  
    std::lock_guard<std::recursive_mutex> lck(mtx_lout);  
  
    std::string  str;
    PROCESS_VALIST(str,fmt);
    log2_w_name(l, f,li, n.c_str(), str);
}


void logger::log2_w_name(unsigned int l, const char* f, int li, const char* name, const std::string& fmt, ...) {
  
    std::lock_guard<std::recursive_mutex> lck(mtx_lout);  
  
    const char* n = "(null)";
    if (name != nullptr) {
        n = name;
    }

    std::string src_info = string_format("%20s:%-4d: ",f,li);
    std::string c_name = string_format("[%s]: ",n);
    
    std::string str;  
    PROCESS_VALIST(str,fmt);
    log(l,src_info+c_name+str);
}



bool logger::click_timer ( std::string xname , int interval) {
	
	std::lock_guard<std::mutex> lck(mtx_timers);
	
	std::string name;
	auto myid = std::this_thread::get_id();
	std::stringstream ss;
	ss << myid;

	name += xname + "_th" + ss.str();
	
	auto r = timers.find(name);
	if (r != timers.end()) {
		// we found entry
		time_t l = (*r).second.last;
		int i = (*r).second.timeout;
		
		time_t now = ::time(NULL);
		
		if( now > l + i) {
			(*r).second.last = now;
			return true;
		} 
		else {
			return false;
		}
	
	} else {
		// we should establish a new timer
		time_t now = ::time(NULL);		
		timer_tt tt;
		tt.last = now;
		tt.timeout = interval;
		
		timers[name] = tt;
		
		return true;
	}
}
