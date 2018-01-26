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

loglevel NON = loglevel(0,0);
loglevel FAT = loglevel(1,0);
loglevel CRI = loglevel(2,0); 
loglevel ERR = loglevel(3,0);
loglevel WAR = loglevel(4,0); 
loglevel NOT = loglevel(5,0); 
loglevel INF = loglevel(6,0); 
loglevel DIA = loglevel(7,0); 
loglevel DEB = loglevel(8,0); 
loglevel DUM = loglevel(9,0); 
loglevel EXT = loglevel(10,0); 

loglevelmore LOG_EXTOPIC = loglevelmore(true,false);
loglevelmore LOG_EXEXACT = loglevelmore(true,true);


logger* lout_ = nullptr;

static  std::string level_table[] = {"None    ","Fatal   ","Critical","Error   ","Warning ","Notify  ","Informat","Diagnose","Debug   ","Dumpit  ","Extreme "};


bool operator== (const loglevel& a, const loglevel& b) { return a.level_ == b.level_; }
bool operator== (const loglevel& a, const unsigned int& b) { return a.level_ == b; }
bool operator== (const unsigned int& a, const loglevel& b) { return a == b.level_; }


bool operator<= (const loglevel& a, const loglevel& b) { return a.level_ <= b.level_; }
bool operator<= (const loglevel& a, const unsigned int& b) { return a.level_ <= b; }
bool operator<= (const unsigned int& a, const loglevel& b) { return a <= b.level_; }


bool operator>= (const loglevel& a, const loglevel& b) { return a.level_ >= b.level_; }
bool operator>= (const loglevel& a, const unsigned int& b) { return a.level_ >= b; }
bool operator>= (const unsigned int& a, const loglevel& b) { return a >= b.level_; }


bool operator!= (const loglevel& a, const loglevel& b) { return a.level_ != b.level_; }
bool operator!= (const loglevel& a, const unsigned int& b) { return a.level_ != b; }
bool operator!= (const unsigned int& a, const loglevel& b) { return a != b.level_; }


bool operator> (const loglevel& a, const loglevel& b) { return a.level_ > b.level_; }
bool operator> (const loglevel& a, const unsigned int& b) { return a.level_ > b; }
bool operator> (const unsigned int& a, const loglevel& b) { return a > b.level_; }


bool operator< (const loglevel& a, const loglevel& b) { return a.level_ < b.level_; }
bool operator< (const loglevel& a, const unsigned int& b) { return a.level_ < b; }
bool operator< (const unsigned int& a, const loglevel& b) { return a < b.level_; }

loglevel operator-(const loglevel& a, const loglevel& b) { loglevel r = a; r.level(a.level() - b.level()); return r; }
loglevel operator-(const loglevel& a, const unsigned int& b) { loglevel r = a; r.level(a.level() - b); return r; }
loglevel operator+(const loglevel& a, const unsigned int& b) { loglevel r = a; r.level(a.level() + b); return r; }


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


bool logger::should_log_topic(loglevel& writer, loglevel& msg) {

    // writer loglevel
    unsigned int t = writer.topic();
    
    // if msg has set topic, we need to check what to do
    if(msg.topic() != 0) {
        if(msg.more() != nullptr) {
            if(msg.more()->exclusive_exact) {
                if(t != msg.topic()) {
                    return false;
                }
            }
            
            // Exclusive topic
            if(msg.more()->exclusive_topic) {
                if(t == iNON) return false;
                
                unsigned int l_area = 0xffff0000 | msg.topic();
                unsigned int t_area = 0xffff0000 | t;
                if(l_area != t_area) {
                    return false;
                }
            }
        }
    } else {
        // msg doesn't have any topic (== 0)
        if(t > 0) {
            
            // we don't want to write generic messages into specialized writer
            return false;
        }
    }
    
    return true;
}

int logger::write_log(loglevel level, std::string& sss) {

    bool really_dup = dup2_cout();
    
    for(std::list<std::ostream*>::iterator i = targets().begin(); i != targets().end(); ++i) {
        if(target_profiles().find((uint64_t)*i) != target_profiles().end()) {
            if(target_profiles()[(uint64_t)*i]->level_ < level && ! forced_) { continue; }
            if(target_profiles()[(uint64_t)*i]->level_ == NON)    { continue; }
        }
        
        if (!should_log_topic(target_profiles()[(uint64_t)*i]->level_,level)) continue;
        
        *(*i) << sss << std::endl;
        //if(target_profiles()[(uint64_t)*i]->dup_to_cout_) really_dup = true;
    }

    for(std::list<int>::iterator i = remote_targets().begin(); i != remote_targets().end(); ++i) {
        
        if(target_profiles().find((uint64_t)*i) != target_profiles().end()) { 
            if(target_profiles()[(uint64_t)*i]->level_ < level && ! forced_ ) { continue; }
            if(target_profiles()[(uint64_t)*i]->level_ == NON)     { continue; }
        }
        
        if (!should_log_topic(target_profiles()[(uint64_t)*i]->level_,level)) continue;
            
        std::stringstream  s;

        // prefixes
        if(target_profiles()[(uint64_t)*i]->logger_type == REMOTE_SYSLOG) {
            s <<  string_format("<%d> ",target_profiles()[(uint64_t)*i]->syslog_settings.prival());
        } 
        
        s << sss ;
        
        // suffixes
        if(target_profiles()[(uint64_t)*i]->logger_type != REMOTE_SYSLOG) {
            s <<  "\r\n";
        } 
        
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

void logger::log(loglevel l, const std::string& fmt, ...) {

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



    std::string str;    
    PROCESS_VALIST(str,fmt);
    
    
    std::string desc = std::string(level_table[0]);
    if (l > sizeof(level_table)-1) {
		desc = string_format("%d",l);
	} else {
		desc = level_table[l.level()];
	}    
    
    
    std::stringstream ss;
    int date_len = std::strftime(date,sizeof(date),"%y-%m-%d %H:%M:%S",tmp);
    
    if(flag_test(l.flags_,LOG_FLRAW)) {
        ss << str;
    }
    else {
        // default line format: date time.usec <threadid> loglevel - MSG
        ss << std::string(date,date_len) << "." << string_format("%06d",tv.tv_usec) << " <" << std::hex << std::this_thread::get_id() << "> " << desc << " - " << str;
    }


    std::string sss = ss.str();
    write_log(l,sss);
};



void logger::log2(loglevel l, const char* src, int line, const std::string& fmt, ...) {
  
    std::lock_guard<std::recursive_mutex> lck(mtx_lout);
  
    std::string src_info = string_format("%20s:%-4d: ",src,line);

    std::string str;

    PROCESS_VALIST(str,fmt);
    
    log(l,src_info + str);
}


void logger::log_w_name(loglevel l, std::string name, const std::string& fmt, ...) {

    std::lock_guard<std::recursive_mutex> lck(mtx_lout);
  
    std::string  str;
    PROCESS_VALIST(str,fmt);
    log_w_name(l, name.c_str(), str);
}

void logger::log_w_name(loglevel l, const char* name, const std::string& fmt, ...) {

    std::lock_guard<std::recursive_mutex> lck(mtx_lout);
  
    const char* n = "(null)";
    if (name != nullptr) {
        n = name;
    }
    
    std::string  str;
    PROCESS_VALIST(str,fmt);
    log(l,string_format("[%s]: ",n)+str);
}

void logger::log2_w_name(loglevel l, const char* f, int li, std::string n, const std::string& fmt, ...) {
  
    std::lock_guard<std::recursive_mutex> lck(mtx_lout);  
  
    std::string  str;
    PROCESS_VALIST(str,fmt);
    log2_w_name(l, f,li, n.c_str(), str);
}


void logger::log2_w_name(loglevel l, const char* f, int li, const char* name, const std::string& fmt, ...) {
  
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


loglevel logger::adjust_level() {

    loglevel curr_level = level();
    loglevel max_common_level = NON;
    
    for(auto i = remote_targets().begin(); i != remote_targets().end(); ++i) {
        loglevel this_level = target_profiles()[(uint64_t)(*i)]->level_;
        if ( this_level > max_common_level) {
            max_common_level = this_level;
        }
    }
    for(auto i = targets().begin(); i != targets().end(); ++i) {
        loglevel this_level = target_profiles()[(uint64_t)(*i)]->level_;
        if ( this_level > max_common_level) {
            max_common_level = this_level;
        }
    }
    
    // if we detect necessity
    if(max_common_level != curr_level) {
        level(max_common_level);
    } 
    
    // return log level difference, therefore negative if we decreased logging level, zero if unchanged, positive if log level is raised.
    return max_common_level - curr_level;
}
    