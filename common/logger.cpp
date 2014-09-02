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

logger lout;

static  std::string level_table[] = {"None"," Fatal","Critical","Error","Warning","Notify","Informal","Diagnose","Debug","Dumpit","Extreme"};


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


void logger::log(unsigned int l, const std::string& fmt, ...) {

	if (l > level()) return;
	
	std::lock_guard<std::mutex> lck(mtx_lout);
	
	struct timeval tv;
	struct timezone tz;
	
	gettimeofday(&tv,&tz);
	
	time_t *now = &tv.tv_sec;
	time(now);
	struct tm *tmp;
	tmp = localtime(now);	
	char date[64];

	
	int date_len = std::strftime(date,sizeof(date),"%y-%m-%d %H:%M:%S",tmp);
	
    int size = 256;
    std::string str;
    va_list ap;
    while (1) {
        str.resize(size);
        va_start(ap, fmt);
        int n = vsnprintf((char *)str.c_str(), size, fmt.c_str(), ap);
        va_end(ap);

		if (n > -1 && n < size) {
            str.resize(n);
				break;
        }
        
        if (n > -1)
            size = n + 1;
        else
            size *= 2;
    }
    
    
    
    std::string desc = std::string(level_table[0]);
    if (l > sizeof(level_table)-1) {
		desc = string_format("%d",l);
	} else {
		desc = level_table[l];
	}
	
    std::cout << std::string(date,date_len) << "." << tv.tv_sec << " <" << std::this_thread::get_id() << "> " << desc << "- " << str << std::endl;
};


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
