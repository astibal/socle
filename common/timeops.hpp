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


#ifndef _TIMEOPS_HPP
	#define _TIMEOPS_HPP

[[maybe_unused]] long timeval_msdelta (struct timeval  *x,struct timeval  *y);
[[maybe_unused]]long timeval_msdelta_now(struct timeval  *x);
std::string uptime_string(unsigned int uptime);

unsigned long time_update_counter_sec(time_t* last_time, unsigned long* prev_counter, unsigned long* curr_counter, int seconds, int increment=1);
unsigned long time_get_counter_sec(time_t const* last_time, unsigned long const* counter, int seconds);

#endif