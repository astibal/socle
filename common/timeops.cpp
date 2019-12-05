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


#include <ctime>
#include <string>
#include <sstream>

#include <timeops.hpp>
#include <sys/time.h>

int timeval_msdelta (struct timeval  *x,struct timeval  *y)  {

    int sec_delta = (x->tv_sec - y->tv_sec) * 1000;
    int usec_delta = (x->tv_usec - y->tv_usec)/1000;
    
    return sec_delta + usec_delta;
}

int timeval_msdelta_now (struct timeval  *x)  {

    timeval now;
    gettimeofday(&now,nullptr);
    
    int sec_delta = (now.tv_sec - x->tv_sec) * 1000;
    int usec_delta = (now.tv_usec - x->tv_usec)/1000;
    
    return sec_delta + usec_delta;
}


std::string uptime_string(unsigned int uptime) {

    double diff = uptime;
    if ( diff < 0 )

        diff*=-1;
    std::ostringstream o;


    if ( diff < 60 )
    {
        o << diff <<"s";
        return o.str();
    }

    if ( diff < 3600 )
    {
        int min = (int)diff/60;
        int sec= (int)diff%60;
	
        o << min <<"m "<< sec << "s";
    }
    else if ( diff < 86400 ) /* DAY */
    {
        int hours = (int) diff/3600;
        int hourRemainder = (int)diff%3600;
        int min = (int)hourRemainder/60;
        int sec= (int)diff%60;
	
        o<< hours << "h "<< min << "m "<< sec << "s";
    }
    else if ( diff < 31536000 ) /* YEAR */
    {
        int days = (int) diff/86400;
        int daysRemainder = (int)diff%86400;
        int hours = (int) daysRemainder/3600;
        int hourRemainder = (int)(diff - 86400)%3600;
        int min = (int)hourRemainder/60;
        int sec= (int)diff%60;
	
        o << days << "d " << hours << "h "<< min << "m "<<sec<< "s";
    }
    else
    {
        int years = (int) diff/31536000;
        int yearsRemainder = (int) diff%31536000;
        int days = (int) yearsRemainder/86400;
        int daysRemainder = (int)diff%86400;
        int hours = (int) daysRemainder/3600;
        int hourRemainder = (int)(diff - 86400)%3600;
        int min = (int)hourRemainder/60;
        int sec= (int)diff%60;
        
	o<< years << "y " << days << "d " << hours << "h " << min << "m " << sec << "s";
    }



    return o.str();
}


// generic counter function:
// increment counter @counter according to time @last_time value.
// If @last_time difference from now is higher than @seconds from now,
// threshold is reached and new @last_time is set to now.
unsigned long time_update_counter_sec(time_t* last_time, unsigned long* prev_counter, unsigned long* curr_counter, int seconds, int increment) {
    time_t now = time(nullptr);

    if( now - *last_time > seconds  ) {
        // threshold is reached => counter contains all bytes in previous second
        *last_time = now;
        *prev_counter  = *curr_counter;

        *curr_counter = increment;

    } else {
        (*curr_counter)+=increment;
    }

    return *prev_counter;
}


unsigned long time_get_counter_sec(time_t const* last_time, unsigned long const* counter, int seconds) {
    time_t now = time(nullptr);

    if( now - *last_time > seconds  ) {
        return 0;
    }

    return *counter;
}