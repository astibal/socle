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

int timeval_msdelta (struct timeval  *x,struct timeval  *y)  {

    int sec_delta = (x->tv_sec - y->tv_sec) * 1000;
    int usec_delta = (x->tv_usec - y->tv_usec)/1000;
    
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
