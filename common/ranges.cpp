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

#include <ranges.hpp>
#include <display.hpp>

std::string rangetos(range r) { return string_format("<%d,%d>",r.first,r.second); }
std::string vrangetos(vector_range r) {
    std::string s;
    for(unsigned int i = 0; i < r.size(); i++) {
        s += rangetos(r[i]);
        if ( ( i + 1 ) < r.size()) {
            s += ",";
        }
    }
    
    return s;
}