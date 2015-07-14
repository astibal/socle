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


#ifndef SOBJECT_HPP_
#define SOBJECT_HPP_

#include <logger.hpp>
#include <ptr_cache.hpp>

namespace socle {

/*
 * Accouting info
*/
struct sobject_info {
};
class sobject;

// Class name -> ptr_cache<key is ptr to sobject*, >
std::unordered_map<std::string,ptr_cache<sobject*,sobject_info>> sobject_db;

class sobject {
    

public:
    sobject() {};
    virtual ~sobject() {};

    // ask kindly to stop use this object (for example, user implementation could set error indicator, etc. )
    virtual bool ask_destroy() = 0;

    // return string representation of the object on single line
    virtual std::string to_string() = 0;

    // return string representation of the object on multiple lines, good for troubleshooting
    virtual std::string to_string_full() = 0;

DECLARE_C_NAME("sobject");
DECLARE_LOGGING_INFO(name);
};


};
#endif
