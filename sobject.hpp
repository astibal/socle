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
#include <display.hpp>

namespace socle {

/*
 * Accouting info
*/
struct sobject_info {
#ifdef SOCLE_MEM_PROFILE
    sobject_info() { bt_ = bt(); }
    std::string bt_;
    
    std::string extra_string() { return string_format("created at\n%s",bt_.c_str()); }
#else
    std::string extra_string() { return "<empty>";}
#endif

    std::string to_string() { return name() + ": extra info: " + extra_string(); };
    virtual ~sobject_info() {};
    DECLARE_C_NAME("sobject_info");
};


class sobject;

extern ptr_cache<sobject*,sobject_info> sobject_db;

std::string sobject_db_to_string(const char* criteria = nullptr,const char* delimiter = nullptr);

class sobject {

public:
    sobject();
    virtual ~sobject();

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

