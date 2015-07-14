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

#include <sobject.hpp>

namespace socle {

ptr_cache<sobject*,sobject_info> sobject_db("global object db",0,true);

sobject::sobject() {
    sobject_db.lock();
    sobject_db.set(this,new sobject_info());
    sobject_db.unlock();
}


sobject::~sobject() {
    sobject_db.lock();
    sobject_db.erase(this);
    sobject_db.unlock();
}


std::string sobject_db_to_string(const char* criteria,const char* delimiter) {
    
    std::string ret;
    sobject_db.lock();
    
    for(auto it: sobject_db.cache()) {
        sobject*       ptr = it.first;
        
        if( criteria == nullptr || ptr->class_name() == criteria ) {
            sobject_info*  si = it.second;
            ret += ptr->to_string();

#ifdef SOCLE_MEM_PROFILE
            ret += "\n";
            if(si != nullptr) 
                ret += si->to_string();
#endif
            (delimiter == nullptr) ? ret += "\n\n" : ret += delimiter;
            
        }
    }
    
    sobject_db.unlock();
    return ret;
}

DEFINE_LOGGING_INFO(sobject);

}