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

DEFINE_LOGGING(sobject)
DEFINE_LOGGING(sobject_info)    
    
ptr_cache<sobject*,sobject_info> sobject_db("global object db",0,true);

meter sobject::mtr_created;
meter sobject::mtr_deleted;


std::string sobject_info::to_string(int verbosity) { 
    std::string r;
    
    if(verbosity > INF) {
        r += "    " + name()+ ": " + string_format("age: %ds", age());
        
        if(verbosity >= DEB ) {
            std::string ex = extra_string();
            if(ex.size() > 0)
                r += " extra info: " + ex; 
        }
    }
    
    return r;
};

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


unsigned long time_get_counter_sec(time_t* last_time, unsigned long* counter, int seconds) {
    time_t now = time(nullptr);
    
    if( now - *last_time > seconds  ) {
        return 0;
    }
    
    return *counter;
}

sobject::sobject() {
    sobject_db.lock();
    sobject_db.set(this,new sobject_info());
    mtr_created.update(1);
    sobject_db.unlock();
}


sobject::~sobject() {
    sobject_db.lock();
    sobject_db.erase(this);
    mtr_deleted.update(1);
    sobject_db.unlock();
}


std::string sobject_db_list(const char* class_criteria,const char* delimiter,int verbosity,const char* content_criteria) {
    
    std::string ret;
    std::string criteria = "";
    sobject_db.lock();
    
    if(class_criteria)
        criteria = class_criteria;
    
    for(auto it: sobject_db.cache()) {
        sobject*       ptr = it.first;

        if(!ptr) continue;
        
        bool matched = true;
        
        //if wehave criteria, select if it's name match, or pointer match
        if(criteria.length()) {
            matched = false;

            if(criteria.compare(0,2,"0x") == 0) {
                std::string str_ptr = string_format("0x%lx",ptr);
                
                //DIA_("comparing pointer: %s and %s",str_ptr.c_str(), criteria.c_str());
                matched = (str_ptr == criteria);
            } else {
                //DIA_("comparing classname: %s and %s",ptr->class_name().c_str(), criteria.c_str());
                matched = (ptr->class_name() == criteria || criteria == "*");
            }
        }
        
        
        if(matched) {
            sobject_info*  si = it.second;
            std::string obj_string = ptr->to_string(verbosity);
            
            if(content_criteria) {
                if(obj_string.find(content_criteria) == std::string::npos) { continue; }
            }

            ret += string_format("Id: 0x%lx | ",ptr) + obj_string;

            if(verbosity >= DEB) {
                ret += "\n";
                if(si != nullptr) 
                    ret += si->to_string(verbosity);
            }
            
            (delimiter == nullptr) ? ret += "\n" : ret += delimiter;
            
        }
    }
    
    sobject_db.unlock();
    return ret;
}


std::string sobject_db_stats_string(const char* criteria) {
    
    std::string ret;
    sobject_db.lock();
    
    unsigned long object_counter = 0;
    
    int youngest_age = -1;
    int oldest_age = -1;
    unsigned int sum_age = 0;
    
    for(auto it: sobject_db.cache()) {
        sobject*       ptr = it.first;
        
        if( criteria == nullptr || ptr->class_name() == criteria ) {
            sobject_info*  si = it.second;
            object_counter++;
            
            if(si != nullptr) {
                int a = si->age();
                sum_age += a;
                
                if(a > oldest_age) oldest_age = a;
                if(a < youngest_age || youngest_age < 0) youngest_age = a;
            }
            
        }
    }
    sobject_db.unlock();
    float avg_age = 0;
    if (object_counter > 0) 
        avg_age = sum_age/object_counter;
    
    ret += string_format("Performance: %ld new objects per second, %ld deleted objects per second.\n",
                            socle::sobject::mtr_created.get(),socle::sobject::mtr_deleted.get());
    ret += string_format("Database contains: %ld entries, oldest %ds, youngest age %ds, average age is %.1fs.",
                         object_counter, oldest_age, youngest_age, avg_age);
    return ret;
}

// asks object to terminate
int sobject_db_ask_destroy(void* ptr) {
    
    int ret = -1;
    
    sobject_db.lock();
    
    auto it = sobject_db.cache().find((sobject*)ptr);
    if(it != sobject_db.cache().end()) {
        ret = 0;
        if(it->first->ask_destroy()) {
            ret = 1;
        }
    }
    sobject_db.unlock();
    
    return ret;
}

long unsigned int meter::update(unsigned long val) {
    
    time_t now = time(nullptr);
    
    if( now - last_update > interval_) {
        // threshold is reached => counter contains all bytes in previous second
        last_update = now;
        prev_counter_  = curr_counter_;
        
        curr_counter_ = val;
        
    } else {
        curr_counter_ += val;
    }
    
    return prev_counter_;
}

}