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
unsigned long sobject::meter_created_second = 0;
unsigned long sobject::meter_deleted_second = 0;

time_t sobject::cnt_created_second = 0;
time_t sobject::cnt_deleted_second = 0;

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
unsigned long time_update_counter_sec(time_t* last_time, unsigned long* counter, int seconds) {
    time_t now = time(nullptr);
    
    if( now - *last_time > seconds  ) {
        // threshold is reached
        *last_time = now;
        
        unsigned long ret = *counter;
        *counter = 1;
        
        return ret;
    } else {
        (*counter)++;
    }
    
    return *counter;
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
    time_update_counter_sec(&cnt_created_second,&meter_created_second,1);
    sobject_db.unlock();
}


sobject::~sobject() {
    sobject_db.lock();
    sobject_db.erase(this);
    time_update_counter_sec(&cnt_deleted_second,&meter_deleted_second,1);
    sobject_db.unlock();
}


std::string sobject_db_to_string(const char* criteria,const char* delimiter,int verbosity) {
    
    std::string ret;
    sobject_db.lock();
    
    for(auto it: sobject_db.cache()) {
        sobject*       ptr = it.first;
        
        if( criteria == nullptr || ptr->class_name() == criteria ) {
            sobject_info*  si = it.second;
            ret += string_format("Id: 0x%lx | ",ptr) + ptr->to_string(verbosity);

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
                            socle::sobject::get_meter_created_second(), socle::sobject::get_meter_created_second());
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

//DEFINE_LOGGING(sobject);

}