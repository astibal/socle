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

#include <set>

#include <time.h>

#include <logger.hpp>
#include <ptr_cache.hpp>
#include <display.hpp>

namespace socle {

std::string sobject_db_list(const char* class_criteria = nullptr,const char* delimiter = nullptr,int verbosity=INF,const char* content_criteria=nullptr);
std::string sobject_db_stats_string(const char* criteria);

unsigned long time_update_counter_sec(time_t* last_time, unsigned long* prev_counter, unsigned long* curr_counter, int seconds, int increment=1);
unsigned long time_get_counter_sec(time_t* last_time, unsigned long* counter, int seconds);

int sobject_db_ask_destroy(void* ptr);

/*
 * Accouting info for all sobjects.
*/
struct sobject_info {
#ifdef SOCLE_MEM_PROFILE
    sobject_info() { bt_ = bt(); init(); }
    std::string bt_;
    
    std::string extra_string() { return string_format("creation point:\n%s",bt_.c_str()); }
#else
    sobject_info() { init(); }
    std::string extra_string() { return ""; }
#endif

    void init() { created_ = time(nullptr); }

    time_t created_ = 0;
    unsigned int age() { return time(nullptr) - created_; }

    std::string to_string(int verbosity=INF);
    virtual ~sobject_info() {};
    
    DECLARE_C_NAME("sobject_info");
};

struct meter;

class sobject {

public:
    sobject();
    virtual ~sobject();

    // ask kindly to stop use this object (for example, user implementation could set error indicator, etc. )
    virtual bool ask_destroy() = 0;

    // return string representation of the object on single line
    virtual std::string to_string(int verbosity=INF) = 0;

    
    static meter mtr_created;
    static meter mtr_deleted;
    
DECLARE_C_NAME("sobject");
// DECLARE_LOGGING(name);
};


template <class T> class sref;

template <class T>
class spointer {
    public:
        spointer() : pointer_(nullptr) {};        
        spointer(T* ptr): pointer_(ptr) {};
        virtual ~spointer() { delete pointer_; }

        unsigned int usage() { return count_; }

        bool valid() { return (pointer_ != nullptr); }
        void invalidate() { delete pointer_; pointer_ = nullptr; count_=0; }
        
        T* operator->() { return pointer_;  }
        T& operator*() { return *pointer_; }
        T* ptr() { return pointer_; }
        void ptr(T* p) { invalidate(); pointer_ = p; }

        spointer<T>& operator=(const spointer<T>&) = delete;
        spointer(const spointer&) = delete;
    private:
        T* pointer_ = nullptr;
        unsigned int count_ = 0;
        
        inline void use() { count_++; };
        inline void unuse() { if(count_>0) count_--; };
        
    friend class sref<T>;
};

template <class T>
class sref {
    public:
        sref() : reference_(nullptr) {};
        sref(spointer<T>* r) : reference_(r) { r->use(); };
        sref(spointer<T>& r) : reference_(&r) { r.use(); };

        sref<T>& operator=(const sref& other) {
            if(this != &other) {
                unref();
                reference_ = other.reference_;
                if(reference_ != nullptr) reference_->use();
            }
            return *this;
        };

        sref<T>& operator=(const spointer<T>* sptr) {
            unref();
            newref(sptr);

            return *this;
        };
        
        sref(const sref<T>& other) {
            reference_ = other.reference_;
            
            if(reference_ != nullptr) {
                reference_->use();
            }
        };

        virtual ~sref() { unref(); };
        
        inline void unref() {
            if(reference_ != nullptr) {
                reference_->unuse();
                reference_ = nullptr;
            }
        }
        
        spointer<T>* ref() { return reference_; }
        
        void newref(spointer<T>* n) { reference_ = n; if(n != nullptr) { n->use(); } };
        void newref(spointer<T>& n) { reference_ = &n; if(reference_ != nullptr) { reference_->use(); } };
        void ref(spointer<T>* n) { unref(); newref(n); };
        void ref(spointer<T>& n) { unref(); newref(&n); };
        
        T* refval() { if(ref() != nullptr)  return ref()->pointer_; return nullptr; }
        
        
    private:
        spointer<T>* reference_ = nullptr;
};


struct meter {
    
    meter(int interval=1): interval_(interval) { last_update = time(nullptr); };
    
    unsigned long prev_counter_{};
    unsigned long curr_counter_{};
    
    time_t last_update;
    int interval_{1};
    
    
    unsigned long update(unsigned long val);
    unsigned long get() const { if(time(nullptr) > last_update + interval_) { return 0; } return prev_counter_; };
};

typedef spointer<std::vector<std::string>> spointer_vector_string;
typedef spointer<std::vector<int>> spointer_vector_int;
typedef spointer<std::set<int>> spointer_set_int;
typedef sref<std::vector<std::string>> sref_vector_string;

extern ptr_cache<sobject*,sobject_info> sobject_db;

};
#endif

