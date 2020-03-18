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

#include <log/logger.hpp>
#include <ptr_cache.hpp>
#include <display.hpp>

namespace socle {


/*
 * Accounting info for all sobjects.
*/
struct sobject_info {
    static bool enable_bt_;
    std::string* bt_ = nullptr;
    
    std::string extra_string() const { if (bt_) { return string_format("creation point:\n%s",bt_->c_str()); } else { return ""; } }
    sobject_info() { init(); }

    void init() { 
        created_ = time(nullptr); 
        if(enable_bt_) {
            bt_ = new std::string(bt());
        }
    }

    time_t created_ = 0;
    unsigned int age() const { return time(nullptr) - created_; }

    std::string to_string(int verbosity=iINF) const;
    virtual ~sobject_info() { if(bt_) delete bt_; };
    
    DECLARE_C_NAME("sobject_info");
    DECLARE_LOGGING(to_string);

protected:
    logan_attached<sobject_info> log = logan_attached<sobject_info>(this, "internal.sobject");
};

struct meter {

private:
    unsigned long total_{};

    unsigned long prev_counter_{};
    unsigned long curr_counter_{};

    std::chrono::system_clock::time_point last_update{};
    int interval_{1};

public:

    explicit meter(int interval=1): interval_(interval) { last_update = std::chrono::system_clock::now(); };

    unsigned long update(unsigned long val);
    [[nodiscard]] unsigned long get() const;
    [[nodiscard]] unsigned long total() const { return total_; };
};


class base_sobject {
    virtual std::string to_string(int verbosity=iINF) const = 0;
};
class sobject;

// Singleton class - used as central sobject storage
class sobjectDB : public base_sobject {

    ptr_cache<sobject*,sobject_info> db_;
    ptr_cache<uint64_t,sobject> oid_db_;

    sobjectDB() : db_("global object db",0, false), oid_db_("oid db", 0, false) {};
    virtual ~sobjectDB() = default;

public:
    static sobjectDB& get() {
        static sobjectDB sobjdb = sobjectDB();
        return sobjdb;
    }

    static ptr_cache<sobject*,sobject_info>& db() { return sobjectDB::get().db_; }
    static ptr_cache<uint64_t,sobject>& oid_db() { return sobjectDB::get().oid_db_; }

    // convenience methods giving info in human readable string form
    static std::string str_list(const char* class_criteria = nullptr,
                                const char* delimiter = nullptr,
                                int verbosity = iINF,
                                const char* content_criteria = nullptr);

    static std::string str_stats(const char* criteria);

    // ask object to destruct itself
    static int ask_destroy(void* ptr);

    std::string to_string(int verbosity=iINF) const override { return this->class_name(); };

    DECLARE_C_NAME("sobjectDB");
    DECLARE_LOGGING(to_string);

protected:
    logan_attached<sobjectDB> log = logan_attached<sobjectDB>(this, "internal.sobject");
};

class sobject : public base_sobject {

public:
    typedef uint64_t oid_type;

private:
    oid_type oid_;

public:
    sobject();
    virtual ~sobject();
    inline const oid_type oid() const { return oid_; };

    // ask kindly to stop use this object (for example, user implementation could set error indicator, etc. )
    virtual bool ask_destroy() = 0;

    // return string representation of the object on single line
    std::string to_string(int verbosity=iINF) const override { std::stringstream ss; ss << this->class_name() << "-" << oid(); return ss.str(); };

    static meter& mtr_created() { static meter mtr_created_; return mtr_created_; } ;
    static meter& mtr_deleted() { static meter mtr_deleted_; return mtr_deleted_; } ;
    static ptr_cache<sobject*,sobject_info>& db() { return sobjectDB::db(); }
    static ptr_cache<uint64_t, sobject>& oid_db() { return sobjectDB::oid_db(); }
    
    DECLARE_C_NAME("sobject");
    DECLARE_LOGGING(to_string);

protected:
    logan_attached<sobject> log = logan_attached<sobject>(this, "internal.sobject");
};


template <class T> class sref;

template <class T>
class spointer {
    public:
        explicit spointer() : pointer_(nullptr) {};
        explicit spointer(T* ptr): pointer_(ptr) {};
        virtual ~spointer() { delete pointer_; }

        unsigned int usage() const { return count_; }

        bool valid() const { return (pointer_ != nullptr); }
        void invalidate() { delete pointer_; pointer_ = nullptr; count_=0; }
        
        T* operator->() const { return pointer_;  }
        T& operator*() const { return *pointer_; }
        T* ptr() const { return pointer_; }
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
        explicit sref() : reference_(nullptr) {};
        explicit sref(spointer<T>* r) : reference_(r) { r->use(); };
        explicit sref(spointer<T>& r) : reference_(&r) { r.use(); };

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


typedef spointer<std::vector<std::string>> spointer_vector_string;
typedef spointer<std::vector<int>> spointer_vector_int;
typedef spointer<std::set<int>> spointer_set_int;
typedef sref<std::vector<std::string>> sref_vector_string;

};
#endif

