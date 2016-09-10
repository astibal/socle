/*
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.
    
*/

#ifndef PTR_CACHE_HPP
 #define PTR_CACHE_HPP

#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <unordered_map>

#include <ctime>

#include <socle_common.hpp>
#include <string.h>
#include <logger.hpp>

template <class T>
struct expiring {
    
    expiring(T v, unsigned int in_seconds): value(v) { expired_at = ::time(nullptr) + in_seconds; }
    virtual ~expiring() {};
    
    T value;
    time_t expired_at;
    
    static bool is_expired(expiring<T> *ptr) { return (ptr->expired_at <= ::time(nullptr)); }

private:
    expiring();
};

template <class T>
struct expiring_ptr {
    
    expiring_ptr(T* v, unsigned int in_seconds): value(v) { expired_at = ::time(nullptr) + in_seconds; }
    virtual ~expiring_ptr() { delete value; };
    
    T* value;
    time_t expired_at;
    
    static bool is_expired(expiring<T> *ptr) { return (ptr->expired_at <= ::time(nullptr)); }

private:
    expiring_ptr();
};



typedef expiring<int> expiring_int;
typedef expiring<std::string> expiring_string;

template <class K, class T>
class ptr_cache {
public:
    ptr_cache(const char* n): auto_delete_(true), max_size_(0) { name(n); }
    ptr_cache(const char* n, unsigned int max_size, bool auto_delete, bool (*fn_exp)(T*) = nullptr ): auto_delete_(auto_delete), max_size_(max_size) { name(n); expiration_check(fn_exp); }
    virtual ~ptr_cache() { clear(); if(default_value_ != nullptr && auto_delete_) { delete default_value_; }; }


    void invalidate() {
        std::lock_guard<std::recursive_mutex> l(lock_);
        
        for(auto it = cache().begin(); it != cache().end() ; ++ it) {
            T*& ptr = it->second;
            if(auto_delete()) {
                delete ptr;
            }
            ptr = default_value();
        }
    }

    void clear() {
        std::lock_guard<std::recursive_mutex> l(lock_);
        cache().clear();
        items_.clear();
    }

    std::unordered_map<K,T*>& cache() { return cache_; }

    void lock() { lock_.lock(); };
    void unlock() { lock_.unlock(); };

    bool auto_delete() const { return auto_delete_; }
    void auto_delete(bool b) { auto_delete_ = b; }

    T*   default_value() const { return default_value_; }
    void default_value(T* d) const { if(default_value_ != nullptr && auto_delete_) { delete default_value_; }; default_value_ = d; }
    
    int max_size() const { return max_size_; }

    
    bool erase(K k) {
        std::lock_guard<std::recursive_mutex> l(lock_);
        auto it = cache().find(k);
        if(it != cache().end()) {
            DEB_("ptr_cache::erase[%s]: erase: key found ", c_name());
            set(k,nullptr);
            cache().erase(k);
            DEB_("ptr_cache::erase[%s]: erase: key erased", c_name());
            
            return true;
        } else {
            DEB_("ptr_cache::erase[%s]: cannot erase: key not found ", c_name());
        }
        
        return false;
    }
    
    T* get(K k) {
        std::lock_guard<std::recursive_mutex> l(lock_);
        auto it = cache().find(k);
        if(it == cache().end()) {
            return default_value();
        }
        else if (fn_expired_check != nullptr) {
            // check if object isn't expired
            if(fn_expired_check(it->second)) {
                erase(k);
                return default_value();
            }
        }
        
        return it->second;
    }
    
    // set the key->value. Return true if other value had been replaced.
    bool set(const K k, T* v) {
        std::lock_guard<std::recursive_mutex> l(lock_);
        bool ret = false;
        
        auto it = cache().find(k);
        if(it != cache().end()) {
            DEB_("ptr_cache::set[%s]: existing entry found", c_name());
            T*& ptr = it->second;
            ret = true;
            
            if(ptr != nullptr) {
                if(auto_delete() && ptr != v) {
                    DEB_("ptr_cache::set[%s]: autodelete set and entry new value is different -- deleting.", c_name());
                    delete ptr;
                } else {
                    DEB_("ptr_cache::set[%s]: not deleting existing object:", c_name());
                    if(!auto_delete()) DEBS_("     autodelete not set");
                    if(ptr == v) DEBS_("     values are the same");
                }
            } else {
                INF_("ptr_cache::set[%s]: existing entry is nullptr", c_name());
            }
            
            ptr = v;
        } else {
            DIA_("ptr_cache::set[%s]: new entry added", c_name());
            cache()[k] = v;
            
            if(max_size_ > 0) {
                items_.push_back(k);
                
                if( items_.size() > max_size_) {
                    DEB_("ptr_cache::set[%s]: max size reached!", c_name());
                    K to_delete = items_.front();
                    
                    if(!erase(to_delete)) {
                        DEB_("ptr_cache::set[%s]: cannot erase expired object : not found!", c_name());
                    }
                    
                    items_.pop_front();
                    DIA_("ptr_cache::set[%s]: expired object removed from cache", c_name());
                }
            }
        }

        return ret;
    }
    
    void expiration_check(bool (*fn_expired_check_ptr)(T*)) { fn_expired_check = fn_expired_check_ptr; };
    
private:
    bool auto_delete_ = true;

    unsigned int max_size_ = 0;
    std::deque<K> items_;
    
    T* default_value_ = nullptr;
    std::unordered_map<K,T*> cache_;
    std::recursive_mutex lock_;
    
    bool (*fn_expired_check)(T*) = nullptr;
    
    DECLARE_C_NAME("object cache");
};

#endif
