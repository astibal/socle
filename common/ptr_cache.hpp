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

#include <socle_common.hpp>
#include <string.h>
#include <logger.hpp>

template <class K, class T>
class ptr_cache {
public:
    ptr_cache(const char* n): auto_delete_(true), max_size_(0) { name(n); }
    ptr_cache(const char* n, unsigned int max_size, bool auto_delete): auto_delete_(auto_delete), max_size_(max_size) { name(n); }
    virtual ~ptr_cache() { clear(); if(default_value_ != nullptr && auto_delete_) { delete default_value_; }; }


    void invalidate() {
        std::lock_guard<std::recursive_mutex> l(lock_);
        
        for(auto it = cache().begin(); it < cache().end() ; ++ it) {
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

    T* get(K& k) {
        auto it = cache().find(k);
        if(it == cache().end()) {
            return default_value();
        }
        return it->second;
    }
    
    // set the key->value. Return true if other value had been replaced.
    bool set(const K k, T* v) {
        bool ret = false;
        
        auto it = cache().find(k);
        if(it != cache().end()) {
            DEB_("ptr_cache:set[%s]: existing entry found", c_name());
            T*& ptr = it->second;
            ret = true;
            
            if(ptr != nullptr) {
                if(auto_delete() && ptr != v) {
                    DEB_("ptr_cache:set[%s]: autodelete set and entry new value is different -- deleting.", c_name());
                    delete ptr;
                } else {
                    DEB_("ptr_cache:set[%s]: not deleting existing object:", c_name());
                    if(!auto_delete()) DEB_("     autodelete not set", c_name());
                    if(ptr == v) DEB_("     values are the same", c_name());
                }
            } else {
                INF_("ptr_cache:set[%s]: existing entry is nullptr", c_name());
            }
            
            ptr = v;
        } else {
            DIA_("ptr_cache:set[%s]: new entry added", c_name());
            cache()[k] = v;
            
            if(max_size_ > 0) {
                items_.push_back(k);
                
                if( items_.size() > max_size_) {
                    DEB_("ptr_cache:set[%s]: max size reached!", c_name());
                    K to_delete = items_.front();
                    
                    if(cache().find(to_delete) != cache().end()) {
                        set(to_delete,nullptr); // to delete element if needed
                    } else {
                        DEB_("ptr_cache:set[%s]: cannot set expired object to nullptr: not found!", c_name());
                    }
                    cache().erase(to_delete);
                    items_.pop_front();
                    DIA_("ptr_cache:set[%s]: expired object removed from cache", c_name());
                }
            }
        }

        return ret;
    }

private:
    bool auto_delete_ = true;

    unsigned int max_size_ = 0;
    std::deque<K> items_;
    
    T* default_value_ = nullptr;
    std::unordered_map<K,T*> cache_;
    std::recursive_mutex lock_;
    
    DECLARE_C_NAME("object cache");
};

#endif
