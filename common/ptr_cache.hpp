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
#include <cstring>

#include <mpstd.hpp>

#include <socle_common.hpp>
#include <log/logger.hpp>
#include <log/logan.hpp>

template <class T>
struct expiring {
    expiring() = delete;
    expiring(T v, unsigned int in_seconds): value_(v) { expired_at_ = ::time(nullptr) + in_seconds; }
    virtual ~expiring() = default;

    T& value() { return value_; };
    time_t& expired_at() { return expired_at_; };

    virtual bool expired() { return (this->expired_at_ <= ::time(nullptr)); }
    static bool is_expired(std::shared_ptr<expiring<T>>& ptr) {  return ptr->expired(); }

private:
    T value_{0};
    time_t expired_at_{0};


};

template <class T>
struct expiring_ptr {

    expiring_ptr() = delete;
    expiring_ptr(T* v, unsigned int in_seconds): value_(v) { expired_at_ = ::time(nullptr) + in_seconds; }
    virtual ~expiring_ptr() { delete value_; };

    T*& value() { return value_; };
    time_t& expired_at() { return expired_at_; };

    virtual bool expired() { return (this->expired_at_ <= ::time(nullptr)); }
    static bool is_expired(expiring<T> *ptr) { return ptr->expired(); }

private:
    T* value_;
    time_t expired_at_;

};



typedef expiring<int> expiring_int;
typedef expiring<std::string> expiring_string;

template <class K, class T>
class ptr_cache {
public:
    explicit ptr_cache(const char* n): auto_delete_(true), max_size_(0) {
        name(n);
        log = logan::create("socle.ptrcache");

    }
    ptr_cache(const char* n, unsigned int max_size, bool auto_delete, bool (*fn_exp)(std::shared_ptr<T>&) = nullptr ): auto_delete_(auto_delete), max_size_(max_size) {
        name(n);
        expiration_check(fn_exp);
        log = logan::create("socle.ptrcache");
    }
    virtual ~ptr_cache() = default;

    void clear() {
        std::lock_guard<std::recursive_mutex> l(lock_);

        cache().clear();
        items_.clear();
    }

    mp::unordered_map<K,std::shared_ptr<T>>& cache() { return cache_; }
    mp::deque<K> const& items() { return items_; };

    std::shared_ptr<T>   default_value() const { return default_value_; }
    int max_size() const { return max_size_; }

    unsigned int opportunistic_removal() const { return opportunistic_removal_; };
    
    bool erase(K k) {
        std::lock_guard<std::recursive_mutex> l(lock_);
        auto it = cache().find(k);
        if(it != cache().end()) {
            _deb("ptr_cache::erase[%s]: erase: key found ", c_name());
            cache().erase(k);
            _dia("ptr_cache::erase[%s]: erase: key erased", c_name());
            
            return true;
        } else {
            _dia("ptr_cache::erase[%s]: cannot erase: key not found ", c_name());
        }
        
        return false;
    }

    // shortcut to erase cache iterator
    typename std::unordered_map<std::string, std::shared_ptr<T>>::iterator erase(typename std::unordered_map<std::string, std::shared_ptr<T>>::iterator& i) {
        return cache().erase(i);
    }

    std::shared_ptr<T> get(K k) {
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

    bool set(const K k, T* v) {
        std::shared_ptr<T> p(v);
        return set(k, p);
    }

    // set the key->value. Return true if other value had been replaced.
    bool set(const K k, std::shared_ptr<T> v) {
        std::lock_guard<std::recursive_mutex> l(lock_);
        bool ret = false;
        
        auto it = cache().find(k);
        if(it != cache().end()) {
            _dia("ptr_cache::set[%s]: existing entry found", c_name());
            auto& ptr = it->second;
            ret = true;
            ptr = v;
        } else {
            _dia("ptr_cache::set[%s]: new entry added", c_name());
            cache()[k] = v;
            
            if(max_size_ > 0) {
                _deb("ptr_cache::set[%s]: current size %d/%d", c_name(), items_.size(), max_size_);

                while( items_.size() >= max_size_) {
                    _deb("ptr_cache::set[%s]: max size reached!", c_name());
                    K to_delete = items_.front();
                    
                    if(!erase(to_delete)) {
                        if( opportunistic_removal() == 0 ) {
                            // log.removal errors only if opportunistic removal is enabled
                            _not("ptr_cache::set[%s]: cannot erase oldest object: not found!", c_name());
                        }
                    } else {
                        _dia("ptr_cache::set[%s]: oldest object removed", c_name());
                    }
                    
                    items_.pop_front();
                    _dia("ptr_cache::set[%s]: max size: object removed from cache", c_name());
                }

                items_.push_back(k);
            }
        }

        return ret;
    }
    
    void expiration_check(bool (*fn_expired_check_ptr)(std::shared_ptr<T>&)) { fn_expired_check = fn_expired_check_ptr; };
    std::recursive_mutex& getlock() { return lock_; }

private:
    bool auto_delete_ = true;
    unsigned int max_size_ = 0;
    unsigned int opportunistic_removal_ = 0;

    mp::deque<K> items_;
    
    std::shared_ptr<T> default_value_{nullptr};
    mp::unordered_map<K,std::shared_ptr<T>> cache_;
    mutable std::recursive_mutex lock_;
    
    bool (*fn_expired_check)(std::shared_ptr<T>&) = nullptr;

    logan_lite log;

    DECLARE_C_NAME("object cache");
};

#endif
