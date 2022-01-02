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
    static bool is_expired(std::shared_ptr<expiring<T>> ptr) {  return ptr->expired(); }

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

    struct DataBlockStats {
        uint32_t total_counter = 0;
    };

    struct DataBlock {

        using timestamp_t = std::chrono::time_point<std::chrono::system_clock>;
        using count_t = uint32_t;

        DataBlock(): dbs_(nullptr), pointer_(nullptr), counter_(0) {}
        explicit DataBlock(std::shared_ptr<DataBlockStats>dbs, std::shared_ptr<T> v) : dbs_(dbs), pointer_(v), counter_(0) {}
        ~DataBlock() = default;

        inline std::shared_ptr<T> ptr() { return pointer_; }
        inline std::shared_ptr<T> ptr() const { return pointer_; }

        void touch() { timestamp_ = std::chrono::system_clock::now(); counter_++; if(dbs_) dbs_->total_counter++; }
        [[nodiscard]] int age() const { return std::chrono::duration_cast<std::chrono::seconds>( std::chrono::system_clock::now() - timestamp_).count(); };
        [[nodiscard]] count_t count() const { return counter_; }
    private:
        std::shared_ptr<DataBlockStats> dbs_;
        std::shared_ptr<T> pointer_;
        timestamp_t timestamp_;
        count_t counter_;

    };

    using cache_t = mp::unordered_map<K, std::unique_ptr<DataBlock>>;
    using queue_t = mp::list<K>;
    enum class MODE { FIFO, LRU };

    explicit ptr_cache(const char* n): auto_delete_(true), max_size_(0) {
        log = logan::create("socle.ptrcache");

    }
    ptr_cache(const char* n, unsigned int max_size, bool auto_delete, bool (*fn_exp)(std::shared_ptr<T>) = nullptr): auto_delete_(auto_delete), max_size_(max_size) {
        expiration_check(fn_exp);
        log = logan::create("socle.ptrcache");
    }

    ptr_cache(const char* n, unsigned int max_size, bool auto_delete, MODE m): auto_delete_(auto_delete), max_size_(max_size) {
        if(m == MODE::LRU) mode_lru();
        log = logan::create("socle.ptrcache");
    }


    virtual ~ptr_cache() { clear(); };


    MODE mode_ = MODE::FIFO;

    inline void mode_lru() { mode_ = MODE::LRU; if(not dbs_) dbs_ = std::make_shared<DataBlockStats>(); }
    inline void mode_fifo() { mode_ = MODE::FIFO; }

    void clear() {
        std::lock_guard<std::recursive_mutex> l(lock_);

        cache().clear();
        items_.clear();
    }

    cache_t& cache() { return cache_; }
    cache_t const& cache() const { return cache_; }

    queue_t& items() { return items_; };
    queue_t const& items() const { return items_; };

    std::shared_ptr<T>   default_value() const { return default_value_; }
    int max_size() const { return max_size_; }

    unsigned int opportunistic_removal() const { return opportunistic_removal_; };

    bool erase(K k) {
        std::lock_guard<std::recursive_mutex> l(lock_);
        auto it = cache().find(k);
        if(it != cache().end()) {
            _deb("ptr_cache::erase[%s]: erase: key found ", c_type());
            cache().erase(k);
            _dia("ptr_cache::erase[%s]: erase: key erased", c_type());
            
            return true;
        } else {
            _dia("ptr_cache::erase[%s]: cannot erase: key not found ", c_type());
        }
        
        return false;
    }

    // shortcut to erase cache iterator
    typename cache_t::iterator erase(typename cache_t::iterator& i) {
        std::lock_guard<std::recursive_mutex> l(lock_);
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
            if(fn_expired_check(it->second->ptr())) {
                erase(k);
                return default_value();
            }
        }

        if(mode_ == MODE::LRU) {
            it->second->touch();
            lru_reoder();
        }
        
        return it->second->ptr();
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
            _dia("ptr_cache::set[%s]: existing entry found", c_type());
            cache()[k] = std::make_unique<DataBlock>(dbs_, v);
        } else {

            if(max_size_ > 0) {
                _deb("ptr_cache::set[%s]: current size %d/%d", c_type(), items().size(), max_size_);

                while( items().size() >= max_size_) {
                    _deb("ptr_cache::set[%s]: max size reached!", c_type());

                    switch(mode_) {
                        case MODE::LRU:
                            lru_reoder();

                            [[fallthrough]];

                        case MODE::FIFO:
                            if(delete_last()) {
                                _dia("ptr_cache::set[%s]: max size: object removed from cache", c_type());
                            }
                            break;
                    }
                }
            }
            _dia("ptr_cache::set[%s]: new entry added", c_type());
            cache()[k] = std::make_unique<DataBlock>(dbs_, v);
            items().push_front(k);
        }

        return ret;
    }

    bool delete_last();
    bool lru_reoder();
    void expiration_check(bool (*fn_expired_check_ptr)(std::shared_ptr<T>)) { fn_expired_check = fn_expired_check_ptr; };
    std::recursive_mutex& getlock() const { return lock_; }

private:
    bool auto_delete_ = true;
    unsigned int max_size_ = 0;
    unsigned int opportunistic_removal_ = 0;

    queue_t items_;
    std::shared_ptr<DataBlockStats> dbs_;
    
    std::shared_ptr<T> default_value_{nullptr};
    cache_t cache_;
    mutable std::recursive_mutex lock_;
    
    bool (*fn_expired_check)(std::shared_ptr<T>) = nullptr;

    logan_lite log;

    TYPENAME_BASE("object cache")
};


template <class K, class T>
inline bool ptr_cache<K,T>::delete_last() {
    bool to_ret = false;

    K to_delete = items().back();

    if(!erase(to_delete)) {
        if( opportunistic_removal() == 0 ) {
            // log.removal errors only if opportunistic removal is enabled
            _not("ptr_cache::set[%s]: cannot erase oldest object: not found!", c_type());
        }
    } else {
        to_ret = true;
        _dia("ptr_cache::set[%s]: oldest object removed", c_type());
    }

    items().pop_back();

    return to_ret;
}

template <class K, class T>
inline bool ptr_cache<K,T>::lru_reoder() {
    bool to_ret = false;

    auto last_key = items().back();
    auto const& last_it  = cache().find(last_key);

    auto first_key = items().front();
    auto const& first_it  = cache().find(first_key);

    auto criteria = first_it->second->count();
    if(dbs_) {
        criteria = dbs_->total_counter / items().size();
    }

    if(last_it != cache().end() and first_it != cache().end()) {
        if( last_it->second->count() > criteria) {
            items().push_front(last_key);
            items().pop_back();

            to_ret = true;
        }
    }
    else {
        // some cleanup
        if(last_it == cache().end()) {
            items().pop_back();
        }
        if(first_it == cache().end()) {
            items().pop_front();
        }
    }

    return to_ret;
}

#endif
