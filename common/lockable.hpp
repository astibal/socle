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

#ifndef __LOCKABLE_HPP__
#define __LOCKABLE_HPP__

#include <shared_mutex>


template <class T>
class locked_ {
public:
    explicit locked_(T const* ref): ref_(ref) { if(ref) ref_->_lock(); };

    locked_() = delete;
    locked_(locked_ const&) = delete;
    locked_(locked_&& other) = delete;

    ~locked_() { if(ref_) ref_->_unlock(); };

    T* operator->() {
        return ref_;
    }
    T const* operator->() const {
        return ref_;
    }

protected:
    T const* ref_;
};

template <class T>
class share_locked_ {
public:
    explicit share_locked_(T const* ref): ref_(ref) { if(ref_) ref_->_lock_shared(); };
    explicit share_locked_(T const& ref): ref_(&ref) { if(ref_) ref_->_lock_shared(); };

    share_locked_() = delete;
    share_locked_(share_locked_ const&) = delete;
    share_locked_(share_locked_&& other) = delete;

    ~share_locked_() { if(ref_) ref_->_unlock_shared(); };

    T* operator->() {
        return ref_;
    }
    T const* operator->() const {
        return ref_;
    }

private:
    T const* ref_{};
};



class lockable {
public:
    virtual ~lockable() = default;

    void _lock_shared() const { lock_.lock_shared(); }
    void _unlock_shared() const { lock_.unlock_shared(); }
    void _lock() const { lock_.lock(); }
    void _unlock() const { lock_.unlock(); }

    friend class locked_<lockable>;
    friend class share_locked_<lockable>;
    mutable std::shared_mutex lock_;
};

#endif