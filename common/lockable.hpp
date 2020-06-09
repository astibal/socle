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

#include <mutex>

template <class T>
class locked_guard {
public:
    explicit locked_guard<T>(T& ref): ref_(&ref) { ref_->_lock(); } ;
    explicit locked_guard<T>(T* ref): ref_(ref) { ref_->_lock(); } ;
    virtual ~locked_guard<T>() { ref_->_unlock(); };
protected:
    T* ref_;
};

class lockable {
public:
    virtual ~lockable() = default;

    void _lock() const { lock_.lock(); }
    void _unlock() const { lock_.unlock(); }

    friend class locked_guard<lockable>;
    mutable std::recursive_mutex lock_;
};


#endif