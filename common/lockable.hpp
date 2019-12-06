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

class lockable {
public:
    virtual ~lockable() { lock_.unlock(); };
    void lock() const { lock_.lock(); }
    void unlock() const { lock_.unlock(); }

protected:
    mutable std::recursive_mutex lock_;
};

template <class T>
class locked_ptr : public lockable {
public:
    locked_ptr<T>(T* ref) { object_ = ref; }
    
    T* acquire() { lock(); return object_; }
    void release() { unlock(); }
    T* operator ->() { return object_; };
    
protected:
    T* object_ = nullptr;
};

template <class T>
class locked_guard {
public:
    locked_guard<T>(T& ref): ref_(&ref) { ref_->lock(); } ;
    locked_guard<T>(T* ref): ref_(ref) { ref_->lock(); } ;
    virtual ~locked_guard<T>() { ref_->unlock(); };
protected:
    T* ref_;
};

#endif