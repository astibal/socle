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

class lockable {
public:
    virtual ~lockable() = default;

    void _lock_shared() const { lock_.lock_shared(); }
    void _unlock_shared() const { lock_.unlock_shared(); }
    void _lock() const { lock_.lock(); }
    void _unlock() const { lock_.unlock(); }

    // to make standard guards work
    void lock() const { lock_.lock(); }
    void unlock() const { lock_.unlock(); }
    bool try_lock() const { return lock_.try_lock(); }

    void lock_shared() const { lock_.lock_shared(); }
    bool try_lock_shared() const { return lock_.try_lock_shared(); }
    void unlock_shared() const { lock_.unlock_shared(); }

    mutable std::shared_mutex lock_;
};

#endif