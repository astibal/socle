#ifndef TIMED_GUARD_HPP
#define TIMED_GUARD_HPP

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

#include <mutex>
#include <chrono>

namespace socle::threads {

    // helper guard class which attempts lock timed_mutex

    class timed_guard {
    public:
        timed_guard(std::timed_mutex& mtx, std::chrono::milliseconds duration) :
        mtx_(mtx), owns_lock_(mtx_.try_lock_for(duration)) {}

        ~timed_guard() {
            if (owns_lock_) {
                mtx_.unlock();
            }
        }
        // Check if the lock was successfully acquired
        bool owns_lock() const {
            return owns_lock_;
        }

        timed_guard(timed_guard const &) = delete;
        timed_guard &operator=(timed_guard const&) = delete;

    private:
        std::timed_mutex &mtx_;
        bool owns_lock_;
    };

}

#endif