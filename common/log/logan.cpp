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

#include <log/logan.hpp>
#include <log/loglevel.hpp>
#include <mutex>

loglevel* logan_lite::level() const {
    std::scoped_lock<std::mutex> l(lock_);

    if(! my_loglevel) {
        my_loglevel = logan::get()[topic_];
    }

    return my_loglevel;
}

void logan_lite::level(loglevel l) {

    if(!my_loglevel) {
        my_loglevel = logan::get()[topic_];
    }
    my_loglevel->level(l.level());
    my_loglevel->topic(l.topic());
    my_loglevel->more(l.more()); // shallow copy?
    my_loglevel->flags(l.flags());
    my_loglevel->subject(l.subject());
    my_loglevel->area(l.area());
}
