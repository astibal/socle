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

logan_lite::logan_lite() : logan_(logan::get()) { };

logan_lite::logan_lite(std::string str) noexcept: topic_(std::move(str)), logan_(logan::get()) { };

logan_lite::logan_lite(logan_lite const& r): topic_(r.topic_), prefix_(r.prefix_), my_loglevel(r.my_loglevel.load()), logan_(logan::get()) {}


loglevel* logan_lite::level() const {

    if(not my_loglevel) {
        my_loglevel = logref()[topic_];
    }

    return my_loglevel;
}

void logan_lite::level(loglevel const& l) {

    if(not my_loglevel) {
        my_loglevel = logref()[topic_];
    }

    auto l_ = std::unique_lock(lock_);

    auto* ml_ptr = my_loglevel.load();
    ml_ptr->level(l.level());
    ml_ptr->topic(l.topic());
    ml_ptr->more(l.more()); // shallow copy?
    ml_ptr->flags(l.flags());
    ml_ptr->subject(l.subject());
    ml_ptr->area(l.area());
}
