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

logan_lite::logan_lite(logan_lite const& r): topic_(r.topic_), my_loglevel(r.my_loglevel), logan_(logan::get()) {}


std::shared_ptr<loglevel> logan_lite::level() const {

    auto locked = my_loglevel.lock();
    if(not locked) {
        auto logan = logref();
        if(logan) {
            my_loglevel = logan->entry(topic_);
            locked = my_loglevel.lock();
        }
    }

    return locked;
}

void logan_lite::level(loglevel const& l) {

    auto locked = my_loglevel.lock();

    if(not locked) {
        my_loglevel = logref()->entry(topic_);
        locked = my_loglevel.lock();
    }

    if (locked){
        auto l_ = std::unique_lock(lock_);

        locked->level(l.level());
        locked->topic(l.topic());
        locked->more(l.more()); // shallow copy?
        locked->flags(l.flags());
        locked->subject(l.subject());
        locked->area(l.area());
    }
}
