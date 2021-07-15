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

#ifndef BASETRAFLOG_HPP
#define BASETRAFLOG_HPP

#include <vars.hpp>

namespace socle {

    class baseTrafficLogger {
        bool status_ {true};

    public:
        [[nodiscard]] inline bool status() const { return status_; }
        inline void status(bool b) { status_ = b; }

        virtual void write(side_t side, const buffer &b) = 0;
        virtual void write_left(buffer const& b) final {  if(status()) write(side_t::LEFT, b); };
        virtual void write_right(buffer const& b) final {  if(status()) write(side_t::RIGHT, b); };

        virtual void write(side_t side, std::string const& s) = 0;
        void write_left(std::string const& s) { if(status()) write(side_t::LEFT, s); };
        void write_right(std::string const& s) { if(status()) write(side_t::RIGHT, s); };
    };


}


#endif //BASETRAFLOG_HPP
