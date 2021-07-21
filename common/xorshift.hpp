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

#ifndef XORSHIFT_HPP
#define XORSHIFT_HPP

// Marsaglia xorshift generator  !! NOT TO BE USED IN CRYPTO !!

namespace xorshift {
    static unsigned long state_x=123456789, state_y=362436069, state_z=521288629;

    unsigned long rand() {          //period 2^96-1
        unsigned long t;
        state_x ^= state_x << 16ul;
        state_x ^= state_x >> 5ul;
        state_x ^= state_x << 1ul;

        t = state_x;
        state_x = state_y;
        state_y = state_z;
        state_z = t ^ state_x ^ state_y;

        return state_z;
    }
}
#endif //XORSHIFT_HPP
