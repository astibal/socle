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

#ifndef MP_CANARY_HPP
#define MP_CANARY_HPP

#include <mempool/mperror.hpp>

struct mp_canary {

    // canary content template string
    const char* txt = "CaNaRy";

    // canary content template size
    std::size_t sz = 6;

    // actual size of the canary (which will be filled with template pattern)
    std::size_t canary_sz = 0;

    unsigned char gen_canary_byte(int index){
        if(canary_sz) {
            const char* canary = txt;
            const int xsz = sz;
            return canary[index % xsz];
        }

        throw mempool_bad_alloc("generating canary bytes for zero size canary");
    };

    // fill first canary
    void write_canary(unsigned char* ptr) {
        for (unsigned int i = 0; i < canary_sz; i++) {
            ptr[i] = gen_canary_byte(i);
        }
    };

    bool check_canary(unsigned char* ptr) {
        for (unsigned int i = 0; i < canary_sz; i++) {
            if(ptr[i] == gen_canary_byte(i))
                continue;

            return false;
        }

        return true;
    }
};

#endif