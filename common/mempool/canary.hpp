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
    constexpr static const char* txt = "CaNaRy";

    // canary content template size
    std::size_t sz = 6;

    // actual size of the canary (which will be filled with template pattern)
    std::size_t canary_sz = 0;

    [[nodiscard]] unsigned char gen_canary_byte(std::size_t index) const {
        if(canary_sz) {
            const char* canary = txt;
            const std::size_t xsz = sz;
            return static_cast<unsigned char>(canary[index % xsz]);
        }

        #ifndef MEMPOOL_NOEXCEPT
        throw mempool_bad_alloc("generating canary bytes for zero size canary");
        #else
        return 0xFF;
        #endif
    };

    // fill first canary
    void write_canary(unsigned char* ptr) const {
        for (unsigned int i = 0; i < canary_sz; i++) {
            ptr[i] = gen_canary_byte(i);
        }
    };

    bool check_canary(unsigned const char* ptr) const {
        for (unsigned int i = 0; i < canary_sz; i++) {
            if(ptr[i] == gen_canary_byte(i))
                continue;

            return false;
        }

        return true;
    }
} __attribute__((aligned(16)));

#endif