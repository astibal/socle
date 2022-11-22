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


#include <mempool/mempool.hpp>
#include <vars.hpp>

namespace socle {

    namespace raw {

        namespace deleters {
            inline void mp_free(void* ptr) { mempool_free(ptr); }
        }

        using memvar = unique<void*>;

        memvar temp_buffer(std::size_t size) {
            return { mempool_alloc(size), deleters::mp_free };
        }

        template <typename T>
        memvar temp_clone(T* source, std::size_t size) {

            auto* buf = mempool_alloc(size);
            std::memcpy((std::byte*)source, buf, size);

            return { std::move(buf), deleters::mp_free };
        }
    }
}