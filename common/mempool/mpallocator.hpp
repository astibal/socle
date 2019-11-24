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

#ifndef MPALLOCATOR_HPP
#define MPALLOCATOR_HPP

template <class T>
class mp_allocator
{
public:
    typedef size_t    size_type;
    typedef ptrdiff_t difference_type;
    typedef T*        pointer;
    typedef const T*  const_pointer;
    typedef T&        reference;
    typedef const T&  const_reference;
    typedef T         value_type;

    mp_allocator() = default;
    mp_allocator(const mp_allocator&) = default;

    pointer   allocate(size_type n, const void * = 0) {
        T* t = (T*) mempool_alloc(n * sizeof(T));
        return t;
    }

    void      deallocate(void* p, size_type) {
        if (p) {
            mempool_free(p);
        }
    }

    pointer           address(reference x) const { return &x; }
    const_pointer     address(const_reference x) const { return &x; }
    mp_allocator<T>&  operator=(const mp_allocator&) = default;
    void              construct(pointer p, const T& val)
    { new ((T*) p) T(val); }
    void              destroy(pointer p) { p->~T(); }

    size_type         max_size() const { return size_t(-1); }

    template <class U>
    struct rebind { typedef mp_allocator<U> other; };

    template <class U>
    explicit mp_allocator(const mp_allocator<U>&) {};

    template <class U>
    mp_allocator& operator=(const mp_allocator<U>&) { return *this; }
};

#endif //MPALLOCATOR_HPP
