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


#ifndef SMITHPROXY_MALLOC_ALLOCATOR_HPP
#define SMITHPROXY_MALLOC_ALLOCATOR_HPP


#include <cstdlib>
#include <memory>

template <class T>
class malloc_allocator
{
public:

    static const malloc_allocator& self() {
        static const malloc_allocator<T> r;
        return r;
    }

    typedef size_t    size_type;
    typedef ptrdiff_t difference_type;
    typedef T*        pointer;
    typedef const T*  const_pointer;
    typedef T&        reference;
    typedef const T&  const_reference;
    typedef T         value_type;

    malloc_allocator() = default;
    malloc_allocator(const malloc_allocator&) = default;

    pointer   allocate(size_type n, const void * = 0) {
        T* t = (T*) ::malloc(n * sizeof(T));
        return t;
    }

    void      deallocate(void* p, size_type) {
        if (p) {
            ::free(p);
        }
    }

    pointer           address(reference x) const { return &x; }
    const_pointer     address(const_reference x) const { return &x; }
    malloc_allocator<T>&  operator=(const malloc_allocator&) = default;
    void              construct(pointer p, const T& val)
    { new ((T*) p) T(val); }
    void              destroy(pointer p) { p->~T(); }

    size_type         max_size() const { return size_t(-1); }

    template <class U>
    struct rebind { typedef malloc_allocator<U> other; };

    template <class U>
    explicit malloc_allocator(const malloc_allocator<U>&) {};

    template <class U>
    malloc_allocator& operator=(const malloc_allocator<U>&) { return *this; }

    bool operator!=(malloc_allocator const& ref) {
        // there is currently only one mempool, therefore there can't be any other
        // mp_allocator out there.
        return false;
    }
    bool operator==(malloc_allocator const& ref) {
        // see reasons for operator !=
        return true;
    }

    constexpr bool propagate_on_container_move_assignment() const { return true; };
};


#endif //SMITHPROXY_MALLOC_ALLOCATOR_HPP
