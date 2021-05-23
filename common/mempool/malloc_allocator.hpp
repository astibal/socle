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

namespace mp::malloc {
    template<class T>
    class allocator {
    public:

        static const allocator &self () {
            static const allocator<T> r;
            return r;
        }

        typedef size_t size_type;
        typedef ptrdiff_t difference_type;
        typedef T *pointer;
        typedef const T *const_pointer;
        typedef T &reference;
        typedef const T &const_reference;
        typedef T value_type;

        allocator () = default;

        allocator (const allocator &) = default;

        pointer allocate (size_type n, const void * = 0) {
            T *t = (T *) ::malloc(n * sizeof(T));
            return t;
        }

        void deallocate (void *p, size_type) {
            if (p) {
                ::free(p);
            }
        }

        pointer address (reference x) const { return &x; }

        const_pointer address (const_reference x) const { return &x; }

        allocator<T> &operator= (const allocator &) = default;

        void construct (pointer p, const T &val) { new((T *) p) T(val); }

        void destroy (pointer p) { p->~T(); }

        size_type max_size () const { return size_t(-1); }

        template<class U>
        struct rebind {
            typedef allocator<U> other;
        };

        template<class U>
        explicit allocator (const allocator<U> &) {}

        template<class U>
        allocator &operator= (const allocator<U> &) { return *this; }

        bool operator!= (allocator const &ref) {
            // there is currently only one mempool, therefore there can't be any other
            // mp_allocator out there.
            return false;
        }

        bool operator== (allocator const &ref) {
            // see reasons for operator !=
            return true;
        }

        constexpr bool propagate_on_container_move_assignment () const { return true; };
    };


    template<
            class CharT,
            class Traits = std::char_traits<CharT>,
            class Allocator = allocator<CharT>
    >
    class basic_string : public std::basic_string<CharT, Traits, Allocator> {
    public:
        using size_type = typename std::basic_string<CharT, Traits, Allocator>::size_type;

        //basic_string() : std::basic_string<CharT, Traits, Allocator>() {};

        //explicit basic_string(const Allocator& alloc ): std::basic_string<CharT, Traits, Allocator>(alloc) {};

        explicit basic_string (const Allocator &alloc) noexcept
                : std::basic_string<CharT, Traits, Allocator>(alloc) {}

        basic_string () noexcept(noexcept(Allocator()))
                : basic_string<CharT, Traits, Allocator>(Allocator()) {}


        basic_string (size_type count, CharT ch, const Allocator &alloc = Allocator()) :
                std::basic_string<CharT, Traits, Allocator>(count, ch, alloc) {}

        basic_string (const basic_string &other,
                      size_type pos,
                      size_type count = std::basic_string<CharT, Traits, Allocator>::npos,
                      const Allocator &alloc = Allocator())
                : std::basic_string<CharT, Traits, Allocator>(other, pos, count, alloc) {}

        basic_string (const basic_string &other,
                      size_type pos,
                      const Allocator &alloc = Allocator())
                : std::basic_string<CharT, Traits, Allocator>(other, pos, alloc) {}

//        basic_string( const basic_string& other,
//                      size_type pos,
//                      size_type count,
//                      const Allocator& alloc = Allocator() )
//              : std::basic_string<CharT, Traits, Allocator>(other, pos, count, alloc) {};

        basic_string (const CharT *s,
                      size_type count,
                      const Allocator &alloc = Allocator())
                : std::basic_string<CharT, Traits, Allocator>(s, count, alloc) {}

        explicit basic_string (const CharT *s, const Allocator &alloc = Allocator())
                : std::basic_string<CharT, Traits, Allocator>(s, alloc) {}

        template<class InputIt>
        basic_string (InputIt first, InputIt last,
                      const Allocator &alloc = Allocator())
                : std::basic_string<CharT, Traits, Allocator>(first, last, alloc) {}

        basic_string (const basic_string &other)
                : std::basic_string<CharT, Traits, Allocator>(other) {}

        basic_string (const basic_string &other, const Allocator &alloc)
                : std::basic_string<CharT, Traits, Allocator>(other, alloc) {}

        basic_string (basic_string &&other) noexcept
                : std::basic_string<CharT, Traits, Allocator>(other) {}

        basic_string (basic_string &&other, const Allocator &alloc)
                : std::basic_string<CharT, Traits, Allocator>(other, alloc) {}

        basic_string (std::initializer_list<CharT> ilist,
                      const Allocator &alloc = Allocator())
                : std::basic_string<CharT, Traits, Allocator>(ilist, alloc) {}

        template<class T>
        explicit basic_string (const T &t, const Allocator &alloc = Allocator())
                : std::basic_string<CharT, Traits, Allocator>(t, alloc) {}

        template<class T>
        basic_string (const T &t, size_type pos, size_type n,
                      const Allocator &alloc = Allocator())
                : std::basic_string<CharT, Traits, Allocator>(t, pos, n, alloc) {}

        basic_string &operator= (std::basic_string<CharT, Traits, Allocator> const &r) {
            std::basic_string<CharT, Traits, Allocator>::assign(r);
            return *this;
        }

        basic_string &operator= (mp::malloc::basic_string<CharT, Traits, Allocator> const &r) {
            std::basic_string<CharT, Traits, Allocator>::assign(r);
            return *this;
        }

        basic_string &operator= (std::basic_string<CharT, Traits, Allocator> &r) {
            std::basic_string<CharT, Traits, Allocator>::assign(r);
            return *this;
        }

        basic_string &operator= (std::string const &r) {
            std::basic_string<CharT, Traits, Allocator>::assign(r);
            return *this;
        }


        explicit operator const char * () {
            return std::basic_string<CharT, Traits, Allocator>::c_str();
        }

        explicit operator std::basic_string<CharT, Traits, Allocator> () const {
            std::basic_string<CharT, Traits, Allocator> r;
            r.assign(*this);
            return r;
        }
    };

    template<
            class CharT,
            class Traits = std::char_traits<CharT>,
            class Allocator = allocator <CharT>
    >
    basic_string<CharT, Traits, Allocator>
    operator+ (
            std::basic_string<CharT, Traits, Allocator> const &a,
            mp::malloc::basic_string<CharT, Traits, Allocator> const &b) {

        basic_string<CharT, Traits, Allocator> ret;
        ret.append(a);
        ret.append(b);
        return ret;
    }

//    template<
//            class CharT,
//            class Traits = std::char_traits<CharT>,
//            class Allocator = mp_allocator<CharT>
//    >
//    std::basic_string<CharT, Traits, Allocator>
//        operator+(
//            std::basic_string<CharT, Traits, Allocator> const& a,
//            mp::basic_string<CharT, Traits, Allocator> const& b) {
//
//        std::basic_string<CharT, Traits, Allocator> ret;
//        ret.append(a);
//        ret.append(b);
//        return ret;
//    }


    using string = mp::malloc::basic_string<char>;
    using wstring = mp::malloc::basic_string<wchar_t>;

#ifdef    __cpp_char8_t
    using u8string  = mp::basic_string<char8_t>;
#endif
    using u16string = mp::malloc::basic_string<char16_t>;
    using u32string = mp::malloc::basic_string<char32_t>;


    struct hash {
        std::size_t operator()(mp::malloc::string const& v) const {
            return std::hash<const char*>()(v.c_str());
        }
    };

}
#endif //SMITHPROXY_MALLOC_ALLOCATOR_HPP
