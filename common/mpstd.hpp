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


#ifndef SMITHPROXY_MPSTD_HPP
#define SMITHPROXY_MPSTD_HPP

#include <mempool/mpallocator.hpp>

#include <deque>
#include <list>
#include <unordered_map>

namespace mp {

    template<
            class CharT,
            class Traits = std::char_traits<CharT>,
            class Allocator = mp_allocator<CharT>
    >
    class basic_string : public std::basic_string<CharT, Traits, Allocator> {
    public:
        using size_type = typename std::basic_string<CharT, Traits, Allocator>::size_type;

        explicit basic_string( const Allocator& alloc ) noexcept
                : std::basic_string<CharT, Traits, Allocator>(alloc) {}

        basic_string() noexcept( noexcept( Allocator() ))
                : basic_string<CharT, Traits, Allocator>( Allocator() ) {}


        basic_string( size_type count, CharT ch, const Allocator& alloc = Allocator() ) :
            std::basic_string<CharT, Traits, Allocator>(count, ch, alloc ) {};

        basic_string( const basic_string& other,
                      size_type pos,
                      size_type count = std::basic_string<CharT, Traits, Allocator>::npos,
                      const Allocator& alloc = Allocator() )
                      :std::basic_string<CharT, Traits, Allocator>(other, pos, count, alloc) {}

        basic_string( const basic_string& other,
                      size_type pos,
                      const Allocator& alloc = Allocator() )
              : std::basic_string<CharT, Traits, Allocator>(other, pos, alloc ) {}

        basic_string( const CharT* s,
                      size_type count,
                      const Allocator& alloc = Allocator() )
              : std::basic_string<CharT, Traits, Allocator>(s, count, alloc) {}

        explicit basic_string( const CharT* s, const Allocator& alloc = Allocator() )
              : std::basic_string<CharT, Traits, Allocator>(s, alloc) {}

        template< class InputIt >
        basic_string( InputIt first, InputIt last,
                      const Allocator& alloc = Allocator() )
              : std::basic_string<CharT, Traits, Allocator>(first, last, alloc) {}

        basic_string( const basic_string& other )
                : std::basic_string<CharT, Traits, Allocator>(other) {}

        basic_string( const basic_string& other, const Allocator& alloc )
                : std::basic_string<CharT, Traits, Allocator>(other, alloc) {}

        basic_string( basic_string&& other ) noexcept
                : std::basic_string<CharT, Traits, Allocator>(other) {}

        basic_string( basic_string&& other, const Allocator& alloc )
                : std::basic_string<CharT, Traits, Allocator>(other, alloc) {}

        basic_string( std::initializer_list<CharT> ilist,
                      const Allocator& alloc = Allocator() )
                : std::basic_string<CharT, Traits, Allocator>(ilist, alloc) {}

        template < class T >
        explicit basic_string( const T& t, const Allocator& alloc = Allocator() )
               : std::basic_string<CharT, Traits, Allocator>(t, alloc ) {}

        template < class T >
        basic_string( const T& t, size_type pos, size_type n,
                      const Allocator& alloc = Allocator() )
               : std::basic_string<CharT, Traits, Allocator>(t, pos, n, alloc ) {}

        basic_string& operator=(std::basic_string<CharT, Traits, Allocator> const& r) {
            std::basic_string<CharT, Traits, Allocator>::assign(r);
            return *this;
        }
        basic_string& operator=(mp::basic_string<CharT, Traits, Allocator> const& r) {
            std::basic_string<CharT, Traits, Allocator>::assign(r);
            return *this;
        }

        basic_string& operator=(std::basic_string<CharT, Traits, Allocator>& r) {
            std::basic_string<CharT, Traits, Allocator>::assign(r);
            return *this;
        }

        basic_string& operator=(std::string const & r) {
            std::basic_string<CharT, Traits, Allocator>::assign(r);
            return *this;
        }


        explicit operator const char*() {
            return std::basic_string<CharT, Traits, Allocator>::c_str();
        }

        explicit operator std::basic_string<CharT, Traits, Allocator>() const {
            std::basic_string<CharT, Traits, Allocator> r;
            r.assign(*this);
            return r;
        }
    };

    template<
            class CharT,
            class Traits = std::char_traits<CharT>,
            class Allocator = mp_allocator<CharT>
    >
    basic_string<CharT, Traits, Allocator>
        operator+(
            std::basic_string<CharT, Traits, Allocator> const& a,
            mp::basic_string<CharT, Traits, Allocator> const& b) {

        basic_string<CharT, Traits, Allocator> ret;
        ret.append(a);
        ret.append(b);
        return ret;
    }


    using string    = mp::basic_string<char>;
    using wstring 	= mp::basic_string<wchar_t>;

    #ifdef	__cpp_char8_t
    using u8string  = mp::basic_string<char8_t>;
    #endif
    using u16string   = mp::basic_string<char16_t>;
    using u32string   = mp::basic_string<char32_t>;


    template<
            class CharT,
            class Traits = std::char_traits<CharT>,
            class Allocator = mp_allocator<CharT>
    > class basic_stringstream : public std::basic_stringstream<CharT, Traits, Allocator> {
    public:
        basic_stringstream() : std::basic_stringstream<CharT, Traits, Allocator>() {};
        explicit basic_stringstream(mp::string const& r) : std::basic_stringstream<CharT, Traits, Allocator>(r) {};
    };
    using stringstream    = mp::basic_stringstream<char>;
    using wstringstream  = mp::basic_stringstream<wchar_t>;

    #ifdef	__cpp_char8_t
    using u8stringstream  = mp::basic_stringstream<char8_t>;
    #endif
    using u16stringstream   = mp::basic_stringstream<char16_t>;
    using u32stringstream   = mp::basic_stringstream<char32_t>;



    template<class _Ty, class _Ax = mp_allocator<_Ty> >
    class list : public std::list<_Ty, _Ax> {
    };

    template<class _Ty, class _Ax = mp_allocator<_Ty> >
    class deque : public std::deque<_Ty, _Ax> {
    };

    template<
            class Key,
            class T,
            class Hash = std::hash<Key>,
            class KeyEqual = std::equal_to<Key>,
            class Allocator = mp_allocator<std::pair<const Key, T> >
    >
    class unordered_map : public std::unordered_map<Key, T, Hash, KeyEqual, Allocator> {
    };

    template<
            class Key,
            class Compare = std::less<Key>,
            class Allocator = mp_allocator<Key>
    >
    class set : public std::set<Key, Compare, Allocator> {
    };

    template<
            class Key,
            class T,
            class Compare = std::less<Key>,
            class Allocator = mp_allocator<std::pair<const Key, T> >
    > class map : public std::map<Key, T, Compare, Allocator> {};

    template<
            class Key,
            class T,
            class Compare = std::less<Key>,
            class Allocator = mp_allocator<std::pair<const Key, T> >
    > class multimap : public std::multimap<Key, T, Compare, Allocator> {};

    template<
            class T,
            class Allocator = mp_allocator<T>
    > class vector: public std::vector<T> {};
}

#endif //SMITHPROXY_MPSTD_HPP
