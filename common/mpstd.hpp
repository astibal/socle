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

    typedef std::basic_stringstream<char, std::char_traits<char>,
            mp_allocator<char> > mp_stringstream;
    typedef std::basic_ostringstream<char, std::char_traits<char>,
            mp_allocator<char> > mp_ostringstream;

    typedef std::basic_stringstream<wchar_t, std::char_traits<wchar_t>,
            mp_allocator<wchar_t> > mp_wstringstream;
    typedef std::basic_ostringstream<wchar_t, std::char_traits<wchar_t>,
            mp_allocator<wchar_t> > mp_wostringstream;


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
}

#endif //SMITHPROXY_MPSTD_HPP
