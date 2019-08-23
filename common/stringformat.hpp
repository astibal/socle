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

#ifndef STRINGFORMAT_HPP
#define STRINGFORMAT_HPP

#include <string>
#include <cstring>

#include <mempool.hpp>

void* mempool_realloc(void*, size_t);
void mempool_free(void*);

template <class ... Args>
std::string string_format(const char* format, Args ... args)
{

    int cap = 512;
    int mul = 1;
    int max = 20;
    void* b = nullptr;

    // data written to buffer
    int w = 0;
    int cursize = cap*mul;

    do {

        cursize = cap*mul;

        b = mempool_realloc(b, cursize);
        memset(b, 0, cursize);

        //  man snprintf:
        //  The functions snprintf() and vsnprintf() write at most size bytes (including the terminating null byte ('\0')) to str.
        w = snprintf((char*)b, cursize, format, args...);

        mul++;
    } while(w >= (int)cursize && mul <= max);


    // w counts in also \0 terminator
    std::string ret((const char*)b, w);
    mempool_free(b);

    return ret;
}

#endif //STRINGFORMAT_HPP
