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

#include <mempool/mempool.hpp>

void* mempool_alloc(size_t);
void mempool_free(void*);

#pragma GCC diagnostic ignored "-Wformat-security"
#pragma GCC diagnostic push


template <class ... Args>
std::string string_format(const char* format, Args ... args)
{
    constexpr int default_buff_sz = 2048;
    char stack_buffer[default_buff_sz]; // intentionally no pre-init, it may be garbage as the buffer will be overwritten
    char* buffer = stack_buffer;

    //  man snprintf:
    //  The functions snprintf() and vsnprintf() write at most size bytes (including the terminating null byte ('\0')) to str.
    //  ... and return bytes that would have been written if buffer is large enough, or < 0 on error.
    auto written_n = snprintf(buffer, default_buff_sz, format, args...);

    if(written_n < 0 or written_n >= default_buff_sz) {

        buffer = (char*)mempool_alloc(written_n+1); //space for \0
        if(not buffer) return {};

        written_n = snprintf((char*)buffer, written_n+1, format, args...);
    }

    // w counts in also \0 terminator
    std::string ret((const char*)buffer, written_n);
    if(buffer != stack_buffer) mempool_free(buffer);

    return ret;
}


#pragma GCC diagnostic pop

#endif //STRINGFORMAT_HPP
