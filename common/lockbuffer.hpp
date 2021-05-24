
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

#ifndef __LOCKBUFFER_HPP
#define __LOCKBUFFER_HPP

#include <buffer.hpp>
#include <lockable.hpp>


class lockbuffer : public buffer, public lockable
{
public:
    using buffer_guard = locked_guard<lockbuffer>;

    explicit lockbuffer (size_type size = 0) : buffer(size) {};
    lockbuffer (size_type s, size_type c) : buffer(s,c) {};
    lockbuffer (const void* data, size_type size) : buffer(data,size) {};
    lockbuffer (const void* data, size_type size, size_type capacity) : buffer(data, size, capacity) {};
    lockbuffer (void* data, size_type size, size_type capacity, bool assume_ownership) : buffer(data,size,capacity,assume_ownership) {};
          
    ~lockbuffer() override = default;
    
    lockbuffer& operator= (const lockbuffer& x);
};

inline lockbuffer& lockbuffer::operator= (const lockbuffer& x)
{
    buffer::operator=(x);
    return *this;
}



#endif