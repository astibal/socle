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

#ifndef MPDISPLAY_HPP
#define MPDISPLAY_HPP

#include <mpstd.hpp>
#include <buffer.hpp>

namespace mp {

    struct facility {
        static std::recursive_mutex& lock() {
            static std::recursive_mutex m;
            return m;
        };
    };

    mp::string string_csv(const mp::vector<mp::string> &str_list_ref, const char delim = ',');

    mp::string hex_dump(unsigned char *data, std::size_t size, unsigned int ltrim, char prefix);
    mp::string hex_dump(buffer* b, unsigned int ltrim, char prefix);
    mp::string hex_dump(buffer& b, unsigned int ltrim, char prefix);


    template <class ... Args>
    mp::string string_format(const char* format, Args ... args)
    {

        int cap = 512;
        int mul = 1;
        int max = 20;
        unsigned char* b = nullptr;

        // data written to buffer
        int w = 0;
        int cursize = cap*mul;

        do {

            cursize = cap*mul;

            auto tmp = mempool_realloc(b, cursize);
            if(tmp)
                b = static_cast<unsigned char*>(tmp);
            else
                break;

            std::memset(b, 0, cursize);

            //  man snprintf:
            //  The functions snprintf() and vsnprintf() write at most size bytes (including the terminating null byte ('\0')) to str.
            w = snprintf((char*)b, cursize, format, args...);

            mul++;
        } while(w >= (int)cursize && mul <= max);


        // w counts in also \0 terminator
        mp::string ret;

        if(b) {
            ret.assign(reinterpret_cast<const char*>(b), w);
            mempool_free(b);
        }

        return ret;
    }


    mp::vector<mp::string>
    string_split(mp::string const& str, char delimiter) {
        mp::vector<mp::string> internal;
        mp::stringstream ss(str); // Turn the string into a stream.
        mp::string tok;

        while(getline(ss, tok, delimiter)) {
            internal.push_back(tok);
        }

        return internal;
    }
}

#endif //MPDISPLAY_HPP
