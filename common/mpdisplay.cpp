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

#include <mpdisplay.hpp>

namespace mp {
    mp::string hex_dump(buffer* b, unsigned int ltrim, char prefix) { return hex_dump((unsigned char*)b->data(),b->size(),ltrim,prefix); }
    mp::string hex_dump(buffer& b, unsigned int ltrim, char prefix) { return hex_dump((unsigned char*)b.data(),b.size(),ltrim,prefix); }

    mp::string hex_dump(unsigned char *data, std::size_t size,unsigned int ltrim, char prefix)
    {
        /* dumps size bytes of *data to stdout. Looks like:
         * [0000] 75 6E 6B 6E 6F 77 6E 20
         *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
         * (in a single line of course)
         */

        // there could be more precious implementation of this in the future
        std::lock_guard<std::recursive_mutex> l(facility::lock());

        unsigned char *p = data;

        unsigned int n;
        char bytestr[4] = {0};
        char addrstr[10] = {0};
        char hexstr[ 16*3 + 5] = {0};
        char charstr[16*1 + 5] = {0};

        mp::stringstream ret;

        unsigned int tr = 0;
        if (ltrim > 0) {
            tr = ltrim + 4;
        }

        mp::string pref;

        if (prefix != 0) {
            if (tr > 1) tr--;
        }

        for (unsigned int i = 0; i < tr; i++) { pref += ' ';}

        if (prefix != 0) {
            pref += prefix;
        }

        for(n=1;n<=size;n++) {
            if (n%16 == 1) {
                /* store address for this line */
                snprintf(addrstr, sizeof(addrstr), "%.4x",
                         (unsigned int)(p-data) );
            }

            unsigned char c = *p;
//         if (isalnum(c) == 0) {
//             c = '.';
//         }

            if(c < 33 || c > 126 || c == 92 || c == 37) {
                c = '.';
            }

            /* store hex str (for left side) */
            snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
            strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

            /* store char str (for right side) */
            snprintf(bytestr, sizeof(bytestr), "%c", c);
            strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

            if(n%16 == 0) {
                /* line completed */
                ret << pref << mp::string_format("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
                hexstr[0] = 0;
                charstr[0] = 0;
            } else if(n%8 == 0) {
                /* half line: add whitespaces */
                strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
                strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
            }
            p++; /* next byte */
        }

        if (strlen(hexstr) > 0) {
            /* print rest of buffer if not empty */
            ret << pref << string_format("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
        }

        return mp::string(ret.str());
    }


    mp::string string_csv(const mp::vector<mp::string> &str_list_ref, const char delim) {
        mp::stringstream build;
        for (unsigned int ii = 0; ii < str_list_ref.size(); ii++) {
            build << str_list_ref[ii];
            if (ii < str_list_ref.size() - 1) {
                build << delim;
            }
        }

        return mp::string(build.str());
    }
}