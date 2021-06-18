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

#ifndef DISPLAY_HPP
#define DISPLAY_HPP

#include <string>
#include <sstream>
#include <vector>
#include <cstring>
#include <arpa/inet.h>

class buffer;



[[maybe_unused]] std::string string_format_old(const char* fmt, ...);
template <class ... Args>
std::string string_format(const char* format, Args ... args);

std::vector<std::string> 
            string_split(const std::string &str, char delimiter);
[[maybe_unused]] std::string string_trim(const std::string& orig);
std::string string_tolower(const std::string& orig);
std::string string_csv(const std::vector<std::string>& str_list_ref, char delim = ',');

std::string number_suffixed(unsigned long n);
std::string hex_print(unsigned char* data, unsigned int len);
std::string hex_dump(unsigned char *data, size_t size, unsigned int=0, unsigned char=0);
std::string hex_dump(buffer&, unsigned int=0, unsigned char=0);
std::string hex_dump(buffer*, unsigned int=0, unsigned char=0);
std::string string_error();
std::string string_error(int code);
std::string bt(bool add_r=false);

std::string escape(const std::string &orig, bool to_print = false);
[[maybe_unused]] inline std::string printable(const std::string &orig) {
    return escape(orig,true);
}

int safe_val(const std::string &str_val, int default_val=-1);

// get sanitized, dot-separated kernel version. 
std::string get_kernel_version();
// compare dot-formated @target version with against @real version. @returns false if real version is lower than target.
bool version_check(const std::string &real_string, std::string v);

template <typename T> inline void flag_set(T* variable, T check) { *variable |= static_cast<T>(check); }
template <typename T> inline T flag_set(const T variable, T check) { T r = variable; r |= static_cast<T>(check); return r; }
template <typename T> inline T flag_reset(const T variable, T check) { T r = variable; r = r & ~(static_cast<T>(check)); return r; }
template <typename T> inline T flag_flip(const T variable, T check) { T r = variable; r ^= static_cast<T>(check); return r; }
template <typename T> inline bool flag_check(const T* variable, T check) { return (*variable & check); }
template <typename T> inline bool flag_check(const T variable, T check) { return (variable & check); }


#define  flag_add    flag_set<unsigned int> 
#define  flag_test   flag_check<unsigned int> 
 

std::string inet_family_str(int fa);
int inet_ss_address_unpack(sockaddr_storage *ptr, std::string* = nullptr, unsigned short* port = nullptr);
int inet_ss_address_remap(sockaddr_storage *orig, sockaddr_storage *mapped);
std::string inet_ss_str(sockaddr_storage *s);


template <typename ... Args>
std::string string_printf(const std::string& fmt, const Args& ... args);

template <typename ... Args>
std::string string_printf(const std::string& fmt, const Args& ... args)
{
    std::stringstream ss;

    size_t fmtIndex = 0;
    size_t placeHolders = 0;
    auto printFmt = [&fmt, &ss, &fmtIndex, &placeHolders]()
    {
        for (; fmtIndex < fmt.size(); ++fmtIndex)
        {
            if (fmt[fmtIndex] != '%')
                ss << fmt[fmtIndex];
            else if (++fmtIndex < fmt.size())
            {
                if (fmt[fmtIndex] == '%')
                    ss << '%';
                else
                {
                    ++fmtIndex;
                    ++placeHolders;
                    break;
                }
            }
        }
    };

    ((printFmt(), ss, ss << args), ..., (printFmt()));

    if (placeHolders < sizeof...(args))
        throw std::runtime_error("extra arguments provided to printf");
    if (placeHolders > sizeof...(args))
        throw std::runtime_error("invalid format string: missing arguments");


    return ss.str();
}

#endif // DISPLAY_HPP