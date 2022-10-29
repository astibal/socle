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

#include <string>
#include <vector>
#include <mutex>
#include <iostream>
#include <algorithm>
#include <cstring>

#include <execinfo.h>
#include <sys/utsname.h>

#include "display.hpp"
#include "buffer.hpp"

#include <cstdarg>
#include <cstdio>
#include <cerrno>

class buffer;



// don't use this function. Its behavior with writing to c_str() is undefined
std::string string_format_old(const char* fmt, ...) {
    
    int size = 512;
    std::string str;
    va_list ap;
    while (true) {
        str.resize(size);
        va_start(ap, fmt);

        //  writing to c_str() produced data is undefined behaviour
        //  https://en.cppreference.com/w/cpp/string/basic_string/c_str

        int n = vsnprintf((char *)str.c_str(), size, fmt, ap);
        va_end(ap);
        if (n > -1 && n < size) {
            str.resize(n);
            return str;
        }
        if (n > -1)
            size = n + 1;
        else
            size *= 2;
    }
    return str;
}


std::string hex_dump(buffer const* b, unsigned int ltrim, unsigned char prefix, bool add_cr, unsigned int fake_pos) {

    return hex_dump(const_cast<unsigned char*>(b->data()), b->size(), ltrim, prefix, add_cr, fake_pos);
}
std::string hex_dump(buffer const& b, unsigned int ltrim, unsigned char prefix,  bool add_cr, unsigned int fake_pos) {

    return hex_dump(const_cast<unsigned char*>(b.data()), b.size(), ltrim, prefix, add_cr, fake_pos);
}

std::string hex_dump2(const unsigned char *data, size_t size, unsigned int ltrim, unsigned char prefix, bool add_cr, unsigned int fake_pos)
{
    /* dumps size bytes of *data to stdout. Looks like:
     * [0000] 75 6E 6B 6E 6F 77 6E 20 30 FF 00 00 00 00 39 00 unknown 0.....9.
     */


    const unsigned char *p = data;

    unsigned int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};
	
	std::stringstream ret;

	int tr = 0;
	if (ltrim > 0) {
		tr = static_cast<int>(ltrim) + 4;
	}

	std::string pref;
	
	if (prefix != 0) {
		if (tr > 1) tr--;
	}
	
	for (int i=0; i<tr; i++) { pref += ' ';}

	if (prefix != 0) {
		pref += static_cast<char>(prefix);
	}
	
    for(n=1;n<=size;n++) {
        if (n%16 == 1) {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4x",
               (unsigned int)(p-data+fake_pos) );
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
            ret << pref << string_format("[%4.4s]   %-50.50s  %s", addrstr, hexstr, charstr);
            if(add_cr) ret << "\r";
            ret << "\n";

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
        ret << pref << string_format("[%4.4s]   %-50.50s  %s", addrstr, hexstr, charstr);
        if(add_cr) ret << "\r";
        ret << "\n";
    }
    
    return ret.str();
}


std::string hex_dump(const unsigned char *data, size_t orig_size, unsigned int ltrim, unsigned char prefix, bool add_cr, unsigned int fake_pos) {
    mp::stringstream ss;


    auto filter_visi = [](const unsigned char c) -> unsigned char {
        if(c < 33 || c > 126 || c == 92 || c == 37) return '.';
        return c;
    };

    mp::stringstream ascii_line;
    bool truncated = false;

    auto size = orig_size;

    for (size_t i = 0; i < size ; ++i) {

        if( i % 16 == 0 )  {

            ss << ascii_line.str();
            ascii_line.clear();
            ascii_line.str(mp::string());
            ascii_line << "  ";

            if(ltrim > 0) for (unsigned int j = 0; j < ltrim; ++j) { ss << " "; }

            if(prefix != 0) ss << prefix;

            if(add_cr) ss << "\r";

            ss << "\n";
            ss << "[";
            ss << string_format("%04X", i + fake_pos);
            ss << "]  ";
        }
        else if( i % 8 == 0) {
            ss << "  ";
        }

        auto curchar = data[i];
        ss << string_format("%02X ", (uint8_t)curchar);
        ascii_line << (char)filter_visi(curchar);

        if(i >= MAX_HEXDUMP_SIZE) {
            truncated = true;
            size = i + 1;
            break;
        }
    }

    for (size_t i = 0; i < 16 - (size % 16); ++i) {
        ss << "   ";
    }

    if((size % 16) != 0) {

        if((size % 16) <= 8) ss << "  "; // center spacer
        ss << ascii_line.str();
    }

    if(truncated) {
        if (add_cr) ss << "\r";
        ss << "\n[....]                                                      <data too large>";
    }

    if(add_cr) ss << "\r";
    ss << "\n";

    return ss.str().c_str();
}

std::string string_error() {
    return string_error(errno);
}

std::string string_error(int code) {

    char msg[255];
    memset(msg,0,255);
    return string_format("error %d: %s", code, strerror_r(code,msg,255));
}



std::string bt(bool add_r) {

#ifndef LIBC_MUSL

    std::string maybe_r;
    if(add_r)
        maybe_r = "\r";

    std::string s;
    s += "\n" + maybe_r + "Backtrace:";

    void *trace[64];
    size_t size;
    size_t i;
    char **strings;

    size    = backtrace( trace, 64 );
    strings = backtrace_symbols( trace, (int) size );

    if (strings == nullptr) {
        s += "\n" + maybe_r + " failure: backtrace_symbols";
        exit(EXIT_FAILURE);
    }


    for( i = 0; i < size; i++ ) {
        s += "\n";
        s += maybe_r;
        s += strings[i];
    }
    delete[] strings;

    s += "--";

    return s;
#else
    return "<musl libc>";
#endif
}

#define POW_1   1024.0
#define POW_2   1048576.0
#define POW_3   1073741824.0
#define POW_4   1099511627776.0

std::string number_suffixed(unsigned long xn) {

    auto n = static_cast<double>(xn);

    if(n < POW_1 ) {
        return string_format("%.1f", n);
    } else 
    if(n >= POW_1 && n < POW_2 ) {
        return string_format("%.2fk", n / POW_1);
    } else 
    if(n >= POW_2 && n < POW_3 ) {
        return string_format("%.2fM", n / POW_2);
    } else 
    if (n >= POW_3 && n < POW_4 ) {
        return string_format("%.2fG", n / POW_3);
    }
    else {
        return string_format("%.3fT", n / POW_4);
    }
}


void chr_cstrlit(unsigned char u, char *buffer, size_t buflen, bool to_print = false) {

    
    if (buflen < 2)
        buffer[0] = '\0';
    else if (isprint(u) && u != '\'' && u != '\"' && u != '\\' && u != '\?')
        sprintf(buffer, "%c", u);
    else if (buflen < 3)
        *buffer = '\0';
    else
    {
        switch (u)
        {
        case '\a':  strcpy(buffer, "\\a"); break;
        case '\b':  strcpy(buffer, "\\b"); break;
        case '\f':  strcpy(buffer, "\\f"); break;
        case '\n':  strcpy(buffer, "\\n"); break;
        case '\r':  strcpy(buffer, "\\r"); break;
        case '\t':  strcpy(buffer, "\\t"); break;
        case '\v':  strcpy(buffer, "\\v"); break;
        case '\\':  strcpy(buffer, "\\\\"); break;
        case '\'':  strcpy(buffer, "\\'"); break;
        case '\"':  strcpy(buffer, "\\\""); break;
        case '\?':  strcpy(buffer, "\\\?"); break;
        
        case '%':
            if(to_print) {
                strcpy(buffer, "%%"); break;
            }

        [[ fallthrough ]];

        default:
            if (buflen < 5)
                *buffer = '\0';
            else
                sprintf(buffer, "\\%03o", u);
            break;
        }
    }
}




/*
 * this function escapes string for 2 purposes:
 * - to use string internally
 * - for printing
 * it behaves slightly different way, depending on mode.
 * For internal only, it will escape everything to be escaped, except formatting character '%'
 * For printing purposes, it will escape only non-printables, + formatting character '%'
 * Sometimes is also handy to escape spaces, set `escape_space` if needed.
 */
std::string escape(const std::string &orig, bool ascii_only, bool escape_space) {
    std::stringstream ret;
    
    for (char c : orig) {
        if (isprint(c) && c != '\'' && c != '\"' && c != '\\' && c != '\?' && c != '%' && c != ' ') {
            ret << c;
        }
        else {
            switch (c)
            {
                
            // escape in all cases
            case '\a':  
                ret << "\\a";
                break;
            case '\b':  
                ret << "\\b";
                break;
            case '\f':  
                ret << "\\f";
                break;
            case '\v':  
                ret << "\\v";
                break;
            case '\\':  
                ret << "\\\\";
                break;

            
            // escape only when we want to print string out
            case '%':
                if(ascii_only)
                    ret << "%%";
                break;
                
            
            // escape if full escape requested
            case '\n':  
                if(! ascii_only)
                    ret << "\\n";
                break;
                
            case '\t':  
                if(! ascii_only)
                    ret << "\\t";
                break;
                
            case '\r':  
                if(! ascii_only)
                    ret << "\\r";
                break;
            

            case '\'':  
                if(! ascii_only)
                    ret << "\\'";
                break;

            case '\"':  
                if(! ascii_only)
                    ret << "\\\"";
                break;

            case '\?':  
                if(! ascii_only)
                    ret << "\\\?";
                break;

            case ' ':
                if(escape_space)
                    ret << "\\ ";
                else
                    ret << " ";
                break;
            
            default:
                if(! ascii_only) ret << string_format("\\%03o", c);
            }
        }
    }
    
    return ret.str();
}


std::vector<std::string> string_split(const std::string &str, char delimiter) {
    std::vector<std::string> internal;
    std::stringstream ss(str); // Turn the string into a stream.
    std::string tok;

    while(getline(ss, tok, delimiter)) {
        internal.push_back(tok);
    }

    return internal;
}

std::string get_kernel_version() {
    utsname u{};
    memset(&u,0,sizeof(utsname));
    uname(&u);

    std::string kernel_ver = u.release;
    //printf("Kernel version detected: %s\n",kernel_ver.c_str());

    std::replace( kernel_ver.begin(), kernel_ver.end(), '-', '.');
    //printf("Kernel version sanitized: %s\n",kernel_ver.c_str());

    return kernel_ver;
}

bool version_check(const std::string &real_string , std::string const& v) {

    std::vector<std::string> real_ver = string_split(real_string,'.');
    std::vector<std::string> target_ver = string_split(v,'.');

    auto max_ver_level = (target_ver.size() < real_ver.size()) ? target_ver.size() : real_ver.size();
    for( size_t i = 0 ; i < max_ver_level; ++i) {

        int real_int = 0;
        int target_int = 0;
        try {
            real_int = std::stoi(real_ver.at(i));
            target_int = std::stoi(target_ver.at(i));
        }
        catch(std::invalid_argument const& e) {
            //printf("error: cannot convert to a number\n");

            // so far we succeeded with version checks
            // or if i == 0 and no checks were possible. Be polite and fail-open.
            return true;
        }

        //printf("Comparing[%d:%d]: real %d with target %d\n",max_ver_level,i,real_int,target_int);

        if( real_int < target_int) {
            return false;
        } else
        if( real_int > target_int) {
            return true;
        }
    }

    return true;
}




int safe_val(const std::string &str_val, int default_val) {
    int ret = default_val;
    
    try {
        ret = std::stoi(str_val);
    }
    catch(std::invalid_argument const&) {}
    catch(std::out_of_range const& ) {}
    catch(std::exception const&) {}

    return ret;
}

std::vector<std::string> args_to_vec(char* argv[], int argc) {
    std::vector<std::string> arg;
    for (int i = 0; i < argc; ++i) {
        arg.emplace_back(argv[i]);
    }

    return arg;
}

std::string string_trim(const std::string& orig) {
    std::string ret;
    bool start = true;
    int spaces = 0;
    
    for(unsigned char c: orig) {
        bool space = isspace(c);
        
        if(space) {
            spaces++;
        } else {
            spaces=0;
        }
        
        if(space and start) {
            continue;
        } else {
            start = false;
            ret += c;
        }
    }
    
    if(spaces > 0) {
        return ret.substr(0,-spaces);
    }
    
    return ret;
}

std::string string_tolower(const std::string& orig) {
    std::stringstream r;

    for(char c: orig) {
        r << (unsigned char)std::tolower((int)c);
    }

    return r.str();
}

std::string string_csv(const std::vector<std::string>& str_list_ref, char delim) {
    std::stringstream build;
    for(unsigned int ii = 0 ; ii < str_list_ref.size() ; ii++ ) {
        build << str_list_ref[ii];
        if( ii < str_list_ref.size() - 1) {
            build << delim;
        }
    }

    return build.str();
}


std::string string_shorten(std::string const& orig, size_t max_len) {
    if(orig.length() > max_len) {
        auto shortened = orig.substr(0, 3);
        auto shortened2 = orig.substr(orig.length() - 3, orig.length());
        return shortened + "..." + shortened2;
    }
    return orig;
};

