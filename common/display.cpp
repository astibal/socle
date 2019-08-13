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
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cstring>

#include <execinfo.h>
#include <sys/utsname.h>
#include <arpa/inet.h>

#include "display.hpp"
#include "buffer.hpp"

#include "stdarg.h"
#include "stdio.h"
#include "errno.h"


std::recursive_mutex formatter_lock;

std::string string_format(const std::string& fmt, ...) {
    
    // there could be more precious implemenatation of this in the future
    std::lock_guard<std::recursive_mutex> l(formatter_lock);
    
    int size = 512;
    std::string str;
    va_list ap;
    while (1) {
        str.resize(size);
        va_start(ap, fmt);
        int n = vsnprintf((char *)str.c_str(), size, fmt.c_str(), ap);
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

std::string hex_print(unsigned char* data, unsigned int len) {
    std::stringstream ss;
    
    for(unsigned int i=0; i < len; i++) {
        ss << string_format("%02X", data[i]);
    }
    
    return ss.str();
}

std::string hex_dump(buffer* b, unsigned int ltrim, unsigned char prefix) { return hex_dump((unsigned char*)b->data(),b->size(),ltrim,prefix); }
std::string hex_dump(buffer& b, unsigned int ltrim, unsigned char prefix) { return hex_dump((unsigned char*)b.data(),b.size(),ltrim,prefix); }


std::string hex_dump(unsigned char *data, int size,unsigned int ltrim, unsigned char prefix)
{
    /* dumps size bytes of *data to stdout. Looks like:
     * [0000] 75 6E 6B 6E 6F 77 6E 20
     *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
     * (in a single line of course)
     */

    // there could be more precious implemenatation of this in the future
    std::lock_guard<std::recursive_mutex> l(formatter_lock);    
    
    unsigned char *p = data;

    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};
	
	std::string ret = std::string();

	int tr = 0;
	if (ltrim > 0) {
		tr = ltrim + 4;
	}

	std::string pref = std::string();
	
	if (prefix != 0) {
		if (tr > 1) tr--;
	}
	
	for (int i=0; i<tr; i++) { pref += ' ';}

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
            ret += pref + string_format("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
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
        ret += pref + string_format("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
    
    return ret;
}

std::string string_error() {
    // there could be more precious implemenatation of this in the future
    std::lock_guard<std::recursive_mutex> l(formatter_lock);
    
    int e = errno;
    char msg[255];
    memset(msg,0,255);
    return string_format("error %d: %s",e,strerror_r(e,msg,255));
}



std::string bt() {

#ifndef LIBC_MUSL
    // there could be more precious implemenatation of this in the future
    std::lock_guard<std::recursive_mutex> l(formatter_lock);    
    
    std::string s;
    s += "\n Backtrace:";

    void *trace[64];
    size_t size;
    size_t i;
    char **strings;

    size    = backtrace( trace, 64 );
    strings = backtrace_symbols( trace, size );

    if (strings == nullptr) {
        s += "\n failure: backtrace_symbols";
        exit(EXIT_FAILURE);
    }


    for( i = 0; i < size; i++ ) {
        s += "\n";
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
    unsigned long n = labs(xn);

    if(n < POW_1 ) {
        return string_format("%.1ld",xn);
    } else 
    if(n >= POW_1 && n < POW_2 ) {
        return string_format("%.fk",xn/POW_1);
    } else 
    if(n >= POW_2 && n < POW_3 ) {
        return string_format("%.2fM",xn/POW_2);
    } else 
    if (n >= POW_3 && n < POW_4 ) {
        return string_format("%.2fG",xn/POW_3);
    }
    else {
        return string_format("%.3fT",xn/POW_4);
    }
}


void chr_cstrlit(unsigned char u, char *buffer, size_t buflen, bool to_print = false) {

    
    if (buflen < 2)
        *buffer = '\0';
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
 * For internal only, it will escape everything to be escaped, except formating character '%'
 * For printing purposes, it will escape only non-printables, + formatting character '%'
 */
std::string escape(std::string orig, bool to_print) {
    std::string ret;
    
    for (size_t i = 0; i < orig.size(); ++i) {
        char c = orig[i];
        if (isprint(c) && c != '\'' && c != '\"' && c != '\\' && c != '\?' && c != '%') {
            ret += c;        
        }
        else {
            switch (c)
            {
                
            // escape in all cases
            case '\a':  
                ret += "\\a"; 
                break;
            case '\b':  
                ret += "\\b"; 
                break;
            case '\f':  
                ret += "\\f"; 
                break;
            case '\v':  
                ret += "\\v"; 
                break;
            case '\\':  
                ret += "\\\\"; 
                break;

            
            // escape only when we want to print string out
            case '%':
                if(to_print) 
                    ret += "%%"; 
                break;
                
            
            // escape if full escape requested
            case '\n':  
                if(! to_print) 
                    ret += "\\n"; 
                break;
                
            case '\t':  
                if(! to_print) 
                    ret += "\\t"; 
                break;
                
            case '\r':  
                if(! to_print) 
                    ret += "\\r"; 
                break;
            

            case '\'':  
                if(! to_print) 
                    ret += "\\'"; 
                break;

            case '\"':  
                if(! to_print) 
                    ret += "\\\""; 
                break;

            case '\?':  
                if(! to_print) 
                    ret += "\\\?"; 
                break;
            
            
            default:
                if(! to_print) ret += string_format("\\%03o", c);
            }
        }
    }
    
    return ret;
}


std::vector<std::string> string_split(std::string str, char delimiter) {
    std::vector<std::string> internal;
    std::stringstream ss(str); // Turn the string into a stream.
    std::string tok;

    while(getline(ss, tok, delimiter)) {
        internal.push_back(tok);
    }

    return internal;
}

std::string get_kernel_version() {
    utsname u;
    memset(&u,0,sizeof(utsname));
    uname(&u);

    std::string kernel_ver = u.release;
    //printf("Kernel version detected: %s\n",kernel_ver.c_str());

    std::replace( kernel_ver.begin(), kernel_ver.end(), '-', '.');
    //printf("Kernel version sanitized: %s\n",kernel_ver.c_str());

    return kernel_ver;
}

bool version_check(std::string real_string ,std::string v) {

    std::vector<std::string> real_ver = string_split(real_string,'.');
    std::vector<std::string> target_ver = string_split(v,'.');

    int max_ver_level = (target_ver.size() < real_ver.size()) ? target_ver.size() : real_ver.size();
    for( int i = 0 ; i < max_ver_level; ++i) {

        int real_int = 0;
        int target_int = 0;
        try {
            real_int = std::stoi(real_ver.at(i));
            target_int = std::stoi(target_ver.at(i));
        }
        catch(std::invalid_argument e) {
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

std::string inet_family_str(int fa) {
    switch(fa) {
        case AF_INET:
            return std::string("IPv4");
        case AF_INET6:
            return std::string("IPv6");
            
        default:
            return string_format("Proto%d",fa);
    }
}


int inet_ss_address_unpack(sockaddr_storage* ptr, std::string* dst, unsigned short* port) {
    char b[64]; memset(b,0,64);
    int family = ptr->ss_family;
    unsigned short val_port = 0;
    
    if(family == AF_INET6) {
        inet_ntop(ptr->ss_family,&(((struct sockaddr_in6*) ptr)->sin6_addr),b,64);
        val_port = ((struct sockaddr_in6*) ptr)->sin6_port;
    }
    else if(family == AF_INET) {
        inet_ntop(ptr->ss_family,&(((struct sockaddr_in*) ptr)->sin_addr),b,64);
        val_port = ((struct sockaddr_in*) ptr)->sin_port;
    }
    
    std::string mapped4_temp = b;
    if(mapped4_temp.find("::ffff:") == 0) {
        mapped4_temp = mapped4_temp.substr(7);
        family = AF_INET;
    }    
    
    if(dst != nullptr) {
        // function can be useful just to detect mapped IP
        dst->assign(mapped4_temp);
    }
    if(port != nullptr) {
        *port = ntohs(val_port);
    }
    return family;
}


int inet_ss_address_remap(sockaddr_storage* orig, sockaddr_storage* mapped) {
    std::string ip_part;
    unsigned short port_part;
    
    int fa = inet_ss_address_unpack(orig,&ip_part,&port_part);
    
    if(fa == AF_INET) {
        inet_pton(fa,ip_part.c_str(),&((struct sockaddr_in*)mapped)->sin_addr);
        ((struct sockaddr_in*)mapped)->sin_port = htons(port_part);
        mapped->ss_family = fa;
    } else
    if(fa == AF_INET6) {
        inet_pton(fa,ip_part.c_str(),&((struct sockaddr_in6*)mapped)->sin6_addr);
        ((struct sockaddr_in6*)mapped)->sin6_port = htons(port_part);
        mapped->ss_family = fa;
    }
    
    return fa;
}

std::string inet_ss_str(sockaddr_storage* s) {
    std::string ip;
    unsigned short port;
    
    int fa = inet_ss_address_unpack(s,&ip,&port);
    
    return string_format("%s/%s:%d", inet_family_str(fa).c_str(),ip.c_str(),port);
}


int safe_val(std::string s, int default_val) {
    int ret = default_val;
    
    try {
        ret = std::stoi(s);
    }
    catch(std::invalid_argument) {}
    catch(std::out_of_range) {}
    catch(std::exception) {}

    return ret;
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

std::string&& string_tolower(const std::string& orig) {
    std::string r;

    for(char c: orig) {
        r += tolower((int)c);
    }

    return std::move(r);
}

std::string string_csv(const std::vector<std::string>& str_list_ref, const char delim) {
    std::stringstream build;
    for(unsigned int ii = 0 ; ii < str_list_ref.size() ; ii++ ) {
        build << str_list_ref[ii];
        if( ii < str_list_ref.size() - 1) {
            build << delim;
        }
    }

    return std::move(build.str());
}