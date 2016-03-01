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
#include <mutex>
#include <execinfo.h>

#include "display.hpp"
#include "buffer.hpp"

#include "string.h"
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
    // there could be more precious implemenatation of this in the future
    std::lock_guard<std::recursive_mutex> l(formatter_lock);    
    
    std::string s;
    s += "\n Backtrace:";

    void *trace[64];
    size_t size, i;
    char **strings;

    size    = backtrace( trace, 64 );
    strings = backtrace_symbols( trace, size );

    if (strings == NULL) {
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
    if (n >= POW_3 && n < POW_3 ) {
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
            case '\a':  ret += "\\a"; break;
            case '\b':  ret += "\\b"; break;
            case '\f':  ret += "\\f"; break;
            case '\v':  ret += "\\v"; break;
            case '\\':  ret += "\\\\"; break;

            
            // escape only when we want to print string out
            case '%':
                if(to_print) ret += "%%"; break;
                
            
            // escape if full escape requested
            case '\n':  
                if(! to_print) ret += "\\n"; break;
                
            case '\t':  
                if(! to_print) ret += "\\t"; break;
                
            case '\r':  
                if(! to_print) ret += "\\r"; break;
            

            case '\'':  
                if(! to_print) ret += "\\'"; break;

            case '\"':  
                if(! to_print) ret += "\\\""; break;

            case '\?':  
                if(! to_print) ret += "\\\?"; break;
            
            
            default:
                if(! to_print) ret += string_format("\\%03o", c);
            }
        }
    }
    
    return ret;
}
