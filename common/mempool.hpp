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

#ifndef __MEMPOOL_HPP__
#define __MEMPOOL_HPP__

#include <cstddef>
#include <vector>
#include <mutex>
#include <unordered_map>

#include <execinfo.h>

#include <display.hpp>
#include <logger.hpp>

#define MEMPOOL_DEBUG

class buffer;

typedef struct mem_chunk
{
    mem_chunk(): ptr(nullptr), capacity(0) {};
    mem_chunk(std::size_t s): capacity(s) { ptr = new unsigned char[s]; };
    mem_chunk(unsigned char* p, std::size_t c): ptr(p), capacity(c) {};

    unsigned char* ptr;
    std::size_t  capacity;
    bool in_pool = false; // set this flag to indicate if the allocation is in pool => allocated, but not used.

    static const bool trace_enabled;
#ifdef MEMPOOL_DEBUG

    #define MEM_CHUNK_TRACE_SZ 64

    void* trace[MEM_CHUNK_TRACE_SZ];
    int trace_size = 0;                 // number of elements (void* pointers) in the trace list
    uint32_t mark = 0;                  // useful for filtering purposes.

    inline void clear_trace() { memset(trace, 0 , MEM_CHUNK_TRACE_SZ*sizeof(void*)); trace_size = 0; mark = 0; }
    inline void set_trace() { clear_trace(); trace_size = backtrace(trace, MEM_CHUNK_TRACE_SZ); };
    #ifndef LIBC_MUSL
    std::string str_trace() {

        std::string ret;
        char **strings;

        strings = backtrace_symbols( trace, trace_size );

        if (strings == nullptr) {
            ret += "failure: backtrace_symbols";
            return  ret;
        }


        for( int i = 0; i < trace_size; i++ ) {
            ret += "\n";
            ret += strings[i];
        }
        delete[] strings;

        return ret;
    };
    std::string simple_trace() {
        std::string ret;
        for( int i = 0; i < trace_size; i++ ) {
            ret += string_format("0x%x ", trace[i]);
        }
        return ret;
    };

    #else //LIBC_MUSL
    std:string str_trace() {
        return simple_trace();
    };
    #endif
#else
    inline void clear_trace() {};
    inline void set_trace() {};
#endif

} mem_chunk_t;


class memPool {

public:
    std::size_t sz32;
    std::size_t sz64;
    std::size_t sz128;
    std::size_t sz256;
    std::size_t sz1k;
    std::size_t sz5k;
    std::size_t sz10k;
    std::size_t sz20k;

    memPool(std::size_t sz256, std::size_t sz1k, std::size_t sz5k, std::size_t sz10k, std::size_t sz20k);

    mem_chunk_t acquire(std::size_t sz);
    void release(mem_chunk_t to_ret);

    std::vector<mem_chunk_t>* pick_acq_set(ssize_t s);
    std::vector<mem_chunk_t>* pick_ret_set(ssize_t s);

    std::vector<mem_chunk_t> available_32;
    std::vector<mem_chunk_t> available_64;
    std::vector<mem_chunk_t> available_128;
    std::vector<mem_chunk_t> available_256;
    std::vector<mem_chunk_t> available_1k;
    std::vector<mem_chunk_t> available_5k;
    std::vector<mem_chunk_t> available_10k;
    std::vector<mem_chunk_t> available_20k;
    std::vector<mem_chunk_t> available_big; // will be empty initially

    static unsigned long long stat_acq;
    static unsigned long long stat_acq_size;

    static unsigned long long stat_ret;
    static unsigned long long stat_ret_size;

    static unsigned long long stat_alloc;
    static unsigned long long stat_alloc_size;

    static unsigned long long stat_free;
    static unsigned long long stat_free_size;

    static unsigned long long stat_out_free;
    static unsigned long long stat_out_free_size;

    std::mutex lock;
};


// hashmap of pointer sizes (for mempool_* functions)
//
extern std::unordered_map<void*, mem_chunk> mempool_ptr_map;
extern std::mutex mempool_ptr_map_lock;

void* mempool_alloc(size_t);
void* mempool_realloc(void*, size_t);
void  mempool_free(void*);


// wrapper functions for compatibility with openssl malloc hooks (see CRYPTO_set_mem_functions)
void* mempool_alloc(size_t, const char*, int);
void* mempool_realloc(void*, size_t, const char*, int);
void mempool_free(void*, const char*, int);

extern unsigned long long stat_mempool_alloc;

extern unsigned long long stat_mempool_realloc;
extern unsigned long long stat_mempool_realloc_miss;
extern unsigned long long stat_mempool_realloc_fitting;

extern unsigned long long stat_mempool_free;
extern unsigned long long stat_mempool_free_miss;

extern unsigned long long stat_mempool_alloc_size;
extern unsigned long long stat_mempool_realloc_size;
extern unsigned long long stat_mempool_free_size;

#endif //__MEMPOOL_HPP__