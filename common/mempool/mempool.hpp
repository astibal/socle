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
#include <atomic>

#include <execinfo.h>

#include <display.hpp>
#include <log/logger.hpp>

#include <mempool/canary.hpp>
#include <mempool/malloc_allocator.hpp>


//#define MEMPOOL_DEBUG
//#define MEMPOOL_ALL

#if defined(MEMPOOL_DEBUG) && defined(MEMPOOL_ALL)
    #warning "MEMPOOL_ALL together with MEMPOOL_DEBUG is highly experimental at this moment."
#endif

class buffer;

typedef struct mem_chunk
{
    mem_chunk(): ptr(nullptr), capacity(0) {};

#ifdef MEMPOOL_ALL
    // mempool should avoid using new() operator - in MEMPOOL_ALL mode it will recurse and dies
    explicit mem_chunk(std::size_t s): capacity(s) { ptr = (unsigned char*)::malloc(s); pool_type = type::HEAP; };
#else
    explicit mem_chunk(std::size_t s): capacity(s) { ptr = new unsigned char[s]; pool_type = type::HEAP; };
#endif
    mem_chunk(unsigned char* p, std::size_t c): ptr(p), capacity(c) {};

    // Actually coverity found wanted feature - mem_chunk is basically pointer with size
    // and should be treated as a copyable *value*.

    // this is for study purposes, but don't use it in production.
    //~mem_chunk () { delete ptr; };   // coverity: 1407975
    //mem_chunk(mem_chunk const& ref) = delete;
    //mem_chunk& operator=(mem_chunk const& ref) = delete;

    unsigned char* ptr;
    std::size_t  capacity;
    bool in_pool = false; // set this flag to indicate if the allocation is in pool => allocated, but not used.

    enum class pool_type_t { POOL, HEAP };
    using type = pool_type_t;
    type pool_type = type::POOL;

#ifdef MEMPOOL_DEBUG
    static inline const bool trace_enabled = true;
#else
    static inline const bool trace_enabled = false;
#endif



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

    std::size_t sz32;
    constexpr static unsigned int m32 = 16;
    std::size_t sz64;
    constexpr static unsigned int m64 = 8;
    std::size_t sz128;
    constexpr static unsigned int m128 = 4;
    std::size_t sz256;
    std::size_t sz1k;
    std::size_t sz5k;
    std::size_t sz10k;
    std::size_t sz20k;
    std::size_t sz35k;
    std::size_t sz50k;

    std::vector<mem_chunk_t>* pick_acq_set(ssize_t s);
    std::vector<mem_chunk_t>* pick_ret_set(ssize_t s);

    std::vector<mem_chunk_t> available_32;
    std::size_t alloc32 = 0;
    unsigned char* bigptr_32 = nullptr;

    std::vector<mem_chunk_t> available_64;
    std::size_t alloc64 = 0;
    unsigned char* bigptr_64 = nullptr;

    std::vector<mem_chunk_t> available_128;
    std::size_t alloc128 = 0;
    unsigned char* bigptr_128 = nullptr;

    std::vector<mem_chunk_t> available_256;
    std::size_t alloc256 = 0;
    unsigned char* bigptr_256 = nullptr;

    std::vector<mem_chunk_t> available_1k;
    std::size_t alloc1k = 0;
    unsigned char* bigptr_1k = nullptr;

    std::vector<mem_chunk_t> available_5k;
    std::size_t alloc5k = 0;
    unsigned char* bigptr_5k = nullptr;

    std::vector<mem_chunk_t> available_10k;
    std::size_t alloc10k = 0;
    unsigned char* bigptr_10k = nullptr;

    std::vector<mem_chunk_t> available_20k;
    std::size_t alloc20k = 0;
    unsigned char* bigptr_20k = nullptr;

    std::vector<mem_chunk_t> available_35k;
    std::size_t alloc35k = 0;
    unsigned char* bigptr_35k = nullptr;

    std::vector<mem_chunk_t> available_50k;
    std::size_t alloc50k = 0;
    unsigned char* bigptr_50k = nullptr;

    using canary_t = mp_canary;

    static canary_t& get_canary() {
        static canary_t c;
        return c;
    };


    memPool(std::size_t sz256, std::size_t sz1k, std::size_t sz5k, std::size_t sz10k, std::size_t sz20k);
    ~memPool() noexcept;

public:

    // indicate to not use any allocation functions which are not safe!
    // resource requests will fail and releases do nothing.
    static inline bool bailing = false;

    static memPool& pool() {
        static memPool m = memPool(100,50,50,10,8);
        return m;
    }

    void allocate(std::size_t sz256, std::size_t sz1k, std::size_t sz5k, std::size_t sz10k, std::size_t sz20k);

    static inline bool heap_on_tension = true;

    static std::atomic_bool& is_ready() {
        static std::atomic_bool is_ready_(false);
        return is_ready_;
    }

    mem_chunk_t acquire(std::size_t sz);
    void release(mem_chunk_t to_ret);
    std::size_t find_ptr_size(void* ptr);

    std::atomic<unsigned long long> stat_acq{0};
    std::atomic<unsigned long long> stat_acq_size{0};

    std::atomic<unsigned long long> stat_ret{0};
    std::atomic<unsigned long long> stat_ret_size{0};

    std::atomic<unsigned long long> stat_alloc{0};
    std::atomic<unsigned long long> stat_alloc_size{0};

    std::atomic<unsigned long long> stat_free{0};
    std::atomic<unsigned long long> stat_free_size{0};

    std::atomic<unsigned long long> stat_out_free{0};
    std::atomic<unsigned long long> stat_out_free_size{0};

    std::atomic<unsigned long long> stat_out_pool_miss{0};
    std::atomic<unsigned long long> stat_out_pool_miss_size{0};


    long unsigned int mem_32_av() const { return static_cast<long unsigned int>(available_32.size()); };
    long unsigned int mem_64_av() const { return static_cast<long unsigned int>(available_64.size()); };
    long unsigned int mem_128_av() const { return static_cast<long unsigned int>(available_128.size()); };
    long unsigned int mem_256_av() const { return static_cast<long unsigned int>(available_256.size()); };
    long unsigned int mem_1k_av() const { return static_cast<long unsigned int>(available_1k.size()); };
    long unsigned int mem_5k_av() const { return static_cast<long unsigned int>(available_5k.size()); };
    long unsigned int mem_10k_av() const { return static_cast<long unsigned int>(available_10k.size()); };
    long unsigned int mem_20k_av() const { return static_cast<long unsigned int>(available_20k.size()); };
    long unsigned int mem_35k_av() const { return static_cast<long unsigned int>(available_35k.size()); };
    long unsigned int mem_50k_av() const { return static_cast<long unsigned int>(available_50k.size()); };


    long unsigned int mem_32_sz() const { return static_cast<long unsigned int>(sz32); };
    long unsigned int mem_64_sz() const { return static_cast<long unsigned int>(sz64); };
    long unsigned int mem_128_sz() const { return static_cast<long unsigned int>(sz128); };
    long unsigned int mem_256_sz() const { return static_cast<long unsigned int>(sz256); };
    long unsigned int mem_1k_sz() const { return static_cast<long unsigned int>(sz1k); };
    long unsigned int mem_5k_sz() const { return static_cast<long unsigned int>(sz5k); };
    long unsigned int mem_10k_sz() const { return static_cast<long unsigned int>(sz10k); };
    long unsigned int mem_20k_sz() const { return static_cast<long unsigned int>(sz20k); };
    long unsigned int mem_35k_sz() const { return static_cast<long unsigned int>(sz35k); };
    long unsigned int mem_50k_sz() const { return static_cast<long unsigned int>(sz50k); };


    std::mutex lock;
};


// hashmap of pointer sizes (for mempool_* functions)
//

struct mpdata {

    #ifdef MEMPOOL_DEBUG
    static std::unordered_map<
                            unsigned long,
                            mem_chunk,
                            std::hash<unsigned long>,
                            std::equal_to<>,
                            mp::malloc::allocator<std::pair<const unsigned long,mem_chunk>>>& trace_map() {

        static std::unordered_map<unsigned long, mem_chunk, std::hash<unsigned long>, std::equal_to<>, mp::malloc::allocator<std::pair<const unsigned long,mem_chunk>>> m;
        return m;
    }
    static std::mutex& trace_lock() {
        static std::mutex m;
        return m;
    };

    #endif

};


void* mempool_alloc(size_t);
void* mempool_realloc(void*, size_t);
void  mempool_free(void*);


// wrapper functions for compatibility with openssl malloc hooks (see CRYPTO_set_mem_functions)
void* mempool_alloc(size_t, const char*, int);
void* mempool_realloc(void*, size_t, const char*, int);
void mempool_free(void*, const char*, int);


struct mp_stats {

    std::atomic<unsigned long long> stat_mempool_alloc;

    std::atomic<unsigned long long> stat_mempool_realloc;
    std::atomic<unsigned long long> stat_mempool_realloc_miss;
    std::atomic<unsigned long long> stat_mempool_realloc_fitting;

    std::atomic<unsigned long long> stat_mempool_free;
    std::atomic<unsigned long long> stat_mempool_free_miss;

    std::atomic<unsigned long long> stat_mempool_alloc_size;
    std::atomic<unsigned long long> stat_mempool_realloc_size;
    std::atomic<unsigned long long> stat_mempool_free_size;

    static mp_stats& get() { static mp_stats m; return m; }

    mp_stats(mp_stats const&) = delete;
    mp_stats& operator=(mp_stats const&) = delete;
private:
    mp_stats() = default;
};

#endif //__MEMPOOL_HPP__