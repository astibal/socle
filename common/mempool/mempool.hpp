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

#ifndef MEMPOOL_HPP
#define MEMPOOL_HPP

#include <cstddef>
#include <vector>
#include <stack>
#include <mutex>
#include <unordered_map>
#include <atomic>

#if defined(MEMPOOL_DEBUG) || !defined(LIBC_MUSL)
#include <execinfo.h>
#endif

#include <display.hpp>
#include <lockable.hpp>
#include <log/logger.hpp>

#include <mempool/canary.hpp>
#include <mempool/malloc_allocator.hpp>


//#define MEMPOOL_DEBUG
//#define MEMPOOL_ALL

#if defined(MEMPOOL_DEBUG) && defined(MEMPOOL_ALL)
    #warning "MEMPOOL_ALL together with MEMPOOL_DEBUG is highly experimental at this moment."
#endif

class buffer;

struct mem_chunk
{
#ifdef MEMPOOL_ALL
    // mempool should avoid using new() operator - in MEMPOOL_ALL mode it will recurse and dies
    explicit mem_chunk(std::size_t s): capacity(s) { ptr = (unsigned char*)::malloc(s); pool_type = type::HEAP; };   // lgtm[cpp/resource-not-released-in-destructor]
#else
    explicit mem_chunk(std::size_t s): ptr(new unsigned char[s]), capacity(s), pool_type(type::HEAP) {}; // lgtm[cpp/resource-not-released-in-destructor]
#endif
    mem_chunk(unsigned char* p, std::size_t c): ptr(p), capacity(c) {};

    // Actually coverity found wanted feature - mem_chunk is basically pointer with size
    // and should be treated as a copyable *value*.

    // this is for study purposes, but don't use it in production.
    //~mem_chunk () { delete ptr; };   // coverity: 1407975
    //mem_chunk(mem_chunk const& ref) = delete;
    //mem_chunk& operator=(mem_chunk const& ref) = delete;

    unsigned char* ptr = nullptr;
    std::size_t  capacity = 0L;
    bool in_pool = false; // set this flag to indicate if the allocation is in pool => allocated, but not used.

    enum class pool_type_t { POOL, HEAP };
    using type = pool_type_t;
    type pool_type = type::POOL;

#ifdef MEMPOOL_DEBUG
    static inline const bool trace_enabled = true;
#else
    static inline const bool trace_enabled = false;
#endif



#if defined(MEMPOOL_DEBUG) || !defined(LIBC_MUSL)

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

};


using mem_chunk_t = mem_chunk;

class memPool {

    std::size_t sz32  = 0L;
    constexpr static unsigned int m32 = 16;
    std::size_t sz64  = 0L;
    constexpr static unsigned int m64 = 8;
    std::size_t sz128 = 0L;
    constexpr static unsigned int m128 = 4;
    std::size_t sz256 = 0L;
    std::size_t sz1k  = 0L;
    std::size_t sz5k  = 0L;
    std::size_t sz10k = 0L;
    std::size_t sz20k = 0L;
    std::size_t sz35k = 0L;
    std::size_t sz50k = 0L;

    class Bucket : public lockable {
    public:
        Bucket() = delete;
        explicit Bucket(std::size_t SZ): sz(SZ) {};

        ~Bucket() override {
            auto lc_ = std::scoped_lock(*this);
            ::free(bigptr);
        }

        /// @return get available chunks in the bucket
        std::size_t size() const;

        /// @return get a chunk if available
        std::optional<mem_chunk> acquire();

        /// return back @param mch to the bucket
        void release(mem_chunk mch);

        /// @return true, if pointer @param ptr is (acquired or not) in the bucket memory.
        bool is_mine(uint8_t const* ptr) const noexcept;

        /// @return true, if pointer @param ptr is aligned with the start of the memory pool
        bool is_aligned(uint8_t const* ptr) const noexcept;

        /// @return of total number elements in the bucket (if none is acquired)
        std::size_t total_count() const noexcept { return count; }

        /// @return size of the single chunk
        std::size_t chunk_size() const noexcept { return sz; }

    private:
        uint64_t ptr_address() const { return reinterpret_cast<uint64_t>(bigptr); }
        void init_memory(std::size_t cnt);

        std::size_t sz = 0L;
        std::stack<mem_chunk_t> bucket;

        std::size_t allocated = 0;
        uint8_t* bigptr = nullptr;
        uint8_t* _endptr = nullptr;
        std::size_t count;
        std::size_t canary_sz;

        friend class memPool;
    };

    /// @return the right bucket for the required size @param s. If none is available,
    /// `nullptr` is returned.
    Bucket* pick_bucket(size_t s);

    /// Iterate all buckets to find available memory chunk and returns first suitable `mem_chunk` for required size of
    /// @param s.
    /// @note: should be used if @ref pick_bucket()->acquire() fails.
    std::optional<mem_chunk> tryhard_available(size_t s);

    /// Allocate `mem_chunk` from the heap, don't bother with buckets at all.
    /// @return mem_chunk with heap origin indication
    mem_chunk from_heap(std::size_t s);

    /// Free heap-allocated memory
    void free_heap(mem_chunk const& mch);

    Bucket bucket_32 {32};
    Bucket bucket_64 {64};
    Bucket bucket_128 {128};
    Bucket bucket_256 {256};
    Bucket bucket_1k {1024};
    Bucket bucket_5k {5L*1024};
    Bucket bucket_10k {10L*1024};
    Bucket bucket_20k {20L*1024};
    Bucket bucket_35k {35L*1024};
    Bucket bucket_50k {50L*1024};

    std::set<Bucket*> buckets;

    using canary_t = mp_canary;

    static canary_t& get_canary() {
        static canary_t c;
        return c;
    };

    memPool(std::size_t sz256, std::size_t sz1k, std::size_t sz5k, std::size_t sz10k, std::size_t sz20k);

public:
    std::set<Bucket*> const& get_buckets() const { return buckets; };
    std::set<Bucket*>& get_buckets() { return buckets; };

    // indicate to not use any allocation functions which are not safe!
    // resource requests will fail and releases do nothing.
    static inline bool bailing = false;

    static memPool& pool() {
        static auto m = memPool(100,50,50,10,8);
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

    Bucket* find_by_address(void* ptr);
    std::size_t find_ptr_size(void* ptr);

    struct stats_t {
        std::atomic<unsigned long long> acq{0};
        std::atomic<unsigned long long> acq_size{0};

        std::atomic<unsigned long long> ret{0};
        std::atomic<unsigned long long> ret_size{0};

        std::atomic<unsigned long long> heap_alloc{0};
        std::atomic<unsigned long long> heap_alloc_size{0};

        std::atomic<unsigned long long> heap_free{0};
        std::atomic<unsigned long long> heap_free_size{0};

        std::atomic<unsigned long long> out_free{0};
        std::atomic<unsigned long long> out_free_size{0};

        std::atomic<unsigned long long> out_pool_miss{0};
        std::atomic<unsigned long long> out_pool_miss_size{0};
    };
    stats_t stats;
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

#endif //MEMPOOL_HPP