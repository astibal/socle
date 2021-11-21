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

#include <mempool/mempool.hpp>

#include <unordered_map>
#include "buffer.hpp"


memPool::memPool(std::size_t sz256, std::size_t sz1k, std::size_t sz5k, std::size_t sz10k, std::size_t sz20k):
        sz32(0), sz64(0), sz128(0), sz256(0), sz1k(0), sz5k(0), sz10k(0), sz20k(0), sz35k(0), sz50k(0)
{
    auto get_env_size = []() -> int {

        auto ptr_str_size = std::getenv("SX_MEMSIZE");

        // size is mentioned as percent of default values, which are:
        // 5000,10000,10000,1000,800
        int size = 100;

        if (ptr_str_size) {
            auto new_size = safe_val(ptr_str_size);

            // accept 10% - 10000%, meaning one tenth to 100-multiple of default value
            if (new_size >= 10 && new_size <= 100 * 100) {
                size = new_size;
            } else {
                std::cerr << "accepting values 10 - 10000" << std::endl;
                std::cerr << "value is understood as percent of default size" << std::endl;
            }
        }

        return size;
    };

    auto size = get_env_size();

    allocate(sz256*size, sz1k*size, sz5k*size, sz10k*size, sz20k*size);
    is_ready() = true; // mark memPool ready for use
}

memPool::~memPool() noexcept {

    try {

        std::lock_guard<std::mutex> g(lock);

        available_32.clear();
        ::free(bigptr_32);

        available_64.clear();
        ::free(bigptr_64);

        available_128.clear();
        ::free(bigptr_128);

        available_256.clear();
        ::free(bigptr_256);

        available_1k.clear();
        ::free(bigptr_1k);

        available_5k.clear();
        ::free(bigptr_5k);

        available_10k.clear();
        ::free(bigptr_10k);

        available_20k.clear();
        ::free(bigptr_20k);

        available_35k.clear();
        ::free(bigptr_35k);

        available_50k.clear();
        ::free(bigptr_50k);
    } catch (std::exception const& e) {
        std::cerr << "exception in ~memPool(): " <<  e.what() << std::endl;
    }
}


void memPool::allocate(std::size_t n_sz256, std::size_t n_sz1k, std::size_t n_sz5k,
                     std::size_t n_sz10k, std::size_t n_sz20k) {

    std::lock_guard<std::mutex> l_(lock);

    sz32  = n_sz256 * m32;
    sz64  = n_sz256 * m64;
    sz128 = n_sz256 * m128;
    sz256 = n_sz256;
    sz1k  = n_sz1k;
    sz5k  = n_sz5k;
    sz10k = n_sz10k;
    sz20k = n_sz20k;
    sz35k = n_sz20k;
    sz50k = n_sz20k;

#ifdef MEMPOOL_DEBUG
    get_canary().canary_sz = 8; // add 8 bytes of canary
#else
    get_canary().canary_sz = 0;
#endif

    std::size_t canary_sz = get_canary().canary_sz;

    alloc32 = sz32 * 32 + sz32*canary_sz + canary_sz;
    bigptr_32 = static_cast<unsigned char*>(::malloc(alloc32));

    alloc64 = sz64 * 64 + sz64*canary_sz + canary_sz;
    bigptr_64 = static_cast<unsigned char*>(::malloc(alloc64));

    alloc128 = sz128 * 128 + sz128*canary_sz  + canary_sz;
    bigptr_128 = static_cast<unsigned char*>(::malloc(alloc128));

    alloc256 = sz256 * 256 + sz256*canary_sz + canary_sz;
    bigptr_256 = static_cast<unsigned char*>(::malloc(alloc256));

    alloc1k = sz1k * 1024 + sz1k*canary_sz + canary_sz;
    bigptr_1k = static_cast<unsigned char*>(::malloc(alloc1k));

    alloc5k = sz5k * 1024 * 5 + sz5k*canary_sz + canary_sz;
    bigptr_5k = static_cast<unsigned char*>(::malloc(alloc5k));

    alloc10k = sz10k * 1024 * 10 + sz10k*canary_sz + canary_sz;
    bigptr_10k = static_cast<unsigned char*>(::malloc(alloc10k));

    alloc20k = sz20k * 1024 * 20 + sz20k*canary_sz + canary_sz;
    bigptr_20k = static_cast<unsigned char*>(::malloc(alloc20k));

    alloc35k = sz35k * 1024 * 35 + sz35k*canary_sz + canary_sz;
    bigptr_35k = static_cast<unsigned char*>(::malloc(alloc35k));

    alloc50k = sz50k * 1024 * 50 + sz50k*canary_sz + canary_sz;
    bigptr_50k = static_cast<unsigned char*>(::malloc(alloc50k));

    // canary is placed at the end of the data, but big chunk is prepended with its own canary.
    // over-runs can be therefore detected for all chunks, even first one from the bigptr.





    auto stockpile = [] (unsigned char* ptr, unsigned int ptr_len, unsigned chunk_len, std::vector<mem_chunk>& storage) {



        get_canary().write_canary(ptr);

        for(unsigned char* cur_ptr = ptr + get_canary().canary_sz; cur_ptr < ptr + ptr_len; cur_ptr += (chunk_len + get_canary().canary_sz)) {
            storage.emplace_back(cur_ptr, chunk_len);

            // write canary string at the end of data
            get_canary().write_canary(cur_ptr + chunk_len);
        }
    };

    available_32.reserve(sz32);
    stockpile(bigptr_32, alloc32, 32, available_32);

    available_64.reserve(sz64);
    stockpile(bigptr_64, alloc64, 64, available_64);

    available_128.reserve(sz128);
    stockpile(bigptr_128, alloc128, 128, available_128);

    available_256.reserve(sz256);
    stockpile(bigptr_256, alloc256, 256, available_256);

    available_1k.reserve(sz1k);
    stockpile(bigptr_1k, alloc1k, 1024, available_1k);

    available_5k.reserve(sz5k);
    stockpile(bigptr_5k, alloc5k, 5*1024, available_5k);

    available_10k.reserve(sz10k);
    stockpile(bigptr_10k, alloc10k, 10*1024, available_10k);

    available_20k.reserve(sz20k);
    stockpile(bigptr_20k, alloc20k, 20*1024, available_20k);

    available_35k.reserve(sz35k);
    stockpile(bigptr_35k, alloc35k, 35*1024, available_35k);

    available_50k.reserve(sz50k);
    stockpile(bigptr_50k, alloc50k, 50*1024, available_50k);

}


std::size_t memPool::find_ptr_size(void* xptr) {

    auto* ptr = static_cast<unsigned char*>(xptr);

    if      (ptr >= bigptr_32 && ptr < bigptr_32 + alloc32) { return 32; }
    else if (ptr >= bigptr_64 && ptr < bigptr_64 + alloc64) { return 64; }
    else if (ptr >= bigptr_128 && ptr < bigptr_128 + alloc128) { return 128; }
    else if (ptr >= bigptr_256 && ptr < bigptr_256 + alloc256) { return 256; }
    else if (ptr >= bigptr_1k && ptr < bigptr_1k + alloc1k) { return 1024; }
    else if (ptr >= bigptr_5k && ptr < bigptr_5k + alloc5k) { return 5*1024; }
    else if (ptr >= bigptr_10k && ptr < bigptr_10k + alloc10k) { return 10*1024; }
    else if (ptr >= bigptr_20k && ptr < bigptr_20k + alloc20k) { return 20*1024; }
    else if (ptr >= bigptr_35k && ptr < bigptr_35k + alloc35k) { return 35*1024; }
    else if (ptr >= bigptr_50k && ptr < bigptr_50k + alloc50k) { return 50*1024; }


    return 0;
}

mem_chunk_t memPool::acquire(std::size_t sz) {

    if(sz == 0) return mem_chunk_t(nullptr, 0);

    auto* mem_pool = pick_acq_set(sz);

    stat_acq++;
    stat_acq_size += sz;

    auto l_ = std::scoped_lock(lock);

    // mempool is not available, or is empty, use heap
    if(not mem_pool or mem_pool->empty()) {

        mem_chunk new_entry(sz);
        stat_alloc++;
        stat_alloc_size += sz;

        new_entry.in_pool = false;
        new_entry.pool_type = mem_chunk::type::HEAP;

        #ifdef MEMPOOL_DEBUG
        if(mem_chunk::trace_enabled) {
            new_entry.set_trace();


            // for tracking purposes only - add this chunk to map!
            {
                std::lock_guard<std::mutex> l(mpdata::trace_lock());
                mpdata::trace_map()[(unsigned long)(new_entry.ptr)] = new_entry;
            }
        }
        #endif

        return new_entry;

    } else {
        mem_chunk_t free_entry = mem_pool->back();
        mem_pool->pop_back();

        free_entry.in_pool = false;
        free_entry.pool_type = mem_chunk::type::POOL;


        #ifdef MEMPOOL_DEBUG
        if(mem_chunk::trace_enabled) {
            free_entry.set_trace();

            // std::cerr << "allocating " << reinterpret_cast<unsigned long>(free_entry.ptr) << ", size " <<  free_entry.capacity << "B" << std::endl;
            // std::cerr << free_entry.str_trace() << std::endl << std::endl;

            // for tracking purposes only - add this chunk to map!
            {
                std::lock_guard<std::mutex> l(mpdata::trace_lock());
                mpdata::trace_map()[(unsigned long)free_entry.ptr] = free_entry;
            }
        }
        #endif

        return free_entry;
    }
}


void memPool::release(mem_chunk_t xto_ret){

    // copy it
    auto to_ret = xto_ret;

    if (!to_ret.ptr) {

        #ifdef MEMPOOL_DEBUG
        //std::cerr << "attempt to release nullptr (no-op)" << std::endl;
        #endif

        return;
    }

    if(bailing) return;


    if(to_ret.pool_type == mem_chunk::type::HEAP) {
        stat_out_free++;
        stat_out_free_size += to_ret.capacity;

#ifdef MEMPOOL_ALL
        // don't recurse to itself
        ::free(to_ret.ptr);
#else
        delete[] to_ret.ptr;
#endif
        return;
    }

    auto* mem_pool = pick_ret_set(to_ret.capacity);
    if (! mem_pool) {

        auto found_size = find_ptr_size(to_ret.ptr);
        if(found_size) {
            #ifdef MEMPOOL_DEBUG
            auto msg = std::unique_ptr<const char, sx::mem::deleters::unique_ptr_deleter_free<const char>>(
                    string_format_heap("memPool::release: found unknown ptr has size %d", found_size),
                    sx::mem::deleters::unique_ptr_deleter_free<const char>());
            _cons(msg.get());
            #endif

            mem_pool = pick_ret_set(found_size);
            to_ret.capacity = found_size;
            to_ret.pool_type = mem_chunk::pool_type_t::POOL;
        } else {
            #ifdef MEMPOOL_DEBUG
            auto msg = std::unique_ptr<const char, sx::mem::deleters::unique_ptr_deleter_free<const char>>(
                    string_format_heap("memPool::release: unknown ptr not in the pool"),
                    sx::mem::deleters::unique_ptr_deleter_free<const char>());
            _cons(msg.get());
            #endif

            stat_out_pool_miss++;
            stat_out_pool_miss_size += to_ret.capacity;


#ifdef MEMPOOL_ALL
            // don't recurse to itself
            ::free(to_ret.ptr);
#else
            delete[] to_ret.ptr;
#endif
            return;
        }
    }

    // not in else block, since we can find pool based on ptr address
    if(mem_pool) {
        stat_ret++;
        stat_ret_size += to_ret.capacity;

        to_ret.in_pool = true;
        {
            std::lock_guard<std::mutex> g(lock);
            mem_pool->push_back(to_ret);
        }

        #ifdef MEMPOOL_DEBUG

        std::lock_guard<std::mutex> l(mpdata::trace_lock());
        if(mem_chunk::trace_enabled) {
            // std::cerr << "releasing " << reinterpret_cast<unsigned long>(to_ret.ptr) << ", size " <<  to_ret.capacity << "B" << std::endl;

            auto i = mpdata::trace_map().find((unsigned long)to_ret.ptr);
            if (i != mpdata::trace_map().end()) {
                mpdata::trace_map().erase(i);
            }
        }

        if(get_canary().canary_sz) {
            if (!get_canary().check_canary(to_ret.ptr - get_canary().canary_sz)) {
                // auto b = bt();
                // std::cerr << "front canary check failed\nbt:\n" << b;

                throw mempool_bad_alloc("front canary check failed");
            }

            if (!get_canary().check_canary(to_ret.ptr + to_ret.capacity)) {
                // auto b = bt();
                // std::cerr << "rear canary check failed\nbt:\n" << b;

                throw mempool_bad_alloc("rear canary check failed");
            }
        }

        #endif

    } else {
        throw mempool_bad_alloc("cannot determine pool to return pointer");
    }
}

std::vector<mem_chunk_t>* memPool::pick_acq_set(size_t s) {
    if      (s > 50 * 1024) return nullptr;
    else if (s > 35 * 1024) return &available_50k;
    else if (s > 20 * 1024) return &available_35k;
    else if (s > 10 * 1024) return &available_20k;
    else if (s >  5 * 1024) return &available_10k;
    else if (s >  1 * 1024) return &available_5k;
    else if (s >       256) return &available_1k;
    else if (s >       128) return &available_256;
    else if (s >       64) return &available_128;
    else if (s >       32) return &available_64;
    else return &available_32;
}

std::vector<mem_chunk_t>* memPool::pick_ret_set(size_t s) {

    std::lock_guard<std::mutex> g(lock);
    if      (s == 50 * 1024) return  &available_50k;
    else if (s == 35 * 1024) return  &available_35k;
    else if (s == 20 * 1024) return  &available_20k;
    else if (s == 10 * 1024) return  &available_10k;
    else if (s ==  5 * 1024) return  &available_5k;
    else if (s ==  1 * 1024) return  &available_1k;
    else if (s ==       256) return  &available_256;
    else if (s ==       128) return  &available_128;
    else if (s ==        64) return  &available_64;
    else if (s ==        32) return  &available_32;
    else {

        return nullptr;
    }
}


void* mempool_alloc(size_t s) {

#ifdef MEMPOOL_ALL
    if(not buffer::use_pool or memPool::bailing or not memPool::is_ready() )
        return ::malloc(s);
#else
    if(not buffer::use_pool or memPool::bailing)
        return malloc(s);
#endif


    mem_chunk_t mch = memPool::pool().acquire(s);

    if(mch.ptr) {
        mp_stats::get().stat_mempool_alloc++;
        mp_stats::get().stat_mempool_alloc_size += s;
    } else {
        throw mempool_bad_alloc("cannot acquire from memory pool", s);
    }

    return mch.ptr;
}

void* mempool_realloc(void* optr, size_t nsz) {

#ifdef MEMPOOL_ALL
    if(not buffer::use_pool or memPool::bailing or not memPool::is_ready())
        return ::realloc(optr,nsz);
#else
    if(not buffer::use_pool) {
        return ::realloc(optr, nsz);
    }

    // if we use pools and exiting, rather leak than crash
    if(buffer::use_pool and memPool::bailing) {
        return ::malloc(nsz);
    }
#endif
    size_t ptr_size = 0;
    if(optr) {
        ptr_size = memPool::pool().find_ptr_size(optr);
    }
    auto old_m = mem_chunk(static_cast<unsigned char*>(optr), ptr_size);

    // if realloc asks for actually already fitting size, return old one
    if(ptr_size >= nsz) {
        mp_stats::get().stat_mempool_realloc_fitting++;
        return optr;
    }

    mem_chunk_t new_m = memPool::pool().acquire(nsz);

    if(!new_m.ptr) {

        memPool::pool().release(old_m);
        if(optr && ! ptr_size) {
            mp_stats::get().stat_mempool_realloc_miss++;
        }

        if(memPool::heap_on_tension)
            return mem_chunk(nsz).ptr;

        return nullptr;

    } else {

        if(optr) {
            if (ptr_size) {
                memcpy(new_m.ptr, optr, nsz <= ptr_size ? nsz : ptr_size);
            }
            memPool::pool().release(old_m);
        }

        if(mem_chunk::trace_enabled)
            new_m.set_trace();

        if(optr && ! ptr_size) {
            mp_stats::get().stat_mempool_realloc_miss++;
        }

        mp_stats::get().stat_mempool_realloc++;
        mp_stats::get().stat_mempool_realloc += (new_m.capacity - old_m.capacity);

        return static_cast<void*>(new_m.ptr);
    }
}


void mempool_free(void* optr) {


#ifdef MEMPOOL_ALL
    if(memPool::bailing) {
        return;
    }
    if(not buffer::use_pool or not memPool::is_ready()) {
        ::free(optr);
        return;
    }
#else
    if(memPool::bailing) {
        return;
    }
    if(not buffer::use_pool) {
        ::free(optr);
        return;
    }
#endif

    auto ptr_size = memPool::pool().find_ptr_size(optr);

    // not in pools
    if(ptr_size == 0) {
        mp_stats::get().stat_mempool_free_miss++;

        auto heap_chunk = mem_chunk(static_cast<unsigned char*>(optr), ptr_size);
        heap_chunk.pool_type = mem_chunk::pool_type_t::HEAP;
        memPool::pool().release(heap_chunk);
    } else {
        memPool::pool().release(mem_chunk(static_cast<unsigned char*>(optr), ptr_size));
    }

    mp_stats::get().stat_mempool_free++;
    mp_stats::get().stat_mempool_free_size += ptr_size;
}


void* mempool_alloc(size_t s, const char* src, int line) {
    return mempool_alloc(s);
}
void* mempool_realloc(void* optr, size_t s, const char* src, int line) {
    return mempool_realloc(optr, s);
}
void mempool_free(void* optr, const char* src, int line) {
    mempool_free(optr);
}