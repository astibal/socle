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
        sz32(0), sz64(0), sz128(0), sz256(0), sz1k(0), sz5k(0), sz10k(0), sz20k(0)
{
    stat_acq = 0;
    stat_acq_size = 0;

    stat_ret = 0;
    stat_ret_size = 0;

    stat_alloc = 0;
    stat_alloc_size = 0;

    stat_free = 0;
    stat_free_size = 0;

    stat_out_free = 0;
    stat_out_free_size = 0;

    extend(sz256, sz1k, sz5k, sz10k, sz20k);
}

void memPool::extend(std::size_t n_sz256, std::size_t n_sz1k, std::size_t n_sz5k,
                     std::size_t n_sz10k, std::size_t n_sz20k) {

    std::lock_guard<std::mutex> l_(lock);

    sz32  += n_sz256*20;
    sz64  += n_sz256*10;
    sz128 += n_sz256*5;
    sz256 += n_sz256;
    sz1k  += n_sz1k;
    sz5k  += n_sz5k;
    sz10k += n_sz10k;
    sz20k += n_sz20k;
    sz35k += n_sz20k;
    sz50k += n_sz20k;

    for(unsigned int i = 0; i < sz32 ; i++) {
        available_32.emplace_back(32);
    }
    for(unsigned int i = 0; i < sz64 ; i++) {
        available_64.emplace_back( 64);
    }
    for(unsigned int i = 0; i < sz128 ; i++) {
        available_128.emplace_back( 128);
    }
    for(unsigned int i = 0; i < sz256 ; i++) {
        available_256.emplace_back(256);
    }
    for(unsigned int i = 0; i < sz1k ; i++) {
        available_1k.emplace_back(1*1024);
    }
    for(unsigned int i = 0; i < sz5k ; i++) {
        available_5k.emplace_back(5*1024);
    }
    for(unsigned int i = 0; i < sz10k ; i++) {
        available_10k.emplace_back(10*1024);
    }
    for(unsigned int i = 0; i < sz20k ; i++) {
        available_20k.emplace_back(20*1024);
    }
    for(unsigned int i = 0; i < sz35k ; i++) {
        available_35k.emplace_back(35 * 1024);
    }
    for(unsigned int i = 0; i < sz50k ; i++) {
        available_50k.emplace_back(50 * 1024);
    }

}

mem_chunk_t memPool::acquire(std::size_t sz) {

    if(sz == 0) return mem_chunk_t(nullptr, 0);

    std::vector<mem_chunk_t>* mem_pool = pick_acq_set(sz);

    stat_acq++;
    stat_acq_size += sz;

    // shall we use standard heap for some reason?
    bool fallback_to_heap = false;

    if(!mem_pool) {

        // no mempool available  - fallback
        fallback_to_heap = true;
    } else {

        std::lock_guard<std::mutex> g(lock);

        // mempool is available, but empty!
        if(mem_pool->empty()) {
            fallback_to_heap = true;
        }
    }

    if (fallback_to_heap) {
        auto new_entry = mem_chunk(sz);
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
                mpdata::trace_map()[new_entry.ptr] = new_entry;
            }
        }
        #endif

        return new_entry;
    } else {
        std::lock_guard<std::mutex> g(lock);

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
                mpdata::trace_map()[free_entry.ptr] = free_entry;
            }
        }
        #endif

        return free_entry;
    }
}


void memPool::release(mem_chunk_t to_ret){

    if (!to_ret.ptr) {

        #ifdef MEMPOOL_DEBUG
        //std::cerr << "attempt to release nullptr (no-op)" << std::endl;
        #endif

        return;
    }

    if(bailing.load()) return;

    std::vector<mem_chunk_t>* mem_pool = pick_ret_set(to_ret.capacity);


    if(to_ret.pool_type == mem_chunk::type::HEAP) {
        stat_out_free++;
        stat_out_free_size += to_ret.capacity;

        delete[] to_ret.ptr;
    }
    else if (! mem_pool) {

        stat_out_pool_miss++;
        stat_out_pool_miss_size+=to_ret.capacity;

        #ifdef MEMPOOL_DEBUG

        std::stringstream ss;
        ss << "cannot pick a mempool for " << reinterpret_cast<unsigned long>(to_ret.ptr) << ", size " <<  to_ret.capacity << "B" << std::endl;
        // std::cerr << ss.str();
        throw std::runtime_error(ss.str());

        #endif

    }
    else {
        stat_ret++;
        stat_ret_size += to_ret.capacity;

        to_ret.in_pool = true;
        std::lock_guard<std::mutex> g(lock);
        mem_pool->push_back(to_ret);


        #ifdef MEMPOOL_DEBUG

        std::lock_guard<std::mutex> l(mpdata::trace_lock());
        if(mem_chunk::trace_enabled) {
            // std::cerr << "releasing " << reinterpret_cast<unsigned long>(to_ret.ptr) << ", size " <<  to_ret.capacity << "B" << std::endl;

            auto i = mpdata::trace_map().find(to_ret.ptr);
            if (i != mpdata::trace_map().end()) {
                mpdata::trace_map().erase(i);
            }
        }

        #endif
    }
}

std::vector<mem_chunk_t>* memPool::pick_acq_set(ssize_t s) {
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

std::vector<mem_chunk_t>* memPool::pick_ret_set(ssize_t s) {

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

        #ifdef MEMPOOL_DEBUG

        throw std::runtime_error("incorrect release chunk size");

        #endif

        return nullptr;
    }
}


void* mempool_alloc(size_t s) {

    if(!buffer::use_pool)
        return malloc(s);

    mem_chunk_t mch = memPool::pool().acquire(s);

    if(mch.ptr) {
        {
            std::lock_guard<std::mutex> l(mpdata::lock());
            mpdata::map()[mch.ptr] = mch;
        }

        mp_stats::get().stat_mempool_alloc++;
        mp_stats::get().stat_mempool_alloc_size += s;
    } else {
        throw mempool_bad_alloc("cannot acquire from memory pool", s);
    }

    return mch.ptr;
}

void* mempool_realloc(void* optr, size_t nsz) {

    auto erase_map_ptr = [](auto ptr) {
        auto i = mpdata::map().find(ptr);
        if (i != mpdata::map().end()) {
            mpdata::map().erase(i);

            return true;
        }
        return false;
    };


    if(!buffer::use_pool)
        return realloc(optr,nsz);

    size_t ptr_size = 0;
    if(optr) {

        std::lock_guard<std::mutex> l(mpdata::lock());

        auto i = mpdata::map().find(optr);
        if (i != mpdata::map().end()) {
            ptr_size = (*i).second.capacity;
        }

    }
    mem_chunk_t old_m = mem_chunk(static_cast<unsigned char*>(optr), ptr_size);

    // if realloc asks for actually already fitting size, return old one
    if(ptr_size >= nsz) {
        mp_stats::get().stat_mempool_realloc_fitting++;
        return optr;
    }

    mem_chunk_t new_m = memPool::pool().acquire(nsz);

    if(!new_m.ptr) {

        memPool::pool().release(old_m);
        std::lock_guard<std::mutex> l(mpdata::lock());

        if(optr && !erase_map_ptr(optr)) {
            mp_stats::get().stat_mempool_realloc_miss++;
        }
        return nullptr;
    } else {

        if(optr) {
            if (ptr_size) {
                memcpy(new_m.ptr, optr, nsz <= ptr_size ? nsz : ptr_size);
            }
            memPool::pool().release(old_m);
        }

        {
            std::lock_guard<std::mutex> l(mpdata::lock());

            if(mem_chunk::trace_enabled)
                new_m.set_trace();

            if(optr && ! erase_map_ptr(optr)) {
                mp_stats::get().stat_mempool_realloc_miss++;
            }
            mpdata::map()[new_m.ptr] = new_m;
        }

        mp_stats::get().stat_mempool_realloc++;
        mp_stats::get().stat_mempool_realloc += (new_m.capacity - old_m.capacity);

        return static_cast<void*>(new_m.ptr);
    }
}


void mempool_free(void* optr) {

    size_t ptr_size = 0;
    {
        std::lock_guard<std::mutex> l(mpdata::lock());

        auto i = mpdata::map().find(optr);
        if (i != mpdata::map().end()) {

            ptr_size = (*i).second.capacity;
            mpdata::map().erase(i);
        } else {
            mp_stats::get().stat_mempool_free_miss++;
        }
    }

    memPool::pool().release(mem_chunk(static_cast<unsigned char *>(optr), ptr_size));

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