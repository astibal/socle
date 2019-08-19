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

#include <mempool.hpp>

#include <unordered_map>
#include "buffer.hpp"


unsigned long long stat_mempool_alloc = 0;
unsigned long long stat_mempool_realloc = 0;
unsigned long long stat_mempool_realloc_miss = 0;
unsigned long long stat_mempool_realloc_fitting = 0;
unsigned long long stat_mempool_free = 0;
unsigned long long stat_mempool_free_miss = 0;

unsigned long long stat_mempool_alloc_size = 0;
unsigned long long stat_mempool_realloc_size = 0;
unsigned long long stat_mempool_free_size = 0;

std::unordered_map<void*, mem_chunk> mempool_ptr_map;
std::mutex mempool_ptr_map_lock;

#ifdef MEMPOOL_DEBUG
const bool mem_chunk_t::trace_enabled = true;
#else
const bool mem_chunk_t::trace_enabled = false;
#endif



memPool::memPool(std::size_t sz256, std::size_t sz1k, std::size_t sz5k, std::size_t sz10k, std::size_t sz20k):
        sz256(0), sz1k(0), sz5k(0), sz10k(0), sz20k(0)
{
    stat_acq = 0;
    stat_acq_size = 0;

    stat_ret = 0;
    stat_ret_size = 0;

    stat_alloc = 0;
    stat_alloc_size = 0;

    stat_out_free = 0;
    stat_out_free_size = 0;

    extend(sz256, sz1k, sz5k, sz10k, sz20k);
}

void memPool::extend(std::size_t n_sz256, std::size_t n_sz1k, std::size_t n_sz5k,
                     std::size_t n_sz10k, std::size_t n_sz20k) {

    std::lock_guard<std::mutex> l_(lock);

    sz256 += n_sz256;
    sz1k  += n_sz1k;
    sz5k  += n_sz5k;
    sz10k += n_sz10k;
    sz20k += n_sz20k;

    for(unsigned int i = 0; i < sz256 ; i++) {
        for (int j = 0; j < 10 ; j++) available_32.emplace_back( mem_chunk(32) );
        available_64.emplace_back( mem_chunk(64) );
        available_128.emplace_back( mem_chunk(128) );
        available_256.emplace_back( mem_chunk(256) );
    }
    for(unsigned int i = 0; i < sz1k ; i++) {
        available_1k.emplace_back( mem_chunk(1*1024) );
    }
    for(unsigned int i = 0; i < sz5k ; i++) {
        available_5k.emplace_back( mem_chunk(5*1024) );
    }
    for(unsigned int i = 0; i < sz10k ; i++) {
        available_10k.emplace_back( mem_chunk(10*1024) );
    }
    for(unsigned int i = 0; i < sz20k ; i++) {
        available_20k.emplace_back( mem_chunk(20*1024) );
    }
}

mem_chunk_t memPool::acquire(std::size_t sz) {

    if(sz == 0) return mem_chunk_t(nullptr, 0);

    std::vector<mem_chunk_t>* mem_pool = pick_acq_set(sz);

    std::lock_guard<std::mutex> g(lock);
    stat_acq++;
    stat_acq_size += sz;

    if (mem_pool->empty()) {
        mem_chunk_t new_entry = mem_chunk(sz);
        stat_alloc++;
        stat_alloc_size += sz;

        new_entry.in_pool = false;
        return new_entry;
    } else {
        mem_chunk_t free_entry = mem_pool->back();
        mem_pool->pop_back();

        free_entry.in_pool = false;

        return free_entry;
    }
}


void memPool::release(mem_chunk_t to_ret){

    if (!to_ret.ptr) {
        return;
    }

    std::vector<mem_chunk_t>* mem_pool = pick_ret_set(to_ret.capacity);


    if(!mem_pool) {
        stat_out_free++;
        stat_out_free_size += to_ret.capacity;

        delete[] to_ret.ptr;
    } else {
        stat_ret++;
        stat_ret_size += to_ret.capacity;

        to_ret.in_pool = true;
        std::lock_guard<std::mutex> g(lock);
        mem_pool->push_back(to_ret);
    }
}

std::vector<mem_chunk_t>* memPool::pick_acq_set(ssize_t s) {
    if      (s > 20 * 1024) return &available_big;
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
    if      (s == 20 * 1024) return  available_20k.size() < sz20k ? &available_20k : nullptr;
    else if (s == 10 * 1024) return  available_10k.size() < sz10k ? &available_10k : nullptr;
    else if (s ==  5 * 1024) return  available_5k.size() < sz5k ? &available_5k : nullptr;
    else if (s ==  1 * 1024) return  available_1k.size() < sz1k ? &available_1k : nullptr;
    else if (s ==       256) return  available_256.size() < sz256 ? &available_256 : nullptr;
    else if (s ==       128) return  available_128.size() < sz256 ? &available_128 : nullptr;
    else if (s ==        64) return  available_64.size() < sz256 ? &available_64 : nullptr;
    else if (s ==        32) return  available_32.size() < 10 * sz256 ? &available_32 : nullptr;
    else return nullptr;
}


void* mempool_alloc(size_t s) {

    if(!buffer::use_pool)
        return malloc(s);

    mem_chunk_t mch = memPool::pool().acquire(s);

    if(mem_chunk::trace_enabled)
            mch.set_trace();

    std::lock_guard<std::mutex> l(mempool_ptr_map_lock);

    mempool_ptr_map[mch.ptr] = mch;

    stat_mempool_alloc++;
    stat_mempool_alloc_size += s;

    return mch.ptr;
}

void* mempool_realloc(void* optr, size_t nsz) {

    if(!buffer::use_pool)
        return realloc(optr,nsz);

    size_t ptr_size = 0;
    if(optr) {

        std::lock_guard<std::mutex> l(mempool_ptr_map_lock);

        auto i = mempool_ptr_map.find(optr);
        if (i != mempool_ptr_map.end()) {
            ptr_size = (*i).second.capacity;
        } else {
            stat_mempool_realloc_miss++;
        }

    }
    mem_chunk_t old_m = mem_chunk(static_cast<unsigned char*>(optr), ptr_size);

    // if realloc asks for actually already fitting size, return old one
    if(ptr_size >= nsz) {
        stat_mempool_realloc_fitting++;
        return optr;
    }

    mem_chunk_t new_m = memPool::pool().acquire(nsz);

    if(!new_m.ptr) {

        memPool::pool().release(old_m);
        std::lock_guard<std::mutex> l(mempool_ptr_map_lock);

        auto i = mempool_ptr_map.find(optr);
        if (i != mempool_ptr_map.end()) {
            mempool_ptr_map.erase(i);
        } else {
            stat_mempool_realloc_miss++;
        }

        return nullptr;
    } else {

        if(ptr_size)
            memcpy(new_m.ptr,optr, nsz <= ptr_size ? nsz : ptr_size);

        memPool::pool().release(old_m);

        {
            std::lock_guard<std::mutex> l(mempool_ptr_map_lock);

            if(mem_chunk::trace_enabled)
                new_m.set_trace();

            mempool_ptr_map[new_m.ptr] = new_m;
        }

        stat_mempool_realloc++;
        stat_mempool_realloc += (new_m.capacity - old_m.capacity);

        return static_cast<void*>(new_m.ptr);
    }
}


void mempool_free(void* optr) {

    std::lock_guard<std::mutex> l(mempool_ptr_map_lock);

    size_t ptr_size = 0;
    auto i = mempool_ptr_map.find(optr);
    if (i != mempool_ptr_map.end()) {

        ptr_size = (*i).second.capacity;
        mempool_ptr_map.erase(i);
    } else {
        stat_mempool_free_miss++;
    }

    stat_mempool_free++;
    stat_mempool_free_size += ptr_size;

    memPool::pool().release( mem_chunk(static_cast<unsigned char*>(optr), ptr_size) );
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