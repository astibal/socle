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

unsigned long long memPool::stat_acq = 0;
unsigned long long memPool::stat_acq_size = 0;

unsigned long long memPool::stat_ret = 0;
unsigned long long memPool::stat_ret_size = 0;

unsigned long long memPool::stat_alloc = 0;
unsigned long long memPool::stat_alloc_size = 0;

unsigned long long memPool::stat_free = 0;
unsigned long long memPool::stat_free_size = 0;


memPool::memPool(std::size_t sz256, std::size_t sz1k, std::size_t sz5k, std::size_t sz10k, std::size_t sz20k):
sz256(sz256), sz1k(sz1k), sz5k(sz5k), sz10k(sz10k), sz20k(sz20k) {

    for(unsigned int i = 0; i < sz256 ; i++) {
        available_256.push_back( { new unsigned char [256], 256 } );
    }
    for(unsigned int i = 0; i < sz1k ; i++) {
        available_1k.push_back( { new unsigned char [1 * 1024], 1 * 1024 } );
    }
    for(unsigned int i = 0; i < sz5k ; i++) {
        available_5k.push_back( { new unsigned char [5 * 1024], 5 * 1024 } );
    }
    for(unsigned int i = 0; i < sz10k ; i++) {
        available_10k.push_back( { new unsigned char [10 * 1024], 10 * 1024 } );
    }
    for(unsigned int i = 0; i < sz20k ; i++) {
        available_20k.push_back( { new unsigned char [20 * 1024], 20 * 1024 } );
    }
}

mem_chunk_t memPool::acquire(std::size_t sz) {

    if(MEMPOOL_DEBUG) {
        ERR_("mempool::acquire(%d)", sz);
    }

    if(sz == 0) return { nullptr, 0 };

    std::vector<mem_chunk_t>* mem_pool = pick_acq_set(sz);

    std::lock_guard<std::mutex> g(lock);
    stat_acq++;
    stat_acq_size += sz;

    if (mem_pool->empty()) {
        mem_chunk_t new_entry = { new unsigned char [sz], sz };
        stat_alloc++;
        stat_alloc_size += sz;

        return new_entry;
    } else {
        mem_chunk_t free_entry = mem_pool->back();
        mem_pool->pop_back();

        return free_entry;
    }
}


void memPool::release(mem_chunk_t to_ret){

    if(MEMPOOL_DEBUG) {
        ERR_("mempool::release(0x%x,%d)", to_ret.ptr, to_ret.capacity);
    }

    if (!to_ret.ptr) {
        return;
    }

    std::vector<mem_chunk_t>* mem_pool = pick_ret_set(to_ret.capacity);

    if(!mem_pool) {
        stat_free++;
        stat_free_size += to_ret.capacity;

        delete[] to_ret.ptr;
    } else {

        std::lock_guard<std::mutex> g(lock);
        mem_pool->push_back(to_ret);

        stat_ret++;
        stat_ret_size += to_ret.capacity;
    }
}

std::vector<mem_chunk_t>* memPool::pick_acq_set(ssize_t s) {
    if      (s > 20 * 1024) return &available_big;
    else if (s > 10 * 1024) return &available_20k;
    else if (s >  5 * 1024) return &available_10k;
    else if (s >  1 * 1024) return &available_5k;
    else if (s >       256) return &available_1k;
    else return &available_256;
}

std::vector<mem_chunk_t>* memPool::pick_ret_set(ssize_t s) {
    if      (s == 20 * 1024) return  available_20k.size() < sz20k ? &available_20k : nullptr;
    else if (s == 10 * 1024) return  available_10k.size() < sz10k ? &available_10k : nullptr;
    else if (s ==  5 * 1024) return  available_5k.size() < sz5k ? &available_5k : nullptr;
    else if (s ==  1 * 1024) return  available_1k.size() < sz1k ? &available_1k : nullptr;
    else if (s ==       256) return  available_256.size() < sz256? &available_256 : nullptr;
    else return nullptr;
}