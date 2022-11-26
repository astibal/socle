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


void memPool::Bucket::init_memory(std::size_t cnt) {
    auto lc_ = locked_(this);

    count = cnt;
    canary_sz = get_canary().canary_sz;

    allocated = count * sz + count * canary_sz + canary_sz;
    bigptr = static_cast<uint8_t*>(::malloc(allocated));
    _endptr = bigptr + allocated;

    // now, stockpile

    auto ptr = bigptr;
    get_canary().write_canary(ptr);
    for(unsigned char* cur_ptr = ptr + canary_sz; cur_ptr < ptr + allocated; cur_ptr += (sz + canary_sz)) {
        bucket.template emplace(cur_ptr, sz);

        // write canary string at the end of data
        get_canary().write_canary(cur_ptr + sz);
    }
}

std::size_t memPool::Bucket::size() const {
    auto lc_ = share_locked_(this);
    return bucket.size();
}

void memPool::Bucket::release(mem_chunk mch) {
    if(is_mine(mch.ptr)) {
        mch.in_pool = true;

        auto lc_ = locked_(this);
        bucket.push(mch);
    }
}

std::optional<mem_chunk> memPool::Bucket::acquire() {
    auto lc_ = locked_(this);

    if(not bucket.empty()) {
        auto mem = bucket.top();
        bucket.pop();
        return mem;
    }
    return std::nullopt;
}

bool memPool::Bucket::is_mine(uint8_t const* ptr) const noexcept {
    bool ret = (ptr >= bigptr and ptr < _endptr);
    return ret;
}

bool memPool::Bucket::is_aligned(uint8_t const* ptr) const noexcept {
    const auto align_start = reinterpret_cast<uint64_t>(bigptr + canary_sz);
    return ( (uint64_t)ptr % align_start == 0);
}



memPool::memPool(std::size_t sz256, std::size_t sz1k, std::size_t sz5k, std::size_t sz10k, std::size_t sz20k) {

#ifndef MEMPOOL_DISABLE

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
#endif

    is_ready() = true; // mark memPool ready for use
}


void memPool::allocate(std::size_t n_sz256, std::size_t n_sz1k, std::size_t n_sz5k,
                     std::size_t n_sz10k, std::size_t n_sz20k) {

#ifdef MEMPOOL_DISABLE
    return;
#endif

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

    bucket_32.init_memory(sz32);
    bucket_64.init_memory(sz64);
    bucket_128.init_memory(sz128);
    bucket_256.init_memory(sz256);
    bucket_1k.init_memory(sz1k);
    bucket_5k.init_memory(sz5k);
    bucket_10k.init_memory(sz10k);
    bucket_20k.init_memory(sz20k);
    bucket_35k.init_memory(sz35k);
    bucket_50k.init_memory(sz50k);

    buckets.emplace(&bucket_32);
    buckets.emplace(&bucket_64);
    buckets.emplace(&bucket_128);
    buckets.emplace(&bucket_256);
    buckets.emplace(&bucket_1k);
    buckets.emplace(&bucket_5k);
    buckets.emplace(&bucket_10k);
    buckets.emplace(&bucket_20k);
    buckets.emplace(&bucket_35k);
    buckets.emplace(&bucket_50k);

}

auto memPool::find_by_address(void* ptr) -> Bucket* {

    auto it = std::find_if(buckets.begin(), buckets.end(), [&ptr](auto const* x) { return x->is_mine((uint8_t*) ptr); });
    if(it != buckets.end()) return *it;

    return nullptr;
}


std::size_t memPool::find_ptr_size(void* ptr) {

    auto it = std::find_if(buckets.begin(), buckets.end(), [&ptr](auto const* x) { return x->is_mine((uint8_t*) ptr); });
    if(it != buckets.end()) return (*it)->sz;

    return 0;
}

mem_chunk_t memPool::acquire(std::size_t sz) {

    if(sz == 0) return mem_chunk_t(nullptr, 0);

    auto* mem_bucket = pick_bucket(sz);

    // mempool is not available, or is empty, use heap
    if(not mem_bucket) {

#ifndef MEMPOOL_DISABLE
        auto try_hard_effort_pays_of = tryhard_available(sz);
        if(try_hard_effort_pays_of) {
            stats.acq++;
            stats.acq_size += try_hard_effort_pays_of.value().capacity;

            return try_hard_effort_pays_of.value();
        }
#endif
       return from_heap(sz);

    } else {

        auto free_entry = mem_bucket->acquire();
        if(free_entry) {

            free_entry->in_pool = false;
            free_entry->pool_type = mem_chunk::type::POOL;

            stats.acq++;
            stats.acq_size += free_entry->capacity;

#ifdef MEMPOOL_DEBUG
            if(mem_chunk::trace_enabled) {
                free_entry->set_trace();

                // for tracking purposes only - add this chunk to map!
                {
                    std::lock_guard<std::mutex> l(mpdata::trace_lock());
                    mpdata::trace_map()[(unsigned long)free_entry->ptr] = free_entry.value();
                }
            }
#endif

            return free_entry.value();
        }
        else {
            return from_heap(sz);
        }
    }
}


void memPool::release(mem_chunk_t to_ret){

    if (not to_ret.ptr) {

        #ifdef MEMPOOL_DEBUG
        //std::cerr << "attempt to release nullptr (no-op)" << std::endl;
        #endif

        return;
    }

    if(bailing) return;

    if(to_ret.pool_type == mem_chunk::type::HEAP) {
        free_heap(to_ret);
        return;
    }

    auto* mem_pool = find_by_address(to_ret.ptr);
    if (not mem_pool) {
        #ifdef MEMPOOL_DEBUG
        auto msg = std::unique_ptr<const char, sx::mem::deleters::unique_ptr_deleter_free<const char>>(
                string_format_heap("memPool::release: unknown ptr not in the pool"),
                sx::mem::deleters::unique_ptr_deleter_free<const char>());
        _cons(msg.get());
        #endif

        stats.out_pool_miss++;
        stats.out_pool_miss_size += to_ret.capacity;

        free_heap(to_ret);
        return;
    }
    else {
        stats.ret++;
        stats.ret_size += mem_pool->chunk_size();

        mem_pool->release(to_ret);

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

                throw mempool_error("front canary check failed");
            }

            if (!get_canary().check_canary(to_ret.ptr + to_ret.capacity)) {
                // auto b = bt();
                // std::cerr << "rear canary check failed\nbt:\n" << b;

                throw mempool_error("rear canary check failed");
            }
        }
        #endif

    }
}

std::optional<mem_chunk> memPool::tryhard_available(size_t s) {

    unsigned short overkill_level = 1;

    for(auto& buck: buckets) {

        // don't allow ridiculously large over-allocations
        if(overkill_level > 3) { break; }

        if(buck->chunk_size() >= s) {

            auto lc_ = locked_(buck);

            if(not buck->bucket.empty()) {
                auto mem = buck->bucket.top();
                buck->bucket.pop();
                return mem;
            }
        }
        ++overkill_level;
    }
    return std::nullopt;
}

mem_chunk memPool::from_heap(std::size_t s) {
    mem_chunk new_entry(s);

    stats.heap_alloc++;
    stats.heap_alloc_size += s;

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
}

void memPool::free_heap(mem_chunk const& mch) {
    stats.out_free++;
    stats.out_free_size += mch.capacity;

#ifdef MEMPOOL_ALL
    // don't recurse to itself
        ::free(to_ret.ptr);
#else
    delete[] mch.ptr;
#endif
}


auto memPool::pick_bucket(size_t s) -> Bucket* {

#ifdef MEMPOOL_DISABLE
    return nullptr;
#endif

    if      (s > 50L * 1024) return nullptr;
    else if (s <= 32L) return &bucket_32;
    else {
        if (s <= 1024) {
            if (s >       256) return &bucket_1k;
            else if (s >       128) return &bucket_256;
            else if (s >       64) return &bucket_128;
            else if (s >       32) return &bucket_64;
        }
        else {
            if (s > 35L * 1024) return &bucket_50k;
            else if (s > 20L * 1024) return &bucket_35k;
            else if (s > 10L * 1024) return &bucket_20k;
            else if (s >  5L * 1024) return &bucket_10k;
            else if (s >  1L * 1024) return &bucket_5k;
        }
    }

    return nullptr;
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

        #ifndef MEMPOOL_NOEXCEPT
        throw mempool_error("cannot acquire from memory pool", s);
        #endif
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