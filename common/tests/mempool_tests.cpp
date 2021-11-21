#include <gtest/gtest.h>

#include <mempool/mempool.hpp>



struct RinseSetup {
    size_t chunk_size = 1024;
    int cycles_max = 20;
    int chunk_amount = 640;

    bool opt_fail_if_heap = false;
};


void rinse(RinseSetup setup) {

    for (int cycles = 0; cycles < setup.cycles_max; ++cycles) {

        std::vector<void *> allocated;

        for (long long i = 0; i < setup.chunk_amount; ++i) {

            auto chunk = memPool::pool().acquire(setup.chunk_size);


            if(chunk.ptr == nullptr) {
                ASSERT_FALSE(chunk.ptr == nullptr);
            }
            if(setup.opt_fail_if_heap) {
                ASSERT_FALSE(chunk.pool_type == mem_chunk_t::pool_type_t::HEAP);
            }

            std::memset(chunk.ptr, 'C', setup.chunk_size);
            chunk.ptr[0] = 'A';
            chunk.ptr[setup.chunk_size] = 'B';

            allocated.push_back(chunk.ptr);
        }

        for (auto *x: allocated) {
            mempool_free(x);
        }
    }
};


void rinse_threads(RinseSetup setup) {
    std::vector<std::thread> workers;

    for (int i = 0; i < 7; ++i) {
        workers.emplace_back([&setup] { rinse(setup); });
    }

    for(auto& w: workers) {
    if(w.joinable()) w.join();
    }
}


TEST(Mempool,PoolOnlyConcurrency) {

    RinseSetup s;
    s.chunk_size = 1024;
    s.chunk_amount = 640;
    s.cycles_max = 200;

    memPool::pool();
    ASSERT_TRUE(memPool::pool().is_ready());

    rinse_threads(s);
}


TEST(Mempool,MixedConcurrency) {

    RinseSetup s;
    s.chunk_size = 1024;
    s.chunk_amount = 6400;
    s.cycles_max = 200;

    memPool::pool();
    ASSERT_TRUE(memPool::pool().is_ready());

    rinse_threads(s);
}
