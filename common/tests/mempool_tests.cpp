#include <gtest/gtest.h>

#include <mempool/mempool.hpp>



struct RinseSetup {
    size_t thread_count = 10;

    size_t chunk_size = 1024;
    int cycles_max = 200;
    int chunk_amount = 640;

    bool opt_fail_if_heap = false;
    bool opt_reallocate = false;
    bool opt_check_markers = true;

    size_t chunk_realloc_size = 2048;
};


void rinse(RinseSetup const& setup) {

    for (int cycles = 0; cycles < setup.cycles_max; ++cycles) {

        std::vector<void *> allocated;

        for (long long i = 0; i < setup.chunk_amount; ++i) {

            auto chunk = memPool::pool().acquire(setup.chunk_size);


            if(chunk.ptr == nullptr) {
                ASSERT_FALSE(chunk.ptr == nullptr);
                throw std::bad_alloc();
            }
            if(setup.opt_fail_if_heap) {
                ASSERT_FALSE(chunk.pool_type == mem_chunk_t::pool_type_t::HEAP);
                throw std::invalid_argument("this test should not allocate from heap");
            }

            std::memset(chunk.ptr, 'C', setup.chunk_size);
            chunk.ptr[0] = 'A';
            chunk.ptr[setup.chunk_size-1] = 'B';


            unsigned char* to_save = chunk.ptr;

            if(setup.opt_reallocate) {
                to_save = (unsigned char*)mempool_realloc(to_save, setup.chunk_realloc_size);
                std::memset( &to_save[setup.chunk_size], 'C', setup.chunk_realloc_size - setup.chunk_size);

                // mark start of added bytes
                to_save[setup.chunk_size] = 'X';
                to_save[setup.chunk_realloc_size-1] = 'Z';
            }

            allocated.push_back(to_save);
        }

        for (auto* x: allocated) {
            auto ptr = static_cast<unsigned char*>(x);

            if(setup.opt_check_markers) {
                ASSERT_TRUE(ptr[0] == 'A');
                ASSERT_TRUE(ptr[setup.chunk_size-1] == 'B');

                if(setup.opt_reallocate) {
                    ASSERT_TRUE(ptr[setup.chunk_size] == 'X');
                    ASSERT_TRUE(ptr[setup.chunk_realloc_size-1] == 'Z');
                }
            }

            mempool_free(x);
        }
    }
};


void rinse_threads(RinseSetup const& setup) {
    std::vector<std::thread> workers;

    for (size_t i = 0; i < setup.thread_count; ++i) {
        workers.emplace_back([&setup] { rinse(setup); });
    }

    for(auto& w: workers) {
    if(w.joinable()) w.join();
    }
}


TEST(Mempool,PoolOnlyConcurrency) {

    RinseSetup s;

    memPool::pool();
    ASSERT_TRUE(memPool::pool().is_ready());

    rinse_threads(s);
}


TEST(Mempool,MixedConcurrency) {

    RinseSetup s;
    s.chunk_amount = 6400;

    memPool::pool();
    ASSERT_TRUE(memPool::pool().is_ready());

    rinse_threads(s);
}


TEST(Mempool,MixedConcurrencyRealloc) {

    RinseSetup s;
    s.chunk_amount = 6400;
    s.cycles_max = 200;
    s.opt_reallocate = true;

    memPool::pool();
    ASSERT_TRUE(memPool::pool().is_ready());

    rinse_threads(s);
}
