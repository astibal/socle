#include <gtest/gtest.h>
#include <mempool/mempool.hpp>
#include <stringformat.hpp>

#include <thread>
#include <array>

TEST(MemPool, TooBig) {


    auto runit = []() {
        constexpr size_t count = 10000;
        std::vector<void*> mems;

        for (size_t i = 0; i < count; ++i)
            mems.emplace_back(mempool_alloc(124800));

        ::usleep(1000);

        std::for_each(mems.begin(), mems.end(), [] (auto &r) { mempool_free(r); });
    };

    auto a = std::thread([&runit]() { runit(); });
    auto b = std::thread([&runit]() { runit(); });
    auto c = std::thread([&runit]() { runit(); });

    a.join();
    b.join();
    c.join();
}

TEST(StringFormat, TooLong) {
    std::array<char, 32000> buf {};
    memset(buf.data(), 'A', buf.size());

    auto s = string_format(">>%s<<", (const char*)buf.data());
}