#include <common/meter.hpp>
#include <gtest/gtest.h>
#include <atomic>
#include <thread>
#include <vector>

using socle::meter;
using namespace std::chrono_literals;
namespace { const auto start = meter::clock::time_point{} + 100s; }

TEST(Meter, ShortBurstIsVisibleAndExpiresWithoutMoreWrites) {
    meter m(1, start);
    EXPECT_EQ(m.get(start), 0U);
    EXPECT_EQ(m.update(65536, start + 100ms), 0U);
    EXPECT_EQ(m.get(start + 100ms), 65536U);
    EXPECT_EQ(m.get(start + 1100ms), 32768U);
    EXPECT_EQ(m.get(start + 3999ms), 16384U);
    EXPECT_EQ(m.get(start + 4s), 0U);
    EXPECT_EQ(m.total(), 65536U);
}

TEST(Meter, PacketizationDoesNotChangeRate) {
    meter one(1, start), many(1, start);
    one.update(1000, start);
    for (int i = 0; i < 1000; ++i) many.update(1, start);
    for (int i = 0; i <= 4; ++i) {
        EXPECT_EQ(one.get(start + std::chrono::seconds(i)), many.get(start + std::chrono::seconds(i)));
    }
    EXPECT_EQ(one.total(), many.total());
}

TEST(Meter, SteadyTrafficKeepsRateAcrossRingWraps) {
    meter m(1, start);
    for (int i = 0; i < 20; ++i) {
        auto now = start + std::chrono::seconds(i);
        EXPECT_EQ(m.update(1000, now), i == 0 ? 0U : 1000U);
        EXPECT_EQ(m.get(now), 1000U);
    }
    EXPECT_EQ(m.get(start + 20s), 750U);
    EXPECT_EQ(m.get(start + 21s), 500U);
    EXPECT_EQ(m.get(start + 22s), 250U);
    EXPECT_EQ(m.get(start + 23s), 0U);
    EXPECT_EQ(m.total(), 20000U);
}

TEST(Meter, IdleGapDoesNotReviveExpiredSamples) {
    meter m(1, start);
    m.update(1000, start);
    m.update(2000, start + 1s);
    EXPECT_EQ(m.update(400, start + 100s), 0U);
    EXPECT_EQ(m.get(start + 100s), 100U);
    EXPECT_EQ(m.get(start + 104s), 0U);
    EXPECT_EQ(m.total(), 3400U);
}

TEST(Meter, MissingIntervalsRemainEmpty) {
    meter m(1, start);
    m.update(400, start);
    EXPECT_EQ(m.update(800, start + 2s), 0U);
    EXPECT_EQ(m.get(start + 3s), 300U);
    EXPECT_EQ(m.get(start + 4s), 200U);
    EXPECT_EQ(m.get(start + 6s), 0U);
}

TEST(Meter, CustomIntervalUsesBytesPerSecond) {
    meter m(2, start);
    m.update(2000, start);
    EXPECT_EQ(m.get(start + 1999ms), 1000U);
    EXPECT_EQ(m.update(2000, start + 2s), 2000U);
    EXPECT_EQ(m.get(start + 2s), 1000U);
    EXPECT_EQ(m.get(start + 8s), 250U);
    EXPECT_EQ(m.get(start + 10s), 0U);
}

TEST(Meter, ZeroIntervalIsNormalizedToOneSecond) {
    meter m(0, start);
    m.update(100, start);
    EXPECT_EQ(m.get(start), 100U);
    EXPECT_EQ(m.get(start + 4s), 0U);
}

TEST(Meter, ZeroUpdatesDoNotChangeTrafficOrDenominator) {
    meter m(1, start);
    m.update(100, start);
    for (int i = 0; i < 100; ++i) m.update(0, start);
    EXPECT_EQ(m.get(start), 100U);
    m.update(0, start + 5s);
    EXPECT_EQ(m.get(start + 5s), 0U);
    EXPECT_EQ(m.total(), 100U);
}

TEST(Meter, StaleExplicitTimestampCannotRewindWriteWindow) {
    meter m(1, start);
    m.update(400, start + 10s);
    m.update(400, start + 1s);
    EXPECT_EQ(m.get(start + 10s), 200U);
    EXPECT_EQ(m.get(start + 1s), 200U);
    EXPECT_EQ(m.get(start + 14s), 0U);
}

TEST(Meter, ConcurrentReadersAndWritersDoNotLoseUpdates) {
    meter m(1, start);
    constexpr unsigned long writers = 8, updates = 10000;
    std::atomic_bool finished {false};
    std::thread reader([&] {
        while (!finished.load()) {
            EXPECT_LE(m.get(start), writers * updates);
            EXPECT_LE(m.total(), writers * updates);
        }
    });
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < writers; ++i) {
        threads.emplace_back([&] {
            for (unsigned j = 0; j < updates; ++j) m.update(1, start);
        });
    }
    for (auto& thread : threads) thread.join();
    finished = true;
    reader.join();
    EXPECT_EQ(m.get(start), writers * updates);
    EXPECT_EQ(m.total(), writers * updates);
}

TEST(Meter, DefaultClockIncludesTheCurrentInterval) {
    meter m;
    m.update(65536);
    EXPECT_EQ(m.total(), 65536U);
    EXPECT_GT(m.get(), 0U);
}
