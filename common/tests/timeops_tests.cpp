#include <gtest/gtest.h>

#include <socle/common/timeops.hpp>

#include <regex>
#include <sys/time.h>

TEST(TimeOps, ComputesSignedMillisecondDeltas) {
    timeval older{10, 900000};
    timeval newer{12, 100000};
    EXPECT_EQ(timeval_msdelta(&newer, &older), 1200);
    EXPECT_EQ(timeval_msdelta(&older, &newer), -1200);

    timeval just_now{};
    gettimeofday(&just_now, nullptr);
    const auto delta = timeval_msdelta_now(&just_now);
    EXPECT_GE(delta, 0);
    EXPECT_LT(delta, 1000);
}

TEST(TimeOps, FormatsEveryUptimeBoundaryWithoutNarrowing) {
    EXPECT_EQ(uptime_string(0), "0s");
    EXPECT_EQ(uptime_string(59), "59s");
    EXPECT_EQ(uptime_string(60), "1m 0s");
    EXPECT_EQ(uptime_string(3661), "1h 1m 1s");
    EXPECT_EQ(uptime_string(90061), "1d 1h 1m 1s");
    EXPECT_EQ(uptime_string(31536000 + 90061), "1y 1d 1h 1m 1s");
    EXPECT_EQ(uptime_string(static_cast<time_t>(400) * 31536000 + 1),
              "400y 0d 0h 0m 1s");
}

TEST(TimeOps, ProducesUtcTimestampAndEpochDays) {
    EXPECT_TRUE(std::regex_match(make_ts(),
        std::regex(R"(^\d{4}-\d{2}-\d{2}--\d{2}:\d{2}:\d{2}\.\d{3}$)")));
    EXPECT_EQ(epoch_days(0), 0);
    EXPECT_EQ(epoch_days(86399), 0);
    EXPECT_EQ(epoch_days(86400), 1);
}

TEST(TimeOps, RollsAndExpiresSecondCounters) {
    auto now = time(nullptr);
    unsigned long previous = 3;
    unsigned long current = 7;

    auto recent = now;
    EXPECT_EQ(time_update_counter_sec(&recent, &previous, &current, 10, 2), 3U);
    EXPECT_EQ(current, 9U);
    EXPECT_EQ(time_get_counter_sec(&recent, &current, 10), 9U);

    auto old = now - 20;
    EXPECT_EQ(time_update_counter_sec(&old, &previous, &current, 10, 4), 9U);
    EXPECT_EQ(current, 4U);
    old = now - 20;
    EXPECT_EQ(time_get_counter_sec(&old, &current, 10), 0U);
}
