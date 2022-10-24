#include <socle/common/convert.hpp>
#include <socle/common/display.hpp>
#include <gtest/gtest.h>


using namespace raw;

TEST(DownCast, SimpleOk) {

    uint16_t a = 0xff;
    uint8_t b = down_cast<uint8_t>(a).value_or(0);

    std::cout << string_format("%d", b);

    // can fit
    ASSERT_TRUE(b == 0xff);
}


TEST(DownCast, SimpleFail) {

    uint16_t a = 0xffff;
    uint8_t b = down_cast<uint8_t>(a).value_or(0);

    std::cout << string_format("%d", b);

    // cannot fit
    ASSERT_TRUE(b == 0);
}


TEST(FromUnsigned, Fail) {

    unsigned long a = std::numeric_limits<unsigned long>::max() - 1000;
    long b = to_signed_cast<long>(a).value_or(-1);


    std::cout << string_format("%d", b);

    // fails, because such a big unsigned can't fit signed, even the same size
    ASSERT_TRUE(b < 0);
}


TEST(FromUnsigned, Ok) {

    unsigned long a = 100000;
    long b = to_signed_cast<long>(a).value_or(0);


    std::cout << string_format("%d", b);

    // few thousands can easily fit signed long
    ASSERT_TRUE(b == 100000);
}


TEST(FromSigned, Fail) {

    long a = -100000;
    unsigned long b = from_signed_cast<unsigned long>(a).value_or(0);


    std::cout << string_format("%d", b);

    // negative cannot fit unsigned
    ASSERT_TRUE(b == 0);
}

TEST(FromSigned, Ok) {

    long a = 100000;
    unsigned long b = from_signed_cast<unsigned long>(a).value_or(0);


    std::cout << string_format("%d", b);

    // negative cannot fit unsigned
    ASSERT_TRUE(b == 100000);
}