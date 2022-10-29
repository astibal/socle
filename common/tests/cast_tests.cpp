#include <socle/common/convert.hpp>
#include <socle/common/numops.hpp>
#include <socle/common/display.hpp>
#include <gtest/gtest.h>


using namespace socle::raw;

#define print_size(x) \
    std::cout << #x"::max = " << (long long) std::numeric_limits<x>::max() << "\n"; \
    std::cout << #x"::min = " << (long long) std::numeric_limits<x>::min() << "\n"; \

TEST(DownCast, SimpleOk) {

    print_size(uint16_t);
    print_size(uint8_t);
    print_size(int8_t);

    uint16_t a = 0xff;
    uint8_t b = down_cast<uint8_t>(a).value_or(0);

    std::cout << string_format("%d\n", (int)b);
    // can fit
    ASSERT_TRUE(b == 0xff);

    b = try_down_cast<uint8_t>(a);
    std::cout << string_format("%d\n", (int)b);
    ASSERT_TRUE(b == 0xff);

    int8_t c = down_cast<int8_t>(to_signed_cast<int16_t>(a)).value_or(0);
    std::cout << string_format("%d\n", (int)c);
    ASSERT_TRUE(c == 0);
}


TEST(DownCast, SimpleFail) {

    uint16_t a = 0xffff;
    uint8_t b = down_cast<uint8_t>(a).value_or(0);

    std::cout << string_format("%d", b);

    // cannot fit
    ASSERT_TRUE(b == 0);
    ASSERT_THROW(try_down_cast<uint8_t>(a), cast_overflow);
}


TEST(DownCast, SimpleFail_Signed) {
    uint16_t a = 127;
    int8_t d = down_cast<int8_t>(to_signed_cast<int16_t>(a)).value_or(0);
    std::cout << string_format("%d\n", (int)d);
    ASSERT_TRUE(d == 127);

    ASSERT_NO_THROW(down_cast<int8_t>(to_signed_cast<int16_t>(a)));

    a = 128;
    ASSERT_THROW(try_down_cast<int8_t>(a), cast_overflow);
}

TEST(FromUnsigned, Fail) {

    unsigned long a = std::numeric_limits<unsigned long>::max() - 1000;
    long b = to_signed_cast<long>(a).value_or(-1);

    std::cout << string_format("%l\n", b);

    // fails, because such a big unsigned can't fit signed, even the same size
    ASSERT_TRUE(b < 0);
}

TEST(FromUnsigned, Ok) {

    unsigned long a = 100000;
    long b = to_signed_cast<long>(a).value_or(0);

    std::cout << string_format("%l\n", b);

    // few thousands can easily fit signed long
    ASSERT_TRUE(b == 100000);
}


TEST(FromSigned, Fail) {

    long a = -100000;
    unsigned long b = from_signed_cast<unsigned long>(a).value_or(0);


    std::cout << string_format("%ul", b);

    // negative cannot fit unsigned
    ASSERT_TRUE(b == 0);
    ASSERT_THROW(try_from_signed_cast<unsigned long>(a), cast_overflow);
}

TEST(FromSigned, Ok) {

    long a = 100000;
    unsigned long b = from_signed_cast<unsigned long>(a).value_or(0);


    std::cout << string_format("%ul", b);

    // negative cannot fit unsigned
    ASSERT_TRUE(b == 100000);
}

TEST(Overflow, test1) {
    uint64_t big = 0xffffffff;
    uint16_t x = down_cast<uint16_t>(big).value_or(max_of<uint16_t>());
    uint16_t xx = down_cast<uint16_t>(big).value_or(max_of<uint16_t>());

    ASSERT_TRUE(x == std::numeric_limits<uint16_t>::max());
    ASSERT_TRUE(xx == std::numeric_limits<uint16_t>::max());

}

TEST(Combine, test1) {
    long port = -345;

    // down-cast will succeed, we will fit in the range of signed short
    ASSERT_TRUE(down_cast<short>(port).value_or(-1) == -345);

    //value is however negative, from_signed_cast fails
    ASSERT_TRUE(from_signed_cast<unsigned short>(down_cast<short>(port)).value_or(0) == 0);

    // max-value of unsigned short is 65535
    unsigned short target = from_signed_cast<unsigned short>(down_cast<short>(port)).value_or(max_of<unsigned short>());
    std::cout << target << "\n";
    ASSERT_TRUE(target == 65535);
}

TEST(Combine, test2) {
    int64_t difference = -2149999647;
    ASSERT_THROW(try_down_cast<int32_t>(difference), cast_overflow);
}

TEST(Combine, test3) {
    int64_t difference = 1149999647;
    int32_t x;
    ASSERT_NO_THROW(x = try_down_cast<int32_t>(difference));  // hehe, this might fail to throw on platforms with huge `int` :)
    ASSERT_THROW(try_down_cast<int16_t>(x), cast_overflow);
}

TEST(Combine, test4) {

    std::vector<int64_t> val_vec = { 24000, -24000, 1149999647, -1149999647, 2149999647, -2149999647, INT64_MAX, UINT32_MAX, INT32_MAX, INT64_MIN, INT32_MIN };

    for(auto const& v: val_vec) {
        using my_type = uint32_t;

        my_type x;
        x = down_cast<my_type>(sign_remove(v)).value_or(0);
        std::cout << "int64:" << v << " -> " << "uint32:" << x << "\n";
    }
}


TEST(Numops, Add) {

    uint16_t a = UINT16_MAX - 100;
    auto val1 = safe_add(a, (uint16_t)50u, (uint16_t)50u).value();

    ASSERT_TRUE(val1 == UINT16_MAX);

    uint16_t inc = 45;
    uint8_t inc2= 42;
    auto val2 = safe_add(a, inc, inc, inc, up_cast<uint16_t>(inc2));
    ASSERT_TRUE(not val2.has_value());

    // this won't compile, s is not arithmetic type
    //    std::string s("some non-integral");
    //    auto val2 = safe_add(a, s, s, s, s);
}

TEST(Numops, Add2) {

    using namespace socle::raw;
    using namespace socle::raw::operators;

    n16_t a = UINT16_MAX - 100u;
    auto b = n8_t(50u);
    auto val1 = a + b + n16_t(50u);
    ASSERT_TRUE(val1.value() == UINT16_MAX);
}

TEST(Numops, Add3) {

    using namespace socle::raw;
    using namespace socle::raw::operators;

    n16_t a = 1000u;
    n16_t b = 50u;
    auto val1 = a + b + n8_t(50u);
    ASSERT_TRUE(val1.is(1100));
}

TEST(Numops, Add4) {

    using namespace socle::raw;
    using namespace socle::raw::operators;

    //number<uint16_t> a = 100000;
    n16_t a(100000u);
    number<uint16_t> b = 50u;
    auto val1 = a + b + n8_t(50u);
    ASSERT_TRUE(not val1.has_value());
}


TEST(Numops, Add5) {
    using namespace socle::raw;
    using namespace socle::raw::operators;


    n64_t a = UINT64_MAX;
    a = a + n8_t(1u);

    ASSERT_TRUE(a.is_nan());

    a = 0xff00u;
    sn16_t b = 0xff;
    a = a + b;
    ASSERT_TRUE(a.value_or(0) == 0xffff);

    a = a - sn16_t(-15);
}

TEST(Numpos, Sub1) {
    using namespace socle::raw;
    using namespace socle::raw::operators;


    n32_t a = 45u;
    n8_t b = 3u;
    auto c = a - b;
    ASSERT_TRUE(c.is(42));
}


TEST(Numpos, Sub2) {
    using namespace socle::raw;
    using namespace socle::raw::operators;

    n32_t a = 45u;
    // n8_t b(-3); // this won't assign

    n8_t b(0u); // this won't assign
    b = b - n8_t(3u);

    n16_t bb(0u); // this won't assign
    bb = bb - n16_t(3u);


    auto c = a - b;
    ASSERT_TRUE(c.is_nan());

    ASSERT_FALSE((traits::can_static_cast<uint32_t, uint64_t>::value));
    ASSERT_TRUE((traits::can_static_cast<uint64_t, uint32_t>::value));

    sn16_t x = -30;
    sn32_t y = 20;
    sn32_t z = x - y;

    ASSERT_TRUE(z.is(-50));

    sn16_t xx = -30000;
    n16_t yy = 28000u;
    sn64_t zz = xx.promote<sn64_t::type>() - yy.to_signed<sn32_t::type>().promote<sn64_t::type>();

    ASSERT_TRUE(zz.is(-58000));

    n32_t len = 256u;
    unsigned int rd = 345;

    auto left = len - n32_t(rd);
    ASSERT_TRUE(left.is_nan());

    auto ten = sn64_t(10);
    left = len - n64_t::numeric_cast(ten);
    ASSERT_TRUE(left.is(246));
    left = len - ten.numeric_cast<n64_t>();
    ASSERT_TRUE(left.is(246));
}