#include <gtest/gtest.h>

#include <ltventry.hpp>

#include <array>
#include <cstring>
#include <memory>

namespace {

std::vector<std::uint8_t> bytes_of(const LTVEntry& entry) {
    return {entry.buffer(), entry.buffer() + entry.buflen()};
}

TEST(LTVEntry, ScalarsRoundTripThroughUnalignedInput) {
    LTVEntry original(7, LTVEntry::num, 0x12345678U);
    std::vector<std::uint8_t> unaligned(original.buflen() + 1);
    std::memcpy(unaligned.data() + 1, original.buffer(), original.buflen());

    LTVEntry parsed;
    ASSERT_EQ(parsed.unpack(unaligned.data() + 1, original.buflen()),
              static_cast<int>(original.buflen()));
    EXPECT_EQ(parsed.id(), 7);
    EXPECT_EQ(parsed.type(), LTVEntry::num);
    EXPECT_EQ(parsed.data_int(), 0x12345678U);

    parsed.write_int(42);
    EXPECT_EQ(parsed.data_int(), 42U);
}

TEST(LTVEntry, RejectsTruncatedAndInvalidLengthsWithoutUnsignedUnderflow) {
    LTVEntry parsed;
    EXPECT_EQ(parsed.unpack(nullptr, 0), -1);

    std::array<std::uint8_t, 6> encoded{};
    for (std::uint32_t invalid_length = 0; invalid_length < ltv_header_size(); ++invalid_length) {
        ltv_set_length(encoded.data(), invalid_length);
        EXPECT_EQ(parsed.unpack(encoded.data(), encoded.size()), -1);
        EXPECT_EQ(parsed.datalen(), 0U);
    }

    ltv_set_length(encoded.data(), 10);
    EXPECT_EQ(parsed.unpack(encoded.data(), encoded.size()), 0);
    EXPECT_EQ(parsed.datalen(), 0U);
}

TEST(LTVEntry, BoundedByteSetterAndInputValidationAreStable) {
    LTVEntry entry;
    EXPECT_EQ(entry.data_str(), "");
    EXPECT_EQ(entry.hr(), "LTVEntry::hr: uninitialized");
    EXPECT_THROW({ const auto value = entry.data_str_ip(); (void)value; }, std::invalid_argument);

    entry.set_bytes(3, LTVEntry::str, "longer-than-target", 4);
    EXPECT_EQ(entry.datalen(), 4U);
    EXPECT_EQ(entry.data_str(), "long");

    EXPECT_THROW(entry.set_str(1, LTVEntry::str, nullptr), std::invalid_argument);
    EXPECT_THROW(entry.set_bytes(1, LTVEntry::str, nullptr, 1), std::invalid_argument);
    EXPECT_THROW(entry.set_ip(1, LTVEntry::ip, "not-an-ip"), std::invalid_argument);

    LTVEntry short_value(1, LTVEntry::str, "abc");
    EXPECT_THROW({ const auto value = short_value.data_int(); (void)value; }, std::invalid_argument);
    EXPECT_THROW(short_value.write_int(1), std::invalid_argument);

    LTVEntry ip;
    ip.set_ip(4, LTVEntry::ip, "192.0.2.1");
    EXPECT_EQ(ip.data_str_ip(), "192.0.2.1");
}

TEST(LTVEntry, NestedContainerRoundTripsAndRepeatedPackIsIdempotent) {
    LTVEntry root;
    root.container(1);
    root.add(new LTVEntry(2, LTVEntry::str, "hello"));
    root.add(new LTVEntry(3, LTVEntry::num, 99));

    ASSERT_GT(root.pack(), 0);
    auto first = bytes_of(root);
    ASSERT_EQ(root.pack(), static_cast<int>(first.size()));
    EXPECT_EQ(bytes_of(root), first);

    LTVEntry parsed;
    ASSERT_EQ(parsed.unpack(first.data(), first.size()), static_cast<int>(first.size()));
    ASSERT_EQ(parsed.size(), 2U);
    ASSERT_NE(parsed.search({2}), nullptr);
    EXPECT_EQ(parsed.search({2})->data_str(), "hello");
    ASSERT_NE(parsed.search({3}), nullptr);
    EXPECT_EQ(parsed.search({3})->data_int(), 99U);
    EXPECT_EQ(parsed.search({4}), nullptr);
}

TEST(LTVEntry, ReuseReleasesOldChildrenAndReplacesState) {
    LTVEntry container;
    container.container(1);
    container.add(new LTVEntry(2, LTVEntry::str, "child"));
    ASSERT_GT(container.pack(), 0);

    LTVEntry scalar(9, LTVEntry::str, "replacement");
    ASSERT_EQ(container.unpack(scalar.buffer(), scalar.buflen()),
              static_cast<int>(scalar.buflen()));
    EXPECT_EQ(container.size(), 0U);
    EXPECT_EQ(container.id(), 9);
    EXPECT_EQ(container.data_str(), "replacement");
}

TEST(LTVEntry, RejectsMalformedNestedEntryAtomically) {
    std::array<std::uint8_t, 10> encoded{};
    ltv_set_length(encoded.data(), encoded.size());
    ltv_set_id(encoded.data(), 1);
    ltv_set_type(encoded.data(), LTVEntry::cont);
    // The four payload bytes are only a nested length field; its value of
    // zero is invalid and must reject the complete outer container.

    LTVEntry parsed;
    EXPECT_EQ(parsed.unpack(encoded.data(), encoded.size()), -1);
    EXPECT_EQ(parsed.buflen(), 0U);
    EXPECT_EQ(parsed.size(), 0U);
}

} // namespace
