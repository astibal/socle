#include <gtest/gtest.h>

#include <buffer.hpp>

#include <array>
#include <sstream>

TEST(Buffer, ConstructsAssignsAppendsAndFindsBytes) {
    EXPECT_THROW(buffer(3, 2), std::invalid_argument);
    EXPECT_THROW(buffer("abc", 3, 2), std::invalid_argument);

    buffer value(2);
    EXPECT_TRUE(value.empty());
    value.assign("abc", 3);
    EXPECT_EQ(value.str(), "abc");
    EXPECT_GE(value.capacity(), 3U);

    buffer suffix("def", 3);
    value.append(suffix);
    value.append(&suffix);
    EXPECT_EQ(value.str(), "abcdefdef");
    EXPECT_EQ(value.find('a'), 0U);
    EXPECT_EQ(value.find('d'), 3U);
    EXPECT_EQ(value.find('d', 4), 6U);
    EXPECT_EQ(value.find('z'), buffer::npos);
    EXPECT_EQ(value.rfind('d'), 6U);
    EXPECT_EQ(value.rfind('d', 5), 3U);
    EXPECT_EQ(value.rfind('z'), buffer::npos);

    value.fill('x');
    EXPECT_EQ(value.str(), std::string(9, 'x'));
    EXPECT_THROW(value.at(value.size()), std::out_of_range);
    EXPECT_FALSE(value.capacity(1));
}

TEST(Buffer, TypedAccessViewsAndFlushBoundariesAreChecked) {
    buffer value(8, 8);
    value.fill(0);
    value.set_at<std::uint32_t>(2, 0x12345678U);
    EXPECT_EQ(value.get_at<std::uint32_t>(2), 0x12345678U);
    EXPECT_THROW(value.get_at<std::uint32_t>(6), std::out_of_range);
    EXPECT_THROW(value.set_at<std::uint32_t>(6, 1), std::out_of_range);
    std::array<std::uint8_t, 4> encoded{};
    const std::uint32_t expected = 0x12345678U;
    std::memcpy(encoded.data(), &expected, sizeof(expected));
    EXPECT_EQ(value.copy_from<4>(2), encoded);
    EXPECT_THROW(value.copy_from<4>(5), std::out_of_range);

    buffer text("abcdef", 6);
    EXPECT_EQ(text.view(2, 2).str(), "cd");
    EXPECT_EQ(text.view(4, 20).str(), "ef");
    EXPECT_EQ(text.view().str(), "abcdef");
    EXPECT_THROW(text.view(6, 1), std::out_of_range);

    text.flush(2); // small-prefix memmove path
    EXPECT_EQ(text.str(), "cdef");
    text.flush(3); // large-prefix memcpy path
    EXPECT_EQ(text.str(), "f");
    text.flush(0);
    EXPECT_TRUE(text.empty());
}

TEST(Buffer, CopyAssignmentHasStableOwnedAndBorrowedSemantics) {
    buffer owned("owned", 5);
    buffer owned_copy = owned;
    owned[0] = 'O';
    EXPECT_EQ(owned_copy.str(), "owned");

    std::array<unsigned char, 8> external{'b', 'o', 'r', 'r', 'o', 'w', 'e', 'd'};
    buffer borrowed(external.data(), external.size(), external.size(), false);

    buffer target("stale-data", 10);
    target = borrowed;
    EXPECT_EQ(target.str(), "borrowed");
    external[0] = 'B';
    EXPECT_EQ(target.str(), "Borrowed");

    std::array<unsigned char, 8> destination{'e', 'x', 't', 'e', 'r', 'n', 'a', 'l'};
    buffer borrowed_destination(destination.data(), destination.size(), destination.size(), false);
    borrowed_destination = owned;
    owned[1] = 'X';
    EXPECT_EQ(borrowed_destination.str(), "Owned");
    EXPECT_EQ(std::string(destination.begin(), destination.end()), "external");

    borrowed_destination = borrowed_destination;
    EXPECT_EQ(borrowed_destination.str(), "Owned");

    buffer self_view_owner("prefix-payload", 14);
    self_view_owner = self_view_owner.view(7);
    EXPECT_EQ(self_view_owner.str(), "payload");
    self_view_owner.append("!", 1);
    EXPECT_EQ(self_view_owner.str(), "payload!");
}

TEST(Buffer, MoveSwapStreamAndDetachPreserveOwnership) {
    const bool previous_pool = buffer::use_pool;
    buffer::use_pool = false;
    {
        buffer first("one", 3);
        buffer second("two", 3);
        first.swap(second);
        EXPECT_EQ(first.str(), "two");
        EXPECT_EQ(second.str(), "one");

        buffer moved(std::move(first));
        EXPECT_EQ(moved.str(), "two");
        buffer assigned;
        assigned = std::move(second);
        EXPECT_EQ(assigned.str(), "one");

        std::ostringstream output;
        output << assigned;
        EXPECT_EQ(output.str(), "one");

        auto* detached = moved.detach();
        EXPECT_TRUE(moved.empty());
        EXPECT_EQ(moved.capacity(), 0U);
        delete[] detached;
    }
    buffer::use_pool = previous_pool;
}

TEST(Buffer, RegexReplacementReportsNoMatchAndPreservesRequestedLength) {
    EXPECT_FALSE(regex_replace_fill("alpha", "z+", "x", " ").has_value());
    EXPECT_EQ(regex_replace_fill("abc-abc", "abc", "x", nullptr), "x-x");

    auto filled = regex_replace_fill("abc-abc", "abc", "x", " ");
    ASSERT_TRUE(filled.has_value());
    EXPECT_EQ(filled->size(), std::string("abc-abc").size());
    EXPECT_EQ(filled->substr(0, 3), "x-x");
}
