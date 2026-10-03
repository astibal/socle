#include <gtest/gtest.h>

#include <base64.hpp>

#include <array>
#include <string>

namespace {

std::string encode(std::string const& input) {
    return libbase64::encode<std::string, char, unsigned char, true>(
        reinterpret_cast<unsigned char const*>(input.data()), input.size());
}

std::string decode(std::string const& input) {
    return libbase64::decode<std::string, char, unsigned char, true>(input);
}

} // namespace

TEST(Base64, MatchesRfc4648VectorsIncludingEmptyInput) {
    const std::array<std::pair<std::string, std::string>, 7> vectors{{
        {"", ""},
        {"f", "Zg=="},
        {"fo", "Zm8="},
        {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="},
        {"fooba", "Zm9vYmE="},
        {"foobar", "Zm9vYmFy"},
    }};

    for (auto const& [plain, encoded] : vectors) {
        EXPECT_EQ(encode(plain), encoded) << plain;
        if (encoded.empty()) EXPECT_TRUE(decode(encoded).empty());
        else EXPECT_EQ(decode(encoded), plain) << encoded;
    }
}

TEST(Base64, RoundTripsBinaryDataAndEveryAlignment) {
    std::string binary;
    for (int value = 0; value < 256; ++value) {
        binary.push_back(static_cast<char>(value));
    }
    EXPECT_EQ(decode(encode(binary)), binary);

    for (std::size_t length = 1; length <= 32; ++length) {
        auto sample = binary.substr(0, length);
        EXPECT_EQ(decode(encode(sample)), sample) << length;
    }
}

TEST(Base64, RejectsMalformedLengthAlphabetAndPadding) {
    for (auto const& malformed : {
             "A", "AAA", "A!AA", "=AAA", "A=AA", "AA=A", "AAA==", "AA===", "Zm=v"}) {
        EXPECT_TRUE(decode(malformed).empty()) << malformed;
    }
}

TEST(Base64, SizeCalculatorsMatchEncodedAndMaximumDecodedSizes) {
    for (std::size_t size = 0; size < 64; ++size) {
        std::string input(size, 'x');
        auto encoded = encode(input);
        EXPECT_EQ(libbase64::libbase64_Calculator::getEncodingSize(size), encoded.size());
        EXPECT_GE(libbase64::libbase64_Calculator::getDecodingSize(encoded.size()), size);
        EXPECT_LT(libbase64::libbase64_Calculator::getDecodingSize(encoded.size()) - size, 3U);
    }
}
