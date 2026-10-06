#include <gtest/gtest.h>

#include <biostring.hpp>

#include <openssl/bio.h>

#include <memory>
#include <string>

namespace {

struct BioDeleter {
    void operator()(BIO* bio) const { BIO_free(bio); }
};

TEST(BioString, RejectsNullStorage) {
    EXPECT_EQ(BIO_new_string(nullptr), nullptr);
}

TEST(BioString, WritesTellsFlushesAndResetsCallerOwnedString) {
    std::string output = "prefix:";
    std::unique_ptr<BIO, BioDeleter> bio(BIO_new_string(&output));
    ASSERT_NE(bio, nullptr);

    EXPECT_EQ(BIO_write(bio.get(), "abc", 3), 3);
    EXPECT_EQ(BIO_puts(bio.get(), "-def"), 4);
    EXPECT_EQ(output, "prefix:abc-def");
    EXPECT_EQ(BIO_tell(bio.get()), static_cast<long>(output.size()));
    EXPECT_EQ(BIO_flush(bio.get()), 1);
    EXPECT_EQ(BIO_seek(bio.get(), 0), -1);

    EXPECT_EQ(BIO_reset(bio.get()), 1);
    EXPECT_TRUE(output.empty());
}

} // namespace
