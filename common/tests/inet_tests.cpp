#include <socle/common/internet.hpp>
#include <gtest/gtest.h>

TEST(InetTest, CanDownload1) {

    std::string uri = "http://root.cz/index.html";
    buffer b(16000);
    b.size(0);


    auto x = inet::download(uri, b, 10);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload2) {

    std::string uri = "http://root.cz:80/index.html";
    buffer b(16000);
    b.size(0);


    auto x = inet::download(uri, b, 10);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload3) {

    std::string uri = "root.cz/index.html";
    buffer b(16000);
    b.size(0);


    auto x = inet::download(uri, b, 10);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload4) {

    std::string uri = "root.cz";
    buffer b(16000);
    b.size(0);


    auto x = inet::download(uri, b, 10);

    std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}