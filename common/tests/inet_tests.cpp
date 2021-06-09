#include <socle/common/internet.hpp>
#include <gtest/gtest.h>

constexpr auto& LEVEL = socle::log::level::DIA;

TEST(InetTest, CanResolveVany) {

    std::string host = "root.cz";
    logger().dup2_cout(true);
    inet::Factory::log().level(LEVEL);


    auto x = inet::dns_lookup(host, 0);

    for(auto const& xx: x) {
        std::cout << "ipv-any " << xx << std::endl;

        auto sz4 = string_split(xx, '.').size();
        auto sz6 = string_split(xx, ':').size();
        ASSERT_TRUE( sz4 == 4 or sz6 > 2 );
    }

    ASSERT_TRUE(not x.empty() );
}


TEST(InetTest, CanResolveV4) {

    std::string host = "root.cz";
    logger().dup2_cout(true);
    inet::Factory::log().level(LEVEL);


    auto x = inet::dns_lookup(host);

    for(auto const& xx: x) {
        std::cout << "ipv4 " << xx;
        ASSERT_TRUE(string_split(xx, '.').size() == 4);
    }

    ASSERT_TRUE(not x.empty() );
}

TEST(InetTest, CanResolveV6) {

    std::string host = "root.cz";
    logger().dup2_cout(true);
    inet::Factory::log().level(LEVEL);


    auto x = inet::dns_lookup(host, 6);

    for(auto const& xx: x) {
        std::cout << "ipv6 " << xx;
        ASSERT_TRUE(string_split(xx, ':').size() >= 2);
    }

    ASSERT_TRUE(not x.empty() );
}

TEST(InetTest, CanDownload1_ipv4) {

    std::string uri = "http://root.cz/index.html";
    logger().dup2_cout(true);
    inet::Factory::log().level(LEVEL);


    buffer b(16); // allocate small buffer to test append
    b.size(0);


    auto x = inet::download(uri, b, 10);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload2_ipv4) {

    std::string uri = "http://root.cz:80/index.html";
    logger().dup2_cout(true);
    inet::Factory::log().level(LEVEL);

    buffer b(16000);
    b.size(0);

    auto x = inet::download(uri, b, 10);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload3_ipv4) {

    std::string uri = "root.cz/index.html";
    logger().dup2_cout(true);
    inet::Factory::log().level(LEVEL);

    buffer b(16000);
    b.size(0);

    auto x = inet::download(uri, b, 10);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload4_ipv4) {

    std::string uri = "root.cz";
    logger().dup2_cout(true);
    inet::Factory::log().level(LEVEL);

    buffer b(16000);
    b.size(0);

    auto x = inet::download(uri, b, 10);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}




TEST(InetTest, CanDownload1_ipv6) {

    std::string uri = "http://root.cz/index.html";
    logger().dup2_cout(true);
    inet::Factory::log().level(LEVEL);

    buffer b(16); // allocate small buffer to test append
    b.size(0);

    auto x = inet::download(uri, b, 10, 6);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload2_ipv6) {

    std::string uri = "http://root.cz:80/index.html";
    logger().dup2_cout(true);
    inet::Factory::log().level(LEVEL);

    buffer b(16000);
    b.size(0);

    auto x = inet::download(uri, b, 10, 6);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload3_ipv6) {

    std::string uri = "root.cz/index.html";
    logger().dup2_cout(true);
    inet::Factory::log().level(LEVEL);

    buffer b(16000);
    b.size(0);

    auto x = inet::download(uri, b, 10, 6);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload4_ipv6) {

    std::string uri = "root.cz";
    logger().dup2_cout(true);
    inet::Factory::log().level(LEVEL);

    buffer b(16000);
    b.size(0);

    auto x = inet::download(uri, b, 10, 6);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}