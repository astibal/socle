#include <socle/common/internet.hpp>
#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <string_view>
#include <thread>


static auto const LEVEL = loglevel(iDEB);
static void init_log() {
    Log::init();
    Log::get()->level(LEVEL);
    Log::get()->dup2_cout(true);
}

namespace {

class LoopbackServer {
public:
    explicit LoopbackServer(std::vector<std::string> response_chunks) {
        listener_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listener_ < 0) throw std::runtime_error("cannot create loopback listener");

        int reuse = 1;
        ::setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (::bind(listener_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
            ::listen(listener_, 1) != 0) {
            ::close(listener_);
            throw std::runtime_error("cannot bind loopback listener");
        }
        socklen_t address_size = sizeof(address);
        if (::getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
            ::close(listener_);
            throw std::runtime_error("cannot read loopback listener address");
        }
        port_ = ntohs(address.sin_port);

        worker_ = std::thread([this, chunks = std::move(response_chunks)] {
            const int client = ::accept(listener_, nullptr, nullptr);
            if (client < 0) return;
            std::array<char, 4096> request_buffer{};
            while (request_.find("\r\n\r\n") == std::string::npos) {
                const auto received = ::recv(client, request_buffer.data(), request_buffer.size(), 0);
                if (received <= 0) break;
                request_.append(request_buffer.data(), static_cast<std::size_t>(received));
            }
            for (auto const& chunk : chunks) {
                std::size_t sent = 0;
                while (sent < chunk.size()) {
                    const auto count = ::send(client, chunk.data() + sent, chunk.size() - sent, 0);
                    if (count <= 0) break;
                    sent += static_cast<std::size_t>(count);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            ::shutdown(client, SHUT_RDWR);
            ::close(client);
        });
    }

    LoopbackServer(LoopbackServer const&) = delete;
    LoopbackServer& operator=(LoopbackServer const&) = delete;

    ~LoopbackServer() {
        if (listener_ >= 0) {
            ::shutdown(listener_, SHUT_RDWR);
            ::close(listener_);
            listener_ = -1;
        }
        if (worker_.joinable()) worker_.join();
    }

    [[nodiscard]] unsigned short port() const { return port_; }
    [[nodiscard]] std::string const& request() const { return request_; }

private:
    int listener_ = -1;
    unsigned short port_ = 0;
    std::thread worker_;
    std::string request_;
};

} // namespace

TEST(InetLocalTest, RecognizesNumericAddressesAndResolvesLocalhost) {
    EXPECT_TRUE(inet::is_ipv4_address("127.0.0.1"));
    EXPECT_TRUE(inet::is_ipv4_address("192.0.2.1"));
    EXPECT_FALSE(inet::is_ipv4_address("127.0.0.999"));
    EXPECT_FALSE(inet::is_ipv4_address("example.test"));
    EXPECT_TRUE(inet::is_ipv6_address("::1"));
    EXPECT_TRUE(inet::is_ipv6_address("2001:db8::1"));
    EXPECT_FALSE(inet::is_ipv6_address("2001:db8::gg"));

    auto const ipv4 = inet::dns_lookup("localhost", 4);
    ASSERT_FALSE(ipv4.empty());
    for (auto const& address : ipv4) EXPECT_TRUE(inet::is_ipv4_address(address));

    auto const any = inet::dns_lookup("localhost", 0);
    ASSERT_FALSE(any.empty());
    for (auto const& address : any) {
        EXPECT_TRUE(inet::is_ipv4_address(address) || inet::is_ipv6_address(address));
    }
    EXPECT_TRUE(inet::dns_lookup("invalid..hostname", 4).empty());
}

TEST(InetLocalTest, ConnectsToLoopbackAndRejectsNonAddress) {
    LoopbackServer server({});
    const int socket = inet::socket_connect("127.0.0.1", server.port());
    ASSERT_GE(socket, 0);
    ::close(socket);
    EXPECT_EQ(inet::socket_connect("not-an-ip-address", server.port()), -1);
}

TEST(InetLocalTest, HttpGetReassemblesFragmentedHeaderAndBody) {
    LoopbackServer server({
        "HTTP/1.0 200 OK\r\nContent-L",
        "ength: 11\r\nX-Test: fragmented\r\n\r\nhello ",
        "world",
    });
    buffer body(2);
    body.size(0);
    auto const request = std::string("GET /fragmented HTTP/1.0\r\nHost: localhost\r\n\r\n");

    EXPECT_EQ(inet::http_get(request, "127.0.0.1", server.port(), body, 2), 11);
    EXPECT_EQ(body.string_view(), "hello world");
    EXPECT_EQ(server.request(), request);
}

TEST(InetLocalTest, HttpGetEnforcesContentLengthBoundaries) {
    const auto request = std::string("GET /length HTTP/1.0\r\nHost: localhost\r\n\r\n");
    {
        LoopbackServer server({
            "HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nbodyextra",
        });
        buffer body;
        EXPECT_EQ(inet::http_get(request, "127.0.0.1", server.port(), body, 2), 4);
        EXPECT_EQ(body.string_view(), "body");
    }
    {
        LoopbackServer server({
            "HTTP/1.0 200 OK\r\nContent-Length: 10\r\n\r\nshort",
        });
        buffer body;
        EXPECT_EQ(inet::http_get(request, "127.0.0.1", server.port(), body, 2), -1);
    }
    {
        LoopbackServer server({
            "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nclose-delimited",
        });
        buffer body;
        EXPECT_EQ(inet::http_get(request, "127.0.0.1", server.port(), body, 2), 15);
        EXPECT_EQ(body.string_view(), "close-delimited");
    }
}

TEST(InetLocalTest, DownloadParsesPortPathQueryAndFragment) {
    LoopbackServer server({
        "HTTP/1.0 200 OK\r\nContent-Length: 7\r\n\r\npayload",
    });
    buffer body(1);
    body.size(0);
    auto const url = "127.0.0.1:" + std::to_string(server.port()) +
                     "/resource?q=answer#ignored";

    EXPECT_EQ(inet::download(url, body, 2, 4), 7);
    EXPECT_EQ(body.string_view(), "payload");
    EXPECT_NE(server.request().find("GET /resource?q=answer HTTP/1.0\r\n"), std::string::npos);
    EXPECT_NE(server.request().find("Host: 127.0.0.1\r\n"), std::string::npos);
}

TEST(InetLocalTest, DownloadHonorsExplicitPortWithSchemeAndRejectsInvalidPorts) {
    LoopbackServer server({
        "HTTP/1.0 200 OK\r\nContent-Length: 7\r\n\r\npayload",
    });
    buffer body;
    const auto url = "http://127.0.0.1:" + std::to_string(server.port()) + "/explicit";

    EXPECT_EQ(inet::download(url, body, 2, 4), 7);
    EXPECT_EQ(body.string_view(), "payload");
    EXPECT_NE(server.request().find("GET /explicit HTTP/1.0\r\n"), std::string::npos);

    buffer unused;
    EXPECT_EQ(inet::download("http://127.0.0.1:not-a-port/", unused, 1, 4), 0);
    EXPECT_EQ(inet::download("http://127.0.0.1:70000/", unused, 1, 4), 0);
}

TEST(InetTest, CanResolveVany) {

    std::string host = "root.cz";

    init_log();

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

    init_log();

    auto x = inet::dns_lookup(host);

    for(auto const& xx: x) {
        std::cout << "ipv4 " << xx;
        ASSERT_TRUE(string_split(xx, '.').size() == 4);
    }

    ASSERT_TRUE(not x.empty() );
}

TEST(InetTest, CanResolveV6) {

    std::string host = "root.cz";

    init_log();

    auto x = inet::dns_lookup(host, 6);

    for(auto const& xx: x) {
        std::cout << "ipv6 " << xx;
        ASSERT_TRUE(string_split(xx, ':').size() >= 2);
    }

    ASSERT_TRUE(not x.empty() );
}

TEST(InetTest, CanDownload1_ipv4) {

    std::string uri = "http://root.cz/index.html";


    init_log();
    inet::Factory::log().level(LEVEL);


    buffer b(16); // allocate small buffer to test append
    b.size(0);


    auto x = inet::download(uri, b, 10);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload2_ipv4) {

    std::string uri = "http://root.cz:80/index.html";

    init_log();
    inet::Factory::log().level(LEVEL);

    buffer b(16000);
    b.size(0);

    auto x = inet::download(uri, b, 10);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload3_ipv4) {

    std::string uri = "root.cz/index.html";

    init_log();
    inet::Factory::log().level(LEVEL);

    buffer b(16000);
    b.size(0);

    auto x = inet::download(uri, b, 10);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload4_ipv4) {

    std::string uri = "root.cz";

    init_log();
    inet::Factory::log().level(LEVEL);

    buffer b(16000);
    b.size(0);

    auto x = inet::download(uri, b, 10);

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}




TEST(InetTest, CanDownload1_ipv6) {

    std::string uri = "http://root.cz/index.html";

    init_log();
    inet::Factory::log().level(LEVEL);

    buffer b(16); // allocate small buffer to test append
    b.size(0);

    auto x = inet::download(uri, b, 10, 6);

    if (x <= 0) GTEST_SKIP() << "public IPv6 connectivity is unavailable";

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload2_ipv6) {

    std::string uri = "http://root.cz:80/index.html";

    init_log();
    inet::Factory::log().level(LEVEL);

    buffer b(16000);
    b.size(0);

    auto x = inet::download(uri, b, 10, 6);

    if (x <= 0) GTEST_SKIP() << "public IPv6 connectivity is unavailable";

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload3_ipv6) {

    std::string uri = "root.cz/index.html";

    init_log();
    inet::Factory::log().level(LEVEL);

    buffer b(16000);
    b.size(0);

    auto x = inet::download(uri, b, 10, 6);

    if (x <= 0) GTEST_SKIP() << "public IPv6 connectivity is unavailable";

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}

TEST(InetTest, CanDownload4_ipv6) {

    std::string uri = "root.cz";

    init_log();
    inet::Factory::log().level(LEVEL);

    buffer b(16000);
    b.size(0);

    auto x = inet::download(uri, b, 10, 6);

    if (x <= 0) GTEST_SKIP() << "public IPv6 connectivity is unavailable";

    // std::cout << hex_dump(b);

    ASSERT_TRUE(x > 0 );
}
