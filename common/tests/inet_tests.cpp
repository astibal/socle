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
    explicit LoopbackServer(std::vector<std::string> response_chunks,
                            int family = AF_INET,
                            std::chrono::milliseconds chunk_delay =
                                std::chrono::milliseconds(5)) {
        listener_ = ::socket(family, SOCK_STREAM, 0);
        if (listener_ < 0) throw std::runtime_error("cannot create loopback listener");

        int reuse = 1;
        ::setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        sockaddr_storage address{};
        socklen_t address_size = 0;
        if (family == AF_INET6) {
            auto* address6 = reinterpret_cast<sockaddr_in6*>(&address);
            address6->sin6_family = AF_INET6;
            address6->sin6_addr = in6addr_loopback;
            address6->sin6_port = 0;
            address_size = sizeof(*address6);
        }
        else {
            auto* address4 = reinterpret_cast<sockaddr_in*>(&address);
            address4->sin_family = AF_INET;
            address4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address4->sin_port = 0;
            address_size = sizeof(*address4);
        }
        if (::bind(listener_, reinterpret_cast<sockaddr*>(&address), address_size) != 0 ||
            ::listen(listener_, 1) != 0) {
            ::close(listener_);
            throw std::runtime_error("cannot bind loopback listener");
        }
        address_size = sizeof(address);
        if (::getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
            ::close(listener_);
            throw std::runtime_error("cannot read loopback listener address");
        }
        port_ = family == AF_INET6
            ? ntohs(reinterpret_cast<sockaddr_in6*>(&address)->sin6_port)
            : ntohs(reinterpret_cast<sockaddr_in*>(&address)->sin_port);

        worker_ = std::thread([this, chunks = std::move(response_chunks),
                               chunk_delay] {
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
                std::this_thread::sleep_for(chunk_delay);
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
            "HTTP/1.0 200 OK\r\nX-Content-Length: 1\r\n"
            "content-length: 4\r\n\r\nbodyextra",
        });
        buffer body;
        EXPECT_EQ(inet::http_get(
                      request, "127.0.0.1", server.port(), body, 2), 4);
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
    for(const auto& response : {
            std::string("HTTP/1.0 404 Not Found\r\nContent-Length: 4\r\n\r\nbody"),
            std::string("HTTP/1.0 200 OK\r\nContent-Length: 4\r\n"
                        "Content-Length: 5\r\n\r\nbody!"),
            std::string("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                        "4\r\nbody\r\n0\r\n\r\n"),
            std::string("HTTP/1.0 200 OK\r\nContent-Length: nope\r\n\r\nbody")}) {
        LoopbackServer server({response});
        buffer body;
        EXPECT_EQ(inet::http_get(
                      request, "127.0.0.1", server.port(), body, 2), -1);
        EXPECT_EQ(body.size(), 0);
    }
}

TEST(InetLocalTest, HttpGetEnforcesConfiguredTransferLimits) {
    const auto request = std::string("GET /bounded HTTP/1.0\r\nHost: localhost\r\n\r\n");
    const inet::transfer_limits limits{64, 5};
    {
        LoopbackServer server({
            "HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\ntoolong",
        });
        buffer body;
        EXPECT_EQ(inet::http_get(
                      request, "127.0.0.1", server.port(), body, 2, limits), -1);
        EXPECT_EQ(body.size(), 0);
    }
    {
        LoopbackServer server({
            "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n123456",
        });
        buffer body;
        EXPECT_EQ(inet::http_get(
                      request, "127.0.0.1", server.port(), body, 2, limits), -1);
        EXPECT_LE(body.size(), 5);
    }
    {
        LoopbackServer server({
            "HTTP/1.0 200 OK\r\nX-Padding: " + std::string(64, 'x') + "\r\n\r\n",
        });
        buffer body;
        EXPECT_EQ(inet::http_get(
                      request, "127.0.0.1", server.port(), body, 2, limits), -1);
        EXPECT_EQ(body.size(), 0);
    }
    {
        LoopbackServer server({
            "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\n12345",
        });
        buffer body;
        EXPECT_EQ(inet::http_get(
                      request, "127.0.0.1", server.port(), body, 2, limits), 5);
        EXPECT_EQ(body.string_view(), "12345");
    }
}

TEST(InetLocalTest, HttpGetTimeoutIsOneMonotonicOperationDeadline) {
    LoopbackServer server({
        "HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\n",
        "late",
    }, AF_INET, std::chrono::milliseconds(1600));
    const auto request = std::string("GET /slow HTTP/1.0\r\nHost: localhost\r\n\r\n");
    buffer body;

    const auto started = std::chrono::steady_clock::now();
    EXPECT_EQ(inet::http_get(
                  request, "127.0.0.1", server.port(), body, 1), -1);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);

    EXPECT_LT(elapsed, std::chrono::milliseconds(1400));
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
    EXPECT_NE(server.request().find(
                  "Host: 127.0.0.1:" + std::to_string(server.port()) + "\r\n"),
              std::string::npos);
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
    EXPECT_NE(server.request().find(
                  "Host: 127.0.0.1:" + std::to_string(server.port()) + "\r\n"),
              std::string::npos);

    buffer unused;
    EXPECT_EQ(inet::download("http://127.0.0.1:not-a-port/", unused, 1, 4), 0);
    EXPECT_EQ(inet::download("http://127.0.0.1:70000/", unused, 1, 4), 0);
}

TEST(InetLocalTest, DownloadBracketsIpv6LiteralInHostAuthority) {
    std::unique_ptr<LoopbackServer> server;
    try {
        server = std::make_unique<LoopbackServer>(
            std::vector<std::string>{
                "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\ncrl"},
            AF_INET6);
    }
    catch (const std::runtime_error&) {
        GTEST_SKIP() << "IPv6 loopback is unavailable";
    }

    buffer body;
    const auto url = "http://[::1]:" + std::to_string(server->port()) + "/crl";
    ASSERT_EQ(inet::download(url, body, 2, 6), 3);
    EXPECT_EQ(body.string_view(), "crl");
    EXPECT_NE(server->request().find(
                  "Host: [::1]:" + std::to_string(server->port()) + "\r\n"),
              std::string::npos);
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
