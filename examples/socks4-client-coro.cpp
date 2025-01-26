#include "socks4.hpp"

#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <iostream>
namespace asio = boost::asio;
using boost::asio::ip::tcp;

asio::awaitable<void> socks4_client() {
    auto        ex = co_await asio::this_coro::executor;
    tcp::socket sock{ex};
    tcp::endpoint //
        target{asio::ip::make_address("173.203.57.63"), 80},
        proxy{{}, 1080};

    co_await socks4::async_proxy_connect(sock, target, proxy,
                                         asio::use_awaitable);

    // Now do a request using beast
    namespace beast = boost::beast;
    namespace http  = beast::http;

    {
        http::request<http::empty_body> req(http::verb::get, "/", 11);
        req.set(http::field::host, "coliru.stacked-crooked.com");
        req.set(http::field::connection, "close");
        co_await http::async_write(sock, req, asio::use_awaitable);
    }

    {
        http::response<http::string_body> res;
        beast::flat_buffer                buf;

        co_await http::async_read(sock, buf, res, asio::use_awaitable);
        std::cout << "\n-------\nResponse: " << res << "\n";
    }
}

int main() {
    asio::thread_pool ctx(1); // just one thread will do

    co_spawn(ctx, socks4_client(), [](std::exception_ptr ep) {
        try {
            if (ep)
                std::rethrow_exception(ep);
        } catch (socks4::system_error const& se) {
            std::cerr << "Error: " << se.code().message() << std::endl;
        }
    });

    ctx.join();
}
