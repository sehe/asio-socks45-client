#include "socks5.hpp"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <iostream>
namespace asio = boost::asio;
namespace ssl  = boost::asio::ssl;

asio::awaitable<void> demo() {
    auto ex = co_await asio::this_coro::executor;

    ssl::context ssl_ctx(ssl::context_base::method::sslv23);
    ssl_ctx.set_verify_mode(ssl::verify_peer);
    ssl_ctx.set_default_verify_paths();

    using boost::asio::ip::tcp;
    ssl::stream<tcp::socket> ssl_socket(ex, ssl_ctx);

    auto& socket = ssl_socket.next_layer();

    socks5::TargetSpec target{"example.com", 443};

    co_await socks5::async_proxy_connect(
        socket, target, tcp::endpoint{{}, 1080}, asio::use_awaitable);

    socket.set_option(tcp::no_delay(true));

    co_await ssl_socket.async_handshake(
        ssl::stream_base::handshake_type::client, asio::use_awaitable);

    namespace beast = boost::beast;
    namespace http  = beast::http;
    {
        http::request<http::empty_body> req(http::verb::get, "/", 11);
        req.set(http::field::host, "example.com");
        req.prepare_payload();

        co_await http::async_write(ssl_socket, req, asio::use_awaitable);
    }
    {
        http::response<http::string_body> res;
        beast::flat_buffer                buf;
        co_await http::async_read(ssl_socket, buf, res, asio::use_awaitable);

        std::cout << res;
    }
}

int main()
{
    asio::thread_pool ioc(1); // single-threaded

    co_spawn(ioc, demo, [](std::exception_ptr ep) {
        try {
            if (ep) std::rethrow_exception(ep);
        } catch (boost::system::system_error const& se) {
            std::cerr << "Error: " << se.code().message() << std::endl;
        } catch (std::exception const& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    });

    ioc.join();
}
