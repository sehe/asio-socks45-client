#include "socks5.hpp"
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <iostream>

namespace ssl = boost::asio::ssl;
using namespace std::chrono_literals;

int main(int argc, char**) try {
    bool synchronous = argc > 1;

    boost::asio::thread_pool ioc(1);

    ssl::context ssl_ctx(ssl::context_base::method::sslv23);
    ssl_ctx.set_verify_mode(ssl::verify_peer);
    ssl_ctx.set_default_verify_paths();

    using boost::asio::ip::tcp;
    ssl::stream<tcp::socket> ssl_socket(ioc, ssl_ctx);

    auto& socket = ssl_socket.next_layer();

    socks5::TargetSpec target{"example.com", 443};

    if (!synchronous) {
        std::future<void> conn_result = socks5::async_proxy_connect(
            socket, target, tcp::endpoint{{}, 1080}, boost::asio::use_future);

        if (conn_result.wait_for(1s) == std::future_status::timeout) {
            socket.cancel();
            // no need to throw, `conn_result.get()` will give operation_aborted
        }

        conn_result.get(); // may throw error
    } else {
        // synchronously as well:
        socks5::proxy_connect(socket, target, tcp::endpoint{{}, 1080});
    }

    socket.set_option(tcp::no_delay(true));

    ssl_socket.handshake(ssl::stream_base::handshake_type::client);

    namespace beast = boost::beast;
    namespace http  = beast::http;
    {
        http::request<http::empty_body> req(http::verb::get, "/", 11);
        req.set(http::field::host, "example.com");
        req.prepare_payload();

        http::write(ssl_socket, req);
    }
    {
        http::response<http::string_body> res;
        beast::flat_buffer         buf;
        http::read(ssl_socket, buf, res);

        std::cout << res;
    }

    ioc.join();
} catch (boost::system::system_error const& e) {
    std::cerr << "Error: " << e.code().message() << std::endl;
} catch (std::exception const& e) {
    std::cerr << "Error: " << e.what() << std::endl;
}
