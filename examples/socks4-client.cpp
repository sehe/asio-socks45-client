#include "socks4.hpp"

#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <iostream>

int main(int argc, char**)
{
    bool synchronous = argc > 1;

    using boost::asio::ip::tcp;
    boost::asio::thread_pool ctx(1); // just one thread will do

    tcp::socket   sock{ctx};
    tcp::endpoint //
        target{boost::asio::ip::make_address("173.203.57.63"), 80},
        proxy{{}, 1080};

    try {
        if (!synchronous) {
            std::cerr << "Using asynchronous interface" << std::endl;
            // using the async interface (still emulating synchronous by using
            // future for brevity of this demo)
            auto fut = socks4::async_proxy_connect(sock, target, proxy,
                                                   boost::asio::use_future);

            fut.get(); // throws system_error if failed
        } else {
            std::cerr << "Using synchronous interface" << std::endl;
            socks4::proxy_connect(sock, target,
                                  proxy); // throws system_error if failed
        }

        // Now do a request using beast
        namespace beast = boost::beast;
        namespace http  = beast::http;

        {
            http::request<http::empty_body> req(http::verb::get, "/", 11);
            req.set(http::field::host, "coliru.stacked-crooked.com");
            req.set(http::field::connection, "close");
            http::write(sock, req);
        }

        {
            http::response<http::string_body> res;
            beast::flat_buffer                buf;

            http::read(sock, buf, res);
            std::cout << "\n-------\nResponse: " << res << "\n";
        }
    } catch (socks4::system_error const& se) {
        std::cerr << "Error: " << se.code().message() << std::endl;
    }

    ctx.join();
}
