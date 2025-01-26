# asio-socks45-client
SOCKS4 and SOCKS5 clients for (Boost) Asio

Originally authored in response to StaockOverflow questions:

 - [SOCKS4 With Boost Asio](https://stackoverflow.com/a/67320567/85371)
 - [Is there a native support for proxy connection via socks5 for boost::asio?](https://stackoverflow.com/a/69781530/85371)

The interfaces are sync/async, with a shared underlying implementation.

## SOCK4 Usage

```c++
tcp::socket sock{ctx};
tcp::endpoint
    proxy{{}, 1080},
    target{ip::make_address("173.203.57.63"), 80};

std::cerr << "Using synchronous interface" << std::endl;
socks4::proxy_connect(sock, target,
                      proxy); // throws system_error if failed
```
                           
Or using the async overload:

```c++
// using the async interface (still emulating synchronous by using
// future for brevity of this demo)
auto fut = socks4::async_proxy_connect(sock, target, proxy,
                                       boost::asio::use_future);

fut.get(); // throws system_error if failed
```

> _SOCKS4a (which also allows name resolution) is not implemented. There seems to be little support._

## SOCKS5 Usage

The SOCKS5 interface accepts a qualified domain name as well as resolved end-point.

```c++
socks5::TargetSpec target("example.com", 443);

std::future<void> conn_result = socks5::async_proxy_connect(
    socket, target, tcp::endpoint{{}, 1080}, ba::use_future);
```

Again, synchronous connect is also supported:

```c++
socks5::proxy_connect(socket, target, tcp::endpoint{{}, 1080});
```

> The BIND and UDP ASSOCIATE commands are not implemented.

## DEMO

The answers show live demos. Here's a parallel demo of all SOCKS4 and SOCKS5
example programs demo using an openssh client as the SOCKS server:

![live demo](/doc/demos.gif?raw=true "live demo animations")
