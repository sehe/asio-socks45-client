#include <boost/asio.hpp>
#include <boost/endian/arithmetic.hpp>

namespace socks5 { // threw in the kitchen sink for error codes
    using boost::system::error_category;
    using boost::system::error_code;
    using boost::system::error_condition;
    using boost::system::system_error;

    enum class result_code {
        ok                         = 0,
        invalid_version            = 1,
        disallowed                 = 2,
        auth_method_rejected       = 3,
        network_unreachable        = 4,
        host_unreachable           = 5,
        connection_refused         = 6,
        ttl_expired                = 7,
        command_not_supported      = 8,
        address_type_not_supported = 9,
        //
        failed = 99,
    };

    inline auto const& get_result_category() {
      struct impl : error_category {
        const char* name() const noexcept override { return "result_code"; }
        std::string message(int ev) const override {
          switch (static_cast<result_code>(ev)) {
          case result_code::ok:                         return "Success";
          case result_code::invalid_version:            return "SOCKS5 invalid reply version";
          case result_code::disallowed:                 return "SOCKS5 disallowed";
          case result_code::auth_method_rejected:       return "SOCKS5 no accepted authentication method";
          case result_code::network_unreachable:        return "SOCKS5 network unreachable";
          case result_code::host_unreachable:           return "SOCKS5 host unreachable";
          case result_code::connection_refused:         return "SOCKS5 connection refused";
          case result_code::ttl_expired:                return "SOCKS5 TTL expired";
          case result_code::command_not_supported:      return "SOCKS5 command not supported";
          case result_code::address_type_not_supported: return "SOCKS5 address type not supported";
          case result_code::failed:                     return "SOCKS5 general unexpected failure";
          default:                                      return "unknown error";
          }
        }
        error_condition
        default_error_condition(int ev) const noexcept override {
            return error_condition{ev, *this};
        }
        bool equivalent(int ev, error_condition const& condition)
            const noexcept override {
            return condition.value() == ev && &condition.category() == this;
        }
        bool equivalent(error_code const& error, int ev) const noexcept override
        {
            return error.value() == ev && &error.category() == this;
        }
      } const static instance;
      return instance;
    }

    inline error_code make_error_code(result_code se) {
        return error_code{
            static_cast<std::underlying_type<result_code>::type>(se),
            get_result_category()};
    }
} // namespace socks5

template <>
struct boost::system::is_error_code_enum<socks5::result_code>
    : std::true_type {};

namespace socks5 {
    struct TargetSpec {
        std::string host;
        uint16_t    port;
    };

    template <typename Proto> struct core_t {
        using Endpoint = typename Proto::endpoint;
        Endpoint _proxy;

        core_t(TargetSpec const& target, Endpoint proxy)
            : _proxy(proxy)
            , _request(target)
        {
        }
        core_t(Endpoint const& target, Endpoint proxy)
            : _proxy(proxy)
            , _request(target)
        {
        }

#pragma pack(push)
#pragma pack(1)
        enum class addr_type : uint8_t { IPv4 = 0x01, Domain = 0x03, IPv6 = 0x04 };
        enum class auth_method : uint8_t {
            none   = 0x00, // No authentication
            gssapi = 0x01, // GSSAPI (RFC 1961
            basic  = 0x02, // Username/password (RFC 1929)
            // 0x03–0x7F methods assigned by IANA[11]
            challenge_handshake = 0x03, // Challenge-Handshake Authentication Protocol
            challenge_response = 0x05,  // Challenge-Response Authentication Method
            ssl  = 0x06, // Secure Sockets Layer
            nds  = 0x07, // NDS Authentication
            maf  = 0x08, // Multi-Authentication Framework
            json = 0x09, // JSON Parameter Block
        };
        enum class version : uint8_t {
            none   = 0x00,
            socks4 = 0x04,
            socks5 = 0x05,
        };
        enum class proxy_command : uint8_t {
            connect       = 0x01,
            bind          = 0x02,
            udp_associate = 0x03,
        };
        enum class proxy_reply : uint8_t {
            succeeded                  = 0x00,
            general_failure            = 0x01,
            disallowed                 = 0x02,
            network_unreachable        = 0x03,
            host_unreachable           = 0x04,
            connection_refused         = 0x05,
            ttl_expired                = 0x06,
            command_not_supported      = 0x07,
            address_type_not_supported = 0x08,
        };

        using ipv4_octets = boost::asio::ip::address_v4::bytes_type;
        using ipv6_octets = boost::asio::ip::address_v6::bytes_type;
        using net_short   = boost::endian::big_uint16_t;

        struct {
            version     ver       = version::socks5;
            uint8_t     nmethods  = 0x01;
            auth_method method[1] = {auth_method::none};
        } _greeting;

        struct {
            version reply_version;
            uint8_t cauth;
        } _greeting_response;

        struct wire_address {
            addr_type type{};
            union {
                ipv4_octets              ipv4;
                ipv6_octets              ipv6;
                std::array<uint8_t, 256> domain{0}; // length prefixed
            } payload{};

            size_t var_length() const {
                return sizeof(type) + payload_length();
            }

            size_t payload_length() const
            {
                switch (type) {
                case addr_type::IPv4: return sizeof(payload.ipv4);
                case addr_type::IPv6: return sizeof(payload.ipv6);
                case addr_type::Domain:
                    assert(payload.domain[0] < payload.domain.max_size());
                    return 1 + payload.domain[0];
                }
                return 0;
            }
        };

        struct request_t {
            version       ver      = version::socks5;
            proxy_command cmd      = proxy_command::connect;
            uint8_t       reserved = 0;
            wire_address  var_address;
            net_short     port;

            // constructors
            request_t(Endpoint const& ep) : port(ep.port())
            {
                auto&& addr = ep.address();
                if (addr.is_v4()) {
                    var_address.type         = addr_type::IPv4;
                    var_address.payload.ipv4 = addr.to_v4().to_bytes();
                } else {
                    var_address.type         = addr_type::IPv6;
                    var_address.payload.ipv6 = addr.to_v6().to_bytes();
                }
            }

            request_t(TargetSpec const& s) : port(s.port) {
                std::string const domain = s.host;
                var_address.type         = addr_type::Domain;

                auto len = std::min(var_address.payload.domain.max_size() - 1,
                                    domain.length());
                assert(len == domain.length() || "domain truncated");
                var_address.payload.domain[0] = len;
                std::copy_n(domain.data(), len,
                            var_address.payload.domain.data() + 1);
            }

            auto buffers() const {
                return std::array {
                    boost::asio::buffer(this, offsetof(request_t, var_address)),
                    boost::asio::buffer(&var_address, var_address.var_length()),
                    boost::asio::buffer(&port, sizeof(port)),
                };
            }
        } _request;

        struct response_t {
            version      reply_version;
            proxy_reply  reply;
            uint8_t      reserved = 0x0;
            wire_address var_address {addr_type::IPv4};
            net_short    port;

            auto head_buffers() {
                return std::array{
                    boost::asio::buffer(this, offsetof(response_t, var_address) + sizeof(addr_type)),
                };
            }

            auto tail_buffers() { // depends on head_buffers being correctly received!
                return std::array{
                    boost::asio::buffer(&var_address.payload, var_address.payload_length()),
                    boost::asio::buffer(&port, sizeof(port)),
                };
            }
        } _response;
#pragma pack(pop)

        using const_buffer   = boost::asio::const_buffer;
        using mutable_buffer = boost::asio::mutable_buffer;

        auto greeting_buffers() const {
            return boost::asio::buffer(&_greeting, sizeof(_greeting));
        }

        auto greeting_response_buffers() {
            return boost::asio::buffer(&_greeting_response, sizeof(_greeting_response));
        }

        auto request_buffers() const { return _request.buffers(); }
        auto response_head_buffers() { return _response.head_buffers(); }
        auto response_tail_buffers() { return _response.tail_buffers(); }

        error_code get_greeting_result(error_code ec = {}) const {
            if (ec)
                return ec;
            if (_greeting_response.reply_version != version::socks5)
                return result_code::invalid_version;

            if (_greeting_response.cauth != 0) {
                return result_code::auth_method_rejected;
            }

            return result_code::ok;
        }

        error_code get_result(error_code ec = {}) const {
            if (ec)
                return ec;
            if (_response.reply_version != version::socks5)
                return result_code::invalid_version;

            switch (_response.reply) {
            case proxy_reply::succeeded:                  return result_code::ok;
            case proxy_reply::disallowed:                 return result_code::disallowed;
            case proxy_reply::network_unreachable:        return result_code::network_unreachable;
            case proxy_reply::host_unreachable:           return result_code::host_unreachable;
            case proxy_reply::connection_refused:         return result_code::connection_refused;
            case proxy_reply::ttl_expired:                return result_code::ttl_expired;
            case proxy_reply::command_not_supported:      return result_code::command_not_supported;
            case proxy_reply::address_type_not_supported: return result_code::address_type_not_supported;
            case proxy_reply::general_failure: break;
            }
            return result_code::failed;
        };

    };

    template <typename Socket> struct async_proxy_connect_op {
        using Proto         = typename Socket::protocol_type;
        using Endpoint      = typename Proto::endpoint;
        using executor_type = typename Socket::executor_type;
        auto get_executor() { return _socket.get_executor(); }

      private:
        std::unique_ptr<core_t<Proto>> _core;
        Socket&                        _socket;
        boost::asio::coroutine         _coro; // states

      public:
        template <typename EndpointOrSpec>
        async_proxy_connect_op(Socket& s, EndpointOrSpec target, Endpoint proxy)
            : _core(std::make_unique<core_t<Proto>>(target, proxy))
            , _socket(s)
        {
        }

#include <boost/asio/yield.hpp>
        template <typename Self>
        void operator()(Self& self, error_code ec = {}, size_t /*xfer*/ = 0)
        {
            reenter(_coro)
            {
                yield {
                    auto& proxy = _core->_proxy;
                    _socket.async_connect(proxy, std::move(self));
                }
                if (ec)
                    return self.complete(ec);

                yield {
                    auto buf = _core->greeting_buffers();
                    boost::asio::async_write(_socket, buf,
                                             std::move(self));
                }
                if (ec)
                    return self.complete(ec);

                yield {
                    auto buf = _core->greeting_response_buffers();
                    boost::asio::async_read(
                        _socket, buf,
                        boost::asio::transfer_exactly(buffer_size(buf)),
                        std::move(self));
                }

                ec = _core->get_greeting_result(ec);
                if (ec)
                    return self.complete(ec);

                yield {
                    auto buf = _core->request_buffers();
                    boost::asio::async_write(_socket, buf, std::move(self));
                }

                if (ec)
                    return self.complete(ec);

                yield {
                    auto buf = _core->response_head_buffers();
                    boost::asio::async_read(
                            _socket, buf, boost::asio::transfer_exactly(buffer_size(buf)),
                            std::move(self));
                }

                if (ec)
                    return self.complete(ec);

                yield {
                    auto buf = _core->response_tail_buffers();
                    boost::asio::async_read(
                            _socket, buf,
                            boost::asio::transfer_exactly(buffer_size(buf)),
                            std::move(self));
                }

                self.complete(_core->get_result(ec));
            }
        }
#include <boost/asio/unyield.hpp>
    };

    template <typename Socket, typename EndpointOrSpec,
              typename Endpoint = typename Socket::protocol_type::endpoint>
    void proxy_connect(Socket& s, EndpointOrSpec target, Endpoint proxy,
                             error_code& ec)
    {
        core_t<typename Socket::protocol_type> core(target, proxy);
        ec.clear();

        s.connect(core._proxy, ec);

        if (!ec)
            boost::asio::write(s, core.greeting_buffers(), ec);

        using boost::asio::transfer_exactly;
        if (!ec) {
            auto buf = core.greeting_response_buffers();
            boost::asio::read(s, buf, transfer_exactly(buffer_size(buf)), ec);
        }
        ec = core.get_greeting_result(ec);

        if (!ec) {
            boost::asio::write(s, core.request_buffers(), ec);
        }

        if (!ec) {
            auto buf = core.response_head_buffers();
            boost::asio::read(s, buf, transfer_exactly(buffer_size(buf)), ec);
        }
        if (!ec) {
            auto buf = core.response_tail_buffers();
            boost::asio::read(s, buf, transfer_exactly(buffer_size(buf)), ec);
        }

        ec = core.get_result(ec);
    }

    template <typename Socket, typename EndpointOrSpec,
              typename Endpoint = typename Socket::protocol_type::endpoint>
    void proxy_connect(Socket& s, EndpointOrSpec target, Endpoint proxy)
    {
        error_code ec;
        proxy_connect(s, target, proxy, ec);
        if (ec.failed())
            throw system_error(ec);
    }

    template <typename Socket, typename Token, typename EndpointOrSpec,
              typename Endpoint = typename Socket::protocol_type::endpoint>
    auto async_proxy_connect(Socket& s, EndpointOrSpec target, Endpoint proxy,
                             Token&& token)
    {
        return boost::asio::async_compose<Token, void(error_code)>(
            async_proxy_connect_op<Socket>{s, target, proxy}, token, s);
    }
} // namespace socks5
