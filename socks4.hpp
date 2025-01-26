#include <boost/asio.hpp>
#include <boost/endian/arithmetic.hpp>

namespace socks4 { // threw in the kitchen sink for error codes
    namespace asio = boost::asio;
    using boost::system::error_category;
    using boost::system::error_code;
    using boost::system::error_condition;
    using boost::system::system_error;

    enum class result_code {
        ok                 = 0,
        invalid_version    = 1,
        rejected_or_failed = 3,
        need_identd        = 4,
        unconirmed_userid  = 5,
		//
		failed = 99,
    };

    inline auto const& get_result_category() {
      struct impl : error_category {
        const char* name() const noexcept override { return "result_code"; }
        std::string message(int ev) const override {
          switch (static_cast<result_code>(ev)) {
          case result_code::ok:                 return "Success";
          case result_code::invalid_version:    return "SOCKS4 invalid reply version";
          case result_code::rejected_or_failed: return "SOCKS4 rejected or failed";
          case result_code::need_identd:        return "SOCKS4 unreachable (client not running identd)";
          case result_code::unconirmed_userid:  return "SOCKS4 identd could not confirm user ID";
          case result_code::failed:             return "SOCKS4 general unexpected failure";
          default: return "unknown error";
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
        bool equivalent(error_code const& error,
                        int ev) const noexcept override {
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
} // namespace socks4

template <>
struct boost::system::is_error_code_enum<socks4::result_code>
    : std::true_type {};

namespace socks4 {
    template <typename Endpoint> struct core_t {
        Endpoint _target;
        Endpoint _proxy;

        core_t(Endpoint target, Endpoint proxy)
            : _target(target)
            , _proxy(proxy) {}

#pragma pack(push)
#pragma pack(1)
        using ipv4_octets = asio::ip::address_v4::bytes_type;
        using net_short   = boost::endian::big_uint16_t;

        struct alignas(void*) Req {
            uint8_t     version = 0x04;
            uint8_t     cmd     = 0x01;
            net_short   port;
            ipv4_octets address;
        } _request{0x04, 0x01, _target.port(),
                   _target.address().to_v4().to_bytes()};

        struct alignas(void*) Res {
            uint8_t     reply_version;
            uint8_t     status;
            net_short   port;
            ipv4_octets address;
        } _response;
#pragma pack(pop)

        using const_buffer   = asio::const_buffer;
        using mutable_buffer = asio::mutable_buffer;

        auto request_buffers(char const* szUserId) const {
            return std::array<const_buffer, 2>{
                asio::buffer(&_request, sizeof(_request)),
                asio::buffer(szUserId, strlen(szUserId) + 1)};
        }

        auto response_buffers() {
            return asio::buffer(&_response, sizeof(_response));
        }

        error_code get_result(error_code ec = {}) const {
            if (ec)
                return ec;
            if (_response.reply_version != 0)
                return result_code::invalid_version;

            switch (_response.status) {
              case 0x5a: return result_code::ok; // Request grantd
              case 0x5B: return result_code::rejected_or_failed;
              case 0x5C: return result_code::need_identd;
              case 0x5D: return result_code::unconirmed_userid;
            }

            return result_code::failed;
        }
    };

    template <typename Socket>
    struct async_proxy_connect_op {
        using Endpoint      = typename Socket::protocol_type::endpoint;
        using executor_type = typename Socket::executor_type;
        auto get_executor() { return _socket.get_executor(); }

      private:
        std::unique_ptr<core_t<Endpoint>> _core;
        Socket&                           _socket;
        std::string                       _userId;
        asio::coroutine                   _coro;

      public:
        async_proxy_connect_op(Socket& s, Endpoint target, Endpoint proxy,
                               std::string user_id = {})
            : _core(std::make_unique<core_t<Endpoint>>(target, proxy))
            , _socket(s)
            , _userId(std::move(user_id))
        {
        }

#include <boost/asio/yield.hpp>
        template <typename Self>
        void operator()(Self& self, error_code ec = {}, size_t /*xfer*/ = 0)
        {
            reenter(_coro) {
                yield {
                    auto const& proxy = _core->_proxy;
                    _socket.async_connect(proxy, std::move(self));
                }
                if (ec)
                    return self.complete(ec);

                yield {
                    auto buf = _core->request_buffers(_userId.c_str());
                    asio::async_write(_socket, buf, std::move(self));
                }
                if (ec)
                    return self.complete(ec);

                yield {
                    auto buf = _core->response_buffers();
                    asio::async_read(_socket, buf,
                                     asio::transfer_exactly(buffer_size(buf)),
                                     std::move(self));
                }
                self.complete(_core->get_result(ec));
            }
        }
    };
#include <boost/asio/unyield.hpp>

    template <typename Socket,
              typename Endpoint = typename Socket::protocol_type::endpoint>
    void proxy_connect(Socket& s, Endpoint ep, Endpoint proxy,
                       std::string const& user_id, error_code& ec) {
        core_t<Endpoint> core(ep, proxy);
        ec.clear();

        s.connect(core._proxy, ec);

        if (!ec)
            asio::write(s, core.request_buffers(user_id.c_str()),
                               ec);
        auto buf = core.response_buffers();
        if (!ec)
            asio::read(s, core.response_buffers(),
                              asio::transfer_exactly(buffer_size(buf)), ec);

        ec = core.get_result(ec);
    }

    template <typename Socket,
              typename Endpoint = typename Socket::protocol_type::endpoint>
    void proxy_connect(Socket& s, Endpoint ep, Endpoint proxy,
                       std::string const& user_id = "") {
        error_code ec;
        proxy_connect(s, ep, proxy, user_id, ec);
        if (ec.failed())
            throw system_error(ec);
    }

    template <typename Socket, typename Token,
              typename Endpoint = typename Socket::protocol_type::endpoint>
    auto async_proxy_connect(Socket& s, Endpoint ep, Endpoint proxy,
                             std::string user_id, Token&& token) {
        return asio::async_compose<Token, void(error_code)>(
            async_proxy_connect_op<Socket>{s, ep, proxy, std::move(user_id)},
            token, s);
    }

    template <typename Socket, typename Token,
              typename Endpoint = typename Socket::protocol_type::endpoint>
    auto async_proxy_connect(Socket& s, Endpoint ep, Endpoint proxy, Token&& token) {
        return async_proxy_connect<Socket, Token, Endpoint>(
            s, ep, proxy, "", std::forward<Token>(token));
    }
} // namespace socks4
