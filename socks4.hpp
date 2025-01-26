#include <boost/asio.hpp>
#include <boost/core/ignore_unused.hpp>
#include <boost/endian/arithmetic.hpp>

namespace socks4 { // threw in the kitchen sink for error codes
#ifdef STANDALONE_ASIO
    using std::error_category;
    using std::error_code;
    using std::error_condition;
    using std::system_error;
#else
    namespace asio = boost::asio;
    using boost::system::error_category;
    using boost::system::error_code;
    using boost::system::error_condition;
    using boost::system::system_error;
#endif

    enum class result_code {
        ok                 = 0,
        invalid_version    = 1,
        rejected_or_failed = 3,
        need_identd        = 4,
        unconirmed_userid  = 5,
		//
		failed = 99,
    };

    auto const& get_result_category() {
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

    error_code make_error_code(result_code se) {
        return error_code{
            static_cast<std::underlying_type<result_code>::type>(se),
            get_result_category()};
    }
} // namespace socks4

template <>
struct boost::system::is_error_code_enum<socks4::result_code>
    : std::true_type {};

namespace socks4 {
    using namespace std::placeholders;

    template <typename Endpoint> struct core_t {
        Endpoint _target;
        Endpoint _proxy;

        core_t(Endpoint target, Endpoint proxy)
            : _target(target)
            , _proxy(proxy) {}

#pragma pack(push)
#pragma pack(1)
        using ipv4_octets = boost::asio::ip::address_v4::bytes_type;
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

        using const_buffer   = boost::asio::const_buffer;
        using mutable_buffer = boost::asio::mutable_buffer;

        auto request_buffers(char const* szUserId) const {
            return std::array<const_buffer, 2>{
                boost::asio::buffer(&_request, sizeof(_request)),
                boost::asio::buffer(szUserId, strlen(szUserId) + 1)};
        }

        auto response_buffers() {
            return boost::asio::buffer(&_response, sizeof(_response));
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

    template <typename Socket, typename Completion>
    struct async_proxy_connect_op {
        using Endpoint      = typename Socket::protocol_type::endpoint;
        using executor_type = typename Socket::executor_type;
        auto get_executor() { return _socket.get_executor(); }

      private:
        core_t<Endpoint> _core;
        Socket&          _socket;
        std::string      _userId;
        Completion       _handler;

      public:
        async_proxy_connect_op(Completion handler, Socket& s, Endpoint target,
                               Endpoint proxy, std::string user_id = {})
            : _core(target, proxy)
            , _socket(s)
            , _userId(std::move(user_id))
            , _handler(std::move(handler)) {}

        using Self = std::unique_ptr<async_proxy_connect_op>;
        void init(Self&& self) { operator()(self, INIT{}); }

      private:
        // states
        struct INIT{};
        struct CONNECT{};
        struct SENT{};
        struct ONRESPONSE{};

        struct Binder {
            Self _self;
            template <typename... Args>
            decltype(auto) operator()(Args&&... args) {
                return (*_self)(_self, std::forward<Args>(args)...);
            }
        };

        void operator()(Self& self, INIT) {
            _socket.async_connect(_core._proxy,
               std::bind(Binder{std::move(self)}, CONNECT{}, _1));
        }

        void operator()(Self& self, CONNECT, error_code ec) {
            if (ec) return _handler(ec);
            boost::asio::async_write(
                _socket,
                _core.request_buffers(_userId.c_str()),
                std::bind(Binder{std::move(self)}, SENT{}, _1, _2));
        }

        void operator()(Self& self, SENT, error_code ec, size_t xfer) {
            boost::ignore_unused(xfer);
            if (ec) return _handler(ec);
            auto buf = _core.response_buffers();
            boost::asio::async_read(
                _socket, buf, boost::asio::transfer_exactly(buffer_size(buf)),
                std::bind(Binder{std::move(self)}, ONRESPONSE{}, _1, _2));
        }

        void operator()(Self& self, ONRESPONSE, error_code ec, size_t xfer) {
            boost::ignore_unused(self, xfer);
            _handler(_core.get_result(ec));
        }
    };

    template <typename Socket,
              typename Endpoint = typename Socket::protocol_type::endpoint>
    error_code proxy_connect(Socket& s, Endpoint ep, Endpoint proxy,
                             std::string const& user_id, error_code& ec) {
        core_t<Endpoint> core(ep, proxy);
        ec.clear();

        s.connect(core._proxy, ec);

        if (!ec)
            boost::asio::write(s, core.request_buffers(user_id.c_str()),
                               ec);
        auto buf = core.response_buffers();
        if (!ec)
            boost::asio::read(s, core.response_buffers(),
                              boost::asio::transfer_exactly(buffer_size(buf)), ec);

        return ec = core.get_result(ec);
    }

    template <typename Socket,
              typename Endpoint = typename Socket::protocol_type::endpoint>
    void proxy_connect(Socket& s, Endpoint ep, Endpoint proxy,
                       std::string const& user_id = "") {
        error_code ec;
        if (proxy_connect(s, ep, proxy, user_id, ec))
            throw system_error(ec);
    }

    template <typename Socket, typename Token,
              typename Endpoint = typename Socket::protocol_type::endpoint>
    auto async_proxy_connect(Socket& s, Endpoint ep, Endpoint proxy,
                       std::string user_id, Token&& token) {
        using Result = asio::async_result<std::decay_t<Token>, void(error_code)>;
        using Completion = typename Result::completion_handler_type;

        Completion completion(std::forward<Token>(token));
        Result     result(completion);

        using Op = async_proxy_connect_op<Socket, Completion>;
        // make an owning self ptr, to serve a unique async chain
        auto self =
            std::make_unique<Op>(completion, s, ep, proxy, std::move(user_id));
        self->init(std::move(self));
        return result.get();
    }

    template <typename Socket, typename Token,
              typename Endpoint = typename Socket::protocol_type::endpoint>
    auto async_proxy_connect(Socket& s, Endpoint ep, Endpoint proxy, Token&& token) {
        return async_proxy_connect<Socket, Token, Endpoint>(
            s, ep, proxy, "", std::forward<Token>(token));
    }
} // namespace socks4
