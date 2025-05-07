#include "io_base.hpp"
#include "log.hpp"

#include "helper.hpp"
#include "json.hpp"

#include <http_parser.h>

#include <algorithm>
#include <boost/asio.hpp>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <tuple>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include <inttypes.h>
#include <sys/queue.h>

using boost::asio::ip::tcp;
using json = nlohmann::ordered_json;

template <typename... Args>
static void http_log(log_level level, const char * format, Args... args)
{
    static log_level log_level_ = LOG_TRACE;
    if (level >= log_level_)
    {
        log(format, args...);
    }
}

template <typename... Args>
static void HTTP_LOG_TRACE(const char * format, Args... args)
{
    http_log(LOG_TRACE, format, args...);
}

template <typename... Args>
static void HTTP_LOG_DEBUG(const char * format, Args... args)
{
    http_log(LOG_DEBUG, format, args...);
}

template <typename... Args>
static void HTTP_LOG_INFO(const char * format, Args... args)
{
    http_log(LOG_INFO, format, args...);
}

template <typename... Args>
static void HTTP_LOG_WARN(const char * format, Args... args)
{
    http_log(LOG_WARN, format, args...);
}

template <typename... Args>
static void HTTP_LOG_ERROR(const char * format, Args... args)
{
    http_log(LOG_ERROR, format, args...);
}

struct logger_function_trace
{
public:
    logger_function_trace(std::string cls_, std::string func_) : cls(cls_), func(func_)
    {
        HTTP_LOG_TRACE("%s:%s ENTER\n", cls.c_str(), func.c_str());
    }

    ~logger_function_trace() { HTTP_LOG_TRACE("%s:%s LEAVE\n", cls.c_str(), func.c_str()); }

private:
    const std::string cls;
    const std::string func;
};

#define HTTP_LOG_TRACE_FUNCTION logger_function_trace x_trace_123_("", __FUNCTION__);
#define HTTP_TRACE_CLS_FUNC_TRACE logger_function_trace x_trace_123_(typeid(this).name(), __FUNCTION__);

// forward declaration
namespace http {
enum class method;
}

namespace std {
template <>
class hash<std::tuple<http::method, std::string>>
{
public:
    std::size_t operator()(const std::tuple<http::method, std::string> & s) const
    {
        std::size_t h1 = std::hash<int>{}(static_cast<int>(std::get<0>(s)));
        std::size_t h2 = std::hash<std::string>{}(std::get<1>(s));
        return h1 ^ h2;
    }
};

template <>
struct equal_to<std::tuple<http::method, std::string>>
{
    bool operator()(const std::tuple<http::method, std::string> & lhs, const std::tuple<http::method, std::string> & rhs) const
    {
        return (std::get<0>(lhs) == std::get<0>(rhs)) and (std::get<1>(lhs) == std::get<1>(rhs));
    }
};

} // namespace std

namespace http {

class response;
class request;
enum class status_code;

enum class status_code
{
    switch_protocol = 101,

    ok       = 200,
    accepted = 202,

    bad_request  = 400,
    unauthorized = 401,
    forbiden     = 403,
    not_found    = 404,

    internal_error = 500,
    timeout        = 504
};

enum class method
{
    del = 0,
    get,
    head,
    post,
    put,
    option = 6,
};

inline std::string get_status_code_msg(status_code code_)
{
    if (code_ == status_code::ok)
        return "OK";

    if (code_ == status_code::not_found)
        return "Not Found";

    return "Internal";
}

// i.e HTTP/1.1 200 OK
inline std::string make_status_line(status_code code, std::string msg = "")
{
    std::string status_line = "HTTP/1.1 ";
    status_line += std::to_string(static_cast<int>(code)) + " " + (msg == "" ? get_status_code_msg(code) : msg);
    return status_line;
}

inline int http_parser_get_major(http_parser * parser)
{
    return parser->http_major;
}

inline int http_parser_get_minor(http_parser * parser)
{
    return parser->http_minor;
}

inline method http_parser_get_method(http_parser * parser)
{
    return static_cast<method>(static_cast<int>(parser->method));
}

class request
{
public:
    request()                             = delete;
    request(request & other)              = delete;
    request & operator=(request & other)  = delete;
    request & operator=(request && other) = delete;

    request(request && other)
    {
        uri_path = other.uri_path;
        major    = other.major;
        minor    = other.minor;
        method_  = other.method_;
        headers_ = std::move(other.headers_);
        body_    = std::move(other.body_);

        other.is_owning = false;
        is_owning       = true;
    }

    template <class T>
    request(T parser)
    {
        major   = http_parser_get_major(parser);
        minor   = http_parser_get_minor(parser);
        method_ = http_parser_get_method(parser);
    }

    template <class T>
    request(T parser, std::string _uri_path) : request(parser)
    {
        uri_path = _uri_path;
    }

    template <class T>
    request(T parser, std::string _uri_path, std::unordered_map<std::string, std::string> && _header, std::string _body) :
        request(parser, _uri_path)
    {
        headers_ = std::move(_header);
        body_    = _body;
    }

    const std::string & get_uri_path() { return uri_path; }
    const method & get_method() const { return method_; }
    const std::string & get_header(std::string header_key) { return headers_[header_key]; }
    const std::string & body() const { return body_; }

    ~request() {}

private:
    std::string uri_path;
    method method_;
    char major;
    char minor;
    std::unordered_map<std::string, std::string> headers_;
    std::string body_;

    bool is_owning;

    friend class response;
};

class response
{
    class base
    {
    public:
        base() {};
        base(const base & other) = delete;

        virtual void do_write(std::function<void(boost::system::error_code, std::size_t)>) = 0;
        virtual void do_write()                                                            = 0;
        virtual uint32_t session_id()                                                      = 0;
        virtual ~base() {}
    };

    template <typename T>
    class wrapper : public base
    {
    public:
        wrapper(const wrapper & other) = delete;

        wrapper(wrapper && other) { p = other.p; }
        wrapper(std::weak_ptr<T> p_) { p = p_; }

        void do_write(std::function<void(boost::system::error_code, std::size_t)> on_write)
        {
            if (auto w_p = p.lock())
            {
                w_p->do_write(on_write);
            }
        }

        void do_write()
        {
            if (auto w_p = p.lock())
            {
                w_p->do_write();
            }
        }

        uint32_t session_id()
        {
            if (auto w_p = p.lock())
            {
                return w_p->get_session_id();
            }

            return std::numeric_limits<uint32_t>::max();
        }

        ~wrapper() {}

        std::weak_ptr<T> p;
    };

public:
    response()                              = delete;
    response & operator=(response & other)  = delete;
    response & operator=(response && other) = delete;

    template <class T>
    response(std::weak_ptr<T> connect_, request && req_, boost::asio::streambuf & _out_buffer) :
        req(std::move(req_)), os(&_out_buffer)
    {
        result_            = status_code::ok;
        major              = req_.major;
        minor              = req_.minor;
        headers_["server"] = "av_connect";

        base_     = new wrapper<T>(connect_);
        is_owning = true;
    }

    response(response && other) : req(std::move(other.req)), base_(other.base_), os(other.os.rdbuf())
    {
        result_         = other.result_;
        headers_        = std::move(other.headers_);
        major           = other.major;
        minor           = other.minor;
        body_           = std::move(other.body_);
        is_owning       = other.is_owning;
        other.is_owning = false;
    }

    status_code & result() { return result_; }

    void set_header(std::string header_key, std::string header_val)
    {
        std::transform(header_key.begin(), header_key.end(), header_key.begin(), [](unsigned char c) { return std::tolower(c); });

        headers_[header_key] = header_val;
    }

    uint32_t session_id() { return base_->session_id(); }

    void set_content(std::string _body, std::string content_type = "text/plain")
    {
        body_                    = _body;
        headers_["content-type"] = content_type;
    }

    void end();

    /* chunk writing*/
    void chunk_start();

    void chunk_write(std::string chunk_data);

    void chunk_end();

    /* event source write*/
    void event_source_start()
    {
        if (is_owning)
        {
            // headers_["transfer-encoding"] = "chunked";
            headers_["content-type"] = "text/event-stream";
            headers_["connection"]   = "timeout=5, max=5";
            chunk_start();
        }
    }

    void event_source_oai_end()
    {
        auto self      = std::shared_ptr<response>(new response(*this));
        auto _do_write = [self](boost::system::error_code ec, std::size_t len) { self->chunk_end(); };

        static const std::string oai_end_chunk = "data: [DONE]\n\n";
        self->os << std::hex << oai_end_chunk.size() << "\r\n";
        self->os << oai_end_chunk << "\r\n";
        self->base_->do_write(_do_write);
    }

    request & reqwest() { return req; }

    ~response()
    {
        if (is_owning)
        {
            delete base_;
        }
    }

private:
    response(response & other) : req(std::move(other.req)), base_(other.base_), os(other.os.rdbuf())
    {

        result_         = other.result_;
        headers_        = std::move(other.headers_);
        major           = other.major;
        minor           = other.minor;
        body_           = std::move(other.body_);
        is_owning       = other.is_owning;
        other.is_owning = false;
    }

    bool is_owning;
    request req;
    status_code result_;
    char major;
    char minor;
    std::unordered_map<std::string, std::string> headers_;
    std::string body_;

    std::ostream os;
    base * base_;

    std::mutex chunk_mutex;
};

class session : public std::enable_shared_from_this<session>
{
    struct internal_wrapper
    {
        internal_wrapper(std::shared_ptr<session> _p) { p_session = _p; }

        internal_wrapper(const internal_wrapper & other) { p_session = other.p_session; }

        std::shared_ptr<session> p_session;
    };

    enum
    {
        max_length = 102400
    };

public:
    session(tcp::socket socket, std::function<void(response)> _handler) : socket_(std::move(socket)), handler(_handler)
    {
        data_len          = 0;
        is_request_parsed = false;
        std::memset(&settings, 0, sizeof settings);
    }

    session(tcp::socket socket, std::function<void(response)> _handler, uint64_t _session_id) : session(std::move(socket), _handler)
    {
        session_id = _session_id;
    }

    uint64_t get_session_id() { return session_id; }

    void start()
    {
        static http_data_cb llhttp_on_uri = [](http_parser * _http_parser, const char * at, size_t length) -> int {
            internal_wrapper * wrapper_ = (internal_wrapper *) _http_parser->data;
            auto self                   = wrapper_->p_session;
            self->uri                   = std::string(at, length);
            return 0;
        };

        static http_data_cb llhttp_on_header_field = [](http_parser * _http_parser, const char * at, size_t length) -> int {
            internal_wrapper * wrapper_ = (internal_wrapper *) _http_parser->data;
            auto self                   = wrapper_->p_session;

            self->header_field = std::string((char *) at, length);
            std::transform(self->header_field.begin(), self->header_field.end(), self->header_field.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            return 0;
        };

        static http_data_cb llhttp_on_header_value = [](http_parser * _http_parser, const char * at, size_t length) -> int {
            internal_wrapper * wrapper_ = (internal_wrapper *) _http_parser->data;
            auto self                   = wrapper_->p_session;

            self->headers[self->header_field] = std::string((char *) at, length);
            std::string & header_field_val    = self->headers[self->header_field];
            std::transform(header_field_val.begin(), header_field_val.end(), header_field_val.begin(),
                           [](unsigned char c) { return std::tolower(c); });

            return 0;
        };

        static http_data_cb llhttp_on_body = [](http_parser * _http_parser, const char * at, size_t length) -> int {
            internal_wrapper * wrapper_ = (internal_wrapper *) _http_parser->data;
            auto self                   = wrapper_->p_session;

            self->in_buffer.consume(self->in_buffer.size());
            std::ostream os(&self->in_buffer);
            os << std::string_view((char *) at, length);

            return 0;
        };

        static http_cb llhttp_on_message_complete = [](http_parser * _http_parser) -> int {
            internal_wrapper * wrapper_ = (internal_wrapper *) _http_parser->data;
            auto self                   = wrapper_->p_session;

            self->is_request_parsed = true;
            self->on_read(_http_parser);

            return 0;
        };

        settings.on_header_field     = llhttp_on_header_field;
        settings.on_header_value     = llhttp_on_header_value;
        settings.on_url              = llhttp_on_uri;
        settings.on_body             = llhttp_on_body;
        settings.on_message_complete = llhttp_on_message_complete;
        parser.data                  = new internal_wrapper(shared_from_this());

        do_read();
    }

    void do_write(std::function<void(boost::system::error_code, std::size_t)> on_write)
    {
        HTTP_TRACE_CLS_FUNC_TRACE
        auto on_write_ = [self(shared_from_this()), on_write](boost::system::error_code ec, std::size_t size) {
            self->out_buffer.consume(self->out_buffer.size());
            on_write(ec, size);
        };

        boost::asio::async_write(socket_, boost::asio::buffer(out_buffer.data(), out_buffer.size()), on_write_);
    }

    void do_write()
    {
        HTTP_TRACE_CLS_FUNC_TRACE
        auto self(shared_from_this());
        boost::asio::async_write(socket_, boost::asio::buffer(out_buffer.data(), out_buffer.size()),
                                 [self](boost::system::error_code ec, std::size_t /*length*/) {
                                     if (!ec)
                                     {
                                         self->out_buffer.consume(self->out_buffer.size());
                                         self->do_read();
                                     }
                                 });
    }

private:
    void do_read()
    {
        HTTP_TRACE_CLS_FUNC_TRACE
        auto self(shared_from_this());

        socket_.async_read_some(
            boost::asio::buffer(&data_[0] + data_len, max_length), [this, self](boost::system::error_code ec, std::size_t length) {
                if (!ec)
                {
                    self->data_len += length;
                    is_request_parsed = false;
                    http_parser_init(&parser, HTTP_BOTH);
                    size_t return_size = http_parser_execute(&(self->parser), &(self->settings), self->data_, self->data_len);
                    if (not is_request_parsed)
                    {
                        self->do_read();
                    }
                    else if (return_size < self->data_len)
                    {
                        std::memcpy(self->data_, self->data_ + return_size, self->data_len - return_size);
                    }
                    else if (is_request_parsed)
                    {
                        self->uri      = "";
                        self->data_len = 0;
                    }
                }
                else
                {
                    // todo: need to handle eof
                    // std::cout << "[DEBUG] hummm " << ec.message() << std::endl;
                }
            });
    }

    void on_read(http_parser * _http_parser)
    {
        HTTP_TRACE_CLS_FUNC_TRACE
        response res{ std::weak_ptr<session>(shared_from_this()),
                      request(_http_parser, uri, std::move(headers), { (char *) in_buffer.data().data(), in_buffer.size() }),
                      out_buffer };
        handler(std::move(res));
    }

    tcp::socket socket_;
    int data_len;
    char data_[max_length];
    bool is_request_parsed;
    std::string uri;
    std::string header_field;
    std::unordered_map<std::string, std::string> headers;

    boost::asio::streambuf in_buffer;
    boost::asio::streambuf out_buffer;
    http_parser parser;
    http_parser_settings settings;
    std::function<void(response)> handler;
    uint32_t session_id;
};

template <class T>
class server
{
public:
    server(boost::asio::io_context & io_context, unsigned short port, std::function<void(response)> _handler) :
        handler(_handler), acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
    {
        session_cnt = 0;
        // HTTP_LOG_INFO("session_cnt: %d \n", session_cnt);
        do_accept();
    }

private:
    void do_accept()
    {
        acceptor_.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
            if (!ec)
            {
                HTTP_LOG_INFO("New session is created with id: %ul\n", session_cnt);
                std::make_shared<T>(std::move(socket), handler, session_cnt)->start();
            }
            session_cnt++;
            do_accept();
        });
    }

    tcp::acceptor acceptor_;
    std::function<void(response)> handler;
    uint64_t session_cnt;
};

static auto make_server(unsigned short port, std::function<void(response)> _handler)
{
    return server<session>{ io_context::ioc, port, _handler };
}

static void start_server(unsigned short port, std::function<void(response)> _handler)
{
    auto server_ = make_server(port, _handler);
    io_context::ioc.run();
}

// route

class route
{

public:
    route()
    {
        handle_not_found = [](response res) {
            res.result() = http::status_code::not_found;
            res.end();
        };
    }

    void operator()(response res)
    {
        http::method method_ = res.reqwest().get_method();
        std::string uri      = res.reqwest().get_uri_path();
        if (method_ == http::method::option and handle_option) // handle option
            handle_option(std::move(res));
        if (auto handler = route_map[std::tuple<method, std::string>{ method_, uri }]; handler and method_ != http::method::option)
        { // handle get, post, put, del (other than option)
            res.set_header("Access-Control-Allow-Origin", res.reqwest().get_header("origin"));
            handler(std::move(res));
        }
        else
            handle_not_found(std::move(res));
    }

    void get(std::string path, std::function<void(response)> _func)
    {
        route_map.emplace(std::tuple<method, std::string>(method::get, path), _func);
    }

    void post(std::string path, std::function<void(response)> _func)
    {
        route_map.emplace(std::tuple<method, std::string>(method::post, path), _func);
    }

    void set_option_handler(std::function<void(response)> _func)
    {
        // route_map.emplace(std::tuple<method, std::string>(method::option, path), _func);
        handle_option = _func;
    }

    void set_not_found_handler(std::function<void(response)> func_) { handle_not_found = func_; }

private:
    std::function<void(response)> handle_option;
    std::unordered_map<std::tuple<method, std::string>, std::function<void(response)>> route_map;
    std::function<void(response)> handle_not_found;
};

} // namespace http
