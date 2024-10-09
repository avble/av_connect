#include "io_base.hpp"

#include <http_parser.h>

#include <algorithm>
#include <boost/asio.hpp>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <tuple>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include <sys/queue.h>

using boost::asio::ip::tcp;

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

    timeout = 504
};

std::string get_status_code_msg(status_code code_)
{
    if (code_ == status_code::ok)
        return "OK";

    if (code_ == status_code::not_found)
        return "Not Found";

    return "Internal";
}

// i.e HTTP/1 200 OK
std::string make_status_line(status_code code, std::string msg = "")
{
    std::string status_line = "HTTP/1.0 ";
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
        // evcon         = other.evcon;
        major         = other.major;
        minor         = other.minor;
        is_keep_alive = other.is_keep_alive;

        other.is_owning = false;
        is_owning       = true;
        // req             = other.req;
    }

    template <class T>
    request(T parser)
    {
        major = http_parser_get_major(parser);
        minor = http_parser_get_minor(parser);
    }

    const std::string & get_uri_path() { return uri_path; }

    ~request() {}

private:
    std::string uri_path;
    char major;
    char minor;
    bool is_keep_alive;
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

        virtual void do_write_response(response) = 0;
        virtual ~base() {}
    };

    template <typename T>
    class wrapper : public base
    {
    public:
        wrapper(const wrapper & other) = delete;

        wrapper(wrapper && other) { p = other.p; }
        wrapper(std::weak_ptr<T> p_) { p = p_; }

        void do_write_response(response res)
        {
            if (auto w_p = p.lock())
            {
                w_p->do_write_response(std::move(res));
            }
        }
        ~wrapper() {}

        std::weak_ptr<T> p;
    };

public:
    response()                              = delete;
    response & operator=(response & other)  = delete;
    response & operator=(response && other) = delete;

    template <class T>
    response(std::weak_ptr<T> connect_, request && req_) : req(std::move(req_))
    {
        result_ = status_code::ok;
        major   = req_.major;
        minor   = req_.minor;
        if (req.is_keep_alive)
            headers_["Connection"] = "keep-alive";
        base_     = new wrapper<T>(connect_);
        is_owning = true;
    }

    response(response && other) : req(std::move(other.req)), base_(other.base_)
    {
        // std::cout << "[DEBUG][response] is called. with body: " << other.body_ << std::endl;
        result_         = other.result_;
        headers_        = std::move(other.headers_);
        major           = other.major;
        minor           = other.minor;
        body_           = std::move(other.body_);
        is_owning       = other.is_owning;
        other.is_owning = false;
    }

    status_code & result() { return result_; }

    std::unordered_map<std::string, std::string> header() { return headers_; }

    std::string & body() { return body_; }

    void send()
    {
        if (is_owning)
        {
            base_->do_write_response(*this);
        }
        is_owning = false;
    }

    request & reqwest() { return req; }

    ~response()
    {
        if (is_owning)
            delete base_;
    }

private:
    response(response & other) : req(std::move(other.req)), base_(other.base_)
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
    std::unordered_map<std::string, std::string> headers_;
    char major;
    char minor;
    bool is_keep_alive;

    std::string body_;
    base * base_;
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
        data_len = 0;
        std::memset(&settings, 0, sizeof settings);
    }

    void start()
    {
        static http_cb llhttp_on_message = [](http_parser * _http_parser) -> int {
            internal_wrapper * wrapper_ = (internal_wrapper *) _http_parser->data;
            auto self                   = wrapper_->p_session;

            self->on_read(_http_parser);

            return 0;
        };

        http_parser_init(&parser, HTTP_BOTH);
        settings.on_message_complete = llhttp_on_message;

        parser.data = new internal_wrapper(shared_from_this());

        do_read();
    }

    void do_write_response(response res)
    {
        // std::cout << "[do_write_response] ENTER \n";
        auto self(shared_from_this());

        int body_len = res.body().size();

        std::string header = "HTTP/1.0 200 OK";
        header += "\n";
        header += "Connection: keep-alive";
        header += "\n";
        header += "Content-Length: ";
        header += std::to_string(body_len);
        header += "\r\n\r\n";
        int out_buffer_len = 0;
        std::copy(header.begin(), header.end(), out_buffer.begin());
        out_buffer_len = std::distance(header.begin(), header.end());
        std::copy(res.body().begin(), res.body().end(), out_buffer.begin() + out_buffer_len);
        out_buffer_len += res.body().length();

        boost::asio::async_write(socket_, boost::asio::buffer(out_buffer.data(), out_buffer_len),
                                 [this, self](boost::system::error_code ec, std::size_t /*length*/) {
                                     if (!ec)
                                     {
                                         do_read();
                                     }
                                 });
    }

private:
    void do_read()
    {
        auto self(shared_from_this());

        // std::cout << "[do_read] ENTER \n";

        socket_.async_read_some(
            boost::asio::buffer(&data_[0] + data_len, max_length), [this, self](boost::system::error_code ec, std::size_t length) {
                if (!ec)
                {
                    self->data_len += length;
                    size_t return_size = http_parser_execute(&(self->parser), &(self->settings), self->data_, self->data_len);
                    if (return_size != length)
                    {
                        // std::cout << "[DEBUG] need to handle this case\n";
                        std::memcpy(self->data_, self->data_ + return_size, self->data_len - return_size);
                    }
                    else
                        self->data_len = 0;
                }
            });
    }

    void on_read(http_parser * _http_parser)
    {
        // std::cout << "[on_read] ENTER \n";
        response res{ std::weak_ptr<session>(shared_from_this()), request(_http_parser) };
        handler(std::move(res));
    }

    tcp::socket socket_;
    int data_len;
    char data_[max_length];

    std::array<char, 1024 * 10> out_buffer;
    http_parser parser;
    http_parser_settings settings;
    std::function<void(response)> handler;
};

template <class T>
class server
{
public:
    server(boost::asio::io_context & io_context, unsigned short port, std::function<void(response)> _handler) :
        handler(_handler), acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
    {
        do_accept();
    }

private:
    void do_accept()
    {
        acceptor_.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
            if (!ec)
            {
                std::make_shared<T>(std::move(socket), handler)->start();
            }

            do_accept();
        });
    }

    tcp::acceptor acceptor_;
    std::function<void(response)> handler;
};

auto make_server(unsigned short port, std::function<void(response)> _handler)
{
    return server<session>{ io_context::ioc, port, _handler };
}

void start_server(unsigned short port, std::function<void(response)> _handler)
{
    auto server_ = make_server(port, _handler);
    io_context::ioc.run();
}

} // namespace http
