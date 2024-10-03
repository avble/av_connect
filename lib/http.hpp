/* Copyright (c) 2024-2024 Harry Le (avble.harry at gmail dot com)

It can be used, modified.
*/

#pragma once
#include "llhttp.h"

#include "event.hpp"
#include "internal/base.hpp"

#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include <sys/queue.h>

using namespace std::placeholders;

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

    request(llhttp_t * parser, std::string _uri_path)
    {
        major    = llhttp_get_http_major(parser);
        minor    = llhttp_get_http_minor(parser);
        uri_path = _uri_path;
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

        virtual void do_write_response()         = 0;
        virtual evbuffer * evbuffer_get_output() = 0;
        virtual ~base() {}
    };

    template <typename T>
    class wrapper : public base
    {
    public:
        wrapper(const wrapper & other) = delete;

        wrapper(wrapper && other) { p = other.p; }
        wrapper(std::weak_ptr<T> p_) { p = p_; }
        // wrapper(const wrapper & other) { p = other.p; }

        void do_write_response()
        {
            if (auto w_p = p.lock())
            {
                w_p->do_write_response();
            }
        }
        evbuffer * evbuffer_get_output()
        {
            if (auto w_p = p.lock())
            {
                return w_p->get_output_buffer();
            }

            return NULL;
        }

        ~wrapper() {}

        std::weak_ptr<T> p;
    };

public:
    response()                              = delete;
    response & operator=(response & other)  = delete;
    response & operator=(response && other) = delete;
    response(const response & other)        = delete;

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
        result_  = other.result_;
        headers_ = std::move(other.headers_);
        major    = other.major;
        minor    = other.minor;
        // write_response  = std::move(other.write_response);
        body_           = std::move(other.body_);
        is_owning       = other.is_owning;
        other.is_owning = false;
    }

    status_code & result() { return result_; }

    std::unordered_map<std::string, std::string> header() { return headers_; }

    std::string & body() { return body_; }

    void send()
    {
        // std::cout << "[DEBUG][send] is called. with body: " << body_ << std::endl;
        if (is_owning)
        {
            std::string header = "HTTP/1.0 200 OK";
            header += "\n";
            header += "Connection: keep-alive";
            header += "\n";
            header += "Content-Length: ";
            header += std::to_string(body_.size());
            header += "\r\n\r\n";
            evbuffer * output = base_->evbuffer_get_output();

            if (output != NULL)
            {
                evbuffer_add(output, header.data(), header.size());
                evbuffer_add(output, body_.c_str(), body_.size());
            }

            base_->do_write_response();
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
    response(response & other) = delete;

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

void start_server(unsigned short port, std::function<void(response)> _handler)
{

    class http_session : public std::enable_shared_from_this<http_session>
    {
        struct internal_wrapper
        {
            internal_wrapper(std::shared_ptr<http_session> _p) { p_session = _p; }

            internal_wrapper(const internal_wrapper & other) { p_session = other.p_session; }

            std::shared_ptr<http_session> p_session;
        };

    public:
        http_session(int fd, std::function<void(response)> _handler) : handler(_handler)
        {
            bev = bufferevent_socket_new(Event::event_base_global(), fd, BEV_OPT_CLOSE_ON_FREE);
        }

        ~http_session() { bufferevent_free(bev); }

        void start() { do_read_request(); }

    private:
        http_session()                                  = delete;
        http_session(const http_session &)              = delete;
        http_session(const http_session &&)             = delete;
        http_session & operator=(const http_session &)  = delete;
        http_session & operator=(const http_session &&) = delete;

    public:
        void do_read_request()
        {
            // std::cout << "[do_read_request] ENTER \n";

            static llhttp_cb llhttp_on_message = [](llhttp_t * _req) -> int {
                internal_wrapper * wrapper_ = (internal_wrapper *) _req->data;
                auto self                   = wrapper_->p_session;

                self->on_read_complete(_req);

                evbuffer * input = bufferevent_get_input(self->bev);
                evbuffer_drain(input, evbuffer_get_length(input));

                return 0;
            };

            static llhttp_data_cb llhttp_on_url = [](llhttp_t * _req, const char * at, size_t length) -> int {
                internal_wrapper * wrapper_ = (internal_wrapper *) _req->data;
                auto self                   = wrapper_->p_session;

                self->uri_path = std::string(at, length);

                return 0;
            };

            static bufferevent_data_cb bev_read_cb = [](bufferevent * bev, void * arg) {
                evbuffer * input = bufferevent_get_input(bev);
                int buff_len     = evbuffer_get_length(input);
                char * buff      = (char *) malloc(buff_len);

                llhttp_t parser;
                llhttp_settings_t settings;

                /*Initialize user callbacks and settings */
                llhttp_settings_init(&settings);

                /*Set user callback */
                settings.on_message_complete = llhttp_on_message;
                settings.on_url              = llhttp_on_url;

                llhttp_init(&parser, HTTP_BOTH, &settings);
                parser.data = arg;

                /*Parse request! */
                evbuffer_copyout(input, buff, buff_len);

                enum llhttp_errno err = llhttp_execute(&parser, buff, buff_len);
                if (err == HPE_OK)
                {
                }
                free(buff);
            };

            static bufferevent_event_cb bev_err_cb = [](struct bufferevent * bev, short what, void * ctx) {
                // std::cout << "[bev_err_cb] ENTER what " << what << std::endl;
                void * arg = NULL;
                bufferevent_getcb(bev, NULL, NULL, NULL, &arg);
                internal_wrapper * wrapper_ = (internal_wrapper *) arg;
                delete wrapper_;
            };

            void * arg = NULL;
            bufferevent_getcb(bev, NULL, NULL, NULL, &arg);
            arg = arg != NULL ? arg : new internal_wrapper(shared_from_this());

            bufferevent_setcb(bev, bev_read_cb, NULL, bev_err_cb, arg);

            bufferevent_enable(bev, EV_READ | EV_WRITE);
        }

        void on_read_complete(llhttp_t * _req)
        {
            response res{ std::weak_ptr<http_session>(shared_from_this()), request{ _req, uri_path } };

            handler(std::move(res));
        }

        void do_write_response()
        {
            auto do_write_async = [self = shared_from_this()]() {
                static bufferevent_data_cb writecb_ptr = [](bufferevent * bev, void * arg) {
                    // std::cout << "[writecb_ptr] ENTER \n";
                    internal_wrapper * wrapper_ = (internal_wrapper *) arg;
                    auto self                   = wrapper_->p_session;
                    // evbuffer_drain(bufferevent_get_output(self->bev), evbuffer_get_length(bufferevent_get_output(self->bev)));
                    self->on_write();
                };

                bufferevent_event_cb eventcb_ptr = NULL;
                void * arg;
                bufferevent_getcb(self->bev, NULL, NULL, &eventcb_ptr, &arg);
                bufferevent_setcb(self->bev, NULL, writecb_ptr, eventcb_ptr, arg);

                bufferevent_disable(self->bev, EV_READ);
                bufferevent_enable(self->bev, EV_WRITE);
            };

            Event::call_soon(do_write_async);
        }

        void on_write()
        {
            // std::cout << "[on_write] ENTER \n";
            auto do_read = [func_ = std::bind(&http_session::do_read_request, shared_from_this())]() { func_(); };
            Event::call_soon(do_read);
        }

    private:
        evbuffer * get_output_buffer() { return bufferevent_get_output(bev); }
        std::string uri_path;

    public:
        bufferevent * bev;
        std::function<void(response)> handler;
        friend class response::wrapper<http_session>;
    };

    static evconnlistener_cb on_accept = [](struct evconnlistener * listener, evutil_socket_t fd, struct sockaddr * sa, int socklen,
                                            void * arg) {
        // std::cout << "[DEBUG] on_accept is called.\n";

        std::tuple<std::function<void(response)>> * p = (std::tuple<std::function<void(response)>> *) arg;

        std::shared_ptr<http_session>
        {
            new http_session(fd, std::get<0>(*p)), [](http_session * p) {
                // std::cout << "[DEBUG] http_session is deleted.\n";
                delete p;
            }
        } -> start();

        // delete p;
    };

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);

    int flags            = LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE;
    struct sockaddr * sa = (struct sockaddr *) &addr;

    evconnlistener * listener = evconnlistener_new_bind(
        Event::event_base_global(), on_accept, new std::tuple<decltype(_handler)>(_handler), flags, -1, sa, sizeof(sockaddr_in));

    if (listener != NULL)
    {
        std::cout << "server has started on port: " << port << " using " << event_base_get_method(Event::event_base_global())
                  << std::endl;
        Event::run_forever();
    }
    else
        std::cout << "server failed at starting on port: " << port << std::endl;
}

} // namespace http
