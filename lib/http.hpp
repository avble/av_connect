/* Copyright (c) 2024-2024 Harry Le (avble.harry at gmail dot com)

It can be used, modified.
*/

#pragma once

#include "event.hpp"
#include "internal/base.hpp"

#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/queue.h>

using namespace std::placeholders;

namespace http {

class response;
class request;
enum class status_code;
using on_request_func = std::function<void(response)>;
using on_accept_func  = std::function<void(evhttp_connection * evcon)>;
using on_write_func   = std::function<void(int)>;
using on_read_func    = std::function<void(int, request &&)>;
// clang-format off
void 
start_server(unsigned short port, on_request_func && _route_hdl);
evconnlistener * 
make_listener(unsigned short port, on_accept_func _on_accept);
void 
read_async(evhttp_connection * evcon, on_read_func _on_read);
void 
write_async(evhttp_connection * evcon, status_code _code, on_write_func && _on_write);
void 
write_async(evhttp_connection * evcon, response _res);
// clang-format on

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
        uri_path      = other.uri_path;
        evcon         = other.evcon;
        major         = other.major;
        minor         = other.minor;
        is_keep_alive = other.is_keep_alive;

        other.is_owning = false;
        is_owning       = true;
        req             = other.req;
    }

    request(evhttp_request * _req)
    {
        auto uri = Event_helper::evhttp_request_uri_get_path(_req);
        uri_path = uri.has_value() ? uri.value() : "";
        evcon    = _req->evcon;
        major    = _req->major;
        minor    = _req->minor;

        auto connection = Event_helper::evhttp_request_header_get(_req, "Connection");
        if (connection.has_value())
            is_keep_alive = true;

        is_owning = true;
        req       = _req;
    }

    const std::string & get_uri_path() { return uri_path; }

    ~request()
    {
        if (is_owning and req != NULL)
            evhttp_request_free(req);
    }

private:
    evhttp_connection * evcon;
    std::string uri_path;
    char major;
    char minor;
    bool is_keep_alive;

    bool is_owning;
    evhttp_request * req;

    friend class response;
};

class response
{
public:
    response()                              = delete;
    response & operator=(response & other)  = delete;
    response & operator=(response && other) = delete;

    response(request && req_, on_write_func complete_func_) : req(std::move(req_)), complete_func(complete_func_)
    {
        result_ = status_code::ok;
        major   = req_.major;
        minor   = req_.minor;
        if (req.is_keep_alive)
            headers_["Connection"] = "keep-alive";
    }

    response(response && other) : req(std::move(other.req))
    {
        result_         = other.result_;
        headers_        = std::move(other.headers_);
        major           = other.major;
        minor           = other.minor;
        complete_func   = std::move(other.complete_func);
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
        is_owning = false;
        write_async(req.evcon, *this);
    }

    request & reqwest() { return req; }

    on_write_func & get_complete_func() { return complete_func; }

    ~response()
    {
        if (is_owning)
            write_async(req.evcon, status_code::timeout, std::move(complete_func));
    }

private:
    response(response & other) :
        req(std::move(other.req)), headers_(std::move(other.headers_)), complete_func(std::move(other.complete_func)),
        body_(std::move(other.body_))
    {
        result_         = other.result_;
        major           = other.major;
        minor           = other.minor;
        is_owning       = other.is_owning;
        other.is_owning = false;
    }

private:
    bool is_owning;
    request req;
    status_code result_;
    std::unordered_map<std::string, std::string> headers_;
    char major;
    char minor;
    bool is_keep_alive;

    on_write_func complete_func;
    std::string body_;
};

evconnlistener * make_listener(unsigned short port, on_accept_func on_accept_complete)
{
    class evconnlistener_obj_cb
    {
    public:
        evconnlistener_obj_cb(evhttp * http_, on_accept_func on_accept_complete) : cb(on_accept_complete) { http = http_; }
        void operator()(evhttp_connection * stream) { cb(stream); }

    public:
        evhttp * http;

    private:
        const on_accept_func cb;
    };

    evhttp * http = evhttp_new(Event::event_base_global());

    auto on_accept = [](struct evconnlistener * listener, evutil_socket_t fd, struct sockaddr * sa, int socklen, void * arg) {
        evconnlistener_obj_cb * p = (evconnlistener_obj_cb *) arg;

        char addr[256]{ 0 };
        uint16_t port = ((struct sockaddr_in *) sa)->sin_port;
        if (sa->sa_family == AF_INET)
        {
            if (inet_ntop(AF_INET, &((struct sockaddr_in *) sa)->sin_addr, &addr[0], sizeof(addr)) == NULL)
                std::cerr << "can not get ip address" << std::endl;
        }

        evhttp_connection * evcon = evhttp_connection_base_bufferevent_new(Event::event_base_global(), NULL, NULL, addr, port);
        evcon->http_server        = p->http;
        TAILQ_INSERT_TAIL(&p->http->connections, evcon, next);
        p->http->connection_cnt++;

        evcon->max_headers_size = p->http->default_max_headers_size;
        evcon->max_body_size    = p->http->default_max_body_size;
        if (p->http->flags & EVHTTP_SERVER_LINGERING_CLOSE)
            evcon->flags |= EVHTTP_CON_LINGERING_CLOSE;

        evcon->flags |= EVHTTP_CON_INCOMING;
        evcon->state = EVCON_READING_FIRSTLINE;

        void (*on_con_close)(struct evhttp_connection * evcon, void * arg) = [](struct evhttp_connection * evcon, void * arg) {
            evhttp_request * req = NULL;
            while ((req = TAILQ_FIRST(&evcon->requests)) != NULL)
            {
                event_cb_obj_base * p = (event_cb_obj_base *) req->cb_arg;
                TAILQ_REMOVE(&evcon->requests, req, next);
                evhttp_request_free(req);
                delete p;
            }
        };
        evhttp_connection_set_closecb(evcon, on_con_close, NULL);

        if (bufferevent_replacefd(evcon->bufev, fd))
            goto err;
        (*p)(evcon);
        return;
    err:
        evhttp_connection_free(evcon);
    };

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);

    int flags            = LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE;
    struct sockaddr * sa = (struct sockaddr *) &addr;

    evconnlistener * listener =
        evconnlistener_new_bind(Event::event_base_global(), on_accept, new evconnlistener_obj_cb(http, on_accept_complete), flags,
                                -1, sa, sizeof(sockaddr_in));

    return listener;
};

void read_async(evhttp_connection * evcon, std::function<void(int, request &&)> func_complete_)
{
    class request_cb_obj : public event_cb_obj_base
    {
    public:
        request_cb_obj(std::function<void(int, evhttp_request *)> && on_read_) { on_read = std::move(on_read_); }

        void operator()(int ec, evhttp_request * req) { on_read(ec, req); }

        ~request_cb_obj() { on_read = nullptr; }

    public:
        std::function<void(int, evhttp_request *)> on_read;
    };

    std::function<void(int, evhttp_request *)> on_request = [on_request_ = std::move(func_complete_)](int ec,
                                                                                                      evhttp_request * req) {
        request req_(req);
        TAILQ_REMOVE(&req->evcon->requests, req, next);
        on_request_(ec, std::move(req_));
    };

    if (TAILQ_EMPTY(&evcon->requests)) // create new request if it is empty in list
    {
        auto request_complete_cb = [](evhttp_request * req, void * arg) {
            TAILQ_REMOVE(&req->evcon->requests, req, next);
            request_cb_obj * on_read_cb_ = (request_cb_obj *) arg;
            (*on_read_cb_)(0, req);
            req->cb_arg = NULL;
            req->cb     = NULL;
            delete on_read_cb_;
        };

        auto request_err_cb = [](enum evhttp_request_error ec, void * arg) {
            request_cb_obj * on_read_cb_ = (request_cb_obj *) arg;
            (*on_read_cb_)(ec, NULL);
            delete on_read_cb_;
        };

        struct evhttp_request * req = evhttp_request_new(request_complete_cb, new request_cb_obj(std::move(on_request)));
        evhttp_request_set_error_cb(req, request_err_cb);
        TAILQ_INSERT_HEAD(&evcon->requests, req, next);
        req->evcon    = evcon; /* the request ends up owning the connection */
        req->userdone = 1;
        req->flags |= EVHTTP_REQ_OWN_CONNECTION;
        req->kind = EVHTTP_REQUEST;
    }

    evhttp_start_read_(evcon);
}

void write_async(evhttp_connection * evcon, status_code _code, on_write_func && complete_func_)
{
    class bufev_cb_obj
    {
    public:
        bufev_cb_obj(on_write_func && _complete_func) : complete_func_(std::move(_complete_func)) {}

        void operator()(int rc)
        {
            // std::cout << "bufev_cb_obj-operator is called.\n";
            if (complete_func_)
                complete_func_(rc);
        }

        ~bufev_cb_obj() { /*std::cout << "~bufev_cb_obj is called.\n"; */ }

    private:
        on_write_func complete_func_;
    };

    std::string header = make_status_line(_code);
    header += "\r\n\r\n";
    evbuffer * output = bufferevent_get_output(evcon->bufev);
    evbuffer_add(output, header.data(), header.size());

    bufferevent_data_cb write_cb = [](struct bufferevent * bufev, void * arg) {
        bufev_cb_obj * on_write = (bufev_cb_obj *) arg;
        (*on_write)(0);
        delete on_write;
    };

    bufferevent_data_cb readcb_ptr   = NULL;
    bufferevent_data_cb writecb_ptr  = NULL;
    bufferevent_event_cb eventcb_ptr = NULL;
    void * arg;
    bufferevent_getcb(evcon->bufev, &readcb_ptr, &writecb_ptr, &eventcb_ptr, &arg);
    bufferevent_setcb(evcon->bufev, NULL, /*read*/
                      write_cb, eventcb_ptr, new bufev_cb_obj(std::move(complete_func_)));

    // bufferevent_disable(evcon->bufev, EV_READ);
    bufferevent_enable(evcon->bufev, EV_WRITE | EV_READ);
}

void write_async(evhttp_connection * evcon, response res)
{
    // std::cout << "[write_async] ENTER" << std::endl;
    class bufev_cb_obj
    {
    public:
        bufev_cb_obj(response && _response_ng) : response_ng_(std::move(_response_ng)) {}

        void operator()(int rc) { response_ng_.get_complete_func()(rc); }

    private:
        response response_ng_;
    };

    std::string header = make_status_line(res.result());

    for (const auto & key_val : res.header())
        header += "\n" + key_val.first + ": " + key_val.second;

    header += "\n";
    header += "Content-Length: ";
    header += std::to_string(res.body().size());

    header += "\r\n\r\n";

    evbuffer * output = bufferevent_get_output(evcon->bufev);
    evbuffer_add(output, header.data(), header.size());
    evbuffer_add(output, res.body().c_str(), res.body().size());

    bufferevent_data_cb write_cb = [](struct bufferevent * bufev, void * arg) {
        bufev_cb_obj * on_write = (bufev_cb_obj *) arg;
        (*on_write)(0);
        delete on_write;
    };

    bufferevent_data_cb readcb_ptr   = NULL;
    bufferevent_data_cb writecb_ptr  = NULL;
    bufferevent_event_cb eventcb_ptr = NULL;
    void * arg;
    bufferevent_getcb(evcon->bufev, &readcb_ptr, &writecb_ptr, &eventcb_ptr, &arg);
    bufferevent_setcb(evcon->bufev, NULL, /*read*/
                      write_cb, eventcb_ptr, new bufev_cb_obj(std::move(res)));

    bufferevent_disable(evcon->bufev, EV_READ);
    bufferevent_enable(evcon->bufev, EV_WRITE);
}

void start_server(unsigned short port, std::function<void(response)> && route_hdl_)
{
    class http_session : public std::enable_shared_from_this<http_session>
    {
    public:
        http_session(evhttp_connection * _evcon, std::function<void(response)> _route_hdl)
        {
            route_hdl = _route_hdl;
            evcon     = _evcon;
        }
        void start() { do_read_request(); }

        void on_write(int ec)
        {
            // std::cout << "[DEBUG][on_write] ENTER" << std::endl;
            do_read_request();
        }

    private:
        http_session()                                  = delete;
        http_session(const http_session &)              = delete;
        http_session(const http_session &&)             = delete;
        http_session & operator=(const http_session &)  = delete;
        http_session & operator=(const http_session &&) = delete;

        void do_read_request()
        {
            http::read_async(
                evcon, std::bind(&http_session::on_request, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
        }

        void on_request(int ec, request && req)
        {
            if (route_hdl)
                route_hdl(response(std::move(req), std::bind(&http_session::on_write, shared_from_this(), _1)));
            else
                response{ std::move(req), std::bind(&http_session::on_write, shared_from_this(), std::placeholders::_1) }.send();
        }

    private:
        evhttp_connection * evcon;
        std::function<void(response &&)> route_hdl;
        friend class request;
    };

    on_accept_func on_accept = [route_hdl_](evhttp_connection * evcon) {
        std::shared_ptr<http_session>
        {
            new http_session(evcon, route_hdl_), [](http_session * p) {
                // std::cout << "[DEBUG] http_session is deleted.\n";
                delete p;
            }
        } -> start();
    };

    if (NULL != make_listener(port, on_accept))
    {
        std::cout << "server has started on port: " << port << " using " << event_base_get_method(Event::event_base_global())
                  << std::endl;
        Event::run_forever();
    }
    else
        std::cout << "server failed at starting on port: " << port << std::endl;
}

} // namespace http
