#include "../lib/av_http.hpp"

using namespace std::placeholders;

int main(int argc, char ** argv)
{
    typedef std::function<void(http::response)> route_hanhdl_func;

    std::string addr = "127.0.0.1";
    uint16_t port    = 12345;
    std::unordered_map<std::string, route_hanhdl_func> routes;

    routes["/route_01"] = [](http::response res) {
        res.body() = "hello from route_01";
        res.send_reply();
    };

    routes["/route_02"] = [](http::response res) {
        res.body() = "hello from route_02";
        res.send_reply();
    };

    auto request_dispatch = [&routes](http::response res) {
        auto path = res.reqwest()->get_uri_path();
        if (auto route_ = (path.has_value() ? routes[path.value()] : route_hanhdl_func()))
            route_(std::move(res));
        else
            res.send_reply(404);
    };

    auto on_accept = [&request_dispatch](http::tcp_stream stream) {
        std::make_shared<http_connection>(stream, std::bind(request_dispatch, ::_1))->start();
    };

    http::start_async(port, on_accept, ::_1);

    Event::run_forever();
}
