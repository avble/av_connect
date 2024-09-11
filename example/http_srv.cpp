/* Copyright (c) 2024-2024 Harry Le (avble.harry at gmail dot com)

It can be used, modified.
*/

#include "../lib/http.hpp"

using namespace std::placeholders;
using namespace http;

int main(int argc, char * args[])
{
    if (argc != 3)
    {
        std::cerr << "\nUsage: " << args[0] << " address port\n" << "Example: \n" << args[0] << " 0.0.0.0 12345" << std::endl;
        return -1;
    }

    std::string addr(args[1]);
    uint16_t port = static_cast<uint16_t>(std::atoi(args[2]));

    {
        http::start_server(port, [](http::response res) {
            // std::cout << "[DEBUG][http::start_server] is called.\n";
            res.body() = "hello world";
            res.send();
        });
    }

    // {

    //     std::unordered_map<std::string, std::function<void(http::response)>> routes;

    //     routes["/route_01"] = [](http::response res) {
    //         res.body() = "hello from route_01";
    //         res.send();
    //     };
    //     routes["/route_02"] = [](http::response res) {
    //         res.body() = "hello from route_02";
    //         res.send();
    //     };

    //     auto route_handler = [&routes](http::response res) {
    //         if (auto route_ = routes[res.reqwest().get_uri_path()])
    //             route_(std::move(res));
    //         else
    //             res.send();
    //     };

    //     http::start_server(port, route_handler);
    // }
}
