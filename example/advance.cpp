/* Copyright (c) 2024-2024 Harry Le (avble.harry at gmail dot com)

It can be used, modified.
*/

#include "../lib/av_connect.hpp"

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
        auto http_server_ = http::make_server(port, [](std::shared_ptr<http::response> res) {
            res->set_content("hello world");
            res->end();
        });

        auto ws_server = ws::make_server(port + 1, [](ws::message msg) {}, [](boost::beast::error_code ec) {});

        io_context::ioc.run();
    }
}
