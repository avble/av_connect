/* Copyright (c) 2024-2024 Harry Le (avble.harry at gmail dot com)

It can be used, modified.
*/

#include "../lib/http.hpp"

#include <chrono> // std::chrono::seconds
#include <thread>

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
            res.set_content("hello world");
            res.end();
        });
    }
}
