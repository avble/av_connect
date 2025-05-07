/* Copyright (c) 2024-2024 Harry Le (avble.harry at gmail dot com)

It can be used, modified.
*/
#include "../lib/av_connect.hpp"

#include <chrono> // std::chrono::seconds
#include <thread>

int main(int argc, char ** argv)
{
    // ws::
    // ws::client::start_ws_client("127.0.0.1", "12345");
    {
        std::string addr = "192.168.1.5";
        std::string port = "12345";

        auto matter_send_command = [](std::shared_ptr<ws::client::ws_client> ws_client, std::string cmd) {};

        auto ws_client = ws::client::make_client(
            addr, port, [](std::string message) { std::cout << "[DEBUG] received message: " << message << std::endl; });

        std::thread th([&]() {
            for (int i = 0; i < 3; i++)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(3000));
                ws_client->do_write("onoff toggle 01 02");
            }
        });

        // ws_client->do_write("hello world");

        boost::asio::steady_timer t(io_context::ioc, boost::asio::chrono::seconds(1000));
        t.async_wait([](const boost::system::error_code & /*e*/) { std::cout << "Hello, world!" << std::endl; });

        io_context::ioc.run();
    }

    return 0;
}
