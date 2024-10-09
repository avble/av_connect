#include "../lib/av_connect.hpp"

int main(int argc, char * args[])
{
    if (argc != 3)
    {
        std::cerr << "\nUsage: " << args[0] << " address port\n" << "Example: \n" << args[0] << " 0.0.0.0 12345" << std::endl;
        return -1;
    }

    std::string addr(args[1]);
    uint16_t port   = static_cast<uint16_t>(std::atoi(args[2]));
    auto ws_server_ = ws::make_server(
        port,
        [](ws::message msg) {
            // std::cout << "[Received]: " << msg.data() << std::endl;
            msg.data_out() << "Echo: " << msg.data();
            msg.send();
        },
        [](beast::error_code ec) {});

    // auto ws_server_ = ws::make_server(
    //     port + 1, [](ws::message msg) { std::cout << "[Received]: " << msg.data() << std::endl; }, [](beast::error_code ec) {});

    io_context::ioc.run();
}
