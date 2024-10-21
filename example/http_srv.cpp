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

    // {
    //     static auto chunk_handler = [](http::response res) {
    //         std::cout << "chunk_handler ENTER \n";

    //         std::vector<std::string> chunk_datas = { "one\n",
    //                                                  "twotwo\n",
    //                                                  "threethreethree\n",
    //                                                  "fourfourfourfour\n",
    //                                                  "fivefivefivefivefive\n",
    //                                                  "sixsixsixsixsixsixisxssfdfsafd\n" };

    //         res.chunk_start();
    //         for (int i = 0; i < 6; i++)
    //         {
    //             // std::cout << "[DEBUG] " << chunk_datas[i] << std::endl;
    //             res.chunk_write(chunk_datas[i]);
    //             std::this_thread::sleep_for(std::chrono::seconds(1));
    //         }
    //         res.chunk_end();
    //     };
    //     http::start_server(port, [](http::response res) {
    //         std::cout << "res_handler ENTER \n";
    //         std::thread{ chunk_handler, std::move(res) }.detach();
    //         // std::cout << "[DEBUG][http::start_server] is called.\n";
    //         // res.body() = "hello world";
    //         // // res.send();
    //         std::cout << "res_handler LEAVE \n";
    //         // res.end();
    //     });
    // }

    // {
    //     http::route _routes;
    //     _routes.get("/v1/completions", [](response res) {
    //         std::cout << "/v1/completions ENTER" << std::endl;
    //         // res.start_writing();
    //         // res.write_data();
    //         // res.write_data();
    //         // res.end();
    //         // res.end();
    //         res.end();
    //     });

    //     http::start_server(port, _routes);
    // }

    // {
    //     std::unordered_map<std::string, std::function<void(http::response)>> routes;

    //     routes["/route_01"] = [](http::response res) {
    //         // std::cout << "[DEBUG] /route_01 is called." << std::endl;
    //         res.body() = "hello from route_01";
    //         res.send();
    //     };
    //     routes["/route_02"] = [](http::response res) {
    //         // std::cout << "[DEBUG] /route_02 is called." << std::endl;
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
