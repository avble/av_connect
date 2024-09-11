#include "../lib/av_http.hpp"

#include <fstream>

using namespace std::placeholders;

int main(int argc, char ** argv)
{
    // typedef std::function<void(http::response)> route_hanhdl_func;

    // evhttp * p_evhttp = evhttp_new(Event::event_base_global());
    // std::string addr  = "127.0.0.1";
    // uint16_t port     = 12345;

    // std::function<void(evhttp_connection *, std::function<void(int, evhttp_request *)>, int)> on_write =
    //     [](evhttp_connection * evcon, std::function<void(int, evhttp_request *)> on_read, int rc) {
    //         http::read_async(evcon, on_read);
    //     };

    // std::function<void(int, evhttp_request *)> on_read = [&on_write, &on_read](int rc, evhttp_request * req) {
    //     std::cout << "[DEBUG][file] ENTER" << std::endl;
    //     std::ofstream of("./file_01");
    //     std::vector<uint8_t> buff = http::request_get_input_buffer(req);
    //     for (const auto & v : buff)
    //         of << v;

    //     http::write_async_v1(req, 200, "OK", "", std::bind(on_write, req->evcon, on_read, ::_1));
    // };

    // auto on_accept = [&on_read](struct evhttp_connection * evcon) { http::read_async(evcon, on_read); };

    // http::start_async(p_evhttp, port, on_accept, ::_1);

    // Event::run_forever();
}
