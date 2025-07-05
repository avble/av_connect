/* Copyright (c) 2024-2024 Harry Le (avble.harry at gmail dot com)

It can be used, modified.
*/

#include "../lib/http.hpp"

#include <chrono> // std::chrono::seconds
#include <thread>

using namespace std::placeholders;
using namespace http;

int main(int argc, char *args[]) {
  if (argc != 3) {
    std::cerr << "\nUsage: " << args[0] << " address port\n"
              << "Example: \n"
              << args[0] << " 0.0.0.0 12345" << std::endl;
    return -1;
  }

  std::string addr(args[1]);
  uint16_t port = static_cast<uint16_t>(std::atoi(args[2]));

  {
    http::start_server(port, [](std::shared_ptr<http::response> res) {
      res->set_content("hello world");
      res->end();
    });
  }

  {
    http::start_server(port, [](std::shared_ptr<http::response> res) {
      class data : public http::base_data {
      public:
        data() {
          HTTP_LOG_TRACE("data constructor");
        }
      };

      std::unique_ptr<data> data_ptr(new data());
      res->get_session_data() = std::move(data_ptr);

      res->set_content("hello world");
      res->end();
    });
  }
}
