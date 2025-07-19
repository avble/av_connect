/*
 * sample client to connect to chat completions API of OpenAI
 */

#include "boost/asio.hpp"

#include <iostream>
#include <memory>
#include <string>
#include <vector>

using boost::asio::ip::tcp;

int main(int argc, char **argv) {

  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " address port" << std::endl;
    return 1;
  }

  unsigned short port = static_cast<unsigned short>(std::atoi(argv[2]));
  std::string address = argv[1];

  boost::asio::io_context io_context;
  tcp::resolver resolver(io_context);
  tcp::resolver::results_type endpoints =
      resolver.resolve(address, std::to_string(port));
  tcp::socket socket(io_context);
  boost::asio::connect(socket, endpoints);

  std::cout << "Connected to " << address << ":" << port << std::endl;

  std::string request_body =
      R"({
  "messages": [
    {
      "role": "developer",
      "content": "you are helpful assitant"
    },
    {
      "role": "user",
      "content": "can you help me!"
    }
  ],
  "model": "gpt-4.1",
  "stream": true
})";
  std::cout << "Request body: " << request_body << std::endl;

  std::string request = "POST /v1/chat/completions HTTP/1.1\r\n"
                        "Host: " +
                        address +
                        "\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: " +
                        std::to_string(request_body.size()) +
                        "\r\n"
                        "\r\n" +
                        request_body;

  boost::asio::write(socket, boost::asio::buffer(request));
  std::cout << "Request sent." << std::endl;

  // read http response
  boost::asio::streambuf response;
  boost::asio::read_until(socket, response, "\r\n\r\n");

  // print response headers
  std::istream response_stream(&response);
  std::string header;
  while (std::getline(response_stream, header) && header != "\r") {
    std::cout << "Header: " << header << std::endl;
  }

  // read chunked data
  bool reading_size = false;
  int chunk_size = 0;
  for (; true;) {
    boost::asio::read_until(socket, response, "\r\n");
    std::istream is(&response);
    reading_size = !reading_size; // toggle reading_size
    // std::cout << "debug" << std::endl;
    if (reading_size) {
      // read chunk size
      std::string chunk_size_str;

      // std::cout << "debug[1]" << std::endl;
      std::string line;
      std::getline(is, line);
      if (line.empty())
        break; // end of chunk

      // std::cout << "debug[2]" << std::endl;
      if (line.back() == '\r') {
        line.pop_back(); // remove trailing \r
      }
      // std::cout << "debug[3]: " << line << std::endl;
      chunk_size = std::stoi(line, nullptr, 16);
      // std::cout << "debug[4]" << std::endl;
      std::cout << "Chunk size: " << chunk_size << std::endl;

    } else {
      std::string chunk_data;
      // std::cout << "debug[a]" << std::endl;
      if (chunk_size > 0) {
        chunk_data.resize(chunk_size + 2);
        is.read(&chunk_data[0], chunk_size + 2);

        if (chunk_data.empty()) {
          std::cout << "Empty chunk received." << std::endl;
          break; // empty chunk
        }

        if (chunk_data.back() == '\r') {
          chunk_data.pop_back(); // remove trailing \r
        }

        std::cout << "Chunk data: " << chunk_data << std::endl;
      } else {
        std::cout << "No more chunks." << std::endl;
        break; // no more chunks
      }
    }
  }

  // close socket
  std::cout << "Connection closed." << std::endl;
  socket.close();
  return 0;
}
