# Overview
A collection of networking stuff for making network (client/server) application.

# compilation and run
The program has been tested under the `Linux 5.15.153.1-microsoft-standard-WSL2`
``` shell
$ mkdir build && cd build && cmake ..
$ make        # complation
$ ./example/http_srv  # run server
```

## dependencies
* http_parser
* boost

``` shell 
sudo apt install libhttp-parser-dev libboost-dev
```

# Features
* http/web socket server
* support `transfer-encoding` chunk


# http
I have done couple of experimental results, [libevent-http_parser](https://github.com/avble/libevent-cpp-samples/tree/main/http), [libuv-http_parser](https://github.com/avble/http_parser-libuv), asio-http_parser. 

All of them are performant, however I have personally decided to select asio as IO event and http-parser for a http server. 
And its performance can achieve `220,000 request per seconds` on ubuntu-22.04/intel i5-1135G7 @ 2.40GHz

## [http server example](https://github.com/avble/av_connect/example)

you can quick start creating a http server by the below source code.

``` cpp
int main(int argc, char ** argv)
{
    std::string addr = "127.0.0.1";
    uint16_t port    = 12345;
    http::start_server(port, [](http::response res) {
        res.body() = "[start_server_ng] hello";
        res.send();
    });
}
```

# websocket echo server

``` cpp
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
            msg.data_out() << "Echo: " << msg.data();
            msg.send();
        },
        [](beast::error_code ec) {});

    io_context::ioc.run();
}
```

## Performance
There are several criterias for measuring the performance of a http server.

And it varies from the hardward and OS. THe performance is measured on environment:
* OS: Linux 5.15.153.1-microsoft-standard-WSL2
* Hardware: 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz

The ab tool is used to measure the performance.

### Request per second
It is tested by 50 concurrency active connection and 100,000 request in total.
``` shell
$ ab -k -c 50 -n 100000 127.0.0.1:12345/route_01
```

| http server | Request per second | Remark |
|----|----|---|
| av_connect  |      ~220,000 rps      |  release-0.0.4 |
| nodejs   |    ~12,000 rps  | v12.22.9 |
| asiohttp | ~11,000 rps | 3.10.6 |
| flask   | ~697 rps | 3.0.3 |


Comparing with other http framework, which is found at [here](https://github.com/avble/av_http/example/performance)

# its application
* [OpenAI API server](https://github.com/avble/av_llm) for serving LLM inference
* 


# Reference
* HTTP/1.0 https://datatracker.ietf.org/doc/html/rfc1945
* HTTP/1.1 https://datatracker.ietf.org/doc/html/rfc2616
