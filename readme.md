# av_http
A mini C++ http server backed by I/O event libraries: [libevent](https://github.com/libevent/libevent) 

It is a fun project, creating a http server from scratch. 

# [http server](https://github.com/avble/av_http/)

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

Or you can start writing a simple router which is to dispatch your request to appropriate handler.
As below exapmle, two route handler are created, /route_01 and /route_02

```cpp
int main(int argc, char ** argv)
{
    std::string addr = "127.0.0.1";
    uint16_t port    = 12345;
    std::unordered_map<std::string, std::function<void(http::response)>> routes;

    routes["/route_01"] = [](http::response res) {
        res.body() = "hello from route_01";
        res.send();
    };
    routes["/route_02"] = [](http::response res) {
        res.body() = "hello from route_02";
        res.send();
    };

    auto route_handler = [&routes](http::response res) {
        if (auto route_ = routes[res.reqwest().get_uri_path()])
            route_(std::move(res));
        else
            res.send();
    };

    http::start_server(port, route_handler);
}

```

## compilation and run
The program has been tested under the `Linux 5.15.153.1-microsoft-standard-WSL2`
``` shell
$ mkdir build && cd build && cmake ..
$ make        # complation
$ ./example/http_srv  # run server
```

# Performance
There are several criterias for measuring the performance of a http server.

And it varies from the hardward and OS. THe performance is measured on environment:
* OS: Linux 5.15.153.1-microsoft-standard-WSL2
* Hardware: 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz

The ab tool is used to measure the performance. It is also understood that the evaluation result may vary on the environment (OS and hardware). 

## Request per second
This criteria is to measure the responsive of a http server.
It is tested by 50 concurrency active connection and 100,000 request in total.
``` shell
$ ab -k -c 50 -n 100000 127.0.0.1:12345/route_01
```


| http server | Request per second | Remark |
|----|----|---|
| av_http  |      ~75,000 rps      |  release-0.0.2 |
| nodejs   |    ~12,000 rps  | v12.22.9 |
| asiohttp | ~11,000 rps | 3.10.6 |
| flask   | ~697 rps | 3.0.3 |


Comparing with other http framework, which is found at [here](https://github.com/avble/av_http/example/performance)

## Concurrency Capacity
Concurrency is one of important criteria of measuring http's performance. 
This experimental result is conducted base on environment

``` shell
$ ab -k -c 1000 -n 1000000 127.0.0.1:12345/route_01
```

|server | Concurrency Level | Request per second | Remark |
|----|----|---|---|
| av_http | 1,000 | ~59,000 rps | release-0.0.2 |
| av_http | 5,000 | ~49,000 rps | release-0.0.2 |
| av_http | 10,000 | ~45,000 rps | release-0.0.2 |
| av_http | 15,000 | ~42,000 rps | release-0.0.2 |
| av_http | 20,000 | ~26,000 rps | release-0.0.2 |






