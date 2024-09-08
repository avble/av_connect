# avb_http
A mini C++ http server backed by I/O event libraries: libevent, 

It is much ease of use and more flexible comparing samples provided by each I/O event library.

# Code example
``` cpp
#include "http.hpp"

int main(int argc, char **argv)
{

    event_base *base = event_base_global();

    auto http = make_http(base, "0.0.0.0", 12345);

    // add the lambda function as a route handler
    http->add_handler("/route_01", [](std::shared_ptr<http::request> req)
                      { req->do_write("hello from route 01\n"); });

    // add the callable object as a route handler
    struct route_02
    {
        void operator()(std::shared_ptr<http::request> req)
        {
            req->do_write("hello from route 02\n");
        }
    };
    http->add_handler("/route_02", route_02());

    http->start();

    event_base_dispatch(base);

    event_base_free(base);
}
```

## compilation and run
``` shell
$ mkdir build && cd build && cmake ..
$ make        # complation
$ ./http_srv  # run server
```

