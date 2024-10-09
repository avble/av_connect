#pragma once
#include <boost/asio.hpp>

class io_context
{
public:
    static boost::asio::io_context ioc;
};
