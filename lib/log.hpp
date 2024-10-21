#pragma once

#include <cstdarg>
#include <stdio.h>

enum log_level
{
    LOG_TRACE = 0,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
};

template <typename... Args>
static void log(const char * format, Args... args)
{
    printf(format, args...);
}
