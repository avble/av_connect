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

static void log(const char * format, ...)
{
    va_list args;
    va_start(args, format);
    printf(format, args);
    va_end(args);
}
