#ifndef __LOG_H__
#define __LOG_H__

#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <stdio.h>

enum log_level
{
    LOG_TRACE = 0,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
};

namespace {
    // Default log level based on build type
    #ifdef NDEBUG
        static log_level current_log_level = LOG_INFO;  // Release build
    #else
        static log_level current_log_level = LOG_DEBUG; // Debug build
    #endif

    // Initialize log level from environment variable
    static struct LogLevelInitializer {
        LogLevelInitializer() {
            const char* env_level = std::getenv("AV_CONNECT_LOG_LEVEL");
            if (env_level) {
                if (strcmp(env_level, "TRACE") == 0) current_log_level = LOG_TRACE;
                else if (strcmp(env_level, "DEBUG") == 0) current_log_level = LOG_DEBUG;
                else if (strcmp(env_level, "INFO") == 0) current_log_level = LOG_INFO;
                else if (strcmp(env_level, "WARN") == 0) current_log_level = LOG_WARN;
                else if (strcmp(env_level, "ERROR") == 0) current_log_level = LOG_ERROR;
            }

        }
    } log_level_initializer;

    // Helper function to get log level prefix
    const char* get_level_prefix(log_level level) {
        switch (level) {
            case LOG_TRACE: return "[TRACE]";
            case LOG_DEBUG: return "[DEBUG]";
            case LOG_INFO:  return "[INFO] ";
            case LOG_WARN:  return "[WARN] ";
            case LOG_ERROR: return "[ERROR]";
            default:        return "[?????]";
        }
    }
}

template <typename... Args>
void log(log_level level, const char * format, Args... args)
{
    if (level >= current_log_level)
    {
        printf(format, args...);
    }
}

// Base logging function
template <typename... Args>
static void log(log_level level, const char* module, const char* format, Args... args)
{
    if (level >= current_log_level)
    {
        printf("%s[%s] ", get_level_prefix(level), module);
        printf(format, args...);
    }
}

// Convenience macros for logging
#define LOG_TRACE(...) log(LOG_TRACE, __VA_ARGS__)
#define LOG_DEBUG(...) log(LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...)  log(LOG_INFO, __VA_ARGS__)
#define LOG_WARN(...)  log(LOG_WARN, __VA_ARGS__)
#define LOG_ERROR(...) log(LOG_ERROR, __VA_ARGS__)

#endif