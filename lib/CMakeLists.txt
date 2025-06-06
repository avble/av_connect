option(AV_CONNECT_DISABLE_WS "Disable websocket" OFF)

include(FetchContent)

# Declare Boost dependency
FetchContent_Declare(
    Boost
    URL https://github.com/boostorg/boost/releases/download/boost-1.84.0/boost-1.84.0.tar.gz
    URL_HASH SHA256=4d27e9efed0f6f152dc28db6430b9d3dfb40c0345da7342eaa5a987dde57bd95
)

# Include both system and asio components
set(BOOST_INCLUDE_LIBRARIES system;asio;beast)
set(BOOST_ENABLE_CMAKE ON)
FetchContent_MakeAvailable(Boost)

add_library(av_connect STATIC)

target_sources(av_connect PRIVATE io_base.cpp http.cpp http_parser.cpp)
# http
list(APPEND av_connect_FILES llhttp/api.c)
list(APPEND av_connect_FILES llhttp/http.c)
list(APPEND av_connect_FILES llhttp/llhttp.c)

set(av_connect_include_dir ./)
list(APPEND av_connect_include_dir ${libevent_SOURCE_DIR})
list(APPEND av_connect_include_dir ${llhttp_SOURCE_DIR}/include)

if (UNIX)
if (EXISTS "/proc/version" AND IS_DIRECTORY "/mnt")
    set(IS_WSL TRUE)
    endif()
endif()

if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.30")
    if (POLICY CMP0167)
        cmake_policy(SET CMP0167 OLD)
    endif()
endif()

# Link against both Boost::system and Boost::asio
target_link_libraries(av_connect 
    PUBLIC 
        Boost::system
        Boost::asio
        Boost::beast
)

target_include_directories(av_connect PUBLIC ${av_connect_include_dir})
target_link_libraries(av_connect PUBLIC ${av_connect_dependent_libs})
target_sources(av_connect PRIVATE ${av_connect_FILES})
