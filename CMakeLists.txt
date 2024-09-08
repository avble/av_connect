cmake_minimum_required(VERSION 3.16)

project(libevent_sample_cpp 
    LANGUAGES CXX)

set(CMAKE_BUILD_TYPE "Debug")
include(external.cmake)
add_executable(http_srv)


FILE(GLOB http_srv_SRCS "http*.cpp")

target_sources(http_srv PRIVATE ${http_srv_SRCS})

# target_include_directories(http_srv PRIVATE ${LIBEVENT_INCLUDE_DIRS})
target_include_directories(http_srv PRIVATE ${libevent_SOURCE_DIR})
target_compile_options(http_srv PRIVATE -g)

# target_link_directories(http_srv PUBLIC ${libevent_BINARY_DIR})

set_property(TARGET http_srv PROPERTY CXX_STANDARD 17)
target_link_libraries(http_srv PUBLIC event_static event_core_static)
