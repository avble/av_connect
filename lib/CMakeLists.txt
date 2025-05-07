option(AV_CONNECT_DISABLE_WS "Disable websocket" OFF)

add_library(av_connect STATIC)

set(av_connect_FILES io_base.cpp http.cpp http_parser.cpp)
# http
list(APPEND av_connect_FILES llhttp/api.c)
list(APPEND av_connect_FILES llhttp/http.c)
list(APPEND av_connect_FILES llhttp/llhttp.c)

set(av_connect_include_dir ./)
list(APPEND av_connect_include_dir ${libevent_SOURCE_DIR})
list(APPEND av_connect_include_dir ${llhttp_SOURCE_DIR}/include)

if (APPLE)
    cmake_policy(SET CMP0167 OLD)
    find_package(Boost REQUIRED COMPONENTS system)
    target_include_directories(av_connect PUBLIC ${Boost_INCLUDE_DIR})
elseif (UNIX)
    find_package(PkgConfig REQUIRED)
    kg_check_modules(av_boost Boost REQUIRED)
endif()
# set(av_connect_dependent_libs )


target_include_directories(av_connect PUBLIC ${av_connect_include_dir})
target_link_libraries(av_connect PUBLIC ${av_connect_dependent_libs})
target_sources(av_connect PRIVATE ${av_connect_FILES})
