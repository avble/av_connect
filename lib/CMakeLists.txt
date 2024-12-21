option(AV_CONNECT_DISABLE_WS "Disable websocket" OFF)

add_library(av_connect STATIC)

set(av_connect_FILES io_base.cpp http.cpp)
# http
list(APPEND av_connect_FILES llhttp/api.c)
list(APPEND av_connect_FILES llhttp/http.c)
list(APPEND av_connect_FILES llhttp/llhttp.c)

set(av_connect_include_dir ./)
list(APPEND av_connect_include_dir ${libevent_SOURCE_DIR})
list(APPEND av_connect_include_dir ${llhttp_SOURCE_DIR}/include)

set(av_connect_dependent_libs )

find_package(PkgConfig)
# pkg_check_modules(av_boost boost REQUIRED)
# list(APPEND av_connect_dependent_libs  av_boost)

target_include_directories(av_connect PUBLIC ${av_connect_include_dir})
target_link_libraries(av_connect PUBLIC ${av_connect_dependent_libs})
target_sources(av_connect PRIVATE ${av_connect_FILES})
