option(AV_CONNECT_DISABLE_WS "Disable websocket" OFF)

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


if (APPLE OR IS_WSL)
	#cmake_policy(SET CMP0167 OLD)
    find_package(Boost REQUIRED COMPONENTS system)
    target_include_directories(av_connect PUBLIC ${Boost_INCLUDE_DIR})
elseif (UNIX AND NOT MINGW)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(av_boost BOOST REQUIRED)
endif()
# set(av_connect_dependent_libs )


target_include_directories(av_connect PUBLIC ${av_connect_include_dir})
target_link_libraries(av_connect PUBLIC ${av_connect_dependent_libs})
target_sources(av_connect PRIVATE ${av_connect_FILES})
