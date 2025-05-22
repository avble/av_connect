cmake_minimum_required(VERSION 3.16)

project(av_connect_prj 
    LANGUAGES CXX C)


option(AV_CONNECT_BUILD_EXAMPLES "Build examples" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(lib)

if (${AV_CONNECT_BUILD_EXAMPLES} STREQUAL "ON" )
    add_subdirectory(example)
endif()
