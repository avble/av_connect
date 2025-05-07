function(add_example name)
    add_executable(${name})
    target_sources(${name} PRIVATE ${name}.cpp)
    # set_property(TARGET ${name} PROPERTY CXX_STANDARD 17)
    # target_link_libraries(${name} ${CMAKE_SOURCE_DIR}/example/libav_connect.a http_parser)
    target_link_libraries(${name} av_connect)
endfunction()

add_example(http_srv)
add_example(ws_srv)
# add_example(advance)
add_example(ws_client)

