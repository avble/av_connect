function(add_example name)
    add_executable(${name})
    target_sources(${name} PRIVATE ${name}.cpp)
    target_link_libraries(${name} av_connect)
endfunction()

add_example(http_srv)
add_example(http_srv_echo)
add_example(ws_srv)
# add_example(advance)
add_example(ws_client)

