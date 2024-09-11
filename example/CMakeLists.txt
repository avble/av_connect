add_executable(http_srv)

FILE(GLOB http_srv_SRCS "http_srv.cpp")

target_sources(http_srv PRIVATE ${http_srv_SRCS})

target_include_directories(http_srv PRIVATE ${libevent_SOURCE_DIR})

set_property(TARGET http_srv PROPERTY CXX_STANDARD 17)
target_link_libraries(http_srv PUBLIC event_static event_core_static)


# add_executable(http_chunk_srv)

# FILE(GLOB http_chunk_srv_SRCS "http_srv_chunk.cpp")

# target_sources(http_chunk_srv PRIVATE ${http_chunk_srv_SRCS})

# target_include_directories(http_chunk_srv PRIVATE ${libevent_SOURCE_DIR})
# target_compile_options(http_chunk_srv PRIVATE -g)

# set_property(TARGET http_chunk_srv PROPERTY CXX_STANDARD 17)
# target_link_libraries(http_chunk_srv PUBLIC event_static event_core_static)
