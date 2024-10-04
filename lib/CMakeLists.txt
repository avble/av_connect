add_library(av_http INTERFACE)

target_sources(av_http PUBLIC event.hpp http.hpp internal/base.hpp)

target_include_directories(av_http INTERFACE ${libevent_SOURCE_DIR})

target_include_directories(av_http INTERFACE ${llhttp_SOURCE_DIR}/include)

target_link_libraries(av_http INTERFACE llhttp_static event_static event_core_static)
