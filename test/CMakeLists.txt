add_executable(test_routes test_routes.cpp)
target_link_libraries(test_routes PRIVATE av_connect)
target_include_directories(test_routes PRIVATE ${CMAKE_SOURCE_DIR}/lib) 
target_compile_options(test_routes PRIVATE /bigobj)
