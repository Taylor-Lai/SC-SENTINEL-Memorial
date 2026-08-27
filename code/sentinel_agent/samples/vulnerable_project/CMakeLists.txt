cmake_minimum_required(VERSION 3.10)
project(vulnerable_project C CXX)

find_package(OpenSSL REQUIRED)
add_executable(vulnerable_project
    uaf_demo.c
    double_free_demo.c
    heap_overflow_demo.c
    stack_overflow_demo.c
    format_string_demo.c
)
target_link_libraries(vulnerable_project OpenSSL::SSL OpenSSL::Crypto)
