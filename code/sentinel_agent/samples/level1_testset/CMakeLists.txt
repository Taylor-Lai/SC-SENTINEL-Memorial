cmake_minimum_required(VERSION 3.10)
project(sentinel_bench_level1
        VERSION     1.0.0
        DESCRIPTION "Single-file CWE microbenchmark suite for the SENTINEL audit pipeline"
        LANGUAGES   C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─── Build options ────────────────────────────────────────────────────────────
option(ENABLE_ASAN "Build every target with AddressSanitizer"     OFF)
option(ENABLE_AFL  "Build every target with afl-clang-fast"       OFF)
option(BUILD_TESTING "Enable the regression smoke tests"          ON)

# ─── Compile flags ────────────────────────────────────────────────────────────
add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -g)

if(ENABLE_ASAN)
    message(STATUS "[sentinel-bench-l1] AddressSanitizer build enabled")
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer -O0)
    add_link_options(-fsanitize=address)
endif()

if(ENABLE_AFL)
    message(STATUS "[sentinel-bench-l1] AFL++ instrumented build enabled")
    set(CMAKE_C_COMPILER afl-clang-fast)
    add_compile_options(-O1)
endif()

# ─── Shared header ────────────────────────────────────────────────────────────
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# ─── Targets ──────────────────────────────────────────────────────────────────
# Group sources by CWE so reports / IDE views can filter cleanly.
set(SOURCES_CWE_416
    uaf_direct.c
    uaf_cross_function.c
    uaf_array_slot.c
    uaf_struct_field.c)

set(SOURCES_CWE_415
    double_free_direct.c
    double_free_alias.c
    double_free_cleanup.c
    double_free_error_path.c)

set(SOURCES_CWE_122
    heap_overflow_strcpy.c
    heap_overflow_memcpy_len.c
    heap_overflow_off_by_one.c
    heap_overflow_integer_trunc.c)

set(SOURCES_CWE_121
    stack_overflow_strcpy.c
    stack_overflow_sprintf.c
    stack_overflow_index.c
    stack_overflow_loop.c)

set(SOURCES_CWE_134
    format_string_printf.c
    format_string_fprintf.c
    format_string_snprintf.c
    format_string_syslog_like.c)

set(ALL_BENCH_SOURCES
    ${SOURCES_CWE_416}
    ${SOURCES_CWE_415}
    ${SOURCES_CWE_122}
    ${SOURCES_CWE_121}
    ${SOURCES_CWE_134})

foreach(src ${ALL_BENCH_SOURCES})
    get_filename_component(target ${src} NAME_WE)
    add_executable(${target} ${src})
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endforeach()

# ─── Install ──────────────────────────────────────────────────────────────────
install(FILES ${ALL_BENCH_SOURCES} ctf_input.h
        DESTINATION share/sentinel-bench-l1/src)
install(DIRECTORY seeds/
        DESTINATION share/sentinel-bench-l1/seeds)

# ─── Tests (smoke run with default seed) ──────────────────────────────────────
if(BUILD_TESTING)
    enable_testing()
    foreach(src ${ALL_BENCH_SOURCES})
        get_filename_component(name ${src} NAME_WE)
        add_test(
            NAME    smoke_${name}
            COMMAND ${CMAKE_BINARY_DIR}/bin/${name} ${CMAKE_SOURCE_DIR}/seeds/default.bin)
        set_tests_properties(smoke_${name} PROPERTIES
            TIMEOUT 5
            # The targets are intentionally vulnerable. A nonzero exit is
            # acceptable; we only fail if the process hangs.
            PASS_REGULAR_EXPRESSION ".*"
            SKIP_RETURN_CODE        77)
    endforeach()
endif()
