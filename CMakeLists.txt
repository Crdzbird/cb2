cmake_minimum_required(VERSION 3.20)
project(paseto5 VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(PASETO5_PQ "Build v5.public with the Ed25519 + ML-DSA-65 hybrid (requires liboqs)" ON)
option(PASETO5_BUILD_TESTS "Build the test runner and the vector generator" ON)
option(PASETO5_BUILD_BENCH "Build the benchmark against cryptolib's v4.local and cb1.local" ON)
option(PASETO5_FUZZ "Build the libFuzzer targets (LLVM clang only)" OFF)
option(PASETO5_SANITIZE "Build tests and bench with AddressSanitizer + UBSan" OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.18)
pkg_check_modules(BLAKE3 REQUIRED libblake3)

add_library(paseto5 INTERFACE)
add_library(paseto5::paseto5 ALIAS paseto5)
target_include_directories(paseto5 INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    ${SODIUM_INCLUDE_DIRS} ${BLAKE3_INCLUDE_DIRS})
target_link_directories(paseto5 INTERFACE ${SODIUM_LIBRARY_DIRS} ${BLAKE3_LIBRARY_DIRS})
target_link_libraries(paseto5 INTERFACE ${SODIUM_LIBRARIES} ${BLAKE3_LIBRARIES})
target_compile_features(paseto5 INTERFACE cxx_std_20)

if(PASETO5_PQ)
    pkg_check_modules(OQS liboqs)
    if(NOT OQS_FOUND)
        find_library(OQS_LIBRARY oqs PATHS /opt/homebrew/lib /usr/local/lib)
        find_path(OQS_INCLUDE_DIR oqs/oqs.h PATHS /opt/homebrew/include /usr/local/include)
        if(NOT OQS_LIBRARY OR NOT OQS_INCLUDE_DIR)
            message(FATAL_ERROR "paseto5: PASETO5_PQ is ON but liboqs was not found; install liboqs or configure with -DPASETO5_PQ=OFF (v5.public is then unavailable)")
        endif()
        set(OQS_LIBRARIES ${OQS_LIBRARY})
        set(OQS_INCLUDE_DIRS ${OQS_INCLUDE_DIR})
        set(OQS_LIBRARY_DIRS "")
    endif()
    pkg_check_modules(OPENSSL REQUIRED libcrypto>=3.0)
    target_compile_definitions(paseto5 INTERFACE PASETO5_HAS_PQ=1)
    target_include_directories(paseto5 INTERFACE ${OQS_INCLUDE_DIRS})
    target_link_directories(paseto5 INTERFACE ${OQS_LIBRARY_DIRS} ${OPENSSL_LIBRARY_DIRS})
    target_link_libraries(paseto5 INTERFACE ${OQS_LIBRARIES} ${OPENSSL_LIBRARIES})
    message(STATUS "paseto5: v5.public enabled (liboqs)")
else()
    message(STATUS "paseto5: v5.public disabled; only v5.local is built")
endif()

set(PASETO5_WARNINGS -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow)

set(PASETO5_SANITIZE_FLAGS "")
if(PASETO5_SANITIZE)
    set(PASETO5_SANITIZE_FLAGS
        -fsanitize=address,undefined
        -fno-sanitize-recover=all
        -fno-omit-frame-pointer
        -g)
    message(STATUS "paseto5: AddressSanitizer + UBSan enabled")
endif()

if(PASETO5_BUILD_TESTS)
    enable_testing()
    add_executable(paseto5_tests
        tests/test_main.cpp
        tests/test_codec.cpp
        tests/test_local.cpp
        tests/test_public.cpp
        tests/test_claims.cpp
        tests/test_keys.cpp
        tests/test_vectors.cpp
        tests/test_v4_crosscheck.cpp)
    target_link_libraries(paseto5_tests PRIVATE paseto5::paseto5)
    target_compile_options(paseto5_tests PRIVATE ${PASETO5_WARNINGS} ${PASETO5_SANITIZE_FLAGS})
    target_link_options(paseto5_tests PRIVATE ${PASETO5_SANITIZE_FLAGS})
    target_compile_definitions(paseto5_tests PRIVATE
        PASETO5_TEST_NONCE=1
        PASETO5_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors"
        PASETO5_V4_VECTORS="${CMAKE_CURRENT_SOURCE_DIR}/../tests/vectors/paseto/v4.json")
    add_test(NAME paseto5_tests COMMAND paseto5_tests)

    add_executable(paseto5_gen_vectors tests/gen_vectors.cpp)
    target_link_libraries(paseto5_gen_vectors PRIVATE paseto5::paseto5)
    target_compile_options(paseto5_gen_vectors PRIVATE ${PASETO5_WARNINGS} ${PASETO5_SANITIZE_FLAGS})
    target_link_options(paseto5_gen_vectors PRIVATE ${PASETO5_SANITIZE_FLAGS})
    target_compile_definitions(paseto5_gen_vectors PRIVATE PASETO5_TEST_NONCE=1)
endif()

if(PASETO5_BUILD_BENCH)
    set(_cryptolib_include "${CMAKE_CURRENT_SOURCE_DIR}/../include")
    if(EXISTS "${_cryptolib_include}/cryptolib/paseto.hpp")
        add_executable(paseto5_bench bench/bench_main.cpp bench/bench_ref.cpp)
        target_link_libraries(paseto5_bench PRIVATE paseto5::paseto5)
        target_include_directories(paseto5_bench PRIVATE "${_cryptolib_include}")
        target_compile_definitions(paseto5_bench PRIVATE CRYPTOLIB_HAS_BLAKE3=1)
        target_compile_options(paseto5_bench PRIVATE -O2 ${PASETO5_SANITIZE_FLAGS})
        target_link_options(paseto5_bench PRIVATE ${PASETO5_SANITIZE_FLAGS})
    else()
        message(STATUS "paseto5: ../include/cryptolib not found; the benchmark is skipped")
    endif()
endif()

if(PASETO5_FUZZ)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "PASETO5_FUZZ requires clang with the libFuzzer runtime")
    endif()
    foreach(_fz fuzz_local fuzz_public fuzz_claims)
        add_executable(paseto5_${_fz} fuzz/${_fz}.cpp)
        target_link_libraries(paseto5_${_fz} PRIVATE paseto5::paseto5)
        target_compile_options(paseto5_${_fz} PRIVATE -g -O1 -fsanitize=fuzzer,address,undefined)
        target_link_options(paseto5_${_fz} PRIVATE -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()

install(DIRECTORY include/ DESTINATION include)
