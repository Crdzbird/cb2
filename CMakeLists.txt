cmake_minimum_required(VERSION 3.20)
project(cb2 VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(CB2_PQ "Build cb2.public with the Ed25519 + ML-DSA-65 hybrid (requires liboqs)" ON)
option(CB2_BUILD_TESTS "Build the test runner and the vector generator" ON)
option(CB2_BUILD_BENCH "Build the benchmark against CipherBird's v4.local and cb1.local (needs CB2_CRYPTOLIB_INCLUDE)" ON)
option(CB2_BUILD_EXAMPLES "Build the runnable examples under examples/" ON)
option(CB2_BUILD_PLAYGROUND "Build the interactive playground under playground/" ON)
option(CB2_FUZZ "Build the libFuzzer targets (LLVM clang only)" OFF)
option(CB2_SANITIZE "Build tests and bench with AddressSanitizer + UBSan" OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.18)
pkg_check_modules(BLAKE3 REQUIRED libblake3)

add_library(cb2 INTERFACE)
add_library(cb2::cb2 ALIAS cb2)
target_include_directories(cb2 INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    ${SODIUM_INCLUDE_DIRS} ${BLAKE3_INCLUDE_DIRS})
target_link_directories(cb2 INTERFACE ${SODIUM_LIBRARY_DIRS} ${BLAKE3_LIBRARY_DIRS})
target_link_libraries(cb2 INTERFACE ${SODIUM_LIBRARIES} ${BLAKE3_LIBRARIES})
target_compile_features(cb2 INTERFACE cxx_std_20)

if(CB2_PQ)
    pkg_check_modules(OQS liboqs)
    if(NOT OQS_FOUND)
        find_library(OQS_LIBRARY oqs PATHS /opt/homebrew/lib /usr/local/lib)
        find_path(OQS_INCLUDE_DIR oqs/oqs.h PATHS /opt/homebrew/include /usr/local/include)
        if(NOT OQS_LIBRARY OR NOT OQS_INCLUDE_DIR)
            message(FATAL_ERROR "cb2: CB2_PQ is ON but liboqs was not found; install liboqs or configure with -DCB2_PQ=OFF (cb2.public is then unavailable)")
        endif()
        set(OQS_LIBRARIES ${OQS_LIBRARY})
        set(OQS_INCLUDE_DIRS ${OQS_INCLUDE_DIR})
        set(OQS_LIBRARY_DIRS "")
    endif()
    pkg_check_modules(OPENSSL REQUIRED libcrypto>=3.0)
    target_compile_definitions(cb2 INTERFACE CB2_HAS_PQ=1)
    target_include_directories(cb2 INTERFACE ${OQS_INCLUDE_DIRS})
    target_link_directories(cb2 INTERFACE ${OQS_LIBRARY_DIRS} ${OPENSSL_LIBRARY_DIRS})
    target_link_libraries(cb2 INTERFACE ${OQS_LIBRARIES} ${OPENSSL_LIBRARIES})
    message(STATUS "cb2: cb2.public enabled (liboqs)")
else()
    message(STATUS "cb2: cb2.public disabled; only cb2.local is built")
endif()

set(CB2_WARNINGS -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow)

set(CB2_SANITIZE_FLAGS "")
if(CB2_SANITIZE)
    set(CB2_SANITIZE_FLAGS
        -fsanitize=address,undefined
        -fno-sanitize-recover=all
        -fno-omit-frame-pointer
        -g)
    message(STATUS "cb2: AddressSanitizer + UBSan enabled")
endif()

if(CB2_BUILD_TESTS)
    enable_testing()
    add_executable(cb2_tests
        tests/test_main.cpp
        tests/test_codec.cpp
        tests/test_local.cpp
        tests/test_public.cpp
        tests/test_claims.cpp
        tests/test_keys.cpp
        tests/test_vectors.cpp
        tests/test_v4_crosscheck.cpp
        tests/test_text.cpp
        tests/test_holder.cpp)
    target_link_libraries(cb2_tests PRIVATE cb2::cb2)
    target_compile_options(cb2_tests PRIVATE ${CB2_WARNINGS} ${CB2_SANITIZE_FLAGS})
    target_link_options(cb2_tests PRIVATE ${CB2_SANITIZE_FLAGS})
    target_compile_definitions(cb2_tests PRIVATE
        CB2_TEST_NONCE=1
        CB2_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors"
        CB2_V4_VECTORS="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/paseto-v4/v4.json")
    add_test(NAME cb2_tests COMMAND cb2_tests)

    add_executable(cb2_gen_vectors tests/gen_vectors.cpp)
    target_link_libraries(cb2_gen_vectors PRIVATE cb2::cb2)
    target_compile_options(cb2_gen_vectors PRIVATE ${CB2_WARNINGS} ${CB2_SANITIZE_FLAGS})
    target_link_options(cb2_gen_vectors PRIVATE ${CB2_SANITIZE_FLAGS})
    target_compile_definitions(cb2_gen_vectors PRIVATE CB2_TEST_NONCE=1)
endif()

if(CB2_BUILD_EXAMPLES)
    add_executable(cb2_example_text examples/international_text.cpp)
    target_link_libraries(cb2_example_text PRIVATE cb2::cb2)
    target_compile_options(cb2_example_text PRIVATE ${CB2_WARNINGS} ${CB2_SANITIZE_FLAGS})
    target_link_options(cb2_example_text PRIVATE ${CB2_SANITIZE_FLAGS})
    if(CB2_BUILD_TESTS)
        add_test(NAME cb2_example_text COMMAND cb2_example_text)
    endif()
endif()

if(CB2_BUILD_PLAYGROUND)
    add_executable(cb2_playground playground/playground.cpp)
    target_link_libraries(cb2_playground PRIVATE cb2::cb2)
    target_compile_options(cb2_playground PRIVATE ${CB2_WARNINGS} ${CB2_SANITIZE_FLAGS})
    target_link_options(cb2_playground PRIVATE ${CB2_SANITIZE_FLAGS})
    if(CB2_BUILD_TESTS)
        add_test(NAME cb2_playground_demo COMMAND cb2_playground "${CMAKE_CURRENT_SOURCE_DIR}/playground/demo.cb2")
        add_test(NAME cb2_playground_demo_text COMMAND cb2_playground "${CMAKE_CURRENT_SOURCE_DIR}/playground/demo_text.cb2")
        if(CB2_PQ)
            add_test(NAME cb2_playground_demo_public COMMAND cb2_playground "${CMAKE_CURRENT_SOURCE_DIR}/playground/demo_public.cb2")
            add_test(NAME cb2_playground_demo_holder COMMAND cb2_playground "${CMAKE_CURRENT_SOURCE_DIR}/playground/demo_holder.cb2")
        endif()
    endif()
endif()

if(CB2_BUILD_BENCH)
    set(CB2_CRYPTOLIB_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/../cryptolib/include" CACHE PATH
        "CipherBird's include directory, for the reference benchmark against v4.local and cb1.local")
    if(EXISTS "${CB2_CRYPTOLIB_INCLUDE}/cryptolib/paseto.hpp")
        add_executable(cb2_bench bench/bench_main.cpp bench/bench_ref.cpp)
        target_link_libraries(cb2_bench PRIVATE cb2::cb2)
        target_include_directories(cb2_bench PRIVATE "${CB2_CRYPTOLIB_INCLUDE}")
        target_compile_definitions(cb2_bench PRIVATE CRYPTOLIB_HAS_BLAKE3=1)
        target_compile_options(cb2_bench PRIVATE -O2 ${CB2_SANITIZE_FLAGS})
        target_link_options(cb2_bench PRIVATE ${CB2_SANITIZE_FLAGS})
    else()
        message(STATUS "cb2: no cryptolib/paseto.hpp under ${CB2_CRYPTOLIB_INCLUDE}; the benchmark is skipped")
    endif()
endif()

if(CB2_FUZZ)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "CB2_FUZZ requires clang with the libFuzzer runtime")
    endif()
    foreach(_fz fuzz_local fuzz_public fuzz_claims)
        add_executable(cb2_${_fz} fuzz/${_fz}.cpp)
        target_link_libraries(cb2_${_fz} PRIVATE cb2::cb2)
        target_compile_options(cb2_${_fz} PRIVATE -g -O1 -fsanitize=fuzzer,address,undefined)
        target_link_options(cb2_${_fz} PRIVATE -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()

install(DIRECTORY include/ DESTINATION include)
