# The JNI glue for the Java and Kotlin bridges, built on its own against a
# libcb2_c that is already built. CB2_C_LIBRARY_DIR names the directory
# that holds libcb2_c; it defaults to the repository's build tree.

cmake_minimum_required(VERSION 3.16)
project(cb2_jni LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(JNI REQUIRED)

get_filename_component(CB2_DEFAULT_C_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../build/bindings/c" ABSOLUTE)
set(CB2_C_LIBRARY_DIR "${CB2_DEFAULT_C_DIR}" CACHE PATH "Directory that holds the built libcb2_c")
set(CB2_C_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../c/include" CACHE PATH "Directory that holds cb2_c.h")

find_library(CB2_C_LIBRARY NAMES cb2_c PATHS "${CB2_C_LIBRARY_DIR}" NO_DEFAULT_PATH)
if(NOT CB2_C_LIBRARY)
    message(FATAL_ERROR "libcb2_c not found in ${CB2_C_LIBRARY_DIR}; build the C ABI first or set CB2_C_LIBRARY_DIR")
endif()

add_library(cb2_jni SHARED src/main/cpp/cb2_jni.cpp)
target_include_directories(cb2_jni PRIVATE "${CB2_C_INCLUDE_DIR}" ${JNI_INCLUDE_DIRS})
target_link_libraries(cb2_jni PRIVATE "${CB2_C_LIBRARY}")
target_compile_options(cb2_jni PRIVATE -Wall -Wextra -Wpedantic -fvisibility=hidden)
set_target_properties(cb2_jni PROPERTIES
    OUTPUT_NAME cb2_jni
    POSITION_INDEPENDENT_CODE ON
    BUILD_RPATH "${CB2_C_LIBRARY_DIR}"
    INSTALL_RPATH "${CB2_C_LIBRARY_DIR}"
    BUILD_WITH_INSTALL_RPATH ON)
