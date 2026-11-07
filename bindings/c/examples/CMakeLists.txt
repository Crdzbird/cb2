# Builds cb2_c_example against an installed cb2_c:
#
#   cmake -S bindings/c/examples -B build-example -DCMAKE_PREFIX_PATH=<prefix>
#   cmake --build build-example
#
# -DCB2_C_EXAMPLE_STATIC=ON links the static library instead.

cmake_minimum_required(VERSION 3.20)
project(cb2_c_example LANGUAGES C)

option(CB2_C_EXAMPLE_STATIC "Link cb2_c::cb2_c_static instead of the shared library" OFF)

find_package(cb2_c 0.1 REQUIRED)

add_executable(cb2_c_example cb2_c_example.c)
if(CB2_C_EXAMPLE_STATIC)
    target_link_libraries(cb2_c_example PRIVATE cb2_c::cb2_c_static)
else()
    target_link_libraries(cb2_c_example PRIVATE cb2_c::cb2_c)
endif()
