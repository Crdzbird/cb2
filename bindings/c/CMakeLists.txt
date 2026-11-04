# The C ABI as a shared and a static library, and its test. Included from
# the root CMakeLists.txt when CB2_BUILD_BINDINGS is on; also usable on
# its own with -DCB2_C_STANDALONE=ON against an installed cb2.

add_library(cb2_c SHARED src/cb2_c.cpp)
add_library(cb2_c_static STATIC src/cb2_c.cpp)
foreach(_t cb2_c cb2_c_static)
    target_include_directories(${_t} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
    target_link_libraries(${_t} PRIVATE cb2::cb2)
    target_compile_options(${_t} PRIVATE ${CB2_WARNINGS} ${CB2_SANITIZE_FLAGS} -fvisibility=hidden)
    target_link_options(${_t} PRIVATE ${CB2_SANITIZE_FLAGS})
    set_target_properties(${_t} PROPERTIES OUTPUT_NAME cb2_c POSITION_INDEPENDENT_CODE ON)
endforeach()
set_target_properties(cb2_c PROPERTIES VERSION 0.1.0 SOVERSION 0)

if(CB2_BUILD_TESTS)
    add_executable(cb2_c_test test/test_c.c)
    target_link_libraries(cb2_c_test PRIVATE cb2_c)
    target_compile_options(cb2_c_test PRIVATE -Wall -Wextra -Wpedantic ${CB2_SANITIZE_FLAGS})
    target_link_options(cb2_c_test PRIVATE ${CB2_SANITIZE_FLAGS})
    add_test(NAME cb2_c_test COMMAND cb2_c_test)
endif()
