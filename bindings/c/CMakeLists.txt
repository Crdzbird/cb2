# The C ABI as a shared and a static library, its test, the example CLI,
# and the install rules: the header, both libraries, a CMake package
# (find_package(cb2_c), targets cb2_c::cb2_c and cb2_c::cb2_c_static) and
# a pkg-config file (cb2_c.pc). Included from the root CMakeLists.txt when
# CB2_BUILD_BINDINGS is on. The shared library stays at
# build/bindings/c/libcb2_c, where every language bridge links it.

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/include/cb2_c.h" _cb2_c_defines
     REGEX "^#define CB2_C_(VERSION_MAJOR|VERSION_MINOR|VERSION_PATCH|ABI_VERSION) [0-9]+$")
foreach(_line IN LISTS _cb2_c_defines)
    string(REGEX MATCH "^#define CB2_C_([A-Z_]+) ([0-9]+)$" _ "${_line}")
    set(CB2_C_${CMAKE_MATCH_1} ${CMAKE_MATCH_2})
endforeach()
set(CB2_C_VERSION "${CB2_C_VERSION_MAJOR}.${CB2_C_VERSION_MINOR}.${CB2_C_VERSION_PATCH}")
if(NOT CB2_C_VERSION STREQUAL PROJECT_VERSION OR NOT DEFINED CB2_C_ABI_VERSION)
    message(FATAL_ERROR "cb2_c: cb2_c.h says ${CB2_C_VERSION} (ABI ${CB2_C_ABI_VERSION}), the project says ${PROJECT_VERSION}")
endif()

add_library(cb2_c SHARED src/cb2_c.cpp)
add_library(cb2_c_static STATIC src/cb2_c.cpp)
foreach(_t cb2_c cb2_c_static)
    target_include_directories(${_t} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    target_link_libraries(${_t} PRIVATE $<BUILD_INTERFACE:cb2::cb2>)
    target_compile_options(${_t} PRIVATE ${CB2_WARNINGS} ${CB2_SANITIZE_FLAGS} -fvisibility=hidden)
    target_link_options(${_t} PRIVATE ${CB2_SANITIZE_FLAGS})
    set_target_properties(${_t} PROPERTIES OUTPUT_NAME cb2_c POSITION_INDEPENDENT_CODE ON)
endforeach()
target_compile_definitions(cb2_c PRIVATE CB2_C_BUILDING)
target_compile_definitions(cb2_c_static PUBLIC CB2_C_STATIC)
set_target_properties(cb2_c PROPERTIES VERSION ${CB2_C_VERSION} SOVERSION ${CB2_C_ABI_VERSION})
if(WIN32)
    set_target_properties(cb2_c_static PROPERTIES OUTPUT_NAME cb2_c_static)
endif()

if(APPLE)
    set(_cb2_c_exports "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cb2_c.exports")
    target_link_options(cb2_c PRIVATE "LINKER:-exported_symbols_list,${_cb2_c_exports}")
    set_property(TARGET cb2_c APPEND PROPERTY LINK_DEPENDS "${_cb2_c_exports}")
elseif(UNIX)
    set(_cb2_c_map "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cb2_c.map")
    target_link_options(cb2_c PRIVATE "LINKER:--version-script=${_cb2_c_map}")
    set_property(TARGET cb2_c APPEND PROPERTY LINK_DEPENDS "${_cb2_c_map}")
endif()

set(_cb2_c_dep_libs ${SODIUM_LINK_LIBRARIES} ${BLAKE3_LINK_LIBRARIES})
set(_cb2_c_pc_requires "libsodium libblake3")
set(_cb2_c_pc_libs "")
if(CB2_PQ)
    if(OQS_FOUND)
        list(APPEND _cb2_c_dep_libs ${OQS_LINK_LIBRARIES})
        string(APPEND _cb2_c_pc_requires " liboqs")
    else()
        list(APPEND _cb2_c_dep_libs ${OQS_LIBRARIES})
        string(APPEND _cb2_c_pc_libs " ${OQS_LIBRARIES}")
    endif()
endif()
list(APPEND _cb2_c_dep_libs ${OPENSSL_LINK_LIBRARIES})
string(APPEND _cb2_c_pc_requires " libcrypto")
if(APPLE)
    set(_cb2_c_runtime c++)
else()
    set(_cb2_c_runtime stdc++ m)
endif()
list(APPEND _cb2_c_dep_libs ${_cb2_c_runtime})
foreach(_lib IN LISTS _cb2_c_runtime)
    string(APPEND _cb2_c_pc_libs " -l${_lib}")
endforeach()
target_link_libraries(cb2_c_static INTERFACE $<INSTALL_INTERFACE:${_cb2_c_dep_libs}>)

if(CB2_BUILD_TESTS)
    add_executable(cb2_c_test test/test_c.c)
    target_link_libraries(cb2_c_test PRIVATE cb2_c)
    target_compile_options(cb2_c_test PRIVATE -Wall -Wextra -Wpedantic ${CB2_SANITIZE_FLAGS})
    target_link_options(cb2_c_test PRIVATE ${CB2_SANITIZE_FLAGS})
    add_test(NAME cb2_c_test COMMAND cb2_c_test)
endif()

if(CB2_BUILD_EXAMPLES)
    add_executable(cb2_c_example examples/cb2_c_example.c)
    target_link_libraries(cb2_c_example PRIVATE cb2_c)
    target_compile_options(cb2_c_example PRIVATE -Wall -Wextra -Wpedantic ${CB2_SANITIZE_FLAGS})
    target_link_options(cb2_c_example PRIVATE ${CB2_SANITIZE_FLAGS})
    if(CB2_BUILD_TESTS)
        add_test(NAME cb2_c_example COMMAND cb2_c_example)
    endif()
endif()

set(_cb2_c_cmakedir "${CMAKE_INSTALL_LIBDIR}/cmake/cb2_c")
install(TARGETS cb2_c cb2_c_static EXPORT cb2_cTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/cb2_c.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT cb2_cTargets NAMESPACE cb2_c:: DESTINATION ${_cb2_c_cmakedir})

set(CB2_C_HAS_PUBLIC ${CB2_PQ})
configure_package_config_file(cmake/cb2_cConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/cb2_cConfig.cmake"
    INSTALL_DESTINATION ${_cb2_c_cmakedir})
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/cb2_cConfigVersion.cmake"
    VERSION ${CB2_C_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/cb2_cConfig.cmake" "${CMAKE_CURRENT_BINARY_DIR}/cb2_cConfigVersion.cmake"
    DESTINATION ${_cb2_c_cmakedir})

set(_cb2_c_pcdir "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
file(RELATIVE_PATH _cb2_c_pc_up "/root/${_cb2_c_pcdir}" "/root")
string(REGEX REPLACE "/$" "" _cb2_c_pc_up "${_cb2_c_pc_up}")
set(CB2_C_PC_PREFIX "\${pcfiledir}/${_cb2_c_pc_up}")
set(CB2_C_PC_LIBDIR "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
set(CB2_C_PC_INCLUDEDIR "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
set(CB2_C_PC_REQUIRES "${_cb2_c_pc_requires}")
string(STRIP "${_cb2_c_pc_libs}" CB2_C_PC_LIBS_PRIVATE)
configure_file(cmake/cb2_c.pc.in "${CMAKE_CURRENT_BINARY_DIR}/cb2_c.pc" @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/cb2_c.pc" DESTINATION ${_cb2_c_pcdir})
