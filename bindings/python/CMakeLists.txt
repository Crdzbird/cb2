cmake_minimum_required(VERSION 3.20)
project(cb2_python LANGUAGES C CXX)

# Builds the cb2_c target of bindings/c through the repository's root
# CMakeLists.txt, which finds libsodium, BLAKE3, libcrypto and liboqs,
# and installs that shared library inside the cb2 package of the wheel
# under its unversioned name. scikit-build-core drives this file; see
# pyproject.toml.

set(CB2_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." CACHE PATH "The root of the cb2 repository")

set(CB2_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CB2_BUILD_BENCH OFF CACHE BOOL "" FORCE)
set(CB2_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CB2_BUILD_PLAYGROUND OFF CACHE BOOL "" FORCE)
set(CB2_BUILD_BINDINGS ON CACHE BOOL "" FORCE)
add_subdirectory("${CB2_ROOT}" cb2 EXCLUDE_FROM_ALL)

add_custom_target(cb2_python_library ALL DEPENDS cb2_c)

install(FILES "$<TARGET_FILE:cb2_c>"
    DESTINATION cb2
    RENAME "${CMAKE_SHARED_LIBRARY_PREFIX}cb2_c${CMAKE_SHARED_LIBRARY_SUFFIX}"
    COMPONENT cb2_python)
