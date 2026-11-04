# The Flutter tooling requires CMake 3.10 or later; do not raise this.
cmake_minimum_required(VERSION 3.10)

set(PROJECT_NAME "cb2_flutter")
project(${PROJECT_NAME} LANGUAGES CXX)

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../src" "${CMAKE_CURRENT_BINARY_DIR}/shared")

# libcb2_c.so is bundled with the application. Shared dependency libraries
# (libsodium, BLAKE3, liboqs, libcrypto) are not; link them statically into
# libcb2_c or add their paths to this list.
set(cb2_flutter_bundled_libraries
  $<TARGET_FILE:cb2_c>
  PARENT_SCOPE
)
