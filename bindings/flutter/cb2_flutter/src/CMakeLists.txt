# The native library of the cb2_flutter plugin for Android, Linux and
# Windows: the C ABI of cb2 (bindings/c/src/cb2_c.cpp) compiled against the
# cb2 headers. The Flutter tooling requires CMake 3.10 or later; do not
# raise this minimum.
#
# cb2 depends on libsodium and BLAKE3, on liboqs when CB2_PQ is on
# (cb2.public and kcb2.seal), and on libcrypto when CB2_OPENSSL_CHACHA is
# on. Those are not vendored here; supply them for the target platform and
# architecture:
#
#   CB2_DEPS_ROOT   a prefix holding include/ and lib/ for the target, or
#                   on Android a directory with one such prefix per ABI
#                   (<root>/arm64-v8a, <root>/x86_64, ...), as
#                   tool/build_android_deps.sh writes to build/android-deps
#                   of the plugin, the Android default. Also read from the
#                   environment variable of the same name.
#   CB2_DEPS_LIBS   the library names to link, when they differ from the
#                   defaults: sodium and blake3, then crypto with
#                   CB2_OPENSSL_CHACHA and oqs with CB2_PQ.
#   CB2_PQ          ON by default; OFF builds cb2.local only, without liboqs.
#   CB2_OPENSSL_CHACHA
#                   OpenSSL's ChaCha20 for messages of 512 bytes or more;
#                   ON by default except on Android, where every message
#                   stays on libsodium and no OpenSSL is linked.
#
# Without CB2_DEPS_ROOT, pkg-config is consulted where it exists, which is
# the Linux desktop case. Static dependency libraries give a self-contained
# libcb2_c; shared ones must be bundled with the application as well. On
# Android the library links libc++ statically and exports the cb2_*
# functions of cb2_c.h and nothing else.
cmake_minimum_required(VERSION 3.10)

project(cb2_flutter_library VERSION 0.3.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(CB2_PQ "Build cb2.public and kcb2.seal (requires liboqs)" ON)
if(ANDROID)
    option(CB2_OPENSSL_CHACHA "Use OpenSSL's ChaCha20 for messages of 512 bytes or more" OFF)
else()
    option(CB2_OPENSSL_CHACHA "Use OpenSSL's ChaCha20 for messages of 512 bytes or more" ON)
endif()
set(CB2_DEPS_ROOT "" CACHE PATH "Prefix (or per-ABI prefixes on Android) with the dependencies")
set(CB2_DEPS_LIBS "" CACHE STRING "Library names to link instead of the defaults")

if(NOT CB2_DEPS_ROOT AND DEFINED ENV{CB2_DEPS_ROOT})
    set(CB2_DEPS_ROOT "$ENV{CB2_DEPS_ROOT}")
endif()
get_filename_component(_cb2_android_deps "${CMAKE_CURRENT_SOURCE_DIR}/../build/android-deps" ABSOLUTE)
if(ANDROID AND NOT CB2_DEPS_ROOT AND IS_DIRECTORY "${_cb2_android_deps}")
    set(CB2_DEPS_ROOT "${_cb2_android_deps}")
endif()
if(ANDROID AND NOT CB2_DEPS_ROOT)
    message(FATAL_ERROR "cb2_flutter: no dependencies for Android; run tool/build_android_deps.sh in the plugin, or set CB2_DEPS_ROOT to a directory with one prefix per ABI")
endif()

get_filename_component(CB2_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." ABSOLUTE)
set(CB2_C_DIR "${CB2_ROOT}/bindings/c")

add_library(cb2_c SHARED "${CB2_C_DIR}/src/cb2_c.cpp")
set_target_properties(cb2_c PROPERTIES
    OUTPUT_NAME "cb2_c"
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON)
target_include_directories(cb2_c PRIVATE "${CB2_C_DIR}/include" "${CB2_ROOT}/include")
target_compile_definitions(cb2_c PRIVATE CB2_C_BUILDING)

if(CB2_DEPS_LIBS)
    set(_cb2_libs ${CB2_DEPS_LIBS})
else()
    set(_cb2_libs sodium blake3)
    if(CB2_OPENSSL_CHACHA)
        list(APPEND _cb2_libs crypto)
    endif()
    if(CB2_PQ)
        list(APPEND _cb2_libs oqs)
    endif()
endif()

if(CB2_DEPS_ROOT)
    set(_cb2_prefix "${CB2_DEPS_ROOT}")
    if(ANDROID)
        set(_cb2_prefix "${CB2_DEPS_ROOT}/${ANDROID_ABI}")
        if(NOT IS_DIRECTORY "${_cb2_prefix}")
            message(FATAL_ERROR "cb2_flutter: no dependencies for the Android ABI ${ANDROID_ABI}: ${_cb2_prefix} does not exist. Build them with tool/build_android_deps.sh, or leave the ABI out with CB2_ANDROID_ABIS")
        endif()
    endif()
    target_include_directories(cb2_c PRIVATE "${_cb2_prefix}/include")
    target_link_directories(cb2_c PRIVATE "${_cb2_prefix}/lib")
    target_link_libraries(cb2_c PRIVATE ${_cb2_libs})
else()
    find_package(PkgConfig)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(CB2_SODIUM REQUIRED libsodium>=1.0.18)
        pkg_check_modules(CB2_BLAKE3 REQUIRED libblake3)
        target_include_directories(cb2_c PRIVATE ${CB2_SODIUM_INCLUDE_DIRS} ${CB2_BLAKE3_INCLUDE_DIRS})
        target_link_directories(cb2_c PRIVATE ${CB2_SODIUM_LIBRARY_DIRS} ${CB2_BLAKE3_LIBRARY_DIRS})
        target_link_libraries(cb2_c PRIVATE ${CB2_SODIUM_LIBRARIES} ${CB2_BLAKE3_LIBRARIES})
        if(CB2_OPENSSL_CHACHA)
            pkg_check_modules(CB2_CRYPTO REQUIRED libcrypto>=3.0)
            target_include_directories(cb2_c PRIVATE ${CB2_CRYPTO_INCLUDE_DIRS})
            target_link_directories(cb2_c PRIVATE ${CB2_CRYPTO_LIBRARY_DIRS})
            target_link_libraries(cb2_c PRIVATE ${CB2_CRYPTO_LIBRARIES})
        endif()
        if(CB2_PQ)
            pkg_check_modules(CB2_OQS REQUIRED liboqs)
            target_include_directories(cb2_c PRIVATE ${CB2_OQS_INCLUDE_DIRS})
            target_link_directories(cb2_c PRIVATE ${CB2_OQS_LIBRARY_DIRS})
            target_link_libraries(cb2_c PRIVATE ${CB2_OQS_LIBRARIES})
        endif()
    else()
        message(FATAL_ERROR "cb2_flutter: set CB2_DEPS_ROOT to a prefix holding libsodium, BLAKE3 and liboqs for the target, and libcrypto with CB2_OPENSSL_CHACHA")
    endif()
endif()

if(CB2_PQ)
    target_compile_definitions(cb2_c PRIVATE CB2_HAS_PQ=1)
endif()
if(CB2_OPENSSL_CHACHA)
    target_compile_definitions(cb2_c PRIVATE CB2_OPENSSL_CHACHA=1)
endif()

if(ANDROID)
    file(STRINGS "${CB2_C_DIR}/include/cb2_c.h" _cb2_api_lines REGEX "^CB2_API ")
    set(_cb2_exports "")
    foreach(_line IN LISTS _cb2_api_lines)
        string(REGEX REPLACE "^CB2_API[^(]*[^a-z0-9_](cb2_[a-z0-9_]+)\\(.*" "\\1" _name "${_line}")
        string(APPEND _cb2_exports "    ${_name};\n")
    endforeach()
    set(_cb2_map "${CMAKE_CURRENT_BINARY_DIR}/cb2_c.map")
    file(WRITE "${_cb2_map}" "{\n  global:\n${_cb2_exports}  local:\n    *;\n};\n")
    target_compile_options(cb2_c PRIVATE -ffunction-sections -fdata-sections)
    target_link_options(cb2_c PRIVATE
        "-Wl,-z,max-page-size=16384" "-Wl,--exclude-libs,ALL" "-Wl,--gc-sections"
        "-Wl,--version-script=${_cb2_map}")
    set_target_properties(cb2_c PROPERTIES LINK_DEPENDS "${_cb2_map}")
endif()
if(WIN32)
    target_compile_definitions(cb2_c PRIVATE NOMINMAX)
endif()
