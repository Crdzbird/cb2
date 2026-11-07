#!/bin/sh
# Builds cb2_c_bench in release mode and runs it: cb2 through libcb2_c
# against JWT (libjwt, from pkg-config, for example Homebrew's) and
# PASETO v4 (libpaseto, fetched here at a pinned commit and built from
# source). Prints the machine, the compiler and the library versions,
# then the results tables. Extra arguments go to the CMake configure.
#
#   bindings/c/bench/run.sh [build-dir] [cmake arguments...]

set -eu

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
BUILD=${1:-$ROOT/build-c-bench}
if [ $# -gt 0 ]; then shift; fi
PASETO_REPO=https://github.com/kennt/libpaseto
PASETO_COMMIT=15540dc473e254c6c7c4ad44454fa6f4cc0e2070
PASETO=$BUILD/_deps/libpaseto

if [ ! -d "$PASETO/.git" ]; then
    mkdir -p "$PASETO"
    git init -q "$PASETO"
    git -C "$PASETO" fetch -q --depth 1 "$PASETO_REPO" "$PASETO_COMMIT"
    git -C "$PASETO" checkout -q FETCH_HEAD
fi
if [ "$(git -C "$PASETO" rev-parse HEAD)" != "$PASETO_COMMIT" ]; then
    echo "run.sh: $PASETO is not libpaseto $PASETO_COMMIT" >&2
    exit 1
fi

cmake -S "$ROOT" -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCB2_C_BENCH=ON \
    -DCB2_C_BENCH_PASETO_SOURCE="$PASETO" -DCB2_BUILD_TESTS=OFF -DCB2_BUILD_BENCH=OFF \
    -DCB2_BUILD_EXAMPLES=OFF -DCB2_BUILD_PLAYGROUND=OFF "$@" > /dev/null
cmake --build "$BUILD" --target cb2_c_bench > /dev/null

version() {
    pkg-config --modversion "$1" 2>/dev/null || echo "not found"
}

echo "date      $(date -u +%Y-%m-%d)"
if [ "$(uname -s)" = Darwin ]; then
    echo "machine   $(sysctl -n machdep.cpu.brand_string), $(sysctl -n hw.ncpu) cores, $(($(sysctl -n hw.memsize) / 1073741824)) GB"
    echo "os        macOS $(sw_vers -productVersion) ($(uname -m))"
fi
if [ "$(uname -s)" != Darwin ]; then
    echo "machine   $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'), $(nproc) cores"
    echo "os        $(. /etc/os-release && echo "$PRETTY_NAME") ($(uname -m))"
fi
CC_PATH=$(sed -n 's/^CMAKE_C_COMPILER:[A-Z]*=//p' "$BUILD/CMakeCache.txt")
echo "compiler  $("${CC_PATH:-cc}" --version | head -n 1)"
echo "libraries libsodium $(version libsodium), BLAKE3 $(version libblake3), liboqs $(version liboqs), libcrypto $(version libcrypto)"
echo "          libjwt $(version libjwt), jansson $(version jansson), libpaseto ${PASETO_COMMIT%"${PASETO_COMMIT#???????}"} (kennt fork)"
"$BUILD/bindings/c/bench/cb2_c_bench"
