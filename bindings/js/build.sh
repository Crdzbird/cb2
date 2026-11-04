#!/usr/bin/env bash
# Build the JavaScript core: bindings/js/dist/cb2_core.js and cb2_core.wasm
# from the C ABI in bindings/c/src/cb2_c.cpp, compiled with Emscripten the
# way web/build.sh compiles the playground. The wasm32 dependencies come
# from CB2_WASM_PREFIX (default web/deps/wasm32, built on demand by
# web/build_deps.sh); liboqs is required because the bridge is built with
# cb2.public and kcb2.seal. OpenSSL is not used, so XChaCha20 is libsodium's.
# The dist files are committed, like web/dist.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PREFIX="${CB2_WASM_PREFIX:-$ROOT/web/deps/wasm32}"
if [[ ! -f "$PREFIX/lib/libsodium.a" || ! -f "$PREFIX/lib/libblake3.a" || ! -f "$PREFIX/lib/liboqs.a" ]]; then
    bash "$ROOT/web/build_deps.sh" "$PREFIX"
fi
if [[ ! -f "$PREFIX/lib/liboqs.a" ]]; then
    echo "liboqs is required under $PREFIX" >&2
    exit 1
fi
HEADER="$ROOT/bindings/c/include/cb2_c.h"
EXPORTS="$(grep -o 'cb2_[a-z0-9_]*(' "$HEADER" | tr -d '(' | sort -u | sed 's/^/_/' | paste -sd, -)"
EXPORTS="${EXPORTS},_malloc,_free"
RUNTIME="ccall,cwrap,addFunction,removeFunction,UTF8ToString,stringToUTF8,lengthBytesUTF8,HEAPU8,getValue,setValue"
mkdir -p "$HERE/dist"
em++ -std=c++20 -O2 -fwasm-exceptions \
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow \
    -DCB2_HAS_PQ=1 -I "$ROOT/include" -I "$ROOT/bindings/c/include" -I "$PREFIX/include" \
    "$ROOT/bindings/c/src/cb2_c.cpp" -L"$PREFIX/lib" -lsodium -lblake3 -loqs \
    -sMODULARIZE=1 -sEXPORT_ES6=1 -sEXPORT_NAME=createCb2Core \
    -sEXPORTED_FUNCTIONS="$EXPORTS" \
    -sEXPORTED_RUNTIME_METHODS="$RUNTIME" \
    -sALLOW_TABLE_GROWTH=1 \
    -sALLOW_MEMORY_GROWTH=1 -sSTACK_SIZE=8MB -sENVIRONMENT=web,node \
    -sFILESYSTEM=0 -sASSERTIONS=0 -sTEXTDECODER=2 \
    -o "$HERE/dist/cb2_core.js"
ls -la "$HERE/dist"
