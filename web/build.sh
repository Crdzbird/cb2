#!/usr/bin/env bash
# Build the web playground: web/dist/cb2.js and cb2.wasm from
# web/cb2_web.cpp and the shared interpreter in playground/session.hpp,
# plus copies of the demo scripts under web/demo. The wasm32 dependencies
# come from CB2_WASM_PREFIX (default web/deps/wasm32, built on demand by
# web/build_deps.sh). cb2.public is included when liboqs is present.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PREFIX="${CB2_WASM_PREFIX:-$HERE/deps/wasm32}"
if [[ ! -f "$PREFIX/lib/libsodium.a" || ! -f "$PREFIX/lib/libblake3.a" ]]; then
    bash "$HERE/build_deps.sh" "$PREFIX"
fi
PQ_FLAGS=()
PQ_LIBS=()
if [[ -f "$PREFIX/lib/liboqs.a" ]]; then
    PQ_FLAGS=(-DCB2_HAS_PQ=1)
    PQ_LIBS=(-loqs)
    echo "==> cb2.public enabled (liboqs)" >&2
else
    echo "==> cb2.public disabled: no liboqs under $PREFIX" >&2
fi
mkdir -p "$HERE/dist" "$HERE/demo"
cp "$ROOT/playground/demo.cb2" "$ROOT/playground/demo_text.cb2" "$ROOT/playground/demo_public.cb2" "$HERE/demo/"
em++ -std=c++20 -O2 -fwasm-exceptions \
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow \
    "${PQ_FLAGS[@]}" -I "$ROOT/include" -I "$PREFIX/include" \
    "$HERE/cb2_web.cpp" -L"$PREFIX/lib" -lsodium -lblake3 "${PQ_LIBS[@]}" \
    -sMODULARIZE=1 -sEXPORT_NAME=createCb2 \
    -sEXPORTED_FUNCTIONS=_cb2_web_run,_cb2_web_reset,_cb2_web_failures,_cb2_web_has_pq \
    -sEXPORTED_RUNTIME_METHODS=ccall,cwrap \
    -sALLOW_MEMORY_GROWTH=1 -sSTACK_SIZE=8MB -sENVIRONMENT=web,node \
    -sFILESYSTEM=0 -sASSERTIONS=0 -sTEXTDECODER=2 \
    -o "$HERE/dist/cb2.js"
ls -la "$HERE/dist"
