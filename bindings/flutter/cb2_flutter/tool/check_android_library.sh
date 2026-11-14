#!/usr/bin/env bash
# Build libcb2_c.so of cb2_flutter for each Android ABI from src/CMakeLists.txt
# with the NDK, with the arguments the Gradle build passes, and check what an
# app would ship: the library exports exactly the cb2_* functions of
# cb2_c.h, needs neither libc++_shared.so nor libcrypto, and aligns its
# LOAD segments to 16 KB. Run tool/build_android_deps.sh first; it reads
# the same CB2_ANDROID_ABIS, CB2_PQ and ANDROID_NDK_HOME. Needs cmake and
# ninja.
set -euo pipefail
PLUGIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$PLUGIN/../../.." && pwd)"
WORK="$PLUGIN/build/android-check"
ABIS="${CB2_ANDROID_ABIS:-arm64-v8a,armeabi-v7a,x86_64}"
PQ="${CB2_PQ:-ON}"
# shellcheck source=android_ndk.sh
source "$PLUGIN/tool/android_ndk.sh"
NDK="$(find_ndk)"
BIN="$(ls -d "$NDK"/toolchains/llvm/prebuilt/*)/bin"
expected="$(sed -nE 's/^CB2_API[^(]*[^a-z0-9_](cb2_[a-z0-9_]+)\(.*/\1/p' "$ROOT/bindings/c/include/cb2_c.h" | sort -u)"

check_abi() {
    local abi="$1" build="$WORK/$abi"
    cmake -S "$PLUGIN/src" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="$abi" -DANDROID_PLATFORM=android-24 -DANDROID_STL=c++_static \
        -DCB2_PQ="$PQ" -DCB2_OPENSSL_CHACHA=OFF -DCMAKE_CXX_FLAGS=-std=c++20 > "$build.log" 2>&1 \
        || { tail -40 "$build.log" >&2; exit 1; }
    cmake --build "$build" >> "$build.log" 2>&1 || { tail -40 "$build.log" >&2; exit 1; }
    local lib="$build/libcb2_c.so"
    local exported needed align
    exported="$("$BIN/llvm-nm" -D --defined-only "$lib" | awk '{ print $3 }' | sort -u)"
    if [[ "$exported" != "$expected" ]]; then
        echo "$abi: libcb2_c.so exports other symbols than the cb2_* functions of cb2_c.h:" >&2
        diff <(echo "$exported") <(echo "$expected") >&2 || true
        exit 1
    fi
    needed="$("$BIN/llvm-readelf" -d "$lib" | sed -nE 's/.*\(NEEDED\).*\[(.*)\]/\1/p' | tr '\n' ' ')"
    if [[ "$needed" == *"c++_shared"* || "$needed" == *"crypto"* ]]; then
        echo "$abi: libcb2_c.so needs $needed" >&2
        exit 1
    fi
    align="$("$BIN/llvm-readelf" -lW "$lib" | awk '$1 == "LOAD" { print $NF }' | sort -u | tr '\n' ' ')"
    if [[ "$align" != "0x4000 " ]]; then
        echo "$abi: LOAD segments aligned to $align, not 0x4000" >&2
        exit 1
    fi
    "$BIN/llvm-strip" --strip-unneeded -o "$build/libcb2_c.stripped.so" "$lib"
    echo "$abi: $(echo "$expected" | wc -l | tr -d ' ') exports, needs ${needed% }, LOAD aligned to 0x4000," \
        "$(wc -c < "$build/libcb2_c.stripped.so" | tr -d ' ') bytes stripped"
}

mkdir -p "$WORK"
IFS=',' read -r -a abi_list <<< "$ABIS"
for abi in "${abi_list[@]}"; do
    check_abi "$(echo "$abi" | tr -d ' ')"
done
