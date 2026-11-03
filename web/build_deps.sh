#!/usr/bin/env bash
# Build libsodium, BLAKE3 and liboqs for wasm32 with Emscripten from the
# same hash-pinned release tarballs as the Linux CI job, into the prefix
# given as the first argument (default web/deps/wasm32). liboqs is reduced
# to ML-DSA-65, portable code only, no OpenSSL. Needs emcc, cmake, ninja.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${1:-$HERE/deps/wasm32}"
LIBSODIUM_VERSION="1.0.22"
LIBSODIUM_SHA256="adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349"
BLAKE3_VERSION="1.5.4"
BLAKE3_SHA256="ddd24f26a31d23373e63d9be2e723263ac46c8b6d49902ab08024b573fd2a416"
LIBOQS_VERSION="0.15.0"
LIBOQS_SHA256="3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c"
WORK="$(mktemp -d)"
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
mkdir -p "$PREFIX/lib" "$PREFIX/include"

sha256() {
    if command -v sha256sum > /dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

fetch() {
    local url="$1" sha="$2" out="$WORK/$3"
    curl -fsSL -o "$out" "$url"
    if [[ "$(sha256 "$out")" != "$sha" ]]; then
        echo "checksum mismatch for $url" >&2
        exit 1
    fi
    echo "$out"
}

if [[ ! -f "$PREFIX/lib/libsodium.a" ]]; then
    echo "==> libsodium $LIBSODIUM_VERSION (wasm32)" >&2
    A="$(fetch "https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz" "$LIBSODIUM_SHA256" libsodium.tar.gz)"
    mkdir -p "$WORK/libsodium"
    tar -xf "$A" -C "$WORK/libsodium" --strip-components=1
    (cd "$WORK/libsodium" && emconfigure ./configure --host=wasm32-unknown-emscripten \
        --disable-shared --enable-static --disable-ssp --disable-asm --without-pthreads \
        --prefix="$WORK/libsodium/install" > "$WORK/libsodium-configure.log" 2>&1 \
        && emmake make -j"$JOBS" > "$WORK/libsodium-make.log" 2>&1 \
        && emmake make install > "$WORK/libsodium-install.log" 2>&1) \
        || { tail -40 "$WORK"/libsodium-*.log; exit 1; }
    cp "$WORK/libsodium/install/lib/libsodium.a" "$PREFIX/lib/"
    cp -R "$WORK/libsodium/install/include/"* "$PREFIX/include/"
fi

if [[ ! -f "$PREFIX/lib/libblake3.a" ]]; then
    echo "==> blake3 $BLAKE3_VERSION (wasm32)" >&2
    A="$(fetch "https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/${BLAKE3_VERSION}.tar.gz" "$BLAKE3_SHA256" blake3.tar.gz)"
    mkdir -p "$WORK/blake3"
    tar -xf "$A" -C "$WORK/blake3" --strip-components=1
    emcmake cmake -S "$WORK/blake3/c" -B "$WORK/blake3/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF -DBLAKE3_SIMD_TYPE=none \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib > "$WORK/blake3-cmake.log" 2>&1 \
        || { tail -40 "$WORK/blake3-cmake.log"; exit 1; }
    cmake --build "$WORK/blake3/build" --target install -j"$JOBS" > "$WORK/blake3-build.log" 2>&1 \
        || { tail -40 "$WORK/blake3-build.log"; exit 1; }
fi

if [[ ! -f "$PREFIX/lib/liboqs.a" ]]; then
    echo "==> liboqs $LIBOQS_VERSION (wasm32, ML-DSA-65 only)" >&2
    A="$(fetch "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" "$LIBOQS_SHA256" liboqs.tar.gz)"
    mkdir -p "$WORK/liboqs"
    tar -xf "$A" -C "$WORK/liboqs" --strip-components=1
    emcmake cmake -S "$WORK/liboqs" -B "$WORK/liboqs/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=OFF \
        -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65" \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib > "$WORK/liboqs-cmake.log" 2>&1 \
        || { tail -60 "$WORK/liboqs-cmake.log"; exit 1; }
    cmake --build "$WORK/liboqs/build" --target install -j"$JOBS" > "$WORK/liboqs-build.log" 2>&1 \
        || { tail -60 "$WORK/liboqs-build.log"; exit 1; }
fi

rm -rf "$WORK"
ls "$PREFIX/lib"
