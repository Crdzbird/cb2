#!/usr/bin/env bash
# Build BLAKE3 and liboqs from hash-pinned release tarballs into the prefix
# given as the first argument, for the Linux CI job. libsodium and libcrypto
# come from the distribution packages. Both libraries are built static and
# install pkg-config files, which is how CMakeLists.txt finds them; liboqs is
# reduced to ML-DSA-65 and ML-KEM-768, what cb2.public and kcb2.seal use.
set -euo pipefail
PREFIX="${1:?usage: linux_deps.sh <prefix>}"
BLAKE3_VERSION="1.5.4"
BLAKE3_SHA256="ddd24f26a31d23373e63d9be2e723263ac46c8b6d49902ab08024b573fd2a416"
LIBOQS_VERSION="0.15.0"
LIBOQS_SHA256="3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c"
WORK="$(mktemp -d)"
JOBS="$(nproc 2>/dev/null || echo 4)"

fetch() {
    local url="$1" sha="$2" out="$WORK/$3"
    curl -fsSL -o "$out" "$url"
    echo "$sha  $out" | sha256sum -c - > /dev/null
    echo "$out"
}

if [[ ! -f "$PREFIX/lib/pkgconfig/libblake3.pc" ]]; then
    echo "==> blake3 $BLAKE3_VERSION" >&2
    A="$(fetch "https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/${BLAKE3_VERSION}.tar.gz" "$BLAKE3_SHA256" blake3.tar.gz)"
    mkdir -p "$WORK/blake3"
    tar -xf "$A" -C "$WORK/blake3" --strip-components=1
    cmake -S "$WORK/blake3/c" -B "$WORK/blake3/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib
    cmake --build "$WORK/blake3/build" --target install -j"$JOBS"
fi

if [[ ! -f "$PREFIX/lib/pkgconfig/liboqs.pc" ]]; then
    echo "==> liboqs $LIBOQS_VERSION" >&2
    A="$(fetch "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" "$LIBOQS_SHA256" liboqs.tar.gz)"
    mkdir -p "$WORK/liboqs"
    tar -xf "$A" -C "$WORK/liboqs" --strip-components=1
    cmake -S "$WORK/liboqs" -B "$WORK/liboqs/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_USE_OPENSSL=ON -DOQS_DIST_BUILD=ON -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;KEM_ml_kem_768" \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib
    cmake --build "$WORK/liboqs/build" --target install -j"$JOBS"
fi

rm -rf "$WORK"
ls "$PREFIX/lib" "$PREFIX/lib/pkgconfig"
