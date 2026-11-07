#!/usr/bin/env bash
# Builds Cb2C.xcframework: the C ABI of cb2 (bindings/c) linked statically
# with libsodium, BLAKE3 and liboqs (ML-DSA-65 and ML-KEM-768, portable C,
# no OpenSSL), for macOS (arm64, x86_64), iOS (arm64) and the iOS simulator
# (arm64, x86_64). The dependencies come from the hash-pinned release
# tarballs web/build_deps.sh uses and are cached under the work directory.
#
# usage: build-xcframework.sh [output] (default bindings/swift/Cb2C.xcframework)
# environment: CB2_XCFRAMEWORK_WORK (default bindings/swift/.build-xcframework)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$PACKAGE/../.." && pwd)"
OUT="${1:-$PACKAGE/Cb2C.xcframework}"
WORK="${CB2_XCFRAMEWORK_WORK:-$PACKAGE/.build-xcframework}"
MACOS_MIN="13.0"
IOS_MIN="16.0"
LIBSODIUM_VERSION="1.0.22"
LIBSODIUM_SHA256="adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349"
BLAKE3_VERSION="1.5.4"
BLAKE3_SHA256="ddd24f26a31d23373e63d9be2e723263ac46c8b6d49902ab08024b573fd2a416"
LIBOQS_VERSION="0.15.0"
LIBOQS_SHA256="3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c"
JOBS="$(sysctl -n hw.ncpu)"
SLICES=("macosx arm64" "macosx x86_64" "iphoneos arm64" "iphonesimulator arm64" "iphonesimulator x86_64")
mkdir -p "$WORK/src" "$WORK/logs"

fetch() {
    local url="$1" sha="$2" out="$WORK/src/$3"
    if [[ ! -f "$out" ]]; then
        curl -fsSL -o "$out.part" "$url"
        mv "$out.part" "$out"
    fi
    if [[ "$(shasum -a 256 "$out" | cut -d' ' -f1)" != "$sha" ]]; then
        echo "checksum mismatch for $url" >&2
        rm -f "$out"
        exit 1
    fi
    echo "$out"
}

unpack() {
    local archive="$1" dir="$2"
    rm -rf "$dir"
    mkdir -p "$dir"
    tar -xf "$archive" -C "$dir" --strip-components=1
}

run_logged() {
    local log="$1"
    shift
    "$@" > "$log" 2>&1 || { tail -60 "$log" >&2; exit 1; }
}

triple() {
    local sdk="$1" arch="$2"
    case "$sdk" in
        macosx) echo "$arch-apple-macos$MACOS_MIN" ;;
        iphoneos) echo "$arch-apple-ios$IOS_MIN" ;;
        iphonesimulator) echo "$arch-apple-ios$IOS_MIN-simulator" ;;
    esac
}

cmake_platform() {
    local sdk="$1" arch="$2" sysroot="$3"
    PLATFORM=(-DCMAKE_OSX_ARCHITECTURES="$arch" -DCMAKE_OSX_SYSROOT="$sysroot" -DCMAKE_SYSTEM_PROCESSOR="$arch")
    case "$sdk" in
        macosx) PLATFORM+=(-DCMAKE_SYSTEM_NAME=Darwin -DCMAKE_OSX_DEPLOYMENT_TARGET="$MACOS_MIN") ;;
        *) PLATFORM+=(-DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_DEPLOYMENT_TARGET="$IOS_MIN") ;;
    esac
}

build_libsodium() {
    local sdk="$1" arch="$2" prefix="$3" sysroot="$4" target="$5"
    [[ -f "$prefix/lib/libsodium.a" ]] && return
    echo "==> libsodium $LIBSODIUM_VERSION ($sdk $arch)" >&2
    local src="$WORK/build/$sdk-$arch/libsodium" host
    unpack "$(fetch "https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz" "$LIBSODIUM_SHA256" libsodium.tar.gz)" "$src"
    case "$arch" in
        arm64) host="aarch64-apple-darwin" ;;
        *) host="x86_64-apple-darwin" ;;
    esac
    local flags="-O2 -target $target -isysroot $sysroot"
    (cd "$src" && run_logged "$WORK/logs/libsodium-$sdk-$arch-configure.log" \
        env CC="$(xcrun -f clang)" CFLAGS="$flags" LDFLAGS="-target $target -isysroot $sysroot" \
        ./configure --host="$host" --disable-shared --enable-static --prefix="$prefix")
    (cd "$src" && run_logged "$WORK/logs/libsodium-$sdk-$arch-make.log" make -j"$JOBS" install)
}

build_blake3() {
    local sdk="$1" arch="$2" prefix="$3" sysroot="$4"
    [[ -f "$prefix/lib/libblake3.a" ]] && return
    echo "==> blake3 $BLAKE3_VERSION ($sdk $arch)" >&2
    local src="$WORK/build/$sdk-$arch/blake3" simd="none"
    unpack "$(fetch "https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/${BLAKE3_VERSION}.tar.gz" "$BLAKE3_SHA256" blake3.tar.gz)" "$src"
    [[ "$arch" == arm64 ]] && simd="neon-intrinsics"
    cmake_platform "$sdk" "$arch" "$sysroot"
    run_logged "$WORK/logs/blake3-$sdk-$arch-cmake.log" \
        cmake -S "$src/c" -B "$src/build" -G Ninja -DCMAKE_BUILD_TYPE=Release "${PLATFORM[@]}" \
        -DBUILD_SHARED_LIBS=OFF -DBLAKE3_SIMD_TYPE="$simd" \
        -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib
    run_logged "$WORK/logs/blake3-$sdk-$arch-build.log" cmake --build "$src/build" --target install -j"$JOBS"
}

build_liboqs() {
    local sdk="$1" arch="$2" prefix="$3" sysroot="$4"
    [[ -f "$prefix/lib/liboqs.a" ]] && return
    echo "==> liboqs $LIBOQS_VERSION ($sdk $arch, ML-DSA-65 and ML-KEM-768)" >&2
    local src="$WORK/build/$sdk-$arch/liboqs"
    unpack "$(fetch "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" "$LIBOQS_SHA256" liboqs.tar.gz)" "$src"
    cmake_platform "$sdk" "$arch" "$sysroot"
    run_logged "$WORK/logs/liboqs-$sdk-$arch-cmake.log" \
        cmake -S "$src" -B "$src/build" -G Ninja -DCMAKE_BUILD_TYPE=Release "${PLATFORM[@]}" \
        -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=OFF \
        -DOQS_OPT_TARGET=generic -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
        -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;KEM_ml_kem_768" \
        -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib
    run_logged "$WORK/logs/liboqs-$sdk-$arch-build.log" cmake --build "$src/build" --target install -j"$JOBS"
}

build_slice() {
    local sdk="$1" arch="$2"
    local prefix="$WORK/prefix/$sdk-$arch" sysroot target
    sysroot="$(xcrun --sdk "$sdk" --show-sdk-path)"
    target="$(triple "$sdk" "$arch")"
    mkdir -p "$prefix" "$WORK/build/$sdk-$arch"
    build_libsodium "$sdk" "$arch" "$prefix" "$sysroot" "$target"
    build_blake3 "$sdk" "$arch" "$prefix" "$sysroot"
    build_liboqs "$sdk" "$arch" "$prefix" "$sysroot"
    echo "==> cb2_c ($sdk $arch)" >&2
    local obj="$WORK/build/$sdk-$arch/cb2_c.o"
    xcrun clang++ -std=c++20 -O2 -fvisibility=hidden -fvisibility-inlines-hidden \
        -target "$target" -isysroot "$sysroot" -DCB2_HAS_PQ=1 \
        -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow \
        -I "$ROOT/include" -I "$ROOT/bindings/c/include" -I "$prefix/include" \
        -c "$ROOT/bindings/c/src/cb2_c.cpp" -o "$obj"
    xcrun libtool -static -no_warning_for_no_symbols -o "$WORK/build/$sdk-$arch/libcb2_c.a" "$obj" \
        "$prefix/lib/libsodium.a" "$prefix/lib/libblake3.a" "$prefix/lib/liboqs.a"
}

for slice in "${SLICES[@]}"; do
    read -r sdk arch <<< "$slice"
    build_slice "$sdk" "$arch"
done

HEADERS="$WORK/headers"
rm -rf "$HEADERS"
mkdir -p "$HEADERS"
cp "$ROOT/bindings/c/include/cb2_c.h" "$HEADERS/"
cat > "$HEADERS/module.modulemap" << 'EOF'
module CCb2 {
    header "cb2_c.h"
    link "c++"
    export *
}
EOF

LIBRARIES=()
for sdk in macosx iphoneos iphonesimulator; do
    archs=()
    for slice in "${SLICES[@]}"; do
        read -r s a <<< "$slice"
        [[ "$s" == "$sdk" ]] && archs+=("$WORK/build/$s-$a/libcb2_c.a")
    done
    mkdir -p "$WORK/lipo/$sdk"
    xcrun lipo -create "${archs[@]}" -output "$WORK/lipo/$sdk/libcb2_c.a"
    LIBRARIES+=(-library "$WORK/lipo/$sdk/libcb2_c.a" -headers "$HEADERS")
done

rm -rf "$OUT"
xcodebuild -create-xcframework "${LIBRARIES[@]}" -output "$OUT" > "$WORK/logs/xcframework.log"
echo "==> $OUT" >&2
for lib in "$OUT"/*/libcb2_c.a; do
    echo "$(basename "$(dirname "$lib")"): $(xcrun lipo -archs "$lib")"
done
