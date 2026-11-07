#!/usr/bin/env bash
# Build the native dependencies of cb2_flutter for Android: libsodium,
# BLAKE3 and liboqs (ML-DSA-65 and ML-KEM-768, no OpenSSL) from the same
# hash-pinned release tarballs as tool/build_xcframework.sh, as static
# libraries for each Android ABI, with the NDK. The result is one prefix
# per ABI under build/android-deps of the plugin (<root>/arm64-v8a, ...),
# the layout src/CMakeLists.txt expects. Point the Android build at it:
#
#   tool/build_android_deps.sh
#   export CB2_DEPS_ROOT="$PWD/build/android-deps"
#   (cd example && flutter run -d <device>)
#
# ANDROID_NDK_HOME selects the NDK, by default the newest one in the SDK.
# ABIS selects the ABIs, by default those Flutter builds for an APK.
# Needs cmake, ninja and make.
set -euo pipefail
PLUGIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="${CB2_ANDROID_DEPS:-$PLUGIN/build/android-deps}"
API=24
ABIS="${ABIS:-arm64-v8a armeabi-v7a x86_64}"
LIBSODIUM_VERSION="1.0.22"
LIBSODIUM_SHA256="adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349"
BLAKE3_VERSION="1.5.4"
BLAKE3_SHA256="ddd24f26a31d23373e63d9be2e723263ac46c8b6d49902ab08024b573fd2a416"
LIBOQS_VERSION="0.15.0"
LIBOQS_SHA256="3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c"
JOBS="$(getconf _NPROCESSORS_ONLN)"

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
    ANDROID_NDK_HOME="$(ls -d "$SDK"/ndk/* | sort -V | tail -1)"
fi
HOST_TAG="$(ls "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" | head -1)"
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG"
mkdir -p "$CACHE/src" "$CACHE/logs"

fetch() {
    local url="$1" sha="$2" name="$3"
    local file="$CACHE/src/$name.tar.gz" dir="$CACHE/src/$name"
    if [[ ! -f "$file" ]]; then
        curl -fsSL -o "$file.part" "$url"
        mv "$file.part" "$file"
    fi
    if [[ "$(shasum -a 256 "$file" | cut -d' ' -f1)" != "$sha" ]]; then
        echo "checksum mismatch for $url" >&2
        exit 1
    fi
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        tar -xf "$file" -C "$dir" --strip-components=1
    fi
}

run_logged() {
    local log="$1"
    shift
    "$@" > "$log" 2>&1 || { tail -60 "$log" >&2; exit 1; }
}

build_abi() {
    local abi="$1" triple host simd
    case "$abi" in
        arm64-v8a) triple="aarch64-linux-android"; host="aarch64-linux-android"; simd="neon-intrinsics" ;;
        armeabi-v7a) triple="armv7a-linux-androideabi"; host="arm-linux-androideabi"; simd="none" ;;
        x86_64) triple="x86_64-linux-android"; host="x86_64-linux-android"; simd="none" ;;
        *) echo "unsupported ABI $abi" >&2; exit 1 ;;
    esac
    local prefix="$CACHE/$abi" log="$CACHE/logs/$abi"
    local cmake_args=(
        -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
        -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake"
        -DANDROID_ABI="$abi" -DANDROID_PLATFORM="android-$API"
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib
    )
    mkdir -p "$prefix/lib" "$prefix/include"

    if [[ ! -f "$prefix/lib/libsodium.a" ]]; then
        echo "==> libsodium $LIBSODIUM_VERSION ($abi)" >&2
        local work="$CACHE/work/libsodium-$abi"
        rm -rf "$work"
        mkdir -p "$work"
        cp -R "$CACHE/src/libsodium/." "$work"
        (cd "$work" && run_logged "$log-libsodium.log" env \
            CC="$TOOLCHAIN/bin/$triple$API-clang" AR="$TOOLCHAIN/bin/llvm-ar" \
            RANLIB="$TOOLCHAIN/bin/llvm-ranlib" CFLAGS="-O2 -fPIC" \
            ./configure --host="$host" --disable-shared --enable-static --with-pic \
            --disable-dependency-tracking --prefix="$prefix" \
            && run_logged "$log-libsodium-make.log" make -j"$JOBS" install)
    fi

    if [[ ! -f "$prefix/lib/libblake3.a" ]]; then
        echo "==> blake3 $BLAKE3_VERSION ($abi)" >&2
        run_logged "$log-blake3.log" cmake -S "$CACHE/src/blake3/c" -B "$CACHE/work/blake3-$abi" \
            "${cmake_args[@]}" -DBLAKE3_SIMD_TYPE="$simd"
        run_logged "$log-blake3-build.log" cmake --build "$CACHE/work/blake3-$abi" --target install
    fi

    if [[ ! -f "$prefix/lib/liboqs.a" ]]; then
        echo "==> liboqs $LIBOQS_VERSION ($abi, ML-DSA-65 and ML-KEM-768)" >&2
        run_logged "$log-liboqs.log" cmake -S "$CACHE/src/liboqs" -B "$CACHE/work/liboqs-$abi" \
            "${cmake_args[@]}" -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=ON \
            -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;KEM_ml_kem_768"
        run_logged "$log-liboqs-build.log" cmake --build "$CACHE/work/liboqs-$abi" --target install
    fi
}

fetch "https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz" "$LIBSODIUM_SHA256" libsodium
fetch "https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/${BLAKE3_VERSION}.tar.gz" "$BLAKE3_SHA256" blake3
fetch "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" "$LIBOQS_SHA256" liboqs

for abi in $ABIS; do
    build_abi "$abi"
done
echo "Android dependencies in $CACHE (NDK $(basename "$ANDROID_NDK_HOME"), API $API)" >&2
