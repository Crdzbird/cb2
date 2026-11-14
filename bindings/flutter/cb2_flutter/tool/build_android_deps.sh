#!/usr/bin/env bash
# Build the native dependencies of cb2_flutter for Android: libsodium,
# BLAKE3 and liboqs (ML-DSA-65 and ML-KEM-768, no OpenSSL) from the
# hash-pinned release tarballs tool/build_xcframework.sh uses, as static,
# position independent libraries for each ABI. The result is one prefix
# per ABI under build/android-deps of the plugin, the default
# CB2_DEPS_ROOT of the Android build, which links them into libcb2_c.so.
#
#   CB2_ANDROID_ABIS   the ABIs, comma separated; default
#                      arm64-v8a,armeabi-v7a,x86_64. Use the same list
#                      when building the app.
#   CB2_PQ             OFF skips liboqs (cb2.local only); default ON.
#   ANDROID_NDK_HOME   the NDK; default the newest under
#                      $ANDROID_HOME/ndk (or $ANDROID_SDK_ROOT/ndk).
#
# Needs cmake, ninja and make. Sources and logs are kept under
# build/android-work of the plugin.
set -euo pipefail
PLUGIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${CB2_ANDROID_DEPS:-$PLUGIN/build/android-deps}"
WORK="$PLUGIN/build/android-work"
API=24
ABIS="${CB2_ANDROID_ABIS:-arm64-v8a,armeabi-v7a,x86_64}"
PQ="${CB2_PQ:-ON}"
LIBSODIUM_VERSION="1.0.22"
LIBSODIUM_SHA256="adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349"
BLAKE3_VERSION="1.5.4"
BLAKE3_SHA256="ddd24f26a31d23373e63d9be2e723263ac46c8b6d49902ab08024b573fd2a416"
LIBOQS_VERSION="0.15.0"
LIBOQS_SHA256="3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c"
JOBS="$(getconf _NPROCESSORS_ONLN)"

# shellcheck source=android_ndk.sh
source "$PLUGIN/tool/android_ndk.sh"
NDK="$(find_ndk)"
TOOLCHAIN="$(ls -d "$NDK"/toolchains/llvm/prebuilt/* | head -1)"
mkdir -p "$WORK/src" "$WORK/logs" "$OUT"

fetch() {
    local url="$1" sha="$2" name="$3"
    local file="$WORK/src/$name.tar.gz" dir="$WORK/src/$name"
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
    local prefix="$OUT/$abi" log="$WORK/logs/$abi"
    local cflags="-O2 -fPIC -ffunction-sections -fdata-sections"
    local cmake_args=(
        -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
        -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake"
        -DANDROID_ABI="$abi" -DANDROID_PLATFORM="android-$API"
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_C_FLAGS="-ffunction-sections -fdata-sections"
        -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib
    )
    mkdir -p "$prefix/lib" "$prefix/include"

    if [[ ! -f "$prefix/lib/libsodium.a" ]]; then
        echo "==> libsodium $LIBSODIUM_VERSION ($abi)" >&2
        local work="$WORK/build/libsodium-$abi"
        rm -rf "$work"
        mkdir -p "$work"
        cp -R "$WORK/src/libsodium/." "$work"
        (cd "$work" && run_logged "$log-libsodium.log" env \
            CC="$TOOLCHAIN/bin/$triple$API-clang" AR="$TOOLCHAIN/bin/llvm-ar" \
            RANLIB="$TOOLCHAIN/bin/llvm-ranlib" CFLAGS="$cflags" \
            ./configure --host="$host" --disable-shared --enable-static --with-pic \
            --disable-dependency-tracking --prefix="$prefix" \
            && run_logged "$log-libsodium-make.log" make -j"$JOBS" install)
    fi

    if [[ ! -f "$prefix/lib/libblake3.a" ]]; then
        echo "==> blake3 $BLAKE3_VERSION ($abi)" >&2
        run_logged "$log-blake3.log" cmake -S "$WORK/src/blake3/c" -B "$WORK/build/blake3-$abi" \
            "${cmake_args[@]}" -DBLAKE3_SIMD_TYPE="$simd"
        run_logged "$log-blake3-build.log" cmake --build "$WORK/build/blake3-$abi" --target install
    fi

    if [[ "$PQ" != "OFF" && ! -f "$prefix/lib/liboqs.a" ]]; then
        echo "==> liboqs $LIBOQS_VERSION ($abi, ML-DSA-65 and ML-KEM-768)" >&2
        run_logged "$log-liboqs.log" cmake -S "$WORK/src/liboqs" -B "$WORK/build/liboqs-$abi" \
            "${cmake_args[@]}" -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=ON \
            -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;KEM_ml_kem_768"
        run_logged "$log-liboqs-build.log" cmake --build "$WORK/build/liboqs-$abi" --target install
    fi
}

fetch "https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz" "$LIBSODIUM_SHA256" libsodium
fetch "https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/${BLAKE3_VERSION}.tar.gz" "$BLAKE3_SHA256" blake3
if [[ "$PQ" != "OFF" ]]; then
    fetch "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" "$LIBOQS_SHA256" liboqs
fi

IFS=',' read -r -a abi_list <<< "$ABIS"
for abi in "${abi_list[@]}"; do
    build_abi "$(echo "$abi" | tr -d ' ')"
done
echo "Android dependencies for $ABIS in $OUT (NDK $(basename "$NDK"))" >&2
