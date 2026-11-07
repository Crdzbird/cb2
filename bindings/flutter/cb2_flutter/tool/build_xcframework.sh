#!/usr/bin/env bash
# Build cb2_c.xcframework for the iOS and macOS halves of cb2_flutter:
# libsodium, BLAKE3 and liboqs (ML-DSA-65 and ML-KEM-768, no OpenSSL) from
# the hash-pinned release tarballs the web and Linux builds use, linked
# statically with bindings/c/src/cb2_c.cpp into one dynamic framework,
# cb2_c.framework, that exports the cb2_* functions and nothing else.
# Slices: iOS device (arm64), iOS simulator (arm64, x86_64) and macOS
# (arm64, x86_64). The result is copied to ios/cb2_flutter/Frameworks and
# macos/cb2_flutter/Frameworks, where the podspecs and the Swift packages
# vendor it. Dependencies are cached under build/apple-deps of the plugin.
# Needs Xcode, cmake, ninja and make.
set -euo pipefail
PLUGIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$PLUGIN/../../.." && pwd)"
CACHE="${CB2_APPLE_DEPS:-$PLUGIN/build/apple-deps}"
OUT="$PLUGIN/build/xcframework"
IOS_MIN="15.0"
MACOS_MIN="11.0"
VERSION="0.1.0"
LIBSODIUM_VERSION="1.0.22"
LIBSODIUM_SHA256="adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349"
BLAKE3_VERSION="1.5.4"
BLAKE3_SHA256="ddd24f26a31d23373e63d9be2e723263ac46c8b6d49902ab08024b573fd2a416"
LIBOQS_VERSION="0.15.0"
LIBOQS_SHA256="3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c"
JOBS="$(sysctl -n hw.ncpu)"
mkdir -p "$CACHE/src" "$OUT"

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

build_slice() {
    local sdk="$1" arch="$2" triple="$3" system="$4" min="$5"
    local prefix="$CACHE/$sdk-$arch"
    local sysroot
    sysroot="$(xcrun --sdk "$sdk" --show-sdk-path)"
    local flags="-target $triple -isysroot $sysroot -O2"
    local cmake_args=(
        -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
        -DCMAKE_SYSTEM_NAME="$system" -DCMAKE_SYSTEM_PROCESSOR="$arch"
        -DCMAKE_OSX_SYSROOT="$sysroot" -DCMAKE_OSX_ARCHITECTURES="$arch"
        -DCMAKE_C_FLAGS="-target $triple" -DCMAKE_ASM_FLAGS="-target $triple"
        -DCMAKE_OSX_DEPLOYMENT_TARGET="$min" -DCMAKE_INSTALL_PREFIX="$prefix"
        -DCMAKE_INSTALL_LIBDIR=lib
    )
    mkdir -p "$prefix/lib" "$prefix/include" "$CACHE/logs"
    local log="$CACHE/logs/$sdk-$arch"

    if [[ ! -f "$prefix/lib/libsodium.a" ]]; then
        echo "==> libsodium $LIBSODIUM_VERSION ($sdk $arch)" >&2
        local work="$CACHE/work/libsodium-$sdk-$arch"
        rm -rf "$work"
        mkdir -p "$work"
        cp -R "$CACHE/src/libsodium/." "$work"
        local host="$arch"
        [[ "$arch" == "arm64" ]] && host="aarch64"
        (cd "$work" && run_logged "$log-libsodium.log" env CFLAGS="$flags" LDFLAGS="$flags" \
            ./configure --host="$host-apple-darwin10" --disable-shared --enable-static \
            --disable-dependency-tracking --prefix="$prefix" \
            && run_logged "$log-libsodium-make.log" make -j"$JOBS" install)
    fi

    if [[ ! -f "$prefix/lib/libblake3.a" ]]; then
        echo "==> blake3 $BLAKE3_VERSION ($sdk $arch)" >&2
        local simd="neon-intrinsics"
        [[ "$arch" == "x86_64" ]] && simd="none"
        run_logged "$log-blake3.log" cmake -S "$CACHE/src/blake3/c" -B "$CACHE/work/blake3-$sdk-$arch" \
            "${cmake_args[@]}" -DBLAKE3_SIMD_TYPE="$simd"
        run_logged "$log-blake3-build.log" cmake --build "$CACHE/work/blake3-$sdk-$arch" --target install
    fi

    if [[ ! -f "$prefix/lib/liboqs.a" ]]; then
        echo "==> liboqs $LIBOQS_VERSION ($sdk $arch, ML-DSA-65 and ML-KEM-768)" >&2
        run_logged "$log-liboqs.log" cmake -S "$CACHE/src/liboqs" -B "$CACHE/work/liboqs-$sdk-$arch" \
            "${cmake_args[@]}" -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=ON \
            -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;KEM_ml_kem_768"
        run_logged "$log-liboqs-build.log" cmake --build "$CACHE/work/liboqs-$sdk-$arch" --target install
    fi

    echo "==> cb2_c ($sdk $arch)" >&2
    local obj="$CACHE/work/cb2_c-$sdk-$arch"
    local install_name="@rpath/cb2_c.framework/cb2_c"
    [[ "$sdk" == "macosx" ]] && install_name="@rpath/cb2_c.framework/Versions/A/cb2_c"
    mkdir -p "$obj"
    xcrun --sdk "$sdk" clang++ $flags -std=c++20 -fvisibility=hidden -DCB2_HAS_PQ=1 -DCB2_C_BUILDING \
        -I"$ROOT/bindings/c/include" -I"$ROOT/include" -I"$prefix/include" \
        -c "$ROOT/bindings/c/src/cb2_c.cpp" -o "$obj/cb2_c.o"
    xcrun --sdk "$sdk" clang++ $flags -dynamiclib -install_name "$install_name" \
        -compatibility_version 0.1.0 -current_version "$VERSION" -Wl,-dead_strip \
        -Wl,-exported_symbol,'_cb2_*' -o "$obj/cb2_c" "$obj/cb2_c.o" \
        "$prefix/lib/libsodium.a" "$prefix/lib/libblake3.a" "$prefix/lib/liboqs.a"
}

info_plist() {
    local platform="$1" min_key="$2" min="$3"
    cat <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>cb2_c</string>
  <key>CFBundleIdentifier</key><string>dev.cb2.cb2-c</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>cb2_c</string>
  <key>CFBundlePackageType</key><string>FMWK</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleSupportedPlatforms</key><array><string>$platform</string></array>
  <key>$min_key</key><string>$min</string>
</dict>
</plist>
PLIST
}

flat_framework() {
    local name="$1" platform="$2"
    shift 2
    local fw="$OUT/$name/cb2_c.framework"
    rm -rf "$fw"
    mkdir -p "$fw/Headers"
    xcrun lipo -create "$@" -output "$fw/cb2_c"
    cp "$ROOT/bindings/c/include/cb2_c.h" "$fw/Headers/"
    info_plist "$platform" MinimumOSVersion "$IOS_MIN" > "$fw/Info.plist"
}

versioned_framework() {
    local name="$1"
    shift
    local fw="$OUT/$name/cb2_c.framework"
    rm -rf "$fw"
    mkdir -p "$fw/Versions/A/Headers" "$fw/Versions/A/Resources"
    xcrun lipo -create "$@" -output "$fw/Versions/A/cb2_c"
    cp "$ROOT/bindings/c/include/cb2_c.h" "$fw/Versions/A/Headers/"
    info_plist MacOSX LSMinimumSystemVersion "$MACOS_MIN" > "$fw/Versions/A/Resources/Info.plist"
    ln -s A "$fw/Versions/Current"
    ln -s Versions/Current/cb2_c "$fw/cb2_c"
    ln -s Versions/Current/Headers "$fw/Headers"
    ln -s Versions/Current/Resources "$fw/Resources"
}

fetch "https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz" "$LIBSODIUM_SHA256" libsodium
fetch "https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/${BLAKE3_VERSION}.tar.gz" "$BLAKE3_SHA256" blake3
fetch "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" "$LIBOQS_SHA256" liboqs

build_slice iphoneos arm64 "arm64-apple-ios$IOS_MIN" iOS "$IOS_MIN"
build_slice iphonesimulator arm64 "arm64-apple-ios$IOS_MIN-simulator" iOS "$IOS_MIN"
build_slice iphonesimulator x86_64 "x86_64-apple-ios$IOS_MIN-simulator" iOS "$IOS_MIN"
build_slice macosx arm64 "arm64-apple-macos$MACOS_MIN" Darwin "$MACOS_MIN"
build_slice macosx x86_64 "x86_64-apple-macos$MACOS_MIN" Darwin "$MACOS_MIN"

W="$CACHE/work"
flat_framework ios iPhoneOS "$W/cb2_c-iphoneos-arm64/cb2_c"
flat_framework ios-simulator iPhoneSimulator "$W/cb2_c-iphonesimulator-arm64/cb2_c" "$W/cb2_c-iphonesimulator-x86_64/cb2_c"
versioned_framework macos "$W/cb2_c-macosx-arm64/cb2_c" "$W/cb2_c-macosx-x86_64/cb2_c"

rm -rf "$OUT/cb2_c.xcframework"
xcodebuild -create-xcframework \
    -framework "$OUT/ios/cb2_c.framework" \
    -framework "$OUT/ios-simulator/cb2_c.framework" \
    -framework "$OUT/macos/cb2_c.framework" \
    -output "$OUT/cb2_c.xcframework" > /dev/null

for platform in ios macos; do
    rm -rf "$PLUGIN/$platform/cb2_flutter/Frameworks"
    mkdir -p "$PLUGIN/$platform/cb2_flutter/Frameworks"
    cp -R "$OUT/cb2_c.xcframework" "$PLUGIN/$platform/cb2_flutter/Frameworks/"
done
echo "cb2_c.xcframework in ios/cb2_flutter/Frameworks and macos/cb2_flutter/Frameworks" >&2
