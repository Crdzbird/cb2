# Shipping the C library

Provide `libcb2_c` as an XCFramework for apps, or as a system library for development.

## Overview

The Swift target `Cb2` imports a module named `CCb2`, the C ABI header
`cb2_c.h`. `Package.swift` defines `CCb2` in one of two ways and picks
between them when the package is loaded:

- If `Cb2C.xcframework` sits next to `Package.swift`, `CCb2` is a binary
  target over it. This is the layout for macOS and iOS apps.
- Otherwise, or when the environment variable `CB2_SWIFT_SYSTEM_LIBRARY`
  is set, `CCb2` is a system library that links `cb2_c` from wherever the
  linker is told to look. This is the layout for working on the
  repository.

The Swift sources are the same in both layouts.

## Build the XCFramework

```sh
bindings/swift/scripts/build-xcframework.sh
```

The script builds libsodium, BLAKE3 and liboqs (reduced to ML-DSA-65 and
ML-KEM-768, portable C, no OpenSSL) from the hash-pinned release tarballs
the web build uses, compiles `bindings/c/src/cb2_c.cpp` against them, and
merges each slice into one static `libcb2_c.a`:

| Slice | Architectures | Minimum |
| --- | --- | --- |
| macOS | arm64, x86_64 | macOS 13 |
| iOS | arm64 | iOS 16 |
| iOS simulator | arm64, x86_64 | iOS 16 |

The headers directory carries `cb2_c.h` and a module map that defines
`CCb2` and links the C++ runtime. The dependency builds are cached under
`bindings/swift/.build-xcframework`; a second run only recompiles
`cb2_c.cpp`. The first run takes a few minutes. Both outputs are ignored
by git.

The archive bundles its dependencies. An app that links its own copy of
libsodium or liboqs gets duplicate symbols; build the slices against that
copy instead, or link the system-library layout.

## Develop against a CMake build

Build the C ABI from the repository root, then point the linker at it:

```sh
cmake -S . -B build -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0
cmake --build build --target cb2_c
cd bindings/swift
CB2_SWIFT_SYSTEM_LIBRARY=1 swift test \
  -Xlinker -L"$PWD/../../build/bindings/c" \
  -Xlinker -rpath -Xlinker "$PWD/../../build/bindings/c"
```

With `cmake --install build` the library lands under the install prefix
and the linker finds it without flags. Unsafe linker flags in
`Package.swift` would make the package unusable as a dependency, so they
stay on the command line.
