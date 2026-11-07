# cb2_flutter

The cb2 token library for Flutter. cb2 is the post-quantum successor to
PASETO: cb2.local tokens (XChaCha20 with keyed BLAKE3), cb2.public tokens
(Ed25519 and ML-DSA-65, both required), holder proofs and key sealing.

This is an FFI plugin. It ships the native library of cb2 (the C ABI in
`bindings/c`) for each platform and re-exports the Dart API of package
`cb2` (`bindings/dart`), so one import gives the whole API. Nothing of
cb2 is reimplemented here.

## Usage

```dart
import 'package:cb2_flutter/cb2_flutter.dart';

void main() {
  Cb2Flutter.ensureInitialized();
  final key = LocalKey.generate();
  final token = Token.seal(key, {
    'iss': 'https://issuer.example',
    'aud': 'api',
    'exp': '2099-01-01T00:00:00+00:00',
  });
  final claims = Token.open(
    key,
    token,
    const Rules(issuer: 'https://issuer.example', audience: 'api'),
  );
  print(claims['aud']);
  key.dispose();
}
```

Call `Cb2Flutter.ensureInitialized()` once per isolate before the first
cb2 call. cb2.public signing and verification take a few milliseconds;
run them off the UI isolate with `Isolate.run`, as the example app does.
See `bindings/dart/README.md` for the full API.

## Example app

`example/` issues, opens and verifies a cb2.local and a cb2.public token
and shows the library refusing a replay, a tampered token and a token for
another audience. It runs on iOS and macOS:

    tool/build_xcframework.sh
    cd example
    flutter run -d macos
    flutter test integration_test -d macos

## Native library per platform

### iOS and macOS

The plugin bundles `cb2_c.framework`, a dynamic framework that exports
the `cb2_*` functions and nothing else, from
`ios/cb2_flutter/Frameworks/cb2_c.xcframework` (and the same under
`macos/`). The XCFramework is not committed; build it with

    tool/build_xcframework.sh

which fetches hash-pinned libsodium, BLAKE3 and liboqs (ML-DSA-65 and
ML-KEM-768 only, without OpenSSL), compiles them and `cb2_c.cpp` for the
iOS device (arm64), the iOS simulator (arm64, x86_64) and macOS (arm64,
x86_64), and assembles the XCFramework. The first run takes a few
minutes; dependencies are cached under `build/apple-deps`. The minimum
targets are iOS 15.0 and macOS 11.0, the oldest the Xcode C++ library
supports.

Both Swift Package Manager (`ios/cb2_flutter/Package.swift`, the default
in current Flutter) and CocoaPods (`ios/cb2_flutter.podspec`, for apps
that turn Swift Package Manager off) are supported, and both were checked
by building and testing the example app. The framework is embedded in the
app and package `cb2` opens it as `cb2_c.framework/cb2_c`.

### Android, Linux, Windows

`src/CMakeLists.txt` compiles `bindings/c/src/cb2_c.cpp` against the cb2
headers into `libcb2_c.so` (`cb2_c.dll` on Windows). The dependencies are
not vendored; tell the build where they are:

- `CB2_DEPS_ROOT`: a prefix with `include/` and `lib/` for the target. On
  Android, a directory with one prefix per ABI (`arm64-v8a`, `x86_64`,
  ...). The Android build reads the environment variable and passes it
  to CMake; on Linux and Windows CMake reads the environment variable
  itself. Without it, Linux falls back to pkg-config.
- `CB2_DEPS_LIBS`: the library names to link when they differ from
  `sodium;blake3;crypto` plus `oqs`.
- `CB2_PQ`: `OFF` builds cb2.local only, without liboqs (environment
  variable on Android, CMake option elsewhere).

Build the dependencies as static libraries for a self-contained
`libcb2_c`; shared ones must also be bundled with the app. These three
platforms have not been built as part of this package's checks.

## Development

    flutter pub get
    flutter analyze
    CB2_C_LIBRARY=/path/to/build/bindings/c/libcb2_c.dylib flutter test

The plugin and the example follow `very_good_analysis` with strict casts,
inference and raw types. Every Dart file holds one class and stays under
a hundred lines.
