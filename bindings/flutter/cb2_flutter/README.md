# cb2_flutter

The cb2 token library for Flutter: an FFI plugin that provides the C ABI of
cb2 (`bindings/c`) on every platform and re-exports the Dart API of
`package:cb2` (`bindings/dart`). Nothing of cb2 is duplicated here; the
plugin only builds or bundles `libcb2_c` and names it for the loader.

The mobile and desktop native builds described below were not run as part
of writing this package. What was verified: `flutter pub get` and
`flutter analyze` on the plugin, and `dart test` on `package:cb2` against
a macOS build of `libcb2_c.dylib`.

## Native library per platform

cb2 depends on libsodium, BLAKE3 and libcrypto, and on liboqs for
cb2.public and kcb2.seal. They are not vendored; supply them built for
each target.

### Android, Linux, Windows

`src/CMakeLists.txt` compiles `bindings/c/src/cb2_c.cpp` against the cb2
headers into `libcb2_c.so` (`cb2_c.dll` on Windows). Tell it where the
dependencies are:

- `CB2_DEPS_ROOT`: a prefix with `include/` and `lib/` for the target. On
  Android, a directory with one prefix per ABI (`arm64-v8a`, `x86_64`,
  ...). The Android build reads the environment variable `CB2_DEPS_ROOT`
  and passes it to CMake; on Linux and Windows the environment variable is
  read by CMake itself. Without it, Linux falls back to pkg-config.
- `CB2_DEPS_LIBS`: the library names to link when they differ from
  `sodium;blake3;crypto` plus `oqs`.
- `CB2_PQ`: `OFF` builds cb2.local only, without liboqs (environment
  variable on Android, CMake option elsewhere).

Build the dependencies as static libraries for a self-contained
`libcb2_c`; shared ones must also be added to the bundled libraries in
`linux/CMakeLists.txt` and `windows/CMakeLists.txt`, or shipped with the
app on Android.

### iOS and macOS

`ios/cb2_flutter.podspec` and `macos/cb2_flutter.podspec` vendor a prebuilt
`Frameworks/libcb2_c.xcframework`. Build it from the static `cb2_c_static`
target of `bindings/c` with the dependencies merged in, one slice per
platform:

    libtool -static -o libcb2_c-ios.a libcb2_c.a libsodium.a libblake3.a liboqs.a libcrypto.a
    xcodebuild -create-xcframework \
      -library libcb2_c-ios.a -headers ../bindings/c/include \
      -library libcb2_c-sim.a -headers ../bindings/c/include \
      -output libcb2_c.xcframework

Place the result at `ios/Frameworks/libcb2_c.xcframework` (and the macOS
one at `macos/Frameworks/libcb2_c.xcframework`). The podspec adds
`-force_load` for the slice so the linker keeps the `cb2_*` symbols, which
Dart then finds through `DynamicLibrary.process()`.

## Example

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
}
```

Every type of `package:cb2` is available through this import; see
`bindings/dart/README.md` for the API.
