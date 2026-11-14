# cb2_flutter

cb2 is a format for security tokens, the short strings a server hands out
after a login and later accepts as proof of who is calling. It does the
job of JWT and PASETO with more of the checks built in, post-quantum
signatures, and tokens that can be bound to the client they were issued
to. This Flutter plugin ships the native cb2 library for each platform
and re-exports the whole Dart API of package [`cb2`](../../dart), so one
import is enough. The format is described in the
[root README](../../../README.md),
[docs/SPEC.md](../../../docs/SPEC.md) and
[docs/PROTOCOL.md](../../../docs/PROTOCOL.md).

Status: version 0.4.0 of the plugin, over cb2 0.1.0. cb2 has not yet
been reviewed by anyone but its author. iOS, macOS, Android and the web
are built and tested; Linux and Windows are not verified yet.

## Install

The plugin is not on pub.dev, and its native libraries are built
locally rather than committed, so use it from a clone of the repository
and build them for the platforms the app targets:

    git clone https://github.com/Crdzbird/cb2
    cb2/bindings/flutter/cb2_flutter/tool/build_xcframework.sh
    cb2/bindings/flutter/cb2_flutter/tool/build_android_deps.sh

```yaml
dependencies:
  cb2_flutter:
    path: /path/to/cb2/bindings/flutter/cb2_flutter
```

The first script, for iOS and macOS, needs Xcode; the second, for
Android, needs the Android NDK. Both need cmake, ninja and make, and
take a few minutes the first time.

## Quick start

```dart
import 'dart:isolate';

import 'package:cb2_flutter/cb2_flutter.dart';

Future<String> issueAndCheck() => Isolate.run(() {
  Cb2Flutter.ensureInitialized();
  final key = LocalKey.generate();
  final token = Token.seal(key, {
    'iss': 'https://issuer.example',
    'aud': 'api',
    'sub': 'user-1',
    'exp': '2099-01-01T00:00:00+00:00',
  });
  final claims = Token.open(
    key,
    token,
    const Rules(issuer: 'https://issuer.example', audience: 'api'),
  );
  key.dispose();
  return '${claims['sub']}';
});
```

`issueAndCheck()` completes with `user-1`. Call
`Cb2Flutter.ensureInitialized()` once in every isolate before its first
cb2 call; it makes the loader use the library this plugin ships. Every
cb2 call is synchronous and cb2.public signing takes a fraction of a
millisecond, so run token work off the UI isolate as above.

In a browser there is no second isolate and the library is a
WebAssembly engine that loads asynchronously, so await `Cb2Flutter.load()`
once before the first cb2 call, typically in `main`; until it completes
every call throws a `Cb2Exception` named `unavailable`. `load` works on
every platform (natively it opens the library early), so one `main`
serves all of them:

```dart
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await Cb2Flutter.load();
  runApp(const App());
}
```

## Token kinds

| Kind | Use it when |
| --- | --- |
| cb2.local | the service that issues the token also checks it, or shares a key with the one that does; the claims are encrypted |
| cb2.public | others must check tokens without being able to issue them; Ed25519 and ML-DSA-65 both sign every token |
| cb3.local, cb3.public (experimental) | the same as cb2.local and cb2.public with tokens about half the size; the format may still change |
| holder proofs | a stolen token alone must not be enough: the client proves it holds the key the token names |
| key wrapping and sealing | a local key has to be stored, or sent to another party |

## API overview

Everything in package `cb2` is available through
`package:cb2_flutter/cb2_flutter.dart`: `LocalKey`, `SecretKey`,
`PublicKey`, `Token`, `CompactToken`, `ClaimTable`, `Rules`,
`HolderRules`, `Holder`,
`Local`, `Public`, `KeyWrap`, `Seal`, `Cb2Exception` and the rest; see the
[package cb2 README](../../dart/README.md) for each. The plugin adds one
class, `Cb2Flutter`, whose `ensureInitialized()` points the loader at
the bundled library.

## Errors and disposal

Every refusal is a `Cb2Exception` whose `name` is stable, such as
`expired`, `replayed`, `audience_mismatch` or `proof_mismatch`; the full
list is in the package cb2 README. Keys are native handles, freed when
collected or at once by `dispose()`.

## Native library per platform

### iOS and macOS: built and tested

The plugin bundles `cb2_c.framework`, a dynamic framework that exports
the `cb2_*` functions of `cb2_c.h` and nothing else, from
`ios/cb2_flutter/Frameworks/cb2_c.xcframework` (and the same under
`macos/`). `tool/build_xcframework.sh` fetches hash-pinned libsodium,
BLAKE3 and liboqs (ML-DSA-65 and ML-KEM-768 only, without OpenSSL),
compiles them and `cb2_c.cpp` for the iOS device (arm64), the iOS
simulator (arm64, x86_64) and macOS (arm64, x86_64), and assembles the
XCFramework; dependencies are cached under `build/apple-deps`. Each
slice is linked with the list of exported names read from `cb2_c.h`,
dead-stripped and stripped of local symbols, and the script stops if a
slice exports anything else. The minimum targets are iOS 15.0 and macOS
11.0, the oldest the Xcode C++ library supports.

Because the framework is dynamic, a release build keeps the library
whole: nothing in the app refers to the `cb2_*` symbols, and Dart opens
`cb2_c.framework/cb2_c` by name at run time. No OpenSSL is linked on
iOS or macOS, so cb2.local runs every message through libsodium's
XChaCha20.

Both Swift Package Manager (`ios/cb2_flutter/Package.swift`, the default
in current Flutter) and CocoaPods (`ios/cb2_flutter.podspec`, for apps
that turn Swift Package Manager off) are supported; the example app was
built and tested through both.

### Android: built and tested

The Android build compiles `bindings/c/src/cb2_c.cpp` into
`libcb2_c.so` with the NDK, for each ABI, against static libsodium,
BLAKE3 and liboqs, and links libc++ statically. The library exports the
74 `cb2_*` functions of `cb2_c.h` and nothing else, needs only `libc`,
`libm` and `libdl`, links no OpenSSL, and aligns its segments to 16 KB
pages. In a release APK it is about 590 KB on arm64-v8a, 420 KB on
armeabi-v7a and 710 KB on x86_64, with cb2.public.

1. Build the dependencies once, from the plugin directory:

       tool/build_android_deps.sh

   It fetches the same hash-pinned libsodium, BLAKE3 and liboqs as the
   Apple script and builds them for API 24 with the NDK named by
   `ANDROID_NDK_HOME`, or the newest one under `$ANDROID_HOME/ndk`, into
   `build/android-deps/<abi>`. That directory is where the Android
   build looks when `CB2_DEPS_ROOT` is not set.

2. Build the app as usual, `flutter run` or `flutter build apk`.

The Gradle build reads these environment variables, so set them in
the environment of the `flutter` command and of the dependency script
alike:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CB2_ANDROID_ABIS` | `arm64-v8a,armeabi-v7a,x86_64` | the ABIs the library is built for, comma separated |
| `CB2_PQ` | `ON` | `OFF` builds cb2.local and holder proofs only, without liboqs |
| `CB2_DEPS_ROOT` | `build/android-deps` of the plugin | a directory with one prefix (`include/`, `lib/`) per ABI |
| `CB2_DEPS_LIBS` | `sodium;blake3`, plus `oqs` with `CB2_PQ` | the libraries to link, when they differ |
| `CB2_OPENSSL_CHACHA` | `OFF` | `ON` sends cb2.local messages of 512 bytes or more through OpenSSL's ChaCha20, and links `crypto` from the prefix |

The build stops, naming the missing directory, when `CB2_DEPS_ROOT` has
no prefix for one of the ABIs. When another native plugin of the app
ships fewer ABIs, limit both sides to the same list, for example
`CB2_ANDROID_ABIS=arm64-v8a,x86_64` here, `ndk { abiFilters += listOf(
"arm64-v8a", "x86_64") }` in the app's `android/app/build.gradle.kts`,
and `flutter build apk --target-platform android-arm64,android-x64`;
otherwise a phone of the missing ABI installs the app and fails on its
first native call.

`tool/check_android_library.sh` builds the library for each ABI the way
Gradle does and checks the exports, the needed libraries and the page
alignment; CI runs it.

### Web: built and tested

The plugin declares a web platform (`Cb2FlutterWeb`, which registers
nothing), and package cb2 runs in a browser over the WebAssembly build
of the C ABI that `bindings/js` ships: the same C++, with cb2.public and
kcb2.seal. Package cb2 declares that engine as assets, so Flutter
serves it with the app at `assets/packages/cb2/js/src/cb2.js` (and the
core at `assets/packages/cb2/js/dist/cb2_core.wasm`) and
`Cb2Flutter.load()` finds it there with no setup. An app served under
another path keeps working through `<base href>`, which the loader
resolves against; to serve the engine elsewhere, set
`Cb2Library.engineUrl` before `load`, or build with
`--dart-define=CB2_WEB_ENGINE=<url of src/cb2.js>`. The engine fails
closed: a missing or wrong module leaves every call refused as
`unavailable`. Serve `.wasm` as `application/wasm` for a streaming
compile. The example app was built with `flutter build web` and its
demo run in Chrome; package cb2's browser suites run under dart2js and
dart2wasm. See [In a browser](../../dart/README.md#in-a-browser) in the
package cb2 README for what differs there.

### Linux and Windows: not verified yet

`src/CMakeLists.txt` compiles `bindings/c/src/cb2_c.cpp` against the cb2
headers into `libcb2_c.so` (`cb2_c.dll` on Windows), but these builds
have not been run. The dependencies are not vendored; tell the build
where they are:

- `CB2_DEPS_ROOT`: a prefix with `include/` and `lib/` for the target,
  read by CMake from the environment. Without it, Linux falls back to
  pkg-config.
- `CB2_DEPS_LIBS`: the library names to link when they differ from
  `sodium;blake3` plus `crypto` and `oqs`.
- `CB2_PQ`: `OFF` builds cb2.local only, without liboqs.
- `CB2_OPENSSL_CHACHA`: on by default here; `OFF` drops libcrypto.

Build the dependencies as static libraries for a self-contained
`libcb2_c`; shared ones must also be bundled with the app.

## Example app

`example/` seals and opens a cb2.local token and a compact cb3.local
token, alone and under a claim table, signs and verifies a cb2.public
token, and shows the library refusing a replayed token, a tampered token
and a token for another audience, off the UI isolate, or on it in a
browser. It runs on iOS, macOS, Android and the web and has an
integration test:

    cd example
    flutter run -d macos
    flutter run -d chrome
    flutter test integration_test/app_test.dart -d macos

`integration_test/benchmark_test.dart` times every token format on a
device with the cases of the Dart benchmark (`bindings/dart/benchmark`),
in profile mode, and writes the table to
`build/integration_response_data.json`:

    flutter drive --profile --driver=test_driver/integration_test.dart \
        --target=integration_test/benchmark_test.dart -d <device>

## Benchmarks

The timings of cb2 against dart_jsonwebtoken and paseto_dart are in the
[package cb2 README](../../dart/README.md#benchmarks). They come from an
AOT-compiled Dart program on an Apple M3 Max and apply to Flutter apps
too, since the plugin runs the same native library. In short, cb2.local
issues and checks a token in about 9 microseconds; cb2.public in about
150 to 190 microseconds, with tokens of about 4.8 KB because every token
carries a post-quantum ML-DSA-65 signature next to Ed25519. The
experimental compact cb3.local token is about 7 microseconds and 209
bytes against 389, and 176 bytes under a claim table of the issuer and
the audience.

On a phone the same benchmark runs through `integration_test/benchmark_test.dart`.
On a Pixel 7 Pro (Tensor G2, Android 17), profile mode, the median of
three runs, in microseconds:

| format | issue | check | bytes |
| --- | ---: | ---: | ---: |
| cb2.local | 32.6 | 46.9 | 389 |
| cb3.local | 30.4 | 31.1 | 209 |
| cb3.local, claim table | 31.2 | 30.1 | 176 |
| JWT HS256 (dart_jsonwebtoken) | 49.6 | 46.9 | 244 |
| PASETO v4.local (paseto_dart) | 283 | 251 | 303 |
| cb2.public | 567 | 356 | 4,802 |
| cb3.public | 561 | 336 | 4,622 |
| JWT EdDSA (dart_jsonwebtoken) | 2,649 | 2,504 | 287 |
| JWT ES256 (dart_jsonwebtoken) | 6,105 | 8,869 | 287 |
| PASETO v4.public (paseto_dart) | 3,278 | 2,290 | 304 |

The phone is three to five times slower than the M3 Max for the local
tokens and two to three times for the public ones. Checking a compact
token costs a third less than a cb2.local one, because there is no JSON
or RFC 3339 text to parse; issuing costs about the same, because most of
it is the call across FFI with the claims as JSON.

## Development

    flutter pub get
    flutter analyze --fatal-infos
    CB2_C_LIBRARY=/path/to/build/bindings/c/libcb2_c.dylib flutter test

Host tests have no bundled library, so they load the one
`CB2_C_LIBRARY` names. The plugin and the example follow
`very_good_analysis` with strict casts, inference and raw types; every
Dart file holds one class and stays under a hundred lines.
