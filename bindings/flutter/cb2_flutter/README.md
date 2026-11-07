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

Status: version 0.2.0 of the plugin, over cb2 0.1.0. cb2 has not yet
been reviewed by anyone but its author. iOS and macOS are built and
tested; Android, Linux and Windows are not verified yet.

## Install

The plugin is not on pub.dev, and its iOS and macOS framework is built
locally rather than committed, so use it from a clone of the repository:

    git clone https://github.com/Crdzbird/cb2
    cb2/bindings/flutter/cb2_flutter/tool/build_xcframework.sh

```yaml
dependencies:
  cb2_flutter:
    path: /path/to/cb2/bindings/flutter/cb2_flutter
```

The script needs Xcode, cmake, ninja and make, and takes a few minutes
the first time.

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
the `cb2_*` functions and nothing else, from
`ios/cb2_flutter/Frameworks/cb2_c.xcframework` (and the same under
`macos/`). `tool/build_xcframework.sh` fetches hash-pinned libsodium,
BLAKE3 and liboqs (ML-DSA-65 and ML-KEM-768 only, without OpenSSL),
compiles them and `cb2_c.cpp` for the iOS device (arm64), the iOS
simulator (arm64, x86_64) and macOS (arm64, x86_64), and assembles the
XCFramework; dependencies are cached under `build/apple-deps`. The
minimum targets are iOS 15.0 and macOS 11.0, the oldest the Xcode C++
library supports.

Both Swift Package Manager (`ios/cb2_flutter/Package.swift`, the default
in current Flutter) and CocoaPods (`ios/cb2_flutter.podspec`, for apps
that turn Swift Package Manager off) are supported; the example app was
built and tested through both.

### Android, Linux and Windows: not verified yet

`src/CMakeLists.txt` compiles `bindings/c/src/cb2_c.cpp` against the cb2
headers into `libcb2_c.so` (`cb2_c.dll` on Windows), but these builds
have not been run. The dependencies are not vendored; tell the build
where they are:

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
`libcb2_c`; shared ones must also be bundled with the app.

## Example app

`example/` seals and opens a cb2.local token and a compact cb3.local
token, alone and under a claim table, signs and verifies a cb2.public
token, and shows the library refusing a replayed token, a tampered token
and a token for another audience, off the UI isolate.
It runs on iOS and macOS and has an integration test:

    cd example
    flutter run -d macos
    flutter test integration_test -d macos

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

## Development

    flutter pub get
    flutter analyze --fatal-infos
    CB2_C_LIBRARY=/path/to/build/bindings/c/libcb2_c.dylib flutter test

Host tests have no bundled library, so they load the one
`CB2_C_LIBRARY` names. The plugin and the example follow
`very_good_analysis` with strict casts, inference and raw types; every
Dart file holds one class and stays under a hundred lines.
