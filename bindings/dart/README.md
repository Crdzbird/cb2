# cb2 for Dart

Dart bindings for cb2, the post-quantum successor to PASETO, over the C ABI
in `bindings/c` (`cb2_c.h`). The package issues and checks cb2.local
tokens (XChaCha20 with keyed BLAKE3) and cb2.public tokens (Ed25519 and
ML-DSA-65, both required), makes holder proofs, and wraps or seals keys.

- Keys are native handles freed by a `NativeFinalizer`, or at once by
  `dispose()`.
- Every verdict of the library is a `Cb2Exception` carrying the C code
  and its stable name (`invalid`, `expired`, `replayed`,
  `audience_mismatch`, `proof_mismatch`, ...).
- Replay checks are plain Dart callbacks, bridged to the library for the
  duration of one call.

Flutter apps use `cb2_flutter` (`bindings/flutter/cb2_flutter`), which
ships the native library and re-exports this API.

## Quick start

Build the C library from the repository root, then point the package at
it:

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build --target cb2_c
    cd bindings/dart
    dart pub get
    export CB2_C_LIBRARY="$PWD/../../build/bindings/c/libcb2_c.dylib"
    dart test
    dart run example/cb2_example.dart

On Linux the file is `libcb2_c.so`. `hasPublic()` and `hasSeal()` say
whether the loaded build carries cb2.public and kcb2.seal (both need
liboqs).

## Usage

```dart
import 'package:cb2/cb2.dart';

void main() {
  final key = LocalKey.generate();
  final token = Token.seal(key, {
    'iss': 'https://issuer.example',
    'aud': 'api',
    'sub': 'user-1',
    'exp': '2099-01-01T00:00:00+00:00',
    'jti': 'id-1',
  });

  final seen = <String>{};
  final rules = Rules(
    issuer: 'https://issuer.example',
    audience: 'api',
    replay: seen.add,
  );
  print(Token.open(key, token, rules)['sub']);

  try {
    Token.open(key, token, rules);
  } on Cb2Exception catch (e) {
    print(e.name);
  }
  key.dispose();
}
```

The example in `example/cb2_example.dart` does the same for cb2.public
with `SecretKey`, `PublicKey`, `Token.sign` and `Token.verify`, and shows
three refusals.

## API

| Type | What it does |
| --- | --- |
| `LocalKey`, `SecretKey`, `PublicKey` | Keys for cb2.local and cb2.public, from bytes, PASERK text, or fresh randomness. |
| `RecipientKey`, `RecipientPublicKey` | X-Wing pairs for kcb2.seal. |
| `Token` | Claims tokens as `Map<String, Object?>`: `seal`, `open`, `sign`, `verify`, `peekKeyId`. |
| `Rules`, `HolderRules`, `ProofRequest` | What a claims token is checked against; the fields mirror the rules JSON of `cb2_c.h`. |
| `Local`, `Public` | Raw tokens over bytes, with an optional footer and implicit assertion. |
| `Holder` | Holder proofs, public and local mode, and target normalization. |
| `KeyWrap`, `Seal` | Wrap a local key under another, or seal it to a recipient. |
| `Cb2Exception` | Every refusal and failure of the library. |
| `Cb2Library` | Where the native library is looked for. |

## Locating the native library

`Cb2Library.open` tries, in order:

1. the path in the environment variable `CB2_C_LIBRARY`;
2. the platform spelling of `Cb2Library.name` (`cb2_c` by default),
   resolved by the dynamic linker: `cb2_c.framework/cb2_c` then
   `libcb2_c.dylib` on iOS and macOS (the framework is what
   `cb2_flutter` bundles), `cb2_c.dll` on Windows, `libcb2_c.so`
   elsewhere;
3. the symbols of the running process, for a statically linked build.

With `Cb2Library.preferBundled` set, the second step comes first and
`CB2_C_LIBRARY` is only a fallback. `cb2_flutter` sets it, so an app
always uses the library it ships and its environment cannot swap it,
while a host test without a bundled library still finds the one
`CB2_C_LIBRARY` names.

The library is opened on the first call into cb2 and kept for the life
of the isolate, so set `Cb2Library.name` and `Cb2Library.preferBundled`
before that call if needed.

### Why not build hooks (native assets)

Dart build hooks (`hook/build.dart` with `package:hooks` and
`package:code_assets`) are the modern way for a package to ship native
code: the hook builds or fetches a library per target, and `@Native`
bindings resolve it without any loader. They were considered and not
adopted for this release, for three reasons:

- `libcb2_c` depends on libsodium, BLAKE3 and liboqs. A hook would have
  to build all three from source for every target (Android ABIs, iOS
  device and simulator, macOS, Linux, Windows) on every clean build, or
  download prebuilt binaries, which needs published release artifacts
  this repository does not have.
- The same Dart code must run under `dart test` against a library built
  by CMake, in Flutter apps where the plugin ships the library, and in
  statically linked apps. The loader above serves all three without a
  second code path.
- `cb2_flutter` already ships the library through the platform build
  systems (CMake on Android, Linux and Windows, a dynamic XCFramework on
  iOS and macOS), which works with today's Flutter tooling.

The move to hooks becomes worthwhile once hash-pinned release binaries
of `libcb2_c` exist: a hook would then download the one for the target
and emit it as a code asset, and the bindings could switch to `@Native`
with the loader kept as a fallback for local builds.

## Layout

One class per file under `lib/src`, none over a hundred lines. The FFI
signatures and lookups sit under `lib/src/ffi` and are not exported;
`KeyCalls` serves all five key kinds since their entry points share one
naming scheme. Key creation is by static methods (`LocalKey.generate`,
`LocalKey.fromPaserk`, ...) rather than constructors, since a key is a
native handle and cannot be a const value.
