# cb2 for Dart

cb2 is a format for security tokens, the short strings a server hands out
after a login and later accepts as proof of who is calling. It does the
job of JWT and PASETO with more of the checks built in, post-quantum
signatures, and tokens that can be bound to the client they were issued
to. This package is the Dart API over the native cb2 library; the format
itself is described in the [root README](../../README.md),
[docs/SPEC.md](../../docs/SPEC.md) and
[docs/PROTOCOL.md](../../docs/PROTOCOL.md).

Status: version 0.2.0 of the package, over cb2 0.1.0. cb2 has not yet
been reviewed by anyone but its author. Flutter apps use
[`cb2_flutter`](../flutter/cb2_flutter), which ships the native library
and re-exports this API.

## Install

The package is not on pub.dev. Depend on it from git:

```yaml
dependencies:
  cb2:
    git:
      url: https://github.com/Crdzbird/cb2
      path: bindings/dart
```

It calls the native library `libcb2_c` through dart:ffi, so build that
once from a clone of the repository. It needs libsodium, BLAKE3,
libcrypto and liboqs; on macOS,
`brew install cmake ninja libsodium liboqs blake3 openssl@3`.

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build --target cb2_c
    export CB2_C_LIBRARY="$PWD/build/bindings/c/libcb2_c.dylib"

On Linux the file is `libcb2_c.so`.

## Quick start

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
  print(token);

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
    print('refused: ${e.name}');
  }
  key.dispose();
}
```

It prints a token of about 320 characters that starts with
`cb2.local.`, then `user-1`, then `refused: replayed`: the second open
sees the same `jti` again and the replay check refuses it.

## Token kinds

| Kind | Keys | Use it when |
| --- | --- | --- |
| cb2.local | one shared `LocalKey` (XChaCha20 with keyed BLAKE3) | the service that issues the token also checks it, or shares a key with the one that does; the claims are encrypted |
| cb2.public | a `SecretKey` signs, its `PublicKey` verifies (Ed25519 and ML-DSA-65, both required) | others must check tokens without being able to issue them; the claims are readable |
| cb3.local, cb3.public (experimental) | the same keys as cb2.local and cb2.public | the same as cb2.local and cb2.public with tokens about half the size; the format may still change |
| holder proofs | a client key named in the token's `cnf` claim | a stolen token alone must not be enough: the client proves it holds its key on each request |
| `KeyWrap`, `Seal` | a wrapping `LocalKey`, or a `RecipientKey` (X-Wing) | a local key has to be stored, or sent to another party |

## API overview

| Type | What it does |
| --- | --- |
| `LocalKey`, `SecretKey`, `PublicKey` | Keys for cb2.local and cb2.public, from bytes, PASERK text, or fresh randomness; `keyId` names the key in token footers. |
| `RecipientKey`, `RecipientPublicKey` | X-Wing pairs for kcb2.seal. |
| `Token` | Claims tokens as `Map<String, Object?>`: `seal`, `open`, `sign`, `verify`, and `peekKeyId` to pick a key before checking. |
| `CompactToken` | The same claims, rules and verdicts as `Token` as the experimental compact cb3.local and cb3.public tokens: `seal`, `open`, `sign`, `verify`, and `peekKeyDigest` with `keyDigest` to pick a key before checking. Each takes an optional `table:`. |
| `ClaimTable` | An ordered list of strings, typically the issuer and its audiences, that an issuer and its verifiers both configure; under it a compact token carries an iss or aud in the list as an index, and opens only under the same table. `fromEntries`, `digest` to compare tables, `dispose`. |
| `Rules` | What a claims token is checked against: issuer, audience, subject, clock and skew, lifetime, replay, `cnf`. |
| `HolderRules`, `ProofRequest` | The holder proof presented with a token and the request it must match. |
| `Holder` | Makes holder proofs, public and local mode, and normalizes request targets. |
| `Local`, `Public` | Raw tokens over bytes, with an optional footer and implicit assertion. |
| `KeyWrap`, `Seal` | Wrap a local key under another, or seal it to a recipient. |
| `hasPublic()`, `hasSeal()`, `version()` | What the loaded native library was built with. |

Registered times (`exp`, `nbf`, `iat`) are RFC 3339 text. Every call is
synchronous. cb2.public signing takes a fraction of a millisecond, so an
app with a UI should run it off the main isolate with `Isolate.run`.

## Errors and disposal

Every refusal and failure is a `Cb2Exception` with the numeric `code`
and a stable `name`: `invalid`, `too_large`, `argument`,
`rules_incomplete`, `internal`, `unavailable`, `claims_malformed`,
`missing_exp`, `expired`, `not_yet_valid`, `issued_in_future`,
`lifetime_exceeded`, `issuer_mismatch`, `audience_mismatch`,
`subject_mismatch`, `missing_jti`, `replayed`, `missing_cnf`,
`missing_proof`, `proof_invalid`, `proof_malformed`, `proof_expired`,
`proof_mismatch` and `proof_replayed`. Match on `name`.

Keys are native handles. A `NativeFinalizer` frees them when the Dart
object is collected; call `dispose()` to free one at once. A disposed
key throws `StateError` when used. A replay check is a plain Dart
callback, `bool Function(String jti)`, run during the call; one that
throws refuses the id.

## Locating the native library

`Cb2Library.open` tries, in order:

1. the path in the environment variable `CB2_C_LIBRARY`;
2. the platform spelling of `Cb2Library.name` (`cb2_c` by default),
   resolved by the dynamic linker: `cb2_c.framework/cb2_c` then
   `libcb2_c.dylib` on iOS and macOS, `cb2_c.dll` on Windows,
   `libcb2_c.so` elsewhere;
3. the symbols of the running process, for a statically linked build.

With `Cb2Library.preferBundled` set, the second step comes first and
`CB2_C_LIBRARY` is only a fallback. `cb2_flutter` sets it, so an app
always uses the library it ships and its environment cannot swap it.
The library is opened on the first call into cb2 and kept for the life
of the isolate, so set `Cb2Library.name` and `Cb2Library.preferBundled`
before that call if needed.

Dart build hooks (native assets) were considered and not adopted yet.
`libcb2_c` depends on libsodium, BLAKE3 and liboqs, and a hook would
have to build all three for every target on every clean build, or
download release binaries this repository does not publish. Once such
binaries exist, a hook can fetch the one for the target, with the loader
above kept as the fallback for local builds.

## Example

`example/cb2_example.dart` issues, opens and verifies a cb2.local and a
cb2.public token, opens a compact cb3.local token alone and under a
claim table, and shows three refusals:

    dart run example/cb2_example.dart

```
cb2 0.1.0, public true, seal true
cb2.local token: cb2.local.OIsZ972iGacKSe...(347 chars)
opened: sub user-1, role reader
the same token again: refused with replayed
cb3.local token: cb3.local.uSEf1Ahb9aR6Ec...(205 chars)
opened compact: sub user-1, jti local-2
under a claim table: cb3.local.mI82SZ_TTubq1H...(172 chars)
opened tabled: iss https://issuer.example, aud api
a tampered token: refused with invalid
cb2.public token: cb2.public.eyJpc3MiOiJod...(4762 chars)
verified: sub user-1, role reader
a token for another audience: refused with audience_mismatch
```

The Flutter example app in `bindings/flutter/cb2_flutter/example` runs
the same demo on iOS and macOS.

## Benchmarks

`benchmark/` is a separate package, so this one gains no JWT or PASETO
dependency. It times issuing a token, and checking it with its claims
validated (issuer, audience, expiry), on the same claims for every
format: `iss`, `sub`, `aud`, `exp`, `iat`, `jti` and one short custom
claim. cb2 and PASETO carry the times as RFC 3339 text, JWT as seconds.
The competitors are
[dart_jsonwebtoken](https://pub.dev/packages/dart_jsonwebtoken) 3.4.1,
by far the most used JWT package on pub.dev, and
[paseto_dart](https://pub.dev/packages/paseto_dart) 2.1.0, the
maintained PASETO v4 package (the older `paseto` package was last
released in 2023 and needs the Flutter SDK). paseto_dart checks only the
cryptography, so the benchmark adds the same issuer, audience and time
checks after it.

Apple M3 Max, macOS 26.6.2, Dart 3.13.7, compiled with
`dart compile exe`, 2026-11-07. Each cell is the median of three runs;
each run takes the median of 21 samples of 25 ms after 300 ms of
warmup. Times are microseconds per token. Runs differed by up to about
5 percent.

| Format | Library | Issue (us) | Check (us) | Bytes |
| --- | --- | ---: | ---: | ---: |
| cb2.local | cb2 0.1.0 (native, FFI) | 8.2 | 8.6 | 389 |
| cb3.local | cb2 0.1.0 (native, FFI) | 7.0 | 6.7 | 209 |
| cb3.local, claim table | cb2 0.1.0 (native, FFI) | 7.2 | 6.7 | 176 |
| JWT HS256 | dart_jsonwebtoken 3.4.1 (pure Dart) | 31.3 | 29.8 | 244 |
| PASETO v4.local | paseto_dart 2.1.0 (pure Dart) | 128 | 115 | 303 |
| cb2.public | cb2 0.1.0 (native, FFI) | 181 | 146 | 4802 |
| cb3.public | cb2 0.1.0 (native, FFI) | 179 | 142 | 4622 |
| JWT EdDSA | dart_jsonwebtoken 3.4.1 (pure Dart) | 2294 | 2290 | 287 |
| JWT ES256 | dart_jsonwebtoken 3.4.1 (pure Dart) | 5093 | 7554 | 287 |
| PASETO v4.public | paseto_dart 2.1.0 (pure Dart) | 3221 | 2269 | 304 |

Read it with two facts in mind. First, these are different kinds of
implementation: cb2 runs native C++ through FFI, while both competitors
are pure Dart, so the gap mostly measures native against Dart
cryptography, not the formats. Second, cb2.public carries a post-quantum
ML-DSA-65 signature next to Ed25519, so as a format it is slower and much
larger than the classical-only ones: about 4.8 KB against about 300
bytes. It comes out faster here only because the Dart Ed25519 and P-256
code is slow. Against native Ed25519 (PASETO v4.public in the C++
benchmark under "Benchmark in detail" in the root README), cb2.public is
about ten times slower to sign and about twice as slow to verify.
cb2.local tokens are larger than PASETO v4.local ones mainly because
they carry the key id in the footer.
The compact cb3.local token carries the same claims as CBOR and a
16-byte digest of the key id instead of its text, which brings it to 209
bytes, below PASETO v4.local, and makes it slightly quicker to issue and
check. cb3.public saves the same 180 bytes, which matters little next to
the signatures. Under a claim table of the issuer and the audience, both
travel as one-byte indexes and cb3.local comes to 176 bytes for the
same time. That row was measured later than the others, with other work
running on the machine, as the median of seven runs.

Run it yourself:

    cd benchmark
    dart pub get
    dart compile exe bin/cb2_benchmark.dart -o cb2_benchmark
    CB2_C_LIBRARY=/path/to/libcb2_c.dylib ./cb2_benchmark

## Development

    dart pub get
    dart format --set-exit-if-changed .
    dart analyze --fatal-infos
    CB2_C_LIBRARY=/path/to/libcb2_c.dylib dart test

The package follows `very_good_analysis` with strict casts, inference
and raw types. Every Dart file holds one class and stays under a hundred
lines. The FFI signatures and lookups sit under `lib/src/ffi` and are not
exported; `KeyCalls` serves all five key kinds, since their entry points
share one naming scheme. Keys are created by static methods
(`LocalKey.generate`, `LocalKey.fromPaserk`, ...) rather than
constructors, since a key is a native handle and cannot be a const
value. CI runs all of the above, the example, and a short smoke run of
the benchmark.
