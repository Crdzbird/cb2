# Verification record

What was built, run and measured, and when, newest first. The README
summarises it; this file keeps the detail. Everything ran on one Apple
silicon Mac (M3 Max) unless an entry says otherwise.

## 2026-11-07, Phase 0 of the compact-tokens branch: the size harness

cb2_size (bench/bench_size.cpp, built with the tests) measures token
sizes on a corpus of 1,000 claim sets drawn from a fixed seed, the
corpus of docs/research/token-size/PLAN.md. Every length depends only
on the claims, so the table is exact and the same on every run; three
runs with fresh keys each matched bench/size_expected.txt with 0
differences. `cb2_size --check` was shown to fail (exit 1) on a changed
mean and on a row missing from the expected file. It passed in the
release build, under ASan and UBSan, and without liboqs (the four
local rows only), and as the CTest test cb2_size_check.

Sizes in characters (bytes for the claims), minimum, mean and maximum:
claims JSON 211, 217.167, 224; cb2.local 462, 470.194, 479; a cb2.local
bound to a local proof key 546, 554.194, 563, with its cb2.holder-local
proof 406; cb2.public 4875, 4883.194, 4892; a cb2.local bound to a
client key pair 4018, 4026.194, 4035; a cb2.public bound to a client
key pair 8431, 8439.194, 8448, with its cb2.holder-public proof 4819.
Every bound cb2.public token is over the 8,192-byte header field
default of nginx, and cb2.public and both public-key rows are over the
4,096-byte cookie limit. This reproduces the 470 and 4,883 the plan
starts from, which is the exit criterion of Phase 0.

Timings on the same corpus, median of five passes: cb2.local seal 5.39
us and open 3.90; cb2.public sign 183.59 and verify 126.86; a bound
cb2.public request check (token and proof) 323.19. They are printed
for reference and not checked.

## 2026-11-07, the Java and Kotlin README and JVM benchmarks

bindings/java/README.md is rewritten for a first-time user, and
bindings/java/bench is a JMH project (never published) that compares the
Java library with JJWT 0.13.0, Nimbus JOSE+JWT 10.10 (Tink 1.24.0 for
Ed25519) and paseto4j 2026.0 (Bouncy Castle 1.84) on one 187-byte claims
payload, issuing and then checking issuer, audience and expiry. Under
Oracle JDK 21.0.1, JMH 1.37, 2 forks, 3 warmup and 5 measured one-second
iterations, with other processes holding the load average at 7 to 10,
in microseconds per operation: cb2.local 6.57 to issue and 6.03 to
check; PASETO v4.local 6.81 and 5.56; JJWT HS256 4.70 and 6.79; Nimbus
HS256 2.55 and 4.90; cb2.public 174.31 and 123.18; PASETO v4.public
57.37 and 76.37; Nimbus EdDSA 63.04 and 174.84; JJWT EdDSA 574.20 and
569.92; Nimbus ES256 152.92 and 533.91; JJWT ES256 163.75 and 536.44.
Every 99.9% interval is within 6% of its score. Tokens: cb2.local 430
bytes, cb2.public 4843, PASETO 344 and 345, JWT 269 to 315. A first run
under a load of 44 had intervals up to 77% and is not used.

The README quick starts are the files QuickStart.java and QuickStart.kt
in the two example projects, run by `quickStart` tasks that CI now runs.
Both printed the token, its claims, the replayed refusal and a verified
cb2.public token; the same two files, built in a separate Gradle project
against the artifacts installed with `publishToMavenLocal` into a
scratch repository through the dependency lines of the README, printed
the same. The published POM of cb2 lists no dependencies.

## 2026-11-07, Go binding README and benchmark against golang-jwt and go-paseto

`bindings/go/README.md` is rewritten for a first-time user: what cb2
is, install and linking, a quick start, the token kinds, an API
overview, errors, key lifetime and concurrency, the example apps, the
benchmark and development notes. The quick start was compiled and run
as its own module with a `replace` directive; its printed output is the
one shown.

`bindings/go/bench` is a separate module (golang-jwt v5.3.1, go-paseto
v1.6.0) so that the binding's go.mod gains no dependency. It issues and
checks one claims payload (iss, sub, aud, exp, iat, jti, role) with
cb2.local, cb2.public, JWT HS256, EdDSA and ES256, and PASETO v4.local
and v4.public; a check verifies the tag or signature, issuer, audience,
expiry and iat, then reads the custom claim. `TestFormats` confirms
each format accepts its own token and refuses a tampered one. go vet
and staticcheck v0.8.2 report nothing.

A first run of `-benchtime 1s -count 10` overlapped other sessions'
builds and benchmarks (load average 31) and showed up to 54 percent
spread, so it was discarded. The second run started at a load average
of 3.7 and every median is within plus or minus 2 percent (benchstat):

| format | token bytes | issue | check |
|---|---:|---:|---:|
| cb2.local | 403 | 7.09 us | 7.56 us |
| jwt HS256 | 259 | 3.27 us | 3.87 us |
| paseto v4.local | 304 | 4.51 us | 7.03 us |
| cb2.public | 4,816 | 174.3 us | 120.2 us |
| jwt EdDSA | 302 | 24.4 us | 50.2 us |
| jwt ES256 | 302 | 30.6 us | 66.5 us |
| paseto v4.public | 305 | 23.3 us | 52.0 us |

A bare cgo call measures 25 ns. The raw output with machine, versions
and command is `bindings/go/bench/results/2026-11-07-apple-m3-max.txt`;
B/op and allocs/op are in the README. CI runs the module's tests and
each benchmark once (`-benchtime 1x`) on macOS and Linux.

## 2026-11-07, the JavaScript package README and its benchmark

`bindings/js/README.md` is rewritten for someone new to cb2: what it is,
install, quick starts for Node and a browser, the token kinds and when
to use each, an API overview with the TypeScript types, errors, memory,
bundlers, the example apps, benchmarks, and development last. The Node
quick start was run as printed and gave `user-1 admin` and `refused:
audience_mismatch`; the browser quick start was served and opened in the
built-in browser and showed `verified a 4695-character token for web`
with nothing on the console. The TypeScript overview type-checks, and
the declared `Cb2` satisfies it.

`bindings/js/bench` has its own package.json, so the package's
dependencies and its 14 packed files are unchanged (the package test
that pins the list passes). One payload (iss, sub, aud, exp, iat, jti,
role) is issued and verified, with the issuer, audience and expiry
checked, by cb2, jose 6.2.15 (HS256, EdDSA, ES256), panva's paseto 4.0.1
(v4.public; its v4.local needs user-supplied XChaCha20 and BLAKE2b) and
paseto-ts 2.0.7 (v4.local and v4.public). Each operation is warmed up,
timed in batches of at least 10 ms and reported as the median of 21
batches over 5 interleaved rounds. On this Mac, macOS 26.6.2, Node
26.12.1, load average about 4 to 5, two full runs agreed within 14%:
cb2.local issued in 25.1 us and verified in 7.1 us against 15.9 and 15.0
for HS256 and 44.5 and 38.4 for v4.local; cb2.public issued in 470 us and
verified in 217 us against 54.9 and 123 for EdDSA, 40.6 and 75.8 for
ES256 and 56.1 and 122 for panva's v4.public; tokens were 430 and 4,843
bytes against 285 to 332. A first attempt under a load average near 7
gave jose timings up to 2.4 times higher from one run to the next and
was discarded. Two runs in the built-in browser (Chromium 152) differed
by up to 37% on the fastest operations and are reported as rough. CI
runs the quick profile on Node 22.12.0 and 24.

## 2026-11-07, the C library's README and a benchmark against libjwt and libpaseto

`bindings/c/README.md` is rewritten for someone new to cb2: what it is,
install, a quick start, the token kinds, an API overview, errors,
threads and lifetimes, the example, benchmarks, and the build notes
last. The quick start was extracted from the README, built against an
install in a temporary prefix with pkg-config and `-Wall -Wextra
-Wpedantic`, and run: it prints the token and its claims, and with the
audience rule changed it prints `refused: audience_mismatch` and exits 1.

`bindings/c/bench` is a new target, `cb2_c_bench`, built only with
`-DCB2_C_BENCH=ON`. It compares cb2 through libcb2_c with JWT through
libjwt 3.6.1 (Homebrew) and PASETO v4 through libpaseto, the kennt fork
of authenticvision/libpaseto (the original has only v2), whose C sources
`bench/run.sh` fetches at commit 15540dc and compiles into the bench.
All formats carry the same claims and every check validates issuer,
audience and expiry; for libpaseto, which leaves claims to the
application, the bench parses them with jansson. Median microseconds per
call of 101 rounds, on the M3 Max with load average about 5 from other
work:

| format | issue | check | bytes |
|---|--:|--:|--:|
| cb2.local seal and open | 5.61 | 4.51 | 430 |
| JWT HS256 | 5.53 | 7.13 | 285 |
| PASETO v4.local | 5.55 | 8.49 | 344 |
| cb2.public sign and verify | 169.06 | 116.06 | 4,843 |
| JWT EdDSA | 42.56 | 111.41 | 328 |
| JWT ES256 | 26.05 | 64.28 | 328 |
| PASETO v4.public | 18.49 | 51.98 | 345 |

A second run was within 15% on the shared-key rows and 10% on the
public-key rows. JWT ML-DSA-65 is not measured: the Homebrew libjwt
refuses to generate the key ("Algorithm does not match the requested key
type"). The bench also builds and runs with neither competitor, printing
them as not measured. It is not in CI, since the runners would need
libjwt and the libpaseto fetch. `cb2_c_test`, the example and
`install_check.sh` still pass on the default build, which configures
without the bench.

## 2026-11-07, Swift benchmarks against jwt-kit and swift-paseto

`bindings/swift/Benchmarks` is a separate package that times cb2 against
vapor/jwt-kit 5.7.1 and aidantwoods/swift-paseto 1.2.0 with
package-benchmark 1.37.0, on the same claims (iss, sub, aud, exp, iat,
jti and one custom claim) and with a validating verify (signature or tag,
expiry, issuer, audience). Release builds, 1000 operations per sample, 3
warmup samples, up to 200 samples or 10 s; median wall clock per
operation on an Apple M3 Max, macOS 26.6.2, Swift 6.4, with `libcb2_c`
from the CMake release build: cb2.local 8 us to issue and 12 us to
verify, JWT HS256 21 and 14, PASETO v4.local 14 and 147, cb2.public 180
and 127, JWT EdDSA 125 and 61, JWT ES256 152 and 145, JWT ML-DSA-65
(CryptoKit) 1,283 and 111, PASETO v4.public 24 and 200. Tokens were 430,
288, 333, 4,843, 331, 331, 4,663 and 334 bytes; `token-sizes` confirmed
every format verifies its own token and refuses a tampered copy. On the
XCFramework (portable liboqs) cb2.local took 7 and 11 us and cb2.public
421 and 153 us.

The first run showed the Swift layer costing about 27 of the 30 us of a
cb2.local verify: `ClaimValue` decoding through `Codable` threw and
caught three errors per string claim, and the rules went through
`JSONEncoder` on every call. Claims and rules are now written byte by
byte and read back through `JSONSerialization`, which took the cb2.local
rows from 14 and 30 us to 8 and 12 us; a new test sends every claim value
kind, the string escapes and a 2^53 + 1 integer through a seal and an
open, and the suite passes 16 of 16 on both layouts. Linking the
XCFramework next to swift-sodium's XCFramework failed with two module
maps at the same include path, so the headers now sit in
`Headers/CCb2`; the walkthrough answers 20 of 20 and the SwiftUI app
builds for macOS and runs on the iOS 27 simulator with it.
## 2026-11-07, the Python package README and a benchmark against PyJWT and pyseto

`bindings/python/README.md`, also the package's long description, is
rewritten for a first-time user: what cb2 is, install, a quick start,
the token kinds and when to use each, the API with its types, the rules,
errors, where the shared library comes from, the example, benchmarks and
the checks. The quick start was run as printed against the installed
wheel, and `twine check` passes on the wheel's metadata.

`bindings/python/bench/bench_tokens.py` times creating a token and a
validating decode (tag or signature, exp, issuer, audience) of one
claims payload (iss, sub, aud, exp, iat, jti and a role) with cb2.local
and cb2.public, PyJWT HS256, EdDSA and ES256, and pyseto v4.local and
v4.public, and records each token's size. Its dependencies are the
`bench` dependency group (pyperf, PyJWT with cryptography, pyseto), not
the package's. On this Mac, macOS 26.6.2, Python 3.12.1, the delocated
cb2 0.1.0 wheel, PyJWT 2.15.1, pyseto 1.10.0, cryptography 50.0.2 and
pyperf 2.10.0, three full pyperf runs (20 worker processes each) were
taken. The first, with other work on the machine, was discarded: its
cb2.public verify median was 175 us with a median absolute deviation of
45 us. The second and third agree within 6 percent in every cell; the
third, medians per operation, create then validating decode:

| token | create | validating decode | size |
|---|---:|---:|---:|
| cb2.local | 10.4 us | 12.7 us | 403 B |
| JWT HS256 (PyJWT) | 12.2 us | 29.8 us | 259 B |
| PASETO v4.local (pyseto) | 18.0 us | 26.9 us | 335 B |
| cb2.public | 183.8 us | 131.3 us | 4816 B |
| JWT EdDSA (PyJWT) | 41.8 us | 132.8 us | 302 B |
| JWT ES256 (PyJWT) | 32.4 us | 88.3 us | 302 B |
| PASETO v4.public (pyseto) | 42.0 us | 119.4 us | 336 B |

Through ctypes, a raw 64-byte `Local.seal` and `Local.open` took 5.0 us
and 3.5 us (timeit, median of seven), against 2.7 us and 1.3 us for the
same operations in `cb2_bench`. CI installs the `bench` group on Linux,
type-checks `bench` with the rest under mypy and runs the benchmark
once with `--debug-single-value`.

## 2026-11-07, Dart READMEs and a benchmark against JWT and PASETO

The READMEs of package cb2 and cb2_flutter are rewritten for a first
time user. The Dart quick start was run as printed against the package
fetched from git (it prints a 322-character cb2.local token, `user-1`
and `refused: replayed`), and the Flutter quick start ran as a host test
through `Isolate.run`.

`bindings/dart/benchmark` is a separate package that times issuing and
checking a token, claims validated, on the same seven claims for cb2,
dart_jsonwebtoken 3.4.1 (HS256, EdDSA, ES256) and paseto_dart 2.1.0
(v4.local, v4.public, with the issuer, audience and time checks it
lacks added after it). Compiled with `dart compile exe`, Dart 3.13.7,
macOS 26.6.2, in microseconds per token as the median of three runs of
21 samples each: cb2.local 8.8 to issue and 9.2 to check, 389 bytes;
JWT HS256 32.7 and 31.1, 244 bytes; PASETO v4.local 133 and 117, 303
bytes; cb2.public 184 and 149, 4802 bytes; JWT EdDSA 2417 and 2396, 287
bytes; JWT ES256 5484 and 8053, 287 bytes; PASETO v4.public 3378 and
2402, 304 bytes. Runs differed by up to about 20 percent in the slow
rows. cb2 runs native code through FFI and both competitors are pure
Dart, so this compares implementations as a Dart developer meets them,
not the formats; the README says so. CI compiles the benchmark and runs
it in a quick mode as a smoke test only.

## 2026-11-07, Dart package and Flutter plugin as libraries

Package `cb2` (`bindings/dart`) and the plugin `cb2_flutter` follow pub
conventions: README, CHANGELOG, LICENSE, an example, dartdoc on every
public member, and `very_good_analysis` with strict casts, inference and
raw types. The FFI bindings, one 408-line file, are split by area under
`lib/src/ffi` so that every Dart file holds one class and stays under a
hundred lines; the holder proof members of `Rules` move to
`HolderRules`. Build hooks (native assets) were weighed and not adopted
yet: a hook would have to build libsodium, BLAKE3 and liboqs for every
target or download release binaries that do not exist; the reasoning is
in `bindings/dart/README.md`.

On iOS and macOS the plugin now ships `cb2_c.framework`, a dynamic
framework exporting only the `cb2_*` functions, built by
`tool/build_xcframework.sh` from the hash-pinned libsodium 1.0.22,
BLAKE3 1.5.4 and liboqs 0.15.0 (ML-DSA-65 and ML-KEM-768, no OpenSSL)
for the iOS device, the simulator and macOS, arm64 and x86_64, with
iOS 15.0 and macOS 11.0 as minimums; it is served both through Swift
Package Manager and through CocoaPods. With Flutter 3.47.9 and Xcode 27:
`dart test` passes 14 of 14 against `libcb2_c.dylib`, the CLI example
prints every accepted step and the refusals `replayed`, `invalid` and
`audience_mismatch`, `flutter test` passes 2 of 2 in the plugin and 2 of
2 in the example, the three analyzers report nothing with fatal infos,
and the example app ran on an iPhone 18 Pro simulator (iOS 27.0) and on
macOS with all eight steps as expected; its integration test passed on
both. With Swift Package Manager turned off, through CocoaPods, the app
built for both and its integration test passed on macOS. The first CI run
failed that test because the job exports CB2_C_LIBRARY, which the
sandboxed app inherited and could not open; `cb2_flutter` now sets
`Cb2Library.preferBundled`, so an app loads the framework it ships and
the variable serves only host tests, and the whole sequence passes
locally with the variable set. The Android, Linux and Windows native
builds of the plugin were not run.

## 2026-11-07, the Swift bridge as a package with an XCFramework and examples

`bindings/swift` is now a Swift 6 package (tools 6.0, complete
concurrency checking) whose functions throw only `Cb2Error`, an enum
with one case per verdict, through typed throws. Keys are immutable
`Sendable` classes: a key id is set on a fresh copy of the C handle
before it is published, so no handle is mutated after another thread
can see it. Claims are `[String: ClaimValue]` instead of
`[String: Any]`, and `Rules` and its `@Sendable` replay checks are
`Sendable`. `scripts/build-xcframework.sh` builds libsodium 1.0.22,
BLAKE3 1.5.4 and liboqs 0.15.0 from the hash-pinned tarballs of the web
build, compiles `cb2_c.cpp` against them and produces `Cb2C.xcframework`
with macOS (arm64, x86_64), iOS (arm64) and iOS simulator (arm64,
x86_64) slices in 3 min 29 s from scratch and 15 s with the dependency
cache; `Package.swift` uses it as a binary target when it is present and
the system library otherwise.

With Swift 6.4 and Xcode 27 on macOS 26: `swift build` and `swift test`
pass 15 Swift Testing cases in 5 suites on the XCFramework, and the same
15 on the system-library layout linked against the CMake build of
`libcb2_c` (`CB2_SWIFT_SYSTEM_LIBRARY=1`); `swift format lint --strict`
reports nothing; `xcodebuild docbuild` builds the DocC archive without a
warning. The command-line example `cb2-walkthrough` answers 20 of 20
steps as expected: cb2.local issued and opened, then refused as
`replayed`, `audience_mismatch`, `expired` and twice `invalid`; a local
holder proof refused alone as `missing_proof`, accepted, then refused as
`proof_replayed` and `proof_mismatch`; cb2.public signed, verified and
refused under another key; a public holder proof accepted; a key sealed
with kcb2.seal and refused by another recipient. The SwiftUI example
built for and ran on the iOS 27 simulator (iPhone 18 Pro) and on macOS,
showing the same 20 of 20, a token accepted for the `api` audience and
refused as `audience_mismatch` for `billing`; both builds are universal
(arm64, x86_64).
## 2026-11-07, the Java and Kotlin bridges as Gradle libraries

bindings/java is now a Gradle build (Kotlin DSL, wrapper for Gradle
9.8.2 with its checksum) of two libraries, `cb2` (a Java module with the
JNI glue and the native libraries packed per platform) and `cb2-kotlin`
(Automatic-Module-Name, package com.cipherbird.cb2.kotlin), and two
examples. `./gradlew clean build --rerun-tasks --no-build-cache` passed
under JDK 21.0.1 and under JDK 24.0.2, with the classes compiled for
release 17: 23 JUnit 5 cases with the glue loaded from the jar, the same
23 with the bundled copy turned off and the glue found on
java.library.path, and 12 Kotlin cases, none skipped. The Javadoc is
built with doclint on and warnings as errors; Kotlin compiles in explicit
API mode with warnings as errors.

The JUnit cases keep every check of the two main-based programs they
replace (keys, raw tokens, claims with every rule and both replay
checks, holder proofs of both modes with every proof verdict, wrapping,
sealing, error names, the closed key) and add a token over the size
limit, a server nonce, the rules JSON for every member, JSON quoting,
null arguments, one key used from eight threads while its key id is
set, a key closed by its own replay callback while a call is in flight,
and the platform names of the loader.

The JNI glue lets no C++ exception reach the JVM: the argument copies
turn std::bad_alloc into OutOfMemoryError and every entry point returns
before the C ABI when an exception is pending; a result longer than a
Java array can hold is refused. Key handles are shared between threads
under a use count: a change of key id waits for calls in flight, close
frees the native key once the last one returns, and a Cleaner frees a
key that was never closed.

The Java example, run as a module through `./gradlew
:examples:token-service:run` and from its installed distribution, served
over HTTP on 127.0.0.1 and printed 200 for a bound request with a fresh
holder proof, then 401 proof_replayed, missing_proof, proof_mismatch,
invalid (one character of the token changed) and proof_invalid (a stolen
token with another key's proof), and 200 again with a new proof; its id
token verified with the published cb2.public key. The Kotlin example
sealed, opened and refused a cb2.local token (replayed,
audience_mismatch, expired, invalid), signed and verified a cb2.public
token and refused it under another key, checked a local-mode holder
proof and refused it three ways, and unsealed a key sealed to a
recipient. No extracted library was left in the temporary directory.
CI now runs the Gradle build and both examples on macOS and Linux.

## 2026-11-07, the JavaScript bridge as an npm package

`bindings/js` is the npm package `cb2`: an exports map with `types`
conditions for import (`types/cb2.d.ts`) and require (`types/cb2.d.cts`,
an identical copy), `cb2/core` and `cb2/core.wasm`, `files`, `engines`
(Node 22.12 and later), `sideEffects: false` and the repository fields.
The declarations cover the whole API, with the five key types made
distinct, `Cb2ErrorName` as the union of the 24 verdict names, and every
`cb2_*` function of `cb2_c.h` on the raw core. The old README offered a
`wasmBinary` option that never worked: the Emscripten glue compiles it
out. `load()` now implements it through `instantiateWasm`, rejects when
the bytes are not wasm, and copies its options so one object can serve
two cores. `dist/` was rebuilt from the C ABI as it now stands, with
`cb2_abi_version`.

`npm test` passes 19 tests on Node 26.12.1 and on Node 22.12.0 (the API,
the packed file list, the exports map, the two declaration copies, the
declared ABI against the header and the wasm exports, the runtime API
against the declared members, and CommonJS). `tsc` 7.0.2 checks typed
ES module and CommonJS consumers under `strict` and
`exactOptionalPropertyTypes`, including that a `PublicKey` is refused
where a `LocalKey` is expected; arethetypeswrong 0.18.5 reports no
problem for node16 from CJS and ESM and for bundlers. `npm pack` lists
14 files (152.5 kB); the tarball installed into a scratch project ran an
ES module and a CommonJS consumer by package name and passed `tsc`.
Node 22.12.0 prints an ExperimentalWarning when the CommonJS entry loads
the ES module; 22.13.0 does not.

A page that seals, opens and refuses a token was bundled from the packed
tarball and run in a browser: Vite 8.3.6 needed nothing, in its build
and its dev server; webpack 5.112.2 needed an `IgnorePlugin` for the
`node:` imports the core makes only under Node; esbuild 0.28.2 needed
`--external:node:*` and a copy of the wasm next to its output. The Node
example (a `node:http` server issuing a cb2.local token on login and
checking it on `/me`) passes its 5 tests and its curl session: a wrong
password 401, a login 200, the token 200, the token with one character
changed 401 `invalid`, no token 401, the token after its two-second
lifetime 401 `expired`. The browser example ran in the built-in browser
and in headless Chrome: seal, open, a changed token refused as
`invalid`, sign and verify, with nothing on the console. A new CI job
runs all of this on Node 22.12.0 and 24, and the web job builds the core
from the C ABI and runs the tests on that build.

## 2026-11-07, the Python bridge as a package

`bindings/python` is now a src-layout package built with
scikit-build-core: `bindings/python/CMakeLists.txt` includes the root
CMakeLists.txt, builds the `cb2_c` target of bindings/c and installs it
unversioned inside the `cb2` package, so the wheel
(`py3-none-<platform>`) carries the library. The loader takes
`CB2_C_LIBRARY` alone when it is set, else the bundled copy, else
`find_library`, and refuses a library whose `cb2_abi_version` is not 0.
The package is typed (`py.typed`), the unittest cases became 41 pytest
cases with every earlier assertion kept, and examples/token_service.py
is an http.server token service with a client that checks each answer.

`python -m build --wheel` built cb2-0.1.0-py3-none-macosx_26_0_arm64.whl
in 5 s; `delocate-wheel` copied libsodium, libblake3 and libcrypto into
it (liboqs is linked statically, and only the 61 `cb2_` functions are
exported). scripts/check_wheel.sh installed it under Python 3.12 into a
fresh virtual environment in a temporary directory outside the
repository: `cb2.library_path()` was the copy in site-packages, 41 tests
passed, `mypy --strict` found no issues in the tests and the example,
and the example's nine steps (cb2.local open, a tampered token refused
as `invalid`, cb2.public verify and a foreign signature refused, a bound
token refused as `missing_proof`, accepted with its holder proof,
refused as `proof_replayed` and `proof_mismatch`) all behaved as
expected. Against a libcb2_c built with `-DCB2_PQ=OFF` through
`CB2_C_LIBRARY`, 35 passed and 6 were skipped, and the example used a
kcb2.local proof key instead. `pip install -e` resolves the library from
site-packages while the sources stay in place. In the source tree `ruff
check`, `ruff format --check` and `mypy` (strict, over src, tests and
the example) are clean. CI now builds the wheel on macOS and Linux,
repairs it with delocate-wheel and auditwheel, and runs the same script.

## 2026-11-07, the Go binding as a module library

`bindings/go` is the module `github.com/Crdzbird/cb2/bindings/go`, with a
package `doc.go`, godoc on every exported identifier, runnable `Example`
functions, and two example programs: a net/http service that issues a
cb2.local access token bound to a proof key on login and accepts it only
with a holder proof for the exact request, and a CLI that makes those
proofs. Key handles are reference counted: `Close` is idempotent and lets
calls in flight finish, `SetKeyID` waits for them, and a call on a closed
key returns `ErrClosed`, which also matches `ErrArgument`. A test runs
seals, opens, wraps, key id changes and `Close` on one key from 17
goroutines under the race detector.

`go build ./...`, `go vet ./...`, staticcheck 2026.2.2 and golangci-lint
2.13.2 report nothing; `go test -race ./...` passes with Go 1.27.1,
including the 10 examples with checked output (an eleventh, for
cb2.public signing, is compiled but not run, since cb2.public is
optional in the library) and the service tests under `httptest`. The service binaries were run and driven with curl: a bound
request answered 200; the same request again, a proof for another
target, a proof for another method, a request without a proof, a token
with one character changed and, on an instance with a one-second token
lifetime, a request after the 5 second skew allowance were refused with
401 and `proof_replayed`, `proof_mismatch`, `proof_mismatch`,
`missing_proof`, `invalid` and `expired`. The first attempt at the expiry
case waited only 3 seconds and was accepted, which is the skew allowance
working as configured. Outside the repository, a copy of the module
linked and passed its tests under the race detector through the new
`cb2_pkgconfig` build tag and the `cb2_c.pc` that `cmake --install`
writes, and through `CGO_CFLAGS` and `CGO_LDFLAGS`; CI runs the tag
against a fresh install on macOS and Linux.

## 2026-11-07, the C ABI as an installable library

`bindings/c` installs as a C library: the header, `libcb2_c` shared
(SOVERSION 0) and static, a CMake package with the targets
`cb2_c::cb2_c` and `cb2_c::cb2_c_static`, and `cb2_c.pc`. Before the
change the shared library exported 1,364 symbols, 1,304 of them from the
statically linked liboqs; it now exports the 61 `cb2_` functions (the 60
of before and `cb2_abi_version`) and nothing else (an export list on
macOS, a version script on Linux). The header gained
`CB2_C_VERSION_MAJOR`, `_MINOR`, `_PATCH`, `CB2_C_ABI_VERSION` and
`cb2_abi_version`, and states the ownership,
lifetime, thread and ABI rules; every existing declaration is unchanged.
The ABI now refuses a NULL handle or output pointer with `CB2_ARGUMENT`
instead of dereferencing it, and the functions returning a pointer catch
exceptions like the rest. `cb2_c_test` gained a boundary case and passes
in the release, ASan and UBSan, and no-liboqs builds; the new example
`cb2_c_example` passes in all three, and `bindings/c/examples/install_check.sh`
built and ran it against an installed prefix through `find_package` with
the shared and the static library and through pkg-config, for the
release and the no-liboqs builds. Against this build the other bridges
pass: Swift 10 XCTest cases, Python 26 unittest cases, Node 9 tests, Go
`go test` and `go vet`, Java and Kotlin through `bindings/java/build.sh`,
Dart 14 tests. The export list parsed from the header by
`bindings/js/build.sh` equals the library's exports, and `cb2_c.cpp`
still compiles under em++ with the flags of that script.

## 2026-11-06, ASCII fast path in the claims layer

The identifier and UTF-8 checks skip a leading run of printable ASCII
in blocks of 16 bytes, and the JSON reader and writer copy runs of
plain ASCII in one step. Against the code before the change, on 10
million random strings mixing ASCII, multi-byte UTF-8, controls,
invisible and bidi characters, escapes, surrogate pairs and invalid
bytes, the text checks, the JSON reader and the JSON writer gave the
same verdict and the same output every time. Two new test cases put a
refused or escaped character at every offset of a 70-byte ASCII run;
with the fast path deliberately broken to let 0x7F through they fail,
and restored they pass. The release build passes 100 of 100 cases, the
ASan and UBSan build 100 of 100, the build without liboqs 75 of 75,
tools/check_vectors.py 638 checks, the C, Python, Go and JavaScript
bridges, the six playground demos and the web smoke test; `fuzz_claims`
ran 6,753,301 inputs in 121 s with no report.

Measured on the same machine against the previous commit: `Claims::from_json`
of a 2.7 KB payload carrying a kcb2.public key in cnf went from 19.8 to
2.9 us and its text check from 11.3 to 0.2 us; opening that bound token
before its proof from 29.1 to 11.9 us; the whole bound request from
171.5 to 154.5 us; `Token::open` of a typical 391-character token from
3.35 to 2.84 us. In `cb2_bench`, run alternately with the previous
commit's build, the bearer check went from 3.2 to 2.7 us and the local
holder request from 8.5 to 6.7 to 7.3 us.

## 2026-11-06, holder target normalisation fixed

`fuzz_holder` had found that holder target normalisation was not
idempotent: it split host and port at the last colon, so
`https://h:1:443/x` and `https://h:1/x` normalised to the same target.
docs/PROTOCOL.md 13.2 now refuses a host that holds a colon or a bracket
outside one bracketed IP literal, and the library, the vectors and
tools/check_vectors.py follow it. The release build passes 98 of 98
cases, the ASan and UBSan build 98 of 98, the build without liboqs 73 of
73, tools/check_vectors.py 638 checks with none failed or skipped, and
the C, Python, Go and JavaScript bridges their tests. `fuzz_holder`
checks idempotence on every input again: 121,381 runs in five minutes
from seeds of exactly that shape, no report.

## 2026-11-06, fuzz targets and the constant-time probe

On the tree with the local holder mode and the unrolled Keccak. The
three new fuzz targets ran 181 s each from an empty corpus with no
crash, leak or timeout: `fuzz_seal` 576,181 runs, `fuzz_sha3` 1,277,837
runs (every SHA3-256 and SHAKE256 output equal to OpenSSL's),
`fuzz_holder` 77,092 runs over both holder modes. The constant-time
probe ran in the `linux` CI job (Ubuntu 24.04, x86-64, Valgrind 3.22.0,
gcc, RelWithDebInfo): 0 errors. Its first run reported 43
secret-dependent addresses from 7 places and no secret-dependent branch;
all 7 are the base64url alphabet lookup on a secret key's PASERK text,
now the one suppression, and nothing else in Keccak, cb2.local, Ed25519
signing, verification, X-Wing or ML-KEM decapsulation was reported.

## 2026-11-06, the local holder mode

The release build passes 97 of 97 cases, the ASan and UBSan build 97 of
97, the build without liboqs 72 of 72 (the local mode included), the C
ABI test in all three, the six playground demos, the web module's smoke
test, the Python, Go, JavaScript, Java, Kotlin, Swift and Dart binding
tests, and tools/check_vectors.py with 629 checks and none skipped.

## 2026-11-06, cb2's own SHA3

After cb2 took over SHA3 from liboqs: the release build passes 87 of 87
cases (about 25,600 checks), the ASan and UBSan build 87 of 87 with no
reports, and the build without liboqs 63 of 63. The release build also
links and passes against a shared liboqs 0.16.0 built as Homebrew builds
it, which the tree before that change could not. With the round loops
unrolled, seal, unseal and recipient key import measure within noise of
the tree that used liboqs's SHA3 (about 79, 67 and 35 us), and one
SHA3-256 call costs 0.40 us against liboqs's 0.40 us.

## 2026-11-03, the first full run

The case counts below are those of that day.

All on an Apple silicon Mac on 2026-11-03, from the tree as committed.

- Release build (`cmake -S . -B build -G Ninja`, Apple
  clang 21, `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
  -Wshadow`): zero warnings. `cb2_tests`: 59 cases, 59 passed,
  about 24,600 checks (the exact count varies with the random lengths in
  the codec agreement test).
- The same with `-DCB2_SANITIZE=ON` (AddressSanitizer + UBSan, no
  recovery): 59 of 59, no reports. The sanitizer build caught one bug
  during development, an iterator pair taken from two temporaries in
  the vector generator, which is fixed; the library itself produced no
  report at any point.
- `-DCB2_PQ=OFF` (no liboqs): builds, 47 of 47 cases, cb2.public
  absent as specified.
- `cb2_example_text`: zero warnings, all eight scenarios hold their
  expectations in the release, the sanitizer and the no-liboqs builds.
- Known-answer vectors under `tests/vectors`: 11 cb2.local success
  vectors reproduced byte for byte and 15 failure vectors rejected, 99
  single-character tamper cases of a 99-character token all rejected;
  6 cb2.public success vectors verified and 14 failure vectors rejected,
  38 sampled tamper cases rejected and every byte of a 4512-character
  token swept live; 40 claims-layer vectors with the recorded verdicts
  (among them incomplete rules, replayed and missing token ids); 3 weak
  local keys and 5 corrupted secret keys refused on import;
  the PASERK vectors reproduced.
- Official PASETO v4 vectors (`tests/vectors/paseto/v4.json` in the
  repository): all 9 v4.local tokens reproduced byte for byte and all
  3 v4.public tokens reproduced and verified through cb2's own PAE,
  base64url, token splitting and footer comparison, and the 5 failure
  vectors rejected. This validates the two building blocks cb2
  shares with v4.
- libFuzzer (`/opt/homebrew/opt/llvm/bin/clang++`, `-fsanitize=fuzzer,
  address,undefined`): `fuzz_local` 146,067 runs in 131 s, `fuzz_public`
  143,169 runs in 131 s, `fuzz_claims` 10,489,676 runs in 121 s; no
  crash, leak or timeout. A one-minute confirmation campaign per target
  was run again from the saved corpora after the last header edit.
- Benchmark: the table above, two runs.


## Not verified on this Mac

Behaviour on Windows, the constant-time property under a dynamic probe
(Valgrind is not available here; the probe runs in the `linux` CI job),
and any review by a second person.
