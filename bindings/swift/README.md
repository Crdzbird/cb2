# cb2 for Swift

cb2 is a format and a library for security tokens: the short strings a
server hands out after a login and later accepts as proof of who is
calling and what they may do. It does the job of JWT and PASETO with the
checks built in, post-quantum signatures, and tokens that can be bound to
the client they were issued to. This package brings it to Swift on macOS
and iOS.

The format, its rationale and the comparison with JWT and PASETO are in
the [root README](../../README.md); the precise rules are in
[docs/SPEC.md](../../docs/SPEC.md) and
[docs/PROTOCOL.md](../../docs/PROTOCOL.md), and holder proofs in
[docs/SENDER_CONSTRAINT.md](../../docs/SENDER_CONSTRAINT.md).

Requirements: Swift 6.0 or later (Xcode 16 or later), macOS 13 or iOS 16
or later, and the C library behind the package, provided as described in
[Shipping the C library](#shipping-the-c-library).

## Adding the package

The package lives in `bindings/swift` of the cb2 repository and is not
published to any registry. With SwiftPM, depend on it by path:

```swift
dependencies: [
    .package(path: "../cb2/bindings/swift")
],
targets: [
    .target(name: "App", dependencies: [.product(name: "Cb2", package: "Cb2")])
]
```

In Xcode, choose File, Add Package Dependencies, Add Local, pick the
`bindings/swift` folder and link the `Cb2` product to your target. Build
the XCFramework first (one command, below), since an app links the C
library from it.

## Quick start

```swift
import Cb2

let key = try LocalKey.generate()

let token = try Token.seal(
    [
        "iss": "https://issuer.example", "aud": "api", "sub": "user-1",
        "exp": "2099-01-01T00:00:00+00:00", "jti": "id-1", "role": "admin",
    ],
    key: key)
print(token.prefix(40), "...")

let rules = Rules(issuer: "https://issuer.example", audience: "api")
let claims = try Token.open(token, key: key, rules: rules)
print("role:", claims["role"]?.stringValue ?? "none")

var billing = rules
billing.audience = "billing"
do throws(Cb2Error) {
    _ = try Token.open(token, key: key, rules: billing)
} catch .audienceMismatch {
    print("refused: the token is for another audience")
} catch {
    print("refused:", error.name)
}
```

It prints the start of a `cb2.local.` token, `role: admin`, and the
refusal. `Examples/Cb2Walkthrough` runs the same steps and many more:

```sh
cd bindings/swift/Examples/Cb2Walkthrough
swift run cb2-walkthrough
```

## Token kinds and when to use each

| kind | use it for | key | in this package |
|---|---|---|---|
| `cb2.local` | sessions and calls inside one system; the claims are encrypted | one 32-byte key shared by issuer and verifier | `LocalKey`, `Token.seal`, `Token.open` |
| `cb2.public` | tokens many parties verify but only one issues; signed with Ed25519 and ML-DSA-65 together, both required | a signing pair; verifiers hold the public half | `SecretKey`, `PublicKey`, `Token.sign`, `Token.verify` |
| `cb3.local`, `cb3.public` (experimental) | the same tokens, about half the size for a local one: the claims as CBOR and a 16-byte digest of the key id | the same keys | `Compact.seal`, `Compact.open`, `Compact.sign`, `Compact.verify` |
| `cb2.holder-local`, `cb2.holder-public` | a proof the client makes for each request, so a stolen token is useless without the client's key | the proof key the issuer put in `cnf`, or the client's signing pair | `Holder.proveLocal`, `Holder.prove`, `Rules.proof` |
| `kcb2.local-wrap` | storing a local key under another local key | a local key | `KeyWrap` |
| `kcb2.seal` | delivering a local key to a recipient, safe against a future quantum computer | the recipient's X-Wing pair | `RecipientKey`, `RecipientPublicKey`, `Seal` |

Start with `cb2.local` when the issuer and the verifier are the same
service or share a secret. Use `cb2.public` when verifiers must not be
able to issue. Add a holder proof when a leaked token must not be
replayable from another client. `Local` and `Public` seal and sign raw
bytes when you need the envelope without the claims layer.

## Compact claims tokens

`Compact` issues and checks the experimental `cb3.local.` and
`cb3.public.` formats of
[docs/PROTOCOL.md section 15](../../docs/PROTOCOL.md). They have the
cryptography of cb2.local and cb2.public, take the same `Claims` and
`Rules`, run the same replay closures and give the same verdicts, but
carry the claims as strict canonical CBOR and bind a 16-byte digest of
the key id instead of its text. The `cb3` header is a placeholder while
the format is experimental, which is why the API says "compact".

```swift
let key = try LocalKey.generate()
let token = try Compact.seal(
    ["iss": "https://issuer.example", "aud": "api", "sub": "user-1", "exp": "2099-01-01T00:00:00+00:00"],
    key: key)
let claims = try Compact.open(token, key: key, rules: Rules(issuer: "https://issuer.example", audience: "api"))

let digest = try Compact.peekKeyDigest(token)
let matches = try digest == Compact.keyDigest(key.keyId ?? "")
```

The token above is a `cb3.local.` token of 177 bytes, against 305 for
the same claims as `cb2.local`. `peekKeyDigest(_:)` reads the digest in
the footer without trusting the token (nil when the key had no id), and
`keyDigest(_:)` computes it for a key id, so a verifier holding several
keys picks the one whose digest matches. A cb2 token
never opens through `Compact` and a compact token never opens through
`Token`; both are refused as `invalid`. Holder proofs bind a compact
access token as they bind a cb2 one.

The compact issuer refuses as `argument` what the profile cannot carry,
where `Token` accepts it: a custom number that is not an integer in
`Int64` (`1.5`, `1e3`, `-0`), a time outside years 0000 to 9999, and a
`cnf` that is not a `kcb2.local` or `kcb2.public` key. As with
`Token.sign`, a `kcb2.local` cnf in a cb3.public token is refused too.

## API overview

- **Keys.** `LocalKey`, `SecretKey`, `PublicKey`, `RecipientKey` and
  `RecipientPublicKey` are made with `generate()`, `init(bytes:)` or
  `init(paserk:)` and exported with `toPaserk()`. Each has a `paserkId`;
  local, secret and public keys also carry a `keyId` that tokens bind into
  their footer, changed with `withKeyId(_:)`, which returns a new key.
- **Claims.** `Claims` is `[String: ClaimValue]`, a JSON value written
  with literals: `"sub": "user-1"`, `"level": 3`, `"scope": ["read"]`.
  Times are RFC 3339 strings, such as `"2099-01-01T00:00:00+00:00"`.
  `stringValue`, `integerValue`, `boolValue` and the other accessors read
  them back.
- **Rules.** `Rules(issuer:audience:now:)` plus members for clock skew,
  maximum lifetime, subject, `cnf` handling, the presented holder proof
  and its request, and replay checks. `replay` and `proofReplay` are
  closures that answer true to accept an id the first time; `seenJti`
  and `proofSeenJti` are lists for tests and simple stores.
- **Tokens.** `Token.seal`, `Token.sign`, `Token.open`, `Token.verify`
  and `Token.peekKeyId`, which reads the key id of a footer without
  trusting it, to pick the key.
- **Compact tokens.** `Compact.seal`, `Compact.sign`, `Compact.open`,
  `Compact.verify`, `Compact.peekKeyDigest`, `Compact.keyDigest` and
  `Compact.keyDigestBytes`, the experimental cb3 formats.
- **Holder proofs.** `Holder.prove(client:request:accessToken:jti:)`,
  `Holder.proveLocal(proofKey:request:accessToken:jti:)` and
  `Holder.normalizeTarget(_:)`; a `HolderRequest` is the method, the
  target and an optional server nonce.
- **The build.** `Library.version`, `Library.abiVersion`,
  `Library.hasPublic` and `Library.hasSeal`.

Every public declaration has DocC documentation; see
[Documentation](#documentation).

## Errors and concurrency

Every throwing function throws `Cb2Error` and nothing else (typed
throws). It has one case per verdict of the library, from `invalid` and
`expired` to `proofReplayed`, plus `unknown(Int32)`; `name` is the
library's stable name for it and `code` the C ABI's number. Inside
`do throws(Cb2Error)` the `catch` clauses match the cases directly, as in
the quick start. A replay closure that throws refuses the id; its error
never crosses the C boundary.

The package builds in the Swift 6 language mode with complete
concurrency checking. Keys are immutable final classes that are
`Sendable`, so one key serves every task; the C handle of a key is never
changed once Swift code can reach it, which is why `withKeyId(_:)`
returns a copy. `Rules`, `ClaimValue` and `HolderRequest` are `Sendable`
values and the replay checks are `@Sendable` closures, so a replay store
must be safe to call from any thread (a type that guards its set with a
lock, for example). Every function is synchronous and nonisolated: the
caller decides where it runs. cb2.local calls take microseconds; signing
a cb2.public token takes a fraction of a millisecond, so a UI calls it
from a task off the main actor.

Every key frees its C handle when it is deallocated, and every result is
copied into Swift with the C allocation released at once; the C copies of
secret key text are wiped. The Swift string a `toPaserk()` returns is
ordinary memory and is not.

## Shipping the C library

The Swift target imports `CCb2`, the module of the C ABI header
`cb2_c.h`. `Package.swift` decides what `CCb2` is when the package loads:

- If `Cb2C.xcframework` sits next to `Package.swift`, `CCb2` is a binary
  target over it. This is the layout for macOS and iOS apps.
- Otherwise, or when `CB2_SWIFT_SYSTEM_LIBRARY` is set in the
  environment, `CCb2` is a system library that links `cb2_c` from
  wherever the linker is told to look. This is the layout for working on
  the repository.

The Swift sources are the same in both.

### The XCFramework, for apps

```sh
bindings/swift/scripts/build-xcframework.sh
```

The script downloads libsodium 1.0.22, BLAKE3 1.5.4 and liboqs 0.15.0
from the hash-pinned release tarballs `web/build_deps.sh` uses, builds
each as a static library per slice (liboqs reduced to ML-DSA-65 and
ML-KEM-768, portable C, no OpenSSL), compiles `bindings/c/src/cb2_c.cpp`
against them with cb2.public and kcb2.seal enabled, merges everything
into one `libcb2_c.a` per slice, and wraps the slices with
`xcodebuild -create-xcframework`:

| slice | architectures | minimum |
|---|---|---|
| macOS | arm64, x86_64 | macOS 13 |
| iOS | arm64 | iOS 16 |
| iOS simulator | arm64, x86_64 | iOS 16 |

The headers sit in `Headers/CCb2` with a module map that defines `CCb2`
and links the C++ runtime, so they never collide with the module map of
another static XCFramework in the same app. The first run takes about
three and a half minutes on an M3 Max; the dependency builds are cached
under `.build-xcframework`, and later runs take about 15 seconds. The
XCFramework and the cache are ignored by git.

The archive carries its own libsodium. An app that also links libsodium
through another package still builds (the benchmark package below does,
with swift-paseto's copy), but the linker then takes each libsodium
function from whichever copy it meets first; keep one version of
libsodium in an app where you can.

### The system library, for development

Build the C ABI from the repository root and point the linker at it:

```sh
cmake -S . -B build -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0
cmake --build build --target cb2_c
cd bindings/swift
CB2_SWIFT_SYSTEM_LIBRARY=1 swift test \
  -Xlinker -L"$PWD/../../build/bindings/c" \
  -Xlinker -rpath -Xlinker "$PWD/../../build/bindings/c"
```

With `cmake --install build` the library lands under the install prefix
and the linker finds it without flags. Linker flags stay on the command
line: unsafe flags in `Package.swift` would make the package unusable as
a dependency.

## Example apps

`Examples/Cb2Walkthrough` is a package that depends on this one by path.
Its library issues, opens and verifies cb2.local and cb2.public tokens,
shows the refusals a verifier gives (replay, wrong audience, expiry,
tampering, wrong key), issues and checks the compact cb3 forms, checks
holder proofs of both modes and seals a key; its `cb2-walkthrough`
executable prints the twenty-seven steps and exits non-zero if any step
is answered differently than it should be.

`Examples/Cb2App` is a SwiftUI app for macOS 14 and iOS 17 with one
multiplatform target. It shows the library build, lets you issue a
cb2.local token for a subject and audience, optionally tamper with it,
and see the verifier's answer, and lists the walkthrough's steps. It
needs the XCFramework, since the system-library layout cannot link for
iOS:

```sh
bindings/swift/scripts/build-xcframework.sh
cd bindings/swift/Examples/Cb2App
xcodebuild -scheme Cb2App -destination 'platform=macOS' build
xcodebuild -scheme Cb2App -destination 'platform=iOS Simulator,name=iPhone 16' build
```

or open `Cb2App.xcodeproj` and run it. Signing is ad hoc on macOS and
automatic for the simulator; set a team to run it on a device.

## Benchmarks

`Benchmarks` is a separate package, so this one gains no JWT or PASETO
dependency. It compares cb2 with [vapor/jwt-kit](https://github.com/vapor/jwt-kit)
and [aidantwoods/swift-paseto](https://github.com/aidantwoods/swift-paseto)
on the same claims (`iss`, `sub`, `aud`, `exp`, `iat`, `jti` and one
short custom claim). Every verify is a validating one: signature or tag,
expiry, issuer and audience. It runs on
[package-benchmark](https://github.com/ordo-one/package-benchmark) in
release builds, 1000 operations per sample after 3 warmup samples, up to
200 samples or 10 seconds per benchmark; the table gives the median
wall-clock time of one operation. `token-sizes` checks that every format
verifies its own token and refuses a tampered copy, and prints the sizes.

Measured on 2026-11-07 on an Apple M3 Max (14 cores, 36 GB), macOS
26.6.2, Swift 6.4 (Xcode 27.0), with jwt-kit 5.7.1 (swift-crypto 4.5.2),
swift-paseto 1.2.0 (swift-sodium at eeb18f6, CryptoSwift 1.10.0) and
package-benchmark 1.37.0. cb2 0.1.0 linked `libcb2_c` from the CMake
release build of this repository against Homebrew libsodium 1.0.22,
BLAKE3 1.8.7, liboqs 0.16.0 and OpenSSL 3.6.4:

| format | issue (us) | verify (us) | token bytes |
|---|---:|---:|---:|
| cb2.local | 8 | 12 | 430 |
| cb3.local (compact) | 6 | 11 | 224 |
| JWT HS256 (jwt-kit) | 21 | 14 | 288 |
| PASETO v4.local (swift-paseto) | 14 | 147 | 333 |
| cb2.public (Ed25519 + ML-DSA-65) | 180 | 127 | 4,843 |
| cb3.public (compact) | 175 | 125 | 4,637 |
| JWT EdDSA (jwt-kit) | 125 | 61 | 331 |
| JWT ES256 (jwt-kit) | 152 | 145 | 331 |
| JWT ML-DSA-65 (jwt-kit) | 1,283 | 111 | 4,663 |
| PASETO v4.public (swift-paseto) | 24 | 200 | 334 |

On the XCFramework instead (static, liboqs in portable C, the build an
app ships), cb2.local took 7 us to issue and 11 us to verify, and
cb2.public 421 us to sign and 153 us to verify.

What the numbers say, plainly:

- cb2.public carries a post-quantum ML-DSA-65 signature next to the
  Ed25519 one, and a verifier checks both. It is expected to be larger
  and slower than the classical-only formats, and it is: about 4.8 KB
  against about 330 bytes, and 180 us to sign against 24 to 152 us. The
  closest comparison is jwt-kit's ML-DSA-65 (CryptoKit, macOS 26 only),
  which carries a post-quantum signature alone: cb2.public signed faster
  here and verified slightly slower.
- cb2.local tokens are larger than the other symmetric tokens because
  the footer binds the key id (85 bytes here); a key with
  `withoutKeyId()` writes none.
- The compact cb3.local token is the smallest symmetric token here,
  224 bytes against 288 for JWT HS256, and slightly faster than
  cb2.local, since CBOR is shorter to write and read than JSON. The
  compact cb3.public saves about 200 bytes; the signatures dominate it.
- About 9 of the 12 us of a cb2.local verify are the Swift layer (the
  rules and claims as JSON, and the copies across the C boundary); the
  C++ library opens a typical token in about 3 us (docs/VERIFICATION.md).
- jwt-kit's calls go through its `JWTKeyCollection` actor, which is how
  that library is used, so its numbers include an actor hop.
- These are one machine's numbers on one day. Run them on yours:

```sh
cmake -S . -B build -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0
cmake --build build --target cb2_c
cd bindings/swift/Benchmarks
export BENCHMARK_DISABLE_JEMALLOC=true CB2_SWIFT_SYSTEM_LIBRARY=1
LIB="$PWD/../../../build/bindings/c"
swift package --disable-sandbox -Xlinker -L"$LIB" -Xlinker -rpath -Xlinker "$LIB" benchmark
swift run -c release -Xlinker -L"$LIB" -Xlinker -rpath -Xlinker "$LIB" token-sizes
```

`BENCHMARK_DISABLE_JEMALLOC` lets package-benchmark run without jemalloc
installed; the benchmarks then report time and throughput only. Leave
out `CB2_SWIFT_SYSTEM_LIBRARY` and the linker flags to measure the
XCFramework instead. swift-paseto 1.2.0 tracks a branch of swift-sodium,
so the package pins it by the commit of its 1.2.0 tag, and
`Package.resolved` is committed.

## Tests and documentation

`Tests/Cb2Tests` covers what `bindings/c/test/test_c.c` covers: the local
round trip, the verdicts (`rulesIncomplete`, `audienceMismatch`,
`expired`, `replayed` through a closure and through `seenJti`,
`lifetimeExceeded`, identifiers with a zero-width space refused as
`argument`), key wrapping, public sign and verify, a bound token refused
as `missingProof`, a public holder proof accepted and then
`proofMismatch`, `proofReplayed` and `proofExpired`, a local-mode proof
accepted and then `proofReplayed`, `proofMismatch` and `proofInvalid`,
sealing, and the compact tokens (`test_compact`): shorter than cb2 and
opening to the same claims, neither format opening as the other, the
verdicts, the peeked key digest against the computed one, a key without
an id, the fraction refusal, a compact access token with a local holder
proof, and cb3.public sign and verify. On top of that: the code and name of every verdict, every
claim value kind and the string escapes through a seal and an open, key
ids on copies, a typed `catch`, and one key used by 16 concurrent tasks.
The public and seal suites are disabled on a build of the library
without them.

```sh
cd bindings/swift
swift test
swift format lint -r --strict Package.swift Sources Tests \
  Examples/Cb2Walkthrough/Package.swift Examples/Cb2Walkthrough/Sources Examples/Cb2App/Cb2App \
  Benchmarks/Package.swift Benchmarks/Sources Benchmarks/Benchmarks
```

### Documentation

The DocC catalog is `Sources/Cb2/Cb2.docc`, with a getting-started
article and one on shipping the C library. Build it with Xcode:

```sh
cd bindings/swift
xcodebuild docbuild -scheme Cb2 -destination 'generic/platform=macOS' -derivedDataPath .build/docs
```

The archive lands at `.build/docs/Build/Products/Debug/Cb2.doccarchive`.
The package has no dependency on swift-docc-plugin, so
`swift package generate-documentation` is not available.
