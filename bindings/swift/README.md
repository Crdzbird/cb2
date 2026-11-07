# cb2 for Swift

A Swift package over the C ABI of cb2 (`bindings/c`): cb2.local and
cb2.public claims tokens, raw tokens, holder proofs of both modes, key
wrapping and `kcb2.seal`, for macOS 13 and iOS 16 or later.

- Swift 6 language mode with complete concurrency checking. Keys are
  immutable `Sendable` classes, `Rules` and the claim values are `Sendable`
  values, and every function is synchronous and nonisolated.
- Every throwing function throws `Cb2Error` and nothing else (typed
  throws), one case per verdict of the library, so a `catch .expired`
  reads directly.
- DocC documentation for every public declaration, swift-format clean,
  and Swift Testing tests that mirror `bindings/c/test/test_c.c`.

Requirements: Swift 6.0 or later (Xcode 16 or later) and the C library,
provided in one of the two ways below.

## Adding the package

```swift
dependencies: [
    .package(path: "../cb2/bindings/swift")
],
targets: [
    .target(name: "App", dependencies: [.product(name: "Cb2", package: "Cb2")])
]
```

In Xcode, add the `bindings/swift` folder as a local package and link the
`Cb2` product. The package is not published to any registry.

## Shipping the C library

The Swift target imports `CCb2`, the module of `cb2_c.h`. `Package.swift`
decides what `CCb2` is when the package loads:

- `Cb2C.xcframework` next to `Package.swift`: `CCb2` is a binary target
  over it. This is the layout for macOS and iOS apps.
- No XCFramework, or `CB2_SWIFT_SYSTEM_LIBRARY` set in the environment:
  `CCb2` is a system library that links `cb2_c` from wherever the linker
  is told to look. This is the layout for working on the repository.

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

The headers carry `cb2_c.h` and a module map that defines `CCb2` and
links the C++ runtime. The first run takes about three and a half minutes
on an M3 Max; the dependency builds are cached under
`.build-xcframework`, so later runs only recompile `cb2_c.cpp`. The
XCFramework and the cache are ignored by git. Because the archive bundles
its dependencies, an app that links its own libsodium or liboqs gets
duplicate symbols; use one copy, or the system-library layout.

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

## Example

```swift
import Cb2

let key = try LocalKey.generate()
let token = try Token.seal(
    ["iss": "https://issuer.example", "aud": "api", "sub": "user-1",
     "exp": "2099-01-01T00:00:00+00:00", "jti": "id-1", "role": "admin"],
    key: key)

var rules = Rules(issuer: "https://issuer.example", audience: "api")
rules.replay = { jti in store.accept(jti) }

do throws(Cb2Error) {
    let claims = try Token.open(token, key: key, rules: rules)
    print(claims["role"]?.stringValue ?? "")
} catch .expired {
    print("log in again")
} catch {
    print("refused:", error.name)
}
```

`Rules` mirrors the rules JSON of `cb2_c.h` member for member. The
`replay` and `proofReplay` checks are `@Sendable` closures called
synchronously with the token's or the proof's `jti`; they answer true to
accept it, and an error thrown inside refuses the id without crossing the
C boundary. A proof presented without `proofReplay` or `proofSeenJti` is
refused as `rulesIncomplete`, as the library requires.

Claims are `[String: ClaimValue]`, a JSON value with literal syntax:
`"sub": "user-1"`, `"level": 3`, `"scope": ["read", "write"]`. A key id is
changed with `withKeyId(_:)`, which returns a new key; the C handle of a
published key is never mutated, which is what makes keys `Sendable`.
Every key frees its handle when deallocated; every result is copied into
Swift and the C allocation released with `cb2_free`, or `cb2_free_secret`
for the PASERK text of a secret key. The Swift copy of a secret is
ordinary memory and is not wiped.

## Documentation

The DocC catalog is `Sources/Cb2/Cb2.docc`, with a getting-started
article and one on shipping the C library. Build it with Xcode:

```sh
cd bindings/swift
xcodebuild docbuild -scheme Cb2 -destination 'generic/platform=macOS' -derivedDataPath .build/docs
```

The archive lands at `.build/docs/Build/Products/Debug/Cb2.doccarchive`.
The package has no dependency on swift-docc-plugin, so
`swift package generate-documentation` is not available.

## Examples

`Examples/Cb2Walkthrough` is a package that depends on this one by path.
Its library `Cb2Walkthrough` issues, opens and verifies cb2.local and
cb2.public tokens, shows the refusals a verifier gives (replay, wrong
audience, expiry, tampering, wrong key), checks holder proofs of both
modes and seals a key; its executable prints the result:

```sh
cd bindings/swift/Examples/Cb2Walkthrough
swift run cb2-walkthrough
```

`Examples/Cb2App` is a SwiftUI app for macOS 14 and iOS 17 with one
multiplatform target. It shows the library build, lets you issue a
cb2.local token for a subject and audience, optionally tamper with it, and
see the verifier's answer, and lists the walkthrough's steps. It needs
the XCFramework, since the system-library layout cannot link for iOS:

```sh
bindings/swift/scripts/build-xcframework.sh
cd bindings/swift/Examples/Cb2App
xcodebuild -scheme Cb2App -destination 'platform=macOS' build
xcodebuild -scheme Cb2App -destination 'platform=iOS Simulator,name=iPhone 16' build
```

or open `Cb2App.xcodeproj` and run it. Signing is ad hoc on macOS and
automatic for the simulator; set a team to run it on a device.

## Tests

`Tests/Cb2Tests` covers what `bindings/c/test/test_c.c` covers: the local
round trip, the verdicts (`rulesIncomplete`, `audienceMismatch`,
`expired`, `replayed` through a closure and through `seenJti`,
`lifetimeExceeded`, identifiers with a zero-width space refused as
`argument`), key wrapping, public sign and verify, a bound token refused
as `missingProof`, a public holder proof accepted and then
`proofMismatch`, `proofReplayed` and `proofExpired`, a local-mode proof
accepted and then `proofReplayed`, `proofMismatch` and `proofInvalid`,
and sealing. On top of that: the code and name of every verdict, claim
values through JSON, key ids on copies, a typed `catch`, and one key used
by 16 concurrent tasks. The public and seal suites are disabled on a
build of the library without them.

```sh
cd bindings/swift
swift test
swift format lint -r --strict Package.swift Sources Tests \
  Examples/Cb2Walkthrough/Package.swift Examples/Cb2Walkthrough/Sources Examples/Cb2App/Cb2App
```
