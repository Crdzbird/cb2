# cb2 for Swift

A Swift package over the C ABI of cb2 (`bindings/c`). The package has two
targets: `CCb2`, a system library module that exposes `cb2_c.h` and links
`libcb2_c`, and `Cb2`, the Swift API on top of it. The header is included
from `bindings/c/include` through `Sources/CCb2/shim.h`, so the package
always sees the header of the library it sits next to.

Requirements: Swift 6.0 or later (the package compiles in the Swift 6
language mode), macOS 13 or iOS 16, and a build of `libcb2_c` to link.

## Pointing the package at the C library

The module map says `link "cb2_c"` and nothing more; where the library is
found is up to the build that uses the package.

### A build tree of this repository

Build the C ABI from the repository root (`CB2_BUILD_BINDINGS` is on by
default), then hand the linker the directory of `libcb2_c.dylib` and the
same directory as a run path, since the dylib's install name is
`@rpath/libcb2_c.0.dylib`:

```sh
cmake -S . -B build && cmake --build build
cd bindings/swift
swift test \
  -Xlinker -L"$(pwd)/../../build/bindings/c" \
  -Xlinker -rpath -Xlinker "$(pwd)/../../build/bindings/c"
```

The exact command this package was last verified with, from this
directory, with the build tree at `../../build`:

```sh
swift test -Xlinker -L/Users/crdzbird/CLionProjects/cb2/.claude/worktrees/vigorous-allen-b27545/build/bindings/c -Xlinker -rpath -Xlinker /Users/crdzbird/CLionProjects/cb2/.claude/worktrees/vigorous-allen-b27545/build/bindings/c
```

Replace the absolute prefix with the location of your checkout. A warning
that the dylib "was built for newer version" of macOS than the test binary
is harmless; build the C library with `-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0`
to silence it.

### An installed library

With `cmake --install build` the library lands under the install prefix
(`/usr/local` by default) and the linker finds it on its own:

```sh
swift build
```

If the prefix is elsewhere, pass `-Xlinker -L<prefix>/lib` and a matching
`-rpath`, or add `linkerSettings: [.unsafeFlags([...])]` to the `CCb2`
target in a local fork of `Package.swift` (unsafe flags make the package
unusable as a dependency, so keep them local).

### An XCFramework for iOS

For an app, build `libcb2_c` and its dependencies once per platform and
ship them as a binary target instead of the system library:

1. Build `bindings/c` as a static library for each platform slice with the
   root `CMakeLists.txt` and the matching toolchain (`-DCMAKE_SYSTEM_NAME=iOS`
   plus `-DCMAKE_OSX_SYSROOT=iphoneos` or `iphonesimulator`), with the
   dependencies the root build finds (libsodium, blake3, OpenSSL libcrypto
   and liboqs when present) also built as static libraries for that slice.
2. Merge each slice's archives into one with `libtool -static -o
   libcb2_c_all.a libcb2_c.a libsodium.a libblake3.a libcrypto.a liboqs.a`
   (use the archives your build produced).
3. `xcodebuild -create-xcframework -library <slice>/libcb2_c_all.a
   -headers bindings/c/include ... -output Cb2C.xcframework`, one
   `-library` per slice.
4. In `Package.swift` replace the `CCb2` system library target with
   `.binaryTarget(name: "CCb2", path: "Cb2C.xcframework")` and keep the
   module map's header name as the XCFramework's header.

The Swift sources do not change between the two layouts.

## Example

```swift
import Cb2

let key = try LocalKey.generate()
let token = try Token.seal(key: key, claims: [
    "iss": "https://issuer.example",
    "aud": "api",
    "sub": "user-1",
    "exp": "2099-01-01T00:00:00+00:00",
    "jti": "id-1",
    "role": "admin",
])

var rules = Rules()
rules.issuer = "https://issuer.example"
rules.audience = "api"
rules.replay = { jti in try store.markSeen(jti) }

do {
    let claims = try Token.open(token: token, key: key, rules: rules)
    print(claims["role"] as? String ?? "")
} catch let error as Cb2Error {
    print("refused:", error.name)
}
```

`Rules` mirrors the rules JSON of `cb2_c.h` member for member. The
`replay` and `proofReplay` closures are called with the token's or the
proof's `jti` and answer true to accept it; an error thrown inside a
closure refuses the id, it never crosses the C boundary. A proof presented
without `proofReplay` or `proofSeenJti` is refused as `rules_incomplete`,
as the library requires.

Every key class frees its handle when deallocated; every string or byte
result is copied into Swift and the C allocation released with `cb2_free`,
or `cb2_free_secret` for the PASERK text of a secret key. The Swift copy
of a secret is ordinary memory and is not wiped.

`version()`, `hasPublic()` and `hasSeal()` are module functions; inside
an `XCTestCase` write `Cb2.version()`, since XCTest has a `version`
member of its own.

## Tests

`Tests/Cb2Tests/Cb2Tests.swift` covers what `bindings/c/test/test_c.c`
covers: the local round trip, the verdicts (`rules_incomplete`,
`audience_mismatch`, `expired`, `replayed` through a closure and through
`seenJti`, `lifetime_exceeded`, identifiers with a zero-width space refused
as `argument`), key wrapping, public sign and verify, a bound token refused
as `missing_proof`, a holder proof accepted and then `proof_mismatch`,
`proof_replayed` and `proof_expired`, and sealing. The public and seal
cases skip on a build of the library without them.
