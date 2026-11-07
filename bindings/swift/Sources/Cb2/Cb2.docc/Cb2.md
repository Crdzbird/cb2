# ``Cb2``

Cryptographically bound tokens for Swift: cb2.local, cb2.public, kcb2.seal and holder proofs.

## Overview

Cb2 is the Swift package over the C ABI of cb2 (`bindings/c`). A cb2.local
token is encrypted and authenticated under a shared ``LocalKey``. A
cb2.public token is signed by a ``SecretKey`` with Ed25519 and ML-DSA-65
together and verified by its ``PublicKey``. A token whose claims carry
`cnf` is bound to its holder, who presents a proof made with ``Holder``
on every request.

```swift
import Cb2

let key = try LocalKey.generate()
let token = try Token.seal(
    ["iss": "https://issuer.example", "aud": "api", "sub": "user-1",
     "exp": "2099-01-01T00:00:00+00:00", "jti": "id-1"],
    key: key)

do throws(Cb2Error) {
    let claims = try Token.open(token, key: key, rules: Rules(issuer: "https://issuer.example", audience: "api"))
    print(claims["sub"]?.stringValue ?? "")
} catch .expired {
    print("log in again")
} catch {
    print("refused:", error.name)
}
```

Every throwing function throws ``Cb2Error`` and nothing else. Keys are
immutable and `Sendable`, and every function is synchronous and
nonisolated: call it from whichever actor or task suits the app.

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:ShippingTheCLibrary>

### Keys

- ``LocalKey``
- ``SecretKey``
- ``PublicKey``
- ``RecipientKey``
- ``RecipientPublicKey``

### Claims tokens

- ``Token``
- ``Rules``
- ``Claims``
- ``ClaimValue``

### Holder proofs

- ``Holder``
- ``HolderRequest``

### Raw tokens

- ``Local``
- ``Public``

### Key transport

- ``KeyWrap``
- ``Seal``

### Verdicts and the build

- ``Cb2Error``
- ``Library``
