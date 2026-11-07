# Getting started

Issue a token, check it under rules, and bind it to its holder.

## Add the package

The package lives in `bindings/swift` of the cb2 repository. Depend on it
by path or by the repository URL, and link the `Cb2` product:

```swift
dependencies: [
    .package(path: "../cb2/bindings/swift")
],
targets: [
    .target(name: "App", dependencies: [.product(name: "Cb2", package: "Cb2")])
]
```

The package also needs the C library itself; <doc:ShippingTheCLibrary>
explains the two ways to provide it.

## Issue and open a cb2.local token

```swift
let key = try LocalKey.generate()
let token = try Token.seal(
    ["iss": "https://issuer.example", "aud": "api", "sub": "user-1",
     "exp": "2099-01-01T00:00:00+00:00", "jti": "id-1"],
    key: key)

var rules = Rules(issuer: "https://issuer.example", audience: "api")
rules.replay = { jti in store.accept(jti) }
let claims = try Token.open(token, key: key, rules: rules)
```

``Rules`` mirrors the rules JSON of the C ABI member for member. Times in
claims are RFC 3339 strings. The ``Rules/replay`` check answers true to
accept an id; an error thrown inside it refuses the id and never crosses
the C boundary.

## Sign and verify a cb2.public token

```swift
guard Library.hasPublic else { return }
let issuer = try SecretKey.generate()
let token = try Token.sign(claims, key: issuer)
let verified = try Token.verify(token, key: try issuer.publicKey(), rules: rules)
```

## Handle a refusal

Every verdict is a case of ``Cb2Error``. Inside `do throws(Cb2Error)` the
`catch` clauses match the cases directly:

```swift
do throws(Cb2Error) {
    _ = try Token.open(token, key: key, rules: rules)
} catch .expired {
    refresh()
} catch .replayed, .proofReplayed {
    reject()
} catch {
    log(error.name)
}
```

## Bind a token to its holder

The issuer puts the client's key in `cnf`. The client proves possession on
every request, and the verifier presents the proof with the request:

```swift
let proof = try Holder.prove(
    client: clientPair, request: HolderRequest(htm: "GET", htu: "https://api.example/v1/me"),
    accessToken: token, jti: UUID().uuidString)

var rules = Rules(issuer: "https://issuer.example", audience: "api")
rules.proof = proof
rules.request = HolderRequest(htm: "GET", htu: "https://api.example/v1/me")
rules.proofReplay = { jti in proofStore.accept(jti) }
_ = try Token.open(token, key: key, rules: rules)
```

``Holder/proveLocal(proofKey:request:accessToken:jti:now:lifetime:)`` is
the same with a `kcb2.local` proof key and works in every build.

## Concurrency

Keys are immutable final classes that conform to `Sendable`; share one key
between tasks. ``LocalKey/withKeyId(_:)`` returns a new key rather than
changing the receiver. ``Rules`` is a `Sendable` value and its replay
checks are `@Sendable` closures, so a store they call must be safe to call
from any thread, for example a type that guards its state with a lock.
Every function is synchronous; signing with ML-DSA-65 takes about a
millisecond, so a UI calls it from a task off the main actor.
