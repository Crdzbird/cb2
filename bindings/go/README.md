# cb2 for Go

cb2 is a format and a library for security tokens: the short strings a
server hands out after a login and later accepts as proof of who is
calling. It does the job of JWT and PASETO with the claim checks built
into the library, post-quantum signatures, and tokens that can be tied
to the client they were issued to. This package is the Go binding of
the C++ library, through its C interface and cgo.

The format, its rationale and its comparison with JWT and PASETO are in
the [root README](../../README.md); the specification is
[docs/SPEC.md](../../docs/SPEC.md), the wire format
[docs/PROTOCOL.md](../../docs/PROTOCOL.md) and holder proofs
[docs/SENDER_CONSTRAINT.md](../../docs/SENDER_CONSTRAINT.md).

## Install

The module is `github.com/Crdzbird/cb2/bindings/go` and its package is
`cb2`. The import path ends in `go`, so name the import:

    import cb2 "github.com/Crdzbird/cb2/bindings/go"

The module lives in a subdirectory of the repository, so its versions
are tags with the directory as prefix, such as `bindings/go/v0.1.0`,
fetched with `go get github.com/Crdzbird/cb2/bindings/go@v0.1.0`. No
version is tagged yet. Until one is, depend on a commit:

    go get github.com/Crdzbird/cb2/bindings/go@<commit>

or on a checkout with a `replace` directive in your go.mod:

    replace github.com/Crdzbird/cb2/bindings/go => /path/to/cb2/bindings/go

The module stays at major version 0 until its API is declared stable.
The binding version and the library version (`cb2.Version()`) are
independent; the binding needs a libcb2_c with the functions of the
`cb2_c.h` it was released with.

### Linking

The package is cgo and links the shared library `libcb2_c`, built from
this repository. There are three ways to give cgo its header and
library.

**Inside the cb2 repository** nothing needs setting. The package's cgo
directives point at `bindings/c/include` and `build/bindings/c`, so
after the top-level CMake build (the C library is on by default):

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    cd bindings/go
    go test ./...

A `replace` directive pointing at such a checkout works the same way.

**pkg-config.** `cmake --install build --prefix /opt/cb2` installs
`cb2_c.pc` (see [bindings/c/README.md](../c/README.md)). Build with the
tag `cb2_pkgconfig` and the package takes its flags from
`pkg-config cb2_c` and nothing else:

    PKG_CONFIG_PATH=/opt/cb2/lib/pkgconfig \
    CGO_LDFLAGS="-Wl,-rpath,/opt/cb2/lib" \
    go build -tags cb2_pkgconfig ./...

pkg-config also reads the files of the library's own dependencies
(libsodium, libblake3, liboqs, libcrypto), so they must be on
`PKG_CONFIG_PATH` too. Without the tag nothing depends on pkg-config.

**CGO_CFLAGS and CGO_LDFLAGS.** Against any installed copy, without
pkg-config:

    CGO_CFLAGS="-I/opt/cb2/include" \
    CGO_LDFLAGS="-L/opt/cb2/lib -Wl,-rpath,/opt/cb2/lib" \
    go build ./...

cgo puts these flags before the package's own, so the installed copy is
found first; the linker may warn that the in-repository search path
does not exist, which is harmless.

The library is shared, so it must also be found at run time. The `.pc`
file names no run-time path, hence the rpath in both commands above. On
macOS the install name is `@rpath/libcb2_c.0.dylib`: link with an rpath
that reaches it or set `DYLD_LIBRARY_PATH`. On Linux use `-Wl,-rpath`
or `LD_LIBRARY_PATH` the same way, or install it where the dynamic
loader looks. Cross-compiling needs a libcb2_c built for the target and
`CGO_ENABLED=1` with a matching C toolchain.

## Quick start

A complete program: make a key, issue a token, check it, and see a
damaged one refused.

```go
package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	cb2 "github.com/Crdzbird/cb2/bindings/go"
)

func main() {
	key, err := cb2.GenerateLocalKey()
	if err != nil {
		log.Fatal(err)
	}
	defer key.Close()

	token, err := cb2.TokenSeal(key, map[string]any{
		"iss":  "https://issuer.example",
		"aud":  "api",
		"sub":  "user-1",
		"jti":  "a1b2c3",
		"exp":  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"role": "admin",
	}, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token[:10], len(token), "characters")

	rules := cb2.Rules{
		Issuer:   cb2.String("https://issuer.example"),
		Audience: cb2.String("api"),
	}
	claims, err := cb2.TokenOpen(key, token, rules, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(claims["sub"], claims["role"])

	_, err = cb2.TokenOpen(key, token+"x", rules, nil)
	fmt.Println(errors.Is(err, cb2.ErrInvalid), err)
}
```

It prints:

    cb2.local. 345 characters
    user-1 admin
    true cb2: invalid

`TokenOpen` refuses to run until the rules name the issuer and audience
they accept (or set `AllowAnyIssuer` and `AllowAnyAudience` on
purpose), and it requires `exp` unless `RequireExp` is false. Times in
claims are RFC 3339 strings, not numbers.

## Token kinds and when to use each

| kind | use it for | Go |
|---|---|---|
| `cb2.local` | sessions and calls inside one system, where the issuer and the verifier share a secret key; the claims are encrypted | `GenerateLocalKey`, `TokenSeal`, `TokenOpen` |
| `cb2.public` | tokens that many parties verify but only the issuer can make; the claims are signed (Ed25519 and ML-DSA-65, both must verify) and readable | `GenerateSecretKey`, `TokenSign`, `TokenVerify` |
| `cb2.holder-local` | a per-request proof from the client, so that a stolen access token is useless alone; the proof key travels to the client with the token | `HolderProveLocal`, then `Rules.Proof` and `Rules.Request` |
| `cb2.holder-public` | the same with the client's own key pair, when the client can keep a secret key | `HolderProve`, then `Rules.Proof` and `Rules.Request` |
| compact (`cb3.local`, `cb3.public`) | experimental: the same tokens with the claims as CBOR and a 16-byte key digest as footer, about half the length of `cb2.local` | `CompactSeal`, `CompactOpen`, `CompactSign`, `CompactVerify` |
| `kcb2.local-wrap` | storing or moving a local key encrypted under another local key | `Wrap`, `Unwrap` |
| `kcb2.seal` | delivering a local key to a recipient, safe against a future quantum computer (X-Wing) | `GenerateRecipientKey`, `Seal`, `Unseal` |

`cb2.public` tokens are about 4,800 characters because of the ML-DSA-65
signature, so prefer `cb2.local` wherever the verifier can hold the
secret key. A library built without liboqs has no `cb2.public` and no
`kcb2.seal`; `HasPublic` and `HasSeal` tell, and the calls return
`ErrUnavailable`.

## Compact claims tokens (experimental)

The compact formats of [docs/PROTOCOL.md](../../docs/PROTOCOL.md)
section 15 are experimental and may change before they are released;
their header, `cb3`, is a placeholder, so the Go names say "compact".
They use the cryptography of `cb2.local` and `cb2.public` unchanged, but
carry the claims as strict canonical CBOR and bind the key id as a
16-byte digest instead of its text. A typical local token is about 260
characters against 470.

`CompactSeal`, `CompactOpen`, `CompactSign` and `CompactVerify` take the
same claims map, `Rules`, replay callbacks and implicit assertion as
the `Token` functions and give the same verdicts. A cb2 token never
opens as a compact one and a compact token never opens as a cb2 one;
both give `ErrInvalid`. Holder proofs bind a compact access token as
they bind a cb2 one, so `HolderProveLocal` and `Rules.Proof` work
unchanged.

```go
token, err := cb2.CompactSeal(key, claims, nil)
if err != nil {
	log.Fatal(err)
}
got, err := cb2.CompactOpen(key, token, rules, nil)
```

What the compact profile cannot carry is refused with `ErrArgument` when
the token is made, where `TokenSeal` would accept it: a custom number
that is not an int64 integer written in canonical form (`1.5`, `1e3`,
`-0`), a time outside the years 0000 to 9999, and a `cnf` that is not a
`kcb2.local` or `kcb2.public` key (`CompactSign` also refuses a
`kcb2.local` one). Go integers always qualify; a float64, such as a
number decoded from JSON, qualifies only when it holds a whole number
within int64 and is not negative zero.

The footer carries no key id, only its `KeyDigest`. To pick a key,
compare `PeekKeyDigest(token)` with `KeyDigestOf(id)` for the id of each
key you hold (`KeyID` on the key); `KeyDigest` is an array, so `==`
compares two. `PeekKeyDigest` reports false for a token made with a key
without id, and for any cb2 token. As with `PeekKeyID`, nothing it
returns is authenticated.

## API overview

The package documentation is the reference:
`go doc -all github.com/Crdzbird/cb2/bindings/go`, or pkg.go.dev once a
version is tagged.

| area | functions and types |
|---|---|
| claims tokens | `TokenSeal`, `TokenOpen` (cb2.local); `TokenSign`, `TokenVerify` (cb2.public); `PeekKeyID` to pick a key before checking |
| rules | `Rules` (issuer, audience, subject, clock skew, lifetime, size limit, replay callback or seen list, holder proof fields), `HolderRequest`, and the `String`, `Int64`, `Bool` helpers for its optional fields |
| compact claims tokens | `CompactSeal`, `CompactOpen`, `CompactSign`, `CompactVerify`; `PeekKeyDigest`, `KeyDigestOf`, `KeyDigest` and `KeyDigestBytes` to pick a key |
| raw tokens | `LocalSeal`, `LocalOpen`, `PublicSign`, `PublicVerify` carry any bytes with a footer and an implicit assertion, without claims checks |
| holder proofs | `HolderProveLocal`, `HolderProve`, `NormalizeTarget` |
| keys | `LocalKey`, `SecretKey`, `PublicKey`, `RecipientKey`, `RecipientPublicKey`: generate, from bytes, from and to PASERK text, `PaserkID`, `KeyID`, `SetKeyID`, `ClearKeyID`, `Close` |
| key transport | `Wrap`, `Unwrap`, `Seal`, `Unseal` |
| library | `Version`, `HasPublic`, `HasSeal` |
| errors | `Error`, `ErrorName`, `NewError`, the `Code` constants, the `Err` sentinels and `ErrClosed` |

The `implicit` argument of the token calls is context the token is bound
to but does not carry, such as a request id; pass nil when there is
none.

## Errors

Every verdict of the library is a `*cb2.Error` with the library's
`Code` and stable `Name` (`invalid`, `expired`, `proof_replayed`, ...).
Test for one with `errors.Is(err, cb2.ErrExpired)` and the other `Err`
sentinels, or read the code with `errors.As`:

```go
claims, err := cb2.TokenOpen(key, token, rules, nil)
var e *cb2.Error
switch {
case errors.Is(err, cb2.ErrExpired):
	return errSessionExpired
case errors.As(err, &e):
	return fmt.Errorf("token refused: %s", e.Name)
case err != nil:
	return err
}
fmt.Println(claims["sub"])
```

Each call returns a fresh value, so a caller may keep or change it. A
call on a closed or nil key returns `cb2.ErrClosed`, which also matches
`cb2.ErrArgument`. JSON encoding failures of claims or rules are wrapped
with `%w` and are not `*cb2.Error` values.

## Keys, lifetimes and concurrency

Each key wraps a C handle. Keys are safe for concurrent use by many
goroutines, `Close` and `SetKeyID` included:

- `Close` is idempotent. Calls already in flight on the key finish
  first, then the handle is released; later calls return `ErrClosed`.
- `SetKeyID` and `ClearKeyID` wait for calls in flight and hold new ones
  back while they change the key, so a token is never made with half a
  key id.
- A finalizer closes a key that becomes unreachable without `Close`. It
  is a safety net, not the policy: key material stays in C memory until
  the collector runs, so close keys explicitly.
- `PublicKey`, `Unwrap` and `Unseal` return new keys with their own
  lifetime.

`ToPaserk` of a secret key returns key material in a Go string, which
cannot be wiped; keep such strings short-lived. Replay callbacks
(`Rules.Replay`, `Rules.ProofReplay`) run on the calling goroutine
during `TokenOpen` or `TokenVerify`; they must be safe for concurrent
use when the rules are shared, and a panic in one refuses the id and is
raised again after the library returns.

## Example applications

The `Example` functions in `example_test.go` run under `go test` with
their output checked: a claims round trip, expiry, replay, holder
proofs, errors, closed keys, key ids, raw tokens, key wrapping and the
compact tokens with their key digest. The
cb2.public example is compiled only, since a library built without
liboqs has no cb2.public.

`examples/server` is a net/http service. `POST /login` checks a
password and answers with a cb2.local access token whose `cnf` claim
binds a fresh proof key, and with that proof key. `GET /me` accepts the
token only with a holder proof made with that key for this very
request: method, target and token, used once. Refusals are `401` with
the library's verdict name in the body and in `WWW-Authenticate`. The
proof target is built from the configured `-origin`, never from the
request's Host header; proof ids are kept in a bounded replay store
that refuses new ids when full.

`examples/cb2cli` is the client half: `prove` reads the login answer and
prints the `Authorization` and `CB2-Proof` headers for one request, in
the form `curl -H @file` reads; `keygen` prints a key for
`CB2_EXAMPLE_KEY`; `normalize` prints the target a proof commits to.

    go build -o server ./examples/server
    go build -o cb2cli ./examples/cb2cli
    ./server -addr 127.0.0.1:8080 &

    curl -s -X POST http://127.0.0.1:8080/login \
         -d '{"username":"alice","password":"wonderland"}' > login.json
    ./cb2cli prove -session login.json -method GET -url http://127.0.0.1:8080/me > headers.txt
    curl -s -H @headers.txt http://127.0.0.1:8080/me
    {"sub":"alice","jti":"...","exp":"..."}
    curl -s -H @headers.txt http://127.0.0.1:8080/me
    {"error":"proof_replayed"}

A proof for another target or method is `proof_mismatch`, a request
without one `missing_proof`, an altered token `invalid` and a token past
`exp` (plus the 5 second clock skew the service allows) `expired`.
`examples/server/service_test.go` runs every one of these cases against
the handlers with `httptest`, and `examples/smoke.sh` runs them against
the built binaries.

## Benchmarks

`bench/` is a separate module, so this module's go.mod has no JWT or
PASETO dependency. It compares this binding with
[golang-jwt](https://github.com/golang-jwt/jwt) and
[go-paseto](https://github.com/aidantwoods/go-paseto) on one claims
payload: `iss`, `sub`, `aud`, `exp`, `iat`, `jti` and a short custom
claim `role`, each in its format's own encoding (RFC 3339 times for cb2
and PASETO, NumericDate for JWT). "Issue" makes a token from claims
prepared in advance. "Check" is a validating parse: the tag or
signature, then the issuer, the audience, the expiry and that `iat` is
not in the future, then the custom claim is read back. Every format
gets the same checks; go-paseto has no built-in rule for `iat` at the
current time, so the benchmark adds one. A test in the module makes
sure each format accepts its own token and refuses a tampered one.

    cd bench
    go test -run '^$' -bench . -benchmem -benchtime 1s -count 10 | tee new.txt
    go run golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e new.txt

Measured on 2026-11-07 on an Apple M3 Max, macOS 26.6.2, Go 1.27.1;
cb2 0.1.0 (Release build, liboqs 0.16.0), golang-jwt v5.3.1, go-paseto
v1.6.0. Times are benchstat medians of 10 runs, each within plus or
minus 2 percent. The raw output is in
`bench/results/2026-11-07-apple-m3-max.txt`.

| format | token bytes | issue | issue B/op | issue allocs | check | check B/op | check allocs |
|---|---:|---:|---:|---:|---:|---:|---:|
| cb2.local | 403 | 7.09 us | 857 | 21 | 7.56 us | 1,708 | 42 |
| jwt HS256 | 259 | 3.27 us | 2,723 | 46 | 3.87 us | 2,491 | 45 |
| paseto v4.local | 304 | 4.51 us | 4,384 | 45 | 7.03 us | 4,731 | 82 |
| cb2.public | 4,816 | 174.3 us | 5,311 | 21 | 120.2 us | 1,710 | 42 |
| jwt EdDSA | 302 | 24.4 us | 2,459 | 43 | 50.2 us | 2,028 | 41 |
| jwt ES256 | 302 | 30.6 us | 8,820 | 105 | 66.5 us | 3,358 | 61 |
| paseto v4.public | 305 | 23.3 us | 2,613 | 32 | 52.0 us | 3,344 | 72 |

What the numbers mean:

- Between shared-key formats, cb2.local costs about twice what JWT
  HS256 does to issue and to check; against v4.local it is about 1.6
  times slower to issue and 8 percent slower to check. JWT HS256 only
  signs, and anyone can read its claims; cb2.local and v4.local encrypt
  them.
- cb2.public is the slowest and largest by far, and that is expected.
  It carries an ML-DSA-65 signature next to Ed25519 and checks both,
  so a forger must break a scheme designed to resist a quantum computer
  as well as a classical one; the ML-DSA-65 signature alone is 3,309
  bytes. The other public formats are classical only. Prefer cb2.local
  wherever the verifier can hold the secret key.
- The cost of cgo is part of every cb2 figure. One cgo call on its own
  is 25 ns here (`BenchmarkCgoCall`), and the binding also encodes the
  claims and rules to JSON in Go, which the C library then parses, and
  decodes the claims it returns. The Go libraries do their work in one
  language and pay none of that.
- B/op and allocs/op count Go heap only. Memory the C library uses is
  not seen by the Go benchmark, so the cb2 rows understate their total
  memory use.

The experimental compact formats have their own rows, `compact.local`
and `compact.public`. They were measured in a separate run on the same
machine, next to cb2.local and cb2.public, while other work kept the
load average between 11 and 17, so their times spread by up to 24
percent and compare only roughly. The token sizes and the Go heap
figures do not depend on load. The raw output is in
`bench/results/2026-11-07-apple-m3-max-compact.txt`.

| format | token bytes | issue | issue B/op | issue allocs | check | check B/op | check allocs |
|---|---:|---:|---:|---:|---:|---:|---:|
| cb2.local | 403 | 7.16 us | 857 | 21 | 10.4 us | 1,709 | 42 |
| compact.local | 224 | 6.52 us | 664 | 21 | 7.72 us | 1,709 | 42 |
| cb2.public | 4,816 | 185.2 us | 5,312 | 21 | 124.4 us | 1,711 | 42 |
| compact.public | 4,637 | 193.6 us | 5,312 | 21 | 121.5 us | 1,712 | 42 |

A compact local token is 56 percent of the size of a cb2.local one for
these claims and costs no more to issue or check in this run. A compact
public token saves the same 179 bytes, which matters little beside the
3,309 byte ML-DSA-65 signature.

## Development

    go build ./...
    go vet ./...
    go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
    go test -race ./...
    bash examples/smoke.sh

The tests mirror `bindings/c/test/test_c.c`, add lifetime and
concurrency cases for the key handles, and run the `Example` functions
and the example service. CI runs all of the above on macOS and Linux,
the tests again through the `cb2_pkgconfig` tag against an installed
copy, and the benchmark module once as a smoke test.
