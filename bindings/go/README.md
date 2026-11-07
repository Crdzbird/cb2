# cb2 for Go

The Go binding of cb2, through its C ABI (`bindings/c/include/cb2_c.h`)
with cgo. Module `github.com/Crdzbird/cb2/bindings/go`, package `cb2`:

    import cb2 "github.com/Crdzbird/cb2/bindings/go"

The import path ends in `go`, which is not the package name, so name the
import `cb2` as above (goimports does this for you). The API reference is
the package documentation: `go doc -all github.com/Crdzbird/cb2/bindings/go`
inside the repository, or pkg.go.dev once a version is tagged.

## Versions

The module lives in a subdirectory of the repository, so the Go tooling
expects its versions as tags with the directory as prefix:
`bindings/go/v0.1.0`, fetched with
`go get github.com/Crdzbird/cb2/bindings/go@v0.1.0`. The module stays at
major version 0 until its API is declared stable; a later v2 would move
to the path `github.com/Crdzbird/cb2/bindings/go/v2`. No such tag exists
yet: until one does, use a commit (`go get
github.com/Crdzbird/cb2/bindings/go@<commit>`) or a `replace` directive
pointing at a checkout. The binding version and the library version
(`cb2.Version()`) are independent; the binding needs a libcb2_c with the
functions of the `cb2_c.h` it was released with.

## Linking

The package is cgo and links the shared library `libcb2_c`. There are
three ways to give cgo the header and the library.

**Inside the cb2 repository** nothing needs setting. The package's cgo
directives point at `bindings/c/include` and `build/bindings/c`, so after
the top-level CMake build (the C ABI is on by default):

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    cd bindings/go
    go test -race ./...

**pkg-config.** The C library installs `cb2_c.pc` (see
`bindings/c/README.md`). Build with the tag `cb2_pkgconfig` and the
package takes its compile and link flags from `pkg-config cb2_c` and
nothing else:

    PKG_CONFIG_PATH=/opt/cb2/lib/pkgconfig \
    CGO_LDFLAGS="-Wl,-rpath,/opt/cb2/lib" \
    go build -tags cb2_pkgconfig ./...

The `.pc` file names no run-time path, hence the rpath here (see below).
pkg-config reads the files of the library's own dependencies (libsodium,
libblake3, liboqs, libcrypto) for their include paths, so they must be
on `PKG_CONFIG_PATH` too. Without the tag nothing depends on pkg-config,
and with the tag a missing `cb2_c.pc` stops the build with pkg-config's
own message.

**CGO_CFLAGS and CGO_LDFLAGS.** Against any installed copy, without
pkg-config:

    CGO_CFLAGS="-I/opt/cb2/include" \
    CGO_LDFLAGS="-L/opt/cb2/lib -Wl,-rpath,/opt/cb2/lib" \
    go build ./...

cgo puts these flags before the package's own, so the installed copy is
found first; the linker may warn that the in-repository search path does
not exist, which is harmless.

The library is shared, so it must also be found at run time. On macOS its
install name is `@rpath/libcb2_c.0.dylib`: link with an rpath that
reaches it (as above) or set `DYLD_LIBRARY_PATH`. On Linux use
`-Wl,-rpath` or `LD_LIBRARY_PATH` the same way, or install it where the
dynamic loader looks. Cross-compiling needs a libcb2_c built for the
target and `CGO_ENABLED=1` with a matching C toolchain.

## Usage

    key, err := cb2.GenerateLocalKey()
    if err != nil {
        return err
    }
    defer key.Close()

    token, err := cb2.TokenSeal(key, map[string]any{
        "iss": "https://issuer.example",
        "aud": "api",
        "sub": "user-1",
        "jti": "id-1",
        "exp": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
    }, nil)
    if err != nil {
        return err
    }

    claims, err := cb2.TokenOpen(key, token, cb2.Rules{
        Issuer:   cb2.String("https://issuer.example"),
        Audience: cb2.String("api"),
        Replay:   store.FirstUse,
    }, nil)
    switch {
    case errors.Is(err, cb2.ErrExpired):
        return errSessionExpired
    case err != nil:
        return err
    }
    fmt.Println(claims["sub"])

The `Example` functions in `example_test.go` run under `go test` with
their output checked: a claims round trip, expiry, replay, holder
proofs, errors, closed keys, key ids, raw tokens and key wrapping. The
cb2.public example is compiled only, since a library built without
liboqs has no cb2.public.

## Errors

Every verdict of the library is a `*cb2.Error` with the library's `Code`
and stable `Name` (`invalid`, `expired`, `proof_replayed`, ...). Test for
one with `errors.Is(err, cb2.ErrExpired)` and the other `Err` sentinels,
or read the code with `errors.As`. Each call returns a fresh value, so a
caller may keep it. A call on a closed or nil key returns `cb2.ErrClosed`,
which also matches `cb2.ErrArgument`. JSON encoding failures of claims or
rules are wrapped with `%w` and are not `*cb2.Error` values.

## Keys, lifetime and concurrency

Each key wraps a C handle. Keys are safe for concurrent use by many
goroutines, `Close` and `SetKeyID` included:

- `Close` is idempotent. Calls already in flight on the key finish
  first, then the handle is released; later calls return `ErrClosed`.
- `SetKeyID` and `ClearKeyID` wait for calls in flight and hold new ones
  back while they change the key, so a token is never made with half a
  key id.
- A finalizer closes a key that becomes unreachable without `Close`.
  It is a safety net, not the policy: key material stays in C memory
  until the collector runs, so close keys explicitly.
- `PublicKey`, `Unwrap` and `Unseal` return new keys with their own
  lifetime.

`ToPaserk` of a secret key returns key material in a Go string, which
cannot be wiped; keep such strings short-lived. Replay callbacks
(`Rules.Replay`, `Rules.ProofReplay`) run on the calling goroutine
during `TokenOpen` or `TokenVerify`; they must be safe for concurrent
use when the rules are shared, and a panic in one refuses the id and is
raised again after the library returns.

## Example applications

`examples/server` is a net/http service. `POST /login` checks a password
and answers with a cb2.local access token whose `cnf` claim binds a fresh
proof key, and with that proof key. `GET /me` accepts the token only with
a holder proof made with that key for this very request: method, target
and token, used once. Refusals are `401` with the library's verdict name
in the body and in `WWW-Authenticate`. The proof target is built from the
configured `-origin`, never from the request's Host header; proof ids are
kept in a bounded replay store that refuses new ids when full.

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
the handlers with `httptest`.

## Development

    go build ./...
    go vet ./...
    go test -race ./...

The tests mirror `bindings/c/test/test_c.c`, add lifetime and concurrency
cases for the key handles, and run the `Example` functions and the
example service.
