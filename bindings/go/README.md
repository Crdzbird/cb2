# cb2 for Go

A cgo bridge to cb2 through its C ABI (`bindings/c/include/cb2_c.h`).
Module `github.com/Crdzbird/cb2/bindings/go`, package `cb2`.

## Building

The package's cgo directives point at the in-repository build: the header
in `bindings/c/include` and the shared library in `build/bindings/c`
(built by the top-level CMake project with the C binding enabled). With
that build in place:

    cd bindings/go
    go test ./... -v
    go vet ./...

Against an installed library, add the install paths through the
environment; cgo puts these flags before the package's own, so the
installed header and library are found first:

    CGO_CFLAGS="-I/usr/local/include" \
    CGO_LDFLAGS="-L/usr/local/lib -lcb2_c -Wl,-rpath,/usr/local/lib" \
    go build ./...

On macOS the library's install name is `@rpath/libcb2_c.0.dylib`, so an
rpath that reaches it (or `DYLD_LIBRARY_PATH`) is needed at run time; on
Linux use `-Wl,-rpath` or `LD_LIBRARY_PATH` the same way.

## Example

    package main

    import (
        "errors"
        "fmt"
        "time"

        cb2 "github.com/Crdzbird/cb2/bindings/go"
    )

    func main() {
        key, err := cb2.GenerateLocalKey()
        if err != nil {
            panic(err)
        }
        defer key.Close()

        exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
        token, err := cb2.TokenSeal(key, map[string]any{
            "iss": "https://issuer.example",
            "aud": "api",
            "sub": "user-1",
            "jti": "id-1",
            "exp": exp,
        }, nil)
        if err != nil {
            panic(err)
        }

        seen := map[string]bool{}
        claims, err := cb2.TokenOpen(key, token, cb2.Rules{
            Issuer:   cb2.String("https://issuer.example"),
            Audience: cb2.String("api"),
            Replay: func(jti string) bool {
                if seen[jti] {
                    return false
                }
                seen[jti] = true
                return true
            },
        }, nil)
        if errors.Is(err, cb2.ErrReplayed) {
            fmt.Println("token already used")
            return
        }
        if err != nil {
            panic(err)
        }
        fmt.Println(claims["sub"])
    }

Every verdict comes back as a `*cb2.Error` with the library's `Code` and
`Name`; compare with `errors.Is` against the `cb2.Err*` sentinels or read
the code through `errors.As`. Keys hold C handles: call `Close` when done,
or let the finalizer release them.
