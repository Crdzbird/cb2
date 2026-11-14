# cb2 for C

cb2 is a format and a library for security tokens: the short strings a
server hands out after a login and later accepts as proof of who is
calling and what they may do. It does the job of JWT and PASETO with the
claims checks built in, post-quantum signatures, and tokens that can be
tied to the client they were issued to.

`libcb2_c` is cb2 for C programs: one header, `cb2_c.h`, over a shared or
static library, found with CMake or pkg-config. It is also the layer every
other language bridge in this repository is built on. The format, its
security argument and the C++ library are described in the
[root README](../../README.md), the [specification](../../docs/SPEC.md)
and the [protocol](../../docs/PROTOCOL.md).

## Install

The library is built from source. It needs libsodium 1.0.18 or later,
BLAKE3, OpenSSL's libcrypto 3.0 or later, and liboqs for the post-quantum
parts. On macOS:

```bash
brew install cmake ninja pkg-config libsodium blake3 liboqs openssl@3
```

On Linux, take libsodium and libcrypto from the distribution and build
BLAKE3 and liboqs with `scripts/ci/linux_deps.sh`, as CI does. Then, from
the repository root:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target cb2_c cb2_c_static
cmake --install build --prefix "$HOME/.local"
```

Configure with `-DCB2_PQ=OFF` to build without liboqs; that library has
no `cb2.public`, no public holder proofs and no `kcb2.seal`, and says so
at run time through `cb2_has_public()` and `cb2_has_seal()`.

The install puts these under the prefix:

    include/cb2_c.h
    lib/libcb2_c.0.1.0.dylib, libcb2_c.0.dylib, libcb2_c.dylib   (libcb2_c.so.0.1.0, .so.0, .so on Linux)
    lib/libcb2_c.a
    lib/cmake/cb2_c/                 the CMake package
    lib/pkgconfig/cb2_c.pc

Both the CMake package and the pkg-config file find the prefix from where
they are installed, so an installed tree can be moved.

From CMake:

```cmake
find_package(cb2_c 0.1 REQUIRED)
target_link_libraries(app PRIVATE cb2_c::cb2_c)
```

`cb2_c::cb2_c` is the shared library, `cb2_c::cb2_c_static` the static
one. Pass `-DCMAKE_PREFIX_PATH=<prefix>` for a prefix CMake does not
search. `cb2_c_HAS_PUBLIC` tells whether the installed library has
`cb2.public`.

With pkg-config:

```bash
cc app.c $(pkg-config --cflags --libs cb2_c) -Wl,-rpath,$(pkg-config --variable=libdir cb2_c)
```

Set `PKG_CONFIG_PATH=<prefix>/lib/pkgconfig` for a prefix pkg-config does
not search. The dependencies are listed in `Requires.private`, so their
own `.pc` files must be found as well. On macOS the library's install
name is `@rpath/libcb2_c.0.dylib`, which is why the program needs the
rpath above; CMake adds it by itself.

## Quick start

This program issues a `cb2.local` token for a set of claims and opens it
again under the rules a verifier states. Save it as `quickstart.c`:

```c
#include <cb2_c.h>

#include <stdio.h>
#include <string.h>

int main(void) {
    const char claims[] =
        "{\"iss\":\"https://issuer.example\",\"sub\":\"user-1\",\"aud\":\"api\","
        "\"exp\":\"2099-01-01T00:00:00+00:00\",\"jti\":\"token-1\",\"scope\":\"read\"}";
    const char rules[] = "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\"}";
    cb2_local_key* key = NULL;
    char* token = NULL;
    char* opened = NULL;
    int rc = cb2_local_key_generate(&key);
    if (rc == CB2_OK) rc = cb2_token_seal(key, claims, strlen(claims), NULL, 0, &token, NULL);
    if (rc == CB2_OK)
        rc = cb2_token_open(key, token, strlen(token), rules, strlen(rules), NULL, 0, NULL, NULL, NULL, &opened,
                            NULL);
    if (rc == CB2_OK) printf("token  %.48s...\nclaims %s\n", token, opened);
    if (rc != CB2_OK) fprintf(stderr, "refused: %s\n", cb2_error_name(rc));
    cb2_free(opened);
    cb2_free(token);
    cb2_local_key_free(key);
    return rc == CB2_OK ? 0 : 1;
}
```

Build and run it against the install:

```bash
cc quickstart.c -o quickstart $(pkg-config --cflags --libs cb2_c) -Wl,-rpath,$(pkg-config --variable=libdir cb2_c)
./quickstart
```

It prints the start of the token and the claims it carried:

    token  cb2.local.8LK7WmtDQs8OUXO1lBiNI8yrBjpRSvggEpogPP...
    claims {"iss":"https://issuer.example","sub":"user-1","aud":"api","exp":"2099-01-01T00:00:00+00:00","jti":"token-1","scope":"read"}

Change `"audience":"api"` in the rules to `"billing"` and it prints
`refused: audience_mismatch` instead.

## Token kinds and when to use each

| kind | use it for | functions |
|---|---|---|
| `cb2.local` | sessions and calls between services of one system. One 32-byte key issues and opens; the claims are encrypted, so only key holders can read them. | `cb2_token_seal`, `cb2_token_open` |
| `cb2.public` | tokens many parties verify without being able to issue them. The issuer signs with the secret half of a key pair, anyone with the public half verifies. The claims are readable. The signature is Ed25519 and ML-DSA-65 together, so it stays unforgeable against a future quantum computer. | `cb2_token_sign`, `cb2_token_verify` |
| holder proofs, `cb2.holder-local` and `cb2.holder-public` | access tokens that are useless when stolen. The issuer names a proof key in the token's `cnf` claim; the client proves it holds that key for every request, and the verifier checks token and proof together. | `cb2_holder_prove_local`, `cb2_holder_prove`, then `cb2_token_open` or `cb2_token_verify` with `proof` and `request` in the rules |
| compact `cb3.local` and `cb3.public` (experimental, on the `compact-tokens` branch) | the same as `cb2.local` and `cb2.public` when the token must be short, such as a cookie or a header with a size limit. The same keys, claims JSON, rules JSON and verdicts; the claims travel as strict CBOR and the key id as a 16-byte digest, so a typical `cb3.local` token is about 45 percent shorter. A custom number that is not an int64 integer is refused with `CB2_ARGUMENT`. | `cb2_compact_seal`, `cb2_compact_open`, `cb2_compact_sign`, `cb2_compact_verify` |
| raw `cb2.local` and `cb2.public` | any bytes as the message, when the payload is not a claims set. | `cb2_local_seal`, `cb2_local_open`, `cb2_public_sign`, `cb2_public_verify` |
| `kcb2.local-wrap` | storing a local key encrypted under another local key. | `cb2_wrap`, `cb2_unwrap` |
| `kcb2.seal` | sending a local key to a recipient, post-quantum (X-Wing). | `cb2_seal`, `cb2_unseal` |

When unsure: a `cb2.local` token if the issuer and the verifier share a
system, a `cb2.public` token if they do not, and a holder proof on top
when a leaked token must not be enough to call the API.

## API overview

Every name below is declared in `cb2_c.h`, which documents each group in
full.

| group | functions |
|---|---|
| library | `cb2_version`, `cb2_abi_version`, `cb2_has_public`, `cb2_has_seal`, `cb2_error_name`, `cb2_free`, `cb2_free_secret` |
| local keys (`cb2_local_key`) | `cb2_local_key_generate`, `_from_bytes`, `_from_paserk`, `_to_paserk`, `_paserk_id`, `_key_id`, `_set_key_id`, `_clear_key_id`, `_free` |
| signing pairs (`cb2_secret_key`) and public keys (`cb2_public_key`) | `cb2_secret_key_generate`, `_from_bytes`, `_from_paserk`, `_to_paserk`, `_public_key`, `_key_id`, `_set_key_id`, `_clear_key_id`, `_free`; `cb2_public_key_from_bytes`, `_from_paserk`, `_to_paserk`, `_paserk_id`, `_key_id`, `_set_key_id`, `_clear_key_id`, `_free` |
| recipient pairs for `kcb2.seal` | `cb2_recipient_key_*` and `cb2_recipient_public_key_*`: generate, from and to bytes and PASERK text, `_public_key`, `_paserk_id`, `_free` |
| claims tokens | `cb2_token_seal`, `cb2_token_open`, `cb2_token_sign`, `cb2_token_verify`, `cb2_peek_key_id` |
| compact claims tokens | `cb2_compact_seal`, `cb2_compact_open`, `cb2_compact_sign`, `cb2_compact_verify`, `cb2_compact_peek_key_digest`, `cb2_compact_key_digest` |
| claim tables (`cb2_claim_table`) | `cb2_claim_table_from_json`, `cb2_claim_table_digest`, `cb2_claim_table_free`, `cb2_compact_seal_with_table`, `cb2_compact_open_with_table`, `cb2_compact_sign_with_table`, `cb2_compact_verify_with_table` |
| raw tokens | `cb2_local_seal`, `cb2_local_open`, `cb2_public_sign`, `cb2_public_verify` |
| holder proofs | `cb2_holder_prove_local`, `cb2_holder_prove`, `cb2_holder_normalize_target` |
| key wrapping and sealing | `cb2_wrap`, `cb2_unwrap`, `cb2_seal`, `cb2_unseal` |

Keys travel as text in the PASERK style, `kcb2.local.`, `kcb2.secret.`,
`kcb2.public.` and so on, through the `_to_paserk` and `_from_paserk`
functions, or as raw bytes through `_from_bytes`. A key's `_paserk_id`
(`kcb2.lid.` for a local key) is a public identifier for it, the key id
a token's footer carries.

A compact token carries `BLAKE3("kcb3.kid." || key id)` cut to 16 bytes
instead of the key id text. `cb2_compact_peek_key_digest` reads it from a
token without verifying anything, and `cb2_compact_key_digest` computes
it for a key id, so a verifier holding several keys can choose the one to
try.

An issuer and its verifiers can also agree on a claim table, the issuer's
name and the audiences it serves as a JSON array such as
`["https://auth.example.com","api","billing"]`. Under the table those
claims travel as one-byte indexes, which brings a typical `cb3.local`
token to about 217 characters. The table is part of what the token
authenticates without being sent, so it must be the same on both sides:
a verifier with another table, or none, gets `CB2_INVALID`. Compare
`cb2_claim_table_digest` on both sides to check that they agree, and
change the table only together with the key id.

Claims go in as a JSON object with the registered claims as strings and
times in RFC 3339 (`"exp":"2099-01-01T00:00:00+00:00"`), plus any claims
of your own. The checks a verifier wants go in as a JSON rules object:
`issuer` and `audience` are required unless the rules say
`allow_any_issuer` or `allow_any_audience`, `exp` is required unless
`require_exp` is false, and `now`, `clock_skew`, `max_lifetime`,
`subject`, `replay`, `proof` and `request` add the rest. The comment
above `cb2_token_seal` in the header lists every member.

Replay checks are callbacks: `cb2_token_open`, `cb2_token_verify` and
their compact counterparts take one for the token's `jti` and one for a holder proof's id. Each returns 1
when the id is new (and remembers it) and 0 when it was seen before.

## Errors

Every fallible function returns `CB2_OK` (0) or a positive `cb2_code`.
`cb2_error_name` gives the code's stable name: `invalid`, `expired`,
`audience_mismatch`, `proof_replayed` and so on, the names the protocol
document and every other bridge use. A token that fails authentication
is `invalid` whatever the cause, so a refusal never tells an attacker
which check failed. No C++ exception crosses into C: anything unexpected
comes back as `CB2_INTERNAL`, or as NULL from a function that returns a
pointer. A NULL handle or output pointer is `CB2_ARGUMENT`.

## Threads and lifetimes

- Inputs are borrowed for the call only. The library keeps no pointer to
  an argument after it returns. Text inputs carry explicit lengths and
  need no NUL; an input pointer may be NULL when its length is 0.
- A handle belongs to the caller from the moment a constructor writes it
  until the caller passes it to the matching free function, once. Handles
  are independent: a public key taken from a signing pair stays valid
  after the pair is freed.
- Every returned `char*` or `uint8_t*` is a fresh malloc'd block for the
  caller, released with `cb2_free`. The texts that carry key material
  (the `to_paserk` results of local keys, signing pairs and recipient
  pairs) are released with `cb2_free_secret`, which wipes them first.
- Outputs are written only on success. A failed call leaves the output
  pointer as it was.
- Text results are NUL-terminated; a reported length excludes the NUL. An
  opened raw message is followed by one 0 byte the length does not count.
- Every free function accepts NULL. The strings from `cb2_version` and
  `cb2_error_name` are static and never freed.
- The library has no mutable global state of its own beyond libsodium's
  one-time initialisation, and every function is reentrant. A handle may
  be shared between threads by every function that takes it as `const`;
  `set_key_id`, `clear_key_id` and the free functions change the handle
  and need exclusive access. Replay callbacks run on the calling thread,
  during the call.

## The example

`examples/cb2_c_example.c` is a small command-line tour. It issues and
opens a `cb2.local` token, signs and verifies a `cb2.public` token, shows
three refusals (a wrong audience, a token that expired, a changed byte),
and binds an access token to a proof key, proves possession for one
request, and replays the proof:

    $ cb2_c_example
    cb2_c 0.1.0 (ABI 0), cb2.public yes
    local   issued  cb2.local.wPiEjM-QLgYN6shGntScBTs3C3UcJD... (346 bytes)
    local   opened  {"iss":"https://issuer.example","sub":"user-1","aud":"api",...}
    public  signed  cb2.public.eyJpc3MiOiJodHRwczovL2lzc3Vlc... (4759 bytes)
    public  opened  {"iss":"https://issuer.example","sub":"user-1","aud":"api",...}
    refuse  wrong audience   audience_mismatch
    refuse  in the year 2100 expired
    refuse  one byte changed invalid
    holder  proof   cb2.holder-local.-dYiHz4knZJICKweaBYXGy-... (362 bytes)
    holder  token without a proof  missing_proof
    holder  token with the proof   ok
    holder  the same proof again   proof_replayed
    every step behaved as expected

`cb2_c_example local`, `public`, `refuse` or `holder` runs one step. Build
it against an install with CMake:

```bash
cmake -S bindings/c/examples -B build-example -DCMAKE_PREFIX_PATH=<prefix>
cmake --build build-example
./build-example/cb2_c_example
```

(`-DCB2_C_EXAMPLE_STATIC=ON` links the static library), or with
pkg-config and the Makefile next to it:

```bash
PKG_CONFIG_PATH=<prefix>/lib/pkgconfig make -C bindings/c/examples
./bindings/c/examples/cb2_c_example
```

It is also built in-tree as `build/bindings/c/cb2_c_example`.

## Benchmarks

`bench/` compares cb2, through this library, with JWT through
[libjwt](https://libjwt.io) and PASETO v4 through
[libpaseto](https://github.com/kennt/libpaseto), each through its own C
API. Every format carries the same claims (`iss`, `sub`, `aud`, `exp`,
`iat`, `jti` and a short `scope`), and every check is a validating
decode: the tag or signature, then the issuer, the audience and the
expiry.

- **issue** is one call that turns the claims into a token: cb2 and
  libpaseto take the claims as JSON text, libjwt builds them from the
  claims set on its builder.
- **check** is one call that validates a token: `cb2_token_open` or
  `cb2_token_verify` with an issuer and audience rule, libjwt's checker
  with the expected issuer and audience, and for libpaseto, which only
  decrypts or verifies, the decrypt or verify followed by parsing the
  claims with jansson and comparing issuer, audience and expiry, which is
  what an application using it has to do.

Each figure is the median of 101 timed rounds after 0.3 seconds of
warm-up, a round being as many calls as fill about 2 ms, in a release
build. The token size is in bytes.

Measured on 2026-11-07 on an Apple M3 Max (14 cores, 36 GB) under
macOS 26.6.2, Apple clang 21.0.0, with libsodium 1.0.22, BLAKE3 1.8.7,
liboqs 0.16.0, libcrypto 4.0.3, libjwt 3.6.1, jansson 2.15.1 and
libpaseto at commit 15540dc. Other work was running on the machine (load
average about 5); a second run differed by up to 15% on the shared-key
rows and by under 10% on the public-key rows.

Shared key:

| format | issue | check | issue (us) | check (us) | token (bytes) |
|---|---|---|--:|--:|--:|
| cb2.local | seal | open | 5.61 | 4.51 | 430 |
| JWT HS256 | generate | verify | 5.53 | 7.13 | 285 |
| PASETO v4.local | encrypt | decrypt | 5.55 | 8.49 | 344 |

Public key:

| format | issue | check | issue (us) | check (us) | token (bytes) |
|---|---|---|--:|--:|--:|
| cb2.public (Ed25519 and ML-DSA-65) | sign | verify | 169.06 | 116.06 | 4,843 |
| JWT EdDSA (Ed25519) | generate | verify | 42.56 | 111.41 | 328 |
| JWT ES256 | generate | verify | 26.05 | 64.28 | 328 |
| JWT ML-DSA-65 | not measured, see below | | | | |
| PASETO v4.public (Ed25519) | sign | verify | 18.49 | 51.98 | 345 |

With a shared key the three issue at the same speed within the noise, and
cb2 checks fastest, its rules included. With a key pair cb2 is the
slowest to sign and about as fast to verify as libjwt's Ed25519, and its
token is the largest by far.

Read these with three things in mind.

- **cb2.public is slower and much larger by design.** It carries an
  ML-DSA-65 signature next to the Ed25519 one, and both must verify, so
  that a token stays unforgeable if either scheme falls, including to a
  future quantum computer. ML-DSA-65 signatures are 3,309 bytes, which is
  most of the 4.8 KB token. The classical formats here are faster and
  about 14 times smaller, and none of them survives a quantum attack on
  its signature.
- **The formats do different work.** `cb2.local` and PASETO `v4.local`
  encrypt the claims; JWT HS256 only authenticates them, and anyone who
  sees the token can read them. A `cb2.local` token is larger than a
  `v4.local` one by the footer that names its key, 86 bytes here; the
  encrypted part is the same size.
- **These are these libraries, not the formats in general.** libjwt's
  check parses the token with jansson and runs the signature through
  OpenSSL's generic interface on every call. A tighter JWS
  implementation verifies Ed25519 in about 47 us on this machine; the
  [root README](../../README.md#benchmark-in-detail) compares the formats
  on equal footing.

`JWT ML-DSA-65` is listed but not measured: libjwt 3.6.1 from Homebrew,
where post-quantum JWS is marked experimental, refuses to generate the
key. No figure is given rather than a guess.

Run it again with:

```bash
bindings/c/bench/run.sh
```

which fetches libpaseto at a pinned commit into `build-c-bench/_deps`,
builds the benchmark in release mode with `-DCB2_C_BENCH=ON`, prints the
machine and the library versions, and prints the tables. libjwt and
jansson come from pkg-config (`brew install libjwt` on macOS). A
competitor that is missing is reported as not measured. The benchmark is
a separate target, off by default; JWT and PASETO are never dependencies
of `libcb2_c`.

## Build and development notes

The library is part of the root build (`-DCB2_BUILD_BINDINGS=ON`, the
default):

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target cb2_c cb2_c_static cb2_c_test cb2_c_example
./build/bindings/c/cb2_c_test
./build/bindings/c/cb2_c_example
```

The shared library lands in `build/bindings/c` as `libcb2_c.dylib` or
`libcb2_c.so`, where the other bridges look for it, and the static one
next to it as `libcb2_c.a`.

    include/cb2_c.h        the whole surface, with the ownership rules
    src/cb2_c.cpp          the C ABI over the header-only C++ library
    test/test_c.c          every call and every verdict, from C
    examples/              the example CLI, its CMake and pkg-config builds, install_check.sh
    bench/                 the benchmark against libjwt and libpaseto, and run.sh
    cmake/                 the export list, the version script, the package and pkg-config templates

`examples/install_check.sh build` installs a configured build into a
temporary prefix, builds and runs the example against it with the shared
library, the static library and pkg-config, and checks that the installed
shared library exports nothing but `cb2_` functions. CI runs it on macOS
and Linux, along with `cb2_c_test` and the example in release,
AddressSanitizer and no-liboqs builds.

**Static linking.** The static library is C++ inside, so a C program
linking it also needs the C++ runtime and cb2's dependencies.
`cb2_c::cb2_c_static` carries both, and so does
`pkg-config --static --libs cb2_c`. The CMake package records the
dependency libraries by the paths they had when cb2 was built, which
suits a library installed on the machine that built it; a package
manager that moves the dependencies should rebuild cb2_c. On Windows,
define `CB2_C_STATIC` when compiling against the static library (the
CMake target does it).

**ABI stability and versioning.** The header carries
`CB2_C_VERSION_MAJOR`, `CB2_C_VERSION_MINOR`, `CB2_C_VERSION_PATCH` and
`CB2_C_ABI_VERSION`; the build refuses to configure when they disagree
with the project version, and the library refuses to compile when they
disagree with `cb2::VERSION`. `CB2_C_ABI_VERSION` is the shared library's
SOVERSION. Within one ABI version the surface only grows: functions and
error codes are added, never removed or changed, and no ownership rule
changes. A program can compare `cb2_abi_version()` with the
`CB2_C_ABI_VERSION` it was compiled against to catch a mismatched library
at run time, as the example does.

**Exported symbols.** The shared library exports the `cb2_` functions
and nothing else: the sources build with hidden visibility, and the link
uses an export list on macOS (`cmake/cb2_c.exports`) and a version script
on Linux (`cmake/cb2_c.map`), so the statically linked parts of liboqs
stay private. Each of these prints nothing, the first on macOS, the
second on Linux:

```bash
nm -gU build/bindings/c/libcb2_c.dylib | grep -v ' _cb2_'
```

```bash
nm -D --defined-only build/bindings/c/libcb2_c.so | grep -v ' cb2_'
```
