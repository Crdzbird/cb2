# cb2

A header-only C++20 token library: cb2.local (XChaCha20 with a keyed
BLAKE3 key split and a key-committing tag) and cb2.public (Ed25519 plus
ML-DSA-65, both required), a typed claims layer that validates before it
trusts, key types that cannot be confused, PASERK-shaped key strings and
ids, and local key wrapping. It is CipherBird's proposal for a successor
to PASETO version 4; it is not a paseto-standard version (docs/SPEC.md,
section 1). It lives in its own repository so that the format can be
versioned, reviewed and audited on its own; CipherBird consumes it for
its C ABI and language bindings.

Status: 0.1.0, built and verified as described at the end of this file. Not yet reviewed by anyone but its author.

## Install

Dependencies: libsodium 1.0.18 or later, BLAKE3 (libblake3), and, for
cb2.public, liboqs with libcrypto. On macOS they come from Homebrew
(`brew install libsodium blake3 liboqs openssl@3`); on Linux the CI job
takes libsodium and libcrypto from the distribution and builds BLAKE3 and
liboqs from pinned sources with `scripts/ci/linux_deps.sh`. All of them
are found through pkg-config.
The test suite compares the base64url decoder against libsodium's;
that reference misreads bytes above 0x7f before libsodium 1.0.21 on
platforms where `char` is signed, so the test feeds those bytes only to
1.0.21 or later. The library itself does not use libsodium's codec.

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/cb2_tests
```

Options: `CB2_PQ` (default ON; OFF builds without liboqs and without
cb2.public), `CB2_BUILD_TESTS`, `CB2_BUILD_PLAYGROUND`, `CB2_BUILD_BENCH` (needs
CipherBird's headers; `CB2_CRYPTOLIB_INCLUDE` names them, default
`../cryptolib/include`), `CB2_FUZZ` (LLVM clang), `CB2_SANITIZE`
(ASan + UBSan).

To use the library, add the `include` directory, define `CB2_HAS_PQ`
when liboqs is linked, and link libsodium, libblake3 and (for PQ) liboqs
and libcrypto; or add this repository with `add_subdirectory` or
`FetchContent` and link `cb2::cb2`.

## Thirty seconds

```cpp
#include <cb2/cb2.hpp>

auto key = cb2::LocalKey::generate().value();

cb2::Claims claims;
claims.iss = "https://issuer.example";
claims.aud = "api";
claims.sub = "user-1";
claims.exp = now + 3600;
claims.iat = now;
(void)claims.set("role", "admin");

auto token = cb2::Token::seal(key, claims, "request-context");

auto rules = cb2::ValidationRules()
    .expect_issuer("https://issuer.example")
    .expect_audience("api")
    .with_replay_check([&](std::string_view jti) { return seen.insert(jti); });
auto opened = cb2::Token::open(token.value(), key, rules, "request-context");
if (opened.is_ok()) use(opened.value().sub);
else log(cb2::error_name(opened.error()));
```

The token carries the key's id in its footer; `Token::open` rebuilds that
footer from the key and refuses any other. `exp` is required unless the
rules say `allow_missing_exp()`; an expected audience and issuer are
required unless the rules say `allow_any_audience()` and
`allow_any_issuer()`, and rules that say neither are `rules_incomplete`
before the token is read. The replay check is optional; installed, it
receives the `jti` of every token that passed every other rule and may
refuse it. A token longer than 16 KiB is refused before it is read.

For cb2.public, `SecretKey::generate()`, `Token::sign(sk, claims)` and
`Token::verify(token, sk.public_key(), rules)`.

## Examples

`examples/international_text.cpp` builds as `cb2_example_text` and
answers one question: does the text policy make a token safer than the
same token through a library without one? It seals eight tokens and
looks at each twice, once with a legacy check (authenticate, parse the
JSON, take every string as it comes) and once with `Token::open`. Same
key, same cipher, same tag; only the text handling differs. The
scenarios are a subject that renders as `admin` but carries a zero-width
space, a bidi override that makes a log line read `useradmin`, a
`\u200b` escape that a scan of the raw payload does not see, a key id
that displays as `prod` and is not, overlong UTF-8 that a lenient
decoder reads as `../`, the same issuer written raw and escaped (one
identity) against its composed and decomposed forms (two), and a
tampered token, which gets `invalid` and nothing more. In every spoof
the legacy check accepts and cb2 refuses on both the issuing side
(`argument`) and the verifying side (`claims_malformed`), and the
program asserts exactly that, exits non-zero otherwise, and runs in CI
as a test. Run it and look at how the spoofed strings render:

```
./build/cb2_example_text
```

`CB2_BUILD_EXAMPLES` (default ON) controls the target.

## Playground

`cb2_playground` is a line-oriented session with the library: generate
and import keys, seal and open, sign and verify, build claims and check
them under rules, wrap keys, peek at a footer, tamper with a token and
watch the verdict change. Run it with no arguments for a prompt, or give
it a script; `help` lists the commands and `$` stands for the last token.

```
./build/cb2_playground
cb2> keygen local alice
cb2> claims alice iss=https://issuer.example aud=api sub=user-1 exp=+3600 role=admin
cb2> check alice $ iss=https://issuer.example aud=api
cb2> check alice $ iss=https://issuer.example aud=other
cb2> tamper $
cb2> check alice $ iss=https://issuer.example aud=api
```

Custom claims are `name=value` for a string and `name:=json` for any
JSON value; `show <key>` prints a stored key's kcb2 strings and `lookup <token>`
names the stored keys whose id matches the footer's kid, unverified.
`export <key>` prints a key as its kcb2 string (`export <pair> public`
the verifying half only) and `export` alone prints every key as a
script of `import` lines, with a `kid` line for each id that is not
the default, so a session's keys can be saved and fed back in.
Inside double quotes `\uXXXX` and `\u{X...}` carry any code point and
`\xNN` a raw byte, so a script stays ASCII while it exercises
international text; `text <string>`
prints the bytes, the code points (marked when the identifier policy
refuses them) and the policy's verdict. `playground/demo.cb2`,
`playground/demo_text.cb2` (the international-text scenarios of the
example, as a session) and `playground/demo_public.cb2` are scripted
sessions whose `assert` lines make them tests; CI runs them in every
build.

### In the browser

The same session runs in the browser: `web/` holds a page that loads the
library compiled to WebAssembly (`web/dist/cb2.js` and `cb2.wasm`, built
by `web/build.sh` with Emscripten against wasm32 builds of the pinned
dependencies from `web/build_deps.sh`) and drives the interpreter of
`playground/session.hpp` through a four-function C shim. The page is a
guided builder: keys, a token form (registered claims, custom claims of
any JSON type, footer and implicit assertion, or a raw message), a token
inspector that colours the header, body and footer, reads them
without verifying and, for a public token, decodes the claims in clear
with a warning that nothing in them is trusted yet, a verifier with every rule, key lookup by the
footer's kid (with a forged kid to follow), key wrapping and
unwrapping, key import and export (one key as its kcb2 string, a
signing pair as its public half only, or every key as a script that
restores the ids too), and an international-text checker, plus scenarios that fill the forms and run them. Every button
runs a playground command, and the transcript beside the forms shows
the command and the library's answer, with any code point outside
printable ASCII written as a `\u{...}` escape, so what the page does
can be repeated in `cb2_playground` by pasting the transcript. Nothing typed
into the page leaves it. It is published at https://crdzbird.github.io/cb2/
by the Pages workflow on every push that touches `web/`; to run it
locally, serve the directory with any static server, for example
`python3 -m http.server -d web`. `node web/smoke.cjs` runs the demo scripts
through the built module; the `web` CI job rebuilds the module from
source and runs the same smoke test.

## API

Everything is in namespace `cb2` and reached through
`<cb2/cb2.hpp>`. Every function returns `Result<T>` (value or
`Error`) or, at the buffer level, `Status`.

Keys (`keys.hpp`)

- `LocalKey`: 32 uniformly random bytes. `generate()`, `from_bytes(span)`,
  `from_paserk("kcb2.local...")`, `to_paserk()` (wiped string),
  `paserk_id()` (`kcb2.lid...`), `key_id()` / `set_key_id()` /
  `clear_key_id()`, `clone()`. Move-only; no implicit copies. The
  importers refuse a key whose bytes are all equal. The key bytes are
  locked in memory for the life of the object where the platform allows
  and wiped when it dies; the same holds for `SecretKey`.
- `PublicKey` (1984 bytes) and `SecretKey` (6048 bytes), with liboqs:
  `SecretKey::generate()`, `public_key()`, `consistent()`, the same
  PASERK functions with `kcb2.public`, `kcb2.secret` and `kcb2.pid`. Importing
  a secret key checks that its public halves belong to its secret
  halves.
- `KeyWrap::wrap(wrapping, key)` / `unwrap(text, wrapping)`:
  `kcb2.local-wrap`.

Tokens

- `Local::seal(key, msg, footer, implicit)` returns the token text in one
  allocation; `Local::open(token, key, expected_footer, implicit,
  max_token_bytes)` returns the message in wiped memory in one
  allocation and refuses a token longer than `max_token_bytes` (default
  1 MiB) before reading it. `seal_into` and `open_into` write into caller
  buffers sized by `token_len` and `open_capacity` and allocate nothing.
- `Public::sign` / `verify` and `sign_into` / `verify_into` likewise,
  with the same default limit on `verify`; `verify_into` takes a buffer
  sized by `verify_capacity`, which includes the scratch for the
  pre-authentication encoding, so it allocates nothing either. The
  ML-DSA half signs under the FIPS 204 context string `cb2.public.`.

Claims (`claims.hpp`)

- `Claims`: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti` as optionals
  (times as Unix seconds, written as RFC 3339), `set(name, string)`,
  `set_json(name, json)`, `get(name)`, `get_json(name)`, `to_json()`,
  `from_json()`, `text_ok()`.
- `ValidationRules`: `expect_issuer`, `expect_audience`,
  `expect_subject`, `allow_any_issuer`, `allow_any_audience`,
  `with_replay_check(fn)`, `with_clock_skew`, `with_max_token_bytes`,
  `with_max_lifetime`, `allow_missing_exp`, `at(now)`; `complete()`,
  `expectations_ok()`, `check(claims)`. For sender-constrained tokens:
  `with_holder_proof(proof, request)`, `with_proof_replay_check(fn)`
  (required with a proof), `with_proof_lifetime`,
  `require_sender_constraint`, `ignore_sender_constraint`.
- `HolderProof` (with liboqs): `make(client_secret_key, request,
  access_token, jti, now, lifetime)` makes the `cb2.holder-public.`
  proof a client presents with a request; `check(client_public_key,
  access_token, rules)` verifies one; `claims_for` builds its claims.
  `Token::open` and `Token::verify` run the check as the last step
  whenever the token carries `cnf`. `Holder::normalize_target` is the
  RFC 9449 target normalisation both ends apply. `Claims::cnf` holds
  the client's `kcb2.public` string.
- `Token::seal` / `open` / `sign` / `verify` / `peek_key_id` /
  `footer_for`.
- `Rfc3339::parse` / `format`; `json::Reader` / `json::Writer`.
- `text::valid_utf8`, `text::identifier_ok`: strings are UTF-8 in any
  script and compared byte for byte; identifiers (iss, sub, aud, jti,
  custom claim names, key ids) may not carry controls, invisible or bidi
  characters, noncharacters or private use (docs/SPEC.md 8.4).

Errors: `invalid` (anything token-dependent before authentication, one
verdict), `too_large`, `argument`, `rules_incomplete`, `internal`,
`unavailable`, and after authentication `claims_malformed`,
`missing_exp`, `expired`, `not_yet_valid`, `issued_in_future`,
`issuer_mismatch`, `audience_mismatch`, `subject_mismatch`,
`missing_jti`, `replayed`.

## Layout

```
include/cb2/cb2.hpp        single include
include/cb2/result.hpp         Result and Error
include/cb2/keys.hpp           LocalKey, PublicKey, SecretKey, PASERK forms and ids
include/cb2/local.hpp          cb2.local
include/cb2/public.hpp         cb2.public (CB2_HAS_PQ)
include/cb2/keywrap.hpp        kcb2.local-wrap
include/cb2/text.hpp           strict UTF-8 decoder and the identifier policy
include/cb2/json.hpp           strict JSON reader and writer
include/cb2/claims.hpp         Claims, ValidationRules, HolderProof, Token, Rfc3339
include/cb2/holder.hpp         HolderRequest and the target normalisation of holder proofs
include/cb2/detail/            base64url, PAE, BLAKE3 and liboqs wrappers, the local core, secure memory
tests/                             runner, cases, gen_vectors.cpp, vectors/*.json, vectors/paseto-v1 to v4 (the official PASETO vectors, ISC)
examples/international_text.cpp    the text policy against a legacy check, eight scenarios, self-checking
playground/                        cb2_playground and the two scripted, self-checking demo sessions
web/                               the browser playground: page, C shim, Emscripten build, the built module, node smoke test
fuzz/                              fuzz_local, fuzz_public, fuzz_claims
bench/                             bench_main.cpp; reference.hpp, PASETO v1 to v4, JWS and JWE from their specifications, checked by tests/test_reference.cpp against the official vectors; bench_ref.cpp, CipherBird's v4.local and cb1.local when cryptolib is present
docs/PROTOCOL.md                   the normative format for implementers, the vector file format, worked examples
tools/check_vectors.py             an independent Python implementation that checks tests/vectors against docs/PROTOCOL.md alone
docs/SPEC.md                       wire format, rationale, threat model
docs/SECURITY.md                   claims and limits
docs/SENDER_CONSTRAINT.md          sender-constrained tokens: the design, its decisions, the symmetric mode still to come
```

## Benchmark

`cb2_bench` (`-DCB2_BUILD_BENCH=ON`), Release build, Apple clang 21,
this Mac (Apple silicon), macOS 26.6, idle machine, 2026-11-04. Each
cell is the median of seven repeats of at least 200 ms of back-to-back
calls, in time per operation, of the allocating functions of every
implementation: a payload of 64 B, 1 KiB or 64 KiB, a 44-byte footer
where the format has one, an empty implicit assertion. libsodium 1.0.22,
libblake3 1.8.7, liboqs 0.16.0 and OpenSSL 4.0.3 under every row. A
second run agreed with this one within 13 percent in the worst cell and
within 8 percent in most, with no row changing place; this is the first.

The PASETO v1 to v4, JWS and JWE rows are `bench/reference.hpp`: each
construction written from its specification on libsodium and OpenSSL,
sharing cb2's pre-authentication encoding and base64url codec, and
checked by `tests/test_reference.cpp` against the official PASETO
vectors of every version (local tokens reproduced byte for byte,
signatures verified, every failure vector refused) and against the RFC
7515 HS256 example before any number was taken. They are plain
implementations that allocate as they go, not tuned ones; the two
cryptolib rows are CipherBird's tuned v4.local and cb1.local and show
what tuning is worth on the same construction. The JWS rows do no header
parsing at all: the verifier knows its algorithm, as a safe JWT verifier
must, which favours JWT, not cb2.

| implementation | token at 64 B | seal 64 B | seal 1 KiB | seal 64 KiB | open 64 B | open 1 KiB | open 64 KiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| cb2.local | 246 | 2938 ns | 6991 ns | 225.3 us | 1437 ns | 5723 ns | 222.6 us |
| PASETO v4.local | 245 | 3507 ns | 7205 ns | 250.6 us | 2207 ns | 5947 ns | 252.7 us |
| PASETO v3.local | 266 | 8238 ns | 9664 ns | 110.3 us | 6840 ns | 8384 ns | 115.0 us |
| PASETO v2.local | 213 | 2889 ns | 7047 ns | 301.9 us | 957 ns | 4039 ns | 207.7 us |
| PASETO v1.local | 266 | 10.0 us | 12.5 us | 170.9 us | 7325 ns | 8995 ns | 116.4 us |
| JWE dir A256GCM | 167 | 2694 ns | 3285 ns | 49.2 us | 773 ns | 1455 ns | 48.2 us |
| cb2.public (Ed25519 + ML-DSA-65) | 4659 | 179.7 us | 188.5 us | 670.8 us | 118.2 us | 126.3 us | 464.1 us |
| PASETO v4.public (Ed25519) | 246 | 18.4 us | 23.2 us | 310.2 us | 50.3 us | 52.2 us | 216.0 us |
| PASETO v3.public (ECDSA P-384) | 289 | 179.7 us | 181.4 us | 275.3 us | 366.1 us | 367.0 us | 461.9 us |
| PASETO v2.public (Ed25519) | 246 | 16.9 us | 23.2 us | 333.4 us | 50.3 us | 53.2 us | 229.0 us |
| PASETO v1.public (RSA-2048 PSS) | 502 | 647.4 us | 640.9 us | 744.1 us | 21.5 us | 23.0 us | 125.9 us |
| JWS EdDSA (Ed25519) | 210 | 18.4 us | 24.3 us | 414.0 us | 51.6 us | 53.6 us | 268.2 us |
| JWS ES256 (ECDSA P-256) | 210 | 23.4 us | 23.1 us | 98.4 us | 62.1 us | 60.3 us | 136.7 us |
| JWS RS256 (RSA-2048) | 466 | 603.1 us | 606.7 us | 690.8 us | 17.5 us | 18.8 us | 94.4 us |
| JWS HS256 (HMAC-SHA256) | 167 | 1113 ns | 2194 ns | 76.6 us | 1071 ns | 2176 ns | 76.3 us |
| cryptolib v4.local | 245 | 1896 ns | 5501 ns | 259.9 us | 1861 ns | 5642 ns | 265.7 us |
| cryptolib cb1.local | 246 | 1339 ns | 5402 ns | 214.1 us | 1273 ns | 5460 ns | 226.3 us |

64 KiB throughput, seal / open, in MB/s:

| implementation | seal | open |
|---|---:|---:|
| cb2.local | 277 | 281 |
| PASETO v4.local | 249 | 247 |
| PASETO v3.local | 567 | 544 |
| PASETO v2.local | 207 | 301 |
| PASETO v1.local | 366 | 537 |
| JWE dir A256GCM | 1271 | 1297 |
| cb2.public | 93 | 135 |
| PASETO v4.public | 201 | 289 |
| PASETO v3.public | 227 | 135 |
| PASETO v2.public | 187 | 273 |
| PASETO v1.public | 84 | 496 |
| JWS EdDSA | 151 | 233 |
| JWS ES256 | 635 | 457 |
| JWS RS256 | 90 | 662 |
| JWS HS256 | 816 | 819 |
| cryptolib v4.local | 240 | 235 |
| cryptolib cb1.local | 292 | 276 |

Reading, local tokens. At the sizes tokens actually have, cb2.local
sits with the fastest of the family: opening a 64 B token costs 1.4 us,
against 2.2 us for v4.local written the same plain way, 1.9 us for the
tuned v4.local, 1.0 us for v2.local (one AEAD call, no key split, and no
key commitment) and about 7 us for v1.local and v3.local, whose
HKDF-SHA384 split and HMAC-SHA384 tag cost more than the cipher at that
size. HS256 and JWE A256GCM are cheaper still at 64 B because they do
less: no key split, and for HS256 no encryption. At 64 KiB the order
inverts: this CPU has AES in hardware and OpenSSL uses it, so the
AES-CTR of v1 and v3 and the AES-GCM of JWE move bulk data two to five
times faster than libsodium's software XChaCha20, which cb2, v2 and v4
share. That is a choice of cipher, not of construction; cb2 keeps
XChaCha20 for its nonce size and its constant-time software
implementation on every platform, and a 64 KiB token is not what the
format is for. Seal costs 1.4 us more than open at every size on the
cb2 row, which is the per-token `randombytes_buf` call the design
requires in place of a nonce batch (docs/SPEC.md section 12, question
5); cb1.local shows the same construction with the batch.

Reading, public tokens. The post-quantum half is the whole difference:
cb2.public signs in 180 us and verifies in 118 us where Ed25519 alone
signs in 18 us and verifies in 50 us, and the token is 4659 bytes
against 246. Against the rest of the field the hybrid is ordinary:
signing is ten times cheaper than RSA-2048 (v1.public and RS256, over
600 us) and equal to ECDSA P-384 (v3.public), and verifying is three
times cheaper than ECDSA P-384 and within a factor of six of RSA, which
verifies fast and signs slowly. A cb2.public verification costs about
what two ECDSA P-256 verifications cost. The size is the price that
matters: it is paid once per token in a service to service call, and
it is why the local purpose is the one for sessions.

## What is covered and what is not

Covered: cb2.local, cb2.public, the claims layer, key types
and ids, kcb2.local-wrap, international text in claims, footers and key ids
(with the self-checking example above), the hardening from the
adversarial review (rules that must declare their audience and issuer,
the raw-layer size limit, the replay check, the weak-key and secret-key
import checks, the ML-DSA context string), the vector files, the official-v4 cross-check of
PAE and base64url, tests under ASan and UBSan, the three fuzz targets, a
build without liboqs, and the benchmark above. CI runs the same matrix
on every push and pull request: the `macos` job (release with cb2.public,
ASan and UBSan, a build without liboqs, one minute of each fuzz target)
and the `linux` job (Ubuntu 24.04 with gcc, BLAKE3 and liboqs built from
pinned sources, release with cb2.public, a build without liboqs, ASan and
UBSan), plus the `web` job (the module rebuilt from source and the demos
run under node) and the `vectors` job (`tools/check_vectors.py`, the
independent Python implementation, against every vector with the ML-DSA
half included, so the reference and docs/PROTOCOL.md cannot drift apart
unnoticed).

Not covered: a C ABI and language bindings (those are CipherBird's,
which consumes this library), interoperability with any other
implementation (there is none), a constant-time probe run under Valgrind
(CipherBird has one; cb2 does not yet), review by a second person,
and the open questions in docs/SPEC.md section 12.

## Verification performed

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

Not verified here: behaviour on Linux or Windows, the constant-time
property under a dynamic probe (Valgrind is not available on this Mac),
and any review by a second person.
