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
  importers refuse a key whose bytes are all equal.
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
  `allow_missing_exp`, `at(now)`; `complete()`, `check(claims)`.
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
include/cb2/claims.hpp         Claims, ValidationRules, Token, Rfc3339
include/cb2/detail/            base64url, PAE, BLAKE3 and liboqs wrappers, the local core, secure memory
tests/                             runner, cases, gen_vectors.cpp, vectors/*.json, vectors/paseto-v4/ (the official v4 vectors, ISC)
examples/international_text.cpp    the text policy against a legacy check, eight scenarios, self-checking
playground/                        cb2_playground and the two scripted, self-checking demo sessions
web/                               the browser playground: page, C shim, Emscripten build, the built module, node smoke test
fuzz/                              fuzz_local, fuzz_public, fuzz_claims
bench/                             bench_main.cpp, bench_ref.cpp (CipherBird's v4.local and cb1.local)
docs/SPEC.md                       wire format, rationale, threat model
docs/SECURITY.md                   claims and limits
```

## Benchmark

`cb2_bench`, Release build, Apple clang 21, this Mac (Apple silicon),
idle machine, 2026-11-03. Each cell is the median of seven repeats of at
least 200 ms of back-to-back calls, in time per operation; a 44-byte
footer, an empty implicit assertion, the same libsodium 1.0.22 and
libblake3 1.8.7 under every implementation. Two runs agreed within a few
percent; this is the first.

| implementation | seal 64 B | seal 1 KiB | seal 64 KiB | open 64 B | open 1 KiB | open 64 KiB |
|---|---:|---:|---:|---:|---:|---:|
| cb2.local (caller buffers) | 2631 ns | 6567 ns | 204.2 us | 1225 ns | 5168 ns | 209.0 us |
| cb2.local (allocating) | 2699 ns | 6638 ns | 209.8 us | 1303 ns | 5381 ns | 226.6 us |
| cryptolib v4.local | 1938 ns | 5641 ns | 250.1 us | 1921 ns | 5739 ns | 257.5 us |
| cryptolib cb1.local | 1271 ns | 5096 ns | 211.9 us | 1206 ns | 5176 ns | 217.4 us |

64 KiB throughput (seal / open): cb2 306 / 299 MB/s, v4.local
250 / 243 MB/s, cb1.local 295 / 287 MB/s.

Reading: open is at parity with cb1 at every size and 36 percent faster
than v4.local at 64 B; at 64 KiB cb2 is the fastest of the three on
both sides (one keyed XOF call for the key split, the PAE streamed
through a buffered sink). Seal is 1.4 us slower than cb1 at every size,
and that 1.4 us is exactly the per-token `randombytes_buf` call that the
design requires in place of cb1's per-thread nonce batch (docs/SPEC.md,
section 12, question 5). The allocating convenience functions cost a few
percent over the caller-buffer functions for one allocation. The absolute
numbers depend on how the Homebrew libblake3 was built; the comparison
does not, since all three share it.

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
UBSan).

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
