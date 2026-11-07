# cb2 (BRACE)

cb2 is a format and a C++ library for security tokens: the short strings
a server hands out after a login and later accepts as proof of who is
calling and what they may do. It does the job JWT and PASETO do, with
more of the checks built in, post-quantum signatures, and tokens that
can be tied to the client they were issued to.

The name stands for **Cryptographically Bound tokens, version 2**: every
token is bound to its key, to the context it was issued for, to the
rules its verifier must declare and, when it carries a `cnf` claim, to
the client that holds the key it names. The format is also called
**BRACE**, for **B**ound, **R**ule-checked, **A**uthenticated,
**C**ommitting **E**nvelope. BRACE is a name only: on the wire every
token and key string keeps its cb2 header, because the format allows
exactly one spelling of each.

Status: version 0.1.0. It is CipherBird's proposal for a successor to
PASETO version 4, not an official PASETO version (docs/SPEC.md,
section 1). It is tested as described under "Testing and verification"
below, and it has not yet been reviewed by anyone but its author.

Try it in the browser, with nothing to install:
https://crdzbird.github.io/cb2/

## What a cb2 token is

A token is one line of text: a header such as `cb2.local.` that says
what kind of token it is, then the body, then, after one more dot, an
optional footer that names the key. The verifier reads the header,
checks the body with its key and only then looks at what the token says.

| kind | what it is for | key | size of a typical token |
|---|---|---|---|
| `cb2.local` | sessions and service to service calls inside one system; the claims are encrypted, so nobody without the key can read them | one 32-byte secret key shared by issuer and verifier | about 250 to 400 characters |
| `cb2.public` | tokens many parties must verify without being able to issue them; the claims are signed and readable | a key pair: the issuer signs with the secret half, anyone with the public half verifies | about 4,700 characters |
| `cb2.holder-local` and `cb2.holder-public` | a proof made by the client for each request, so a stolen token is useless without the client's key | the proof key the issuer put inside the token, or the client's own key pair | about 360 characters (local) or 4,800 (public) |
| `kcb2.seal` | delivering a local key to a recipient, safe against a future quantum computer | the recipient's X-Wing key pair | about 1,600 characters |

A few words that come up below:

- **Claims** are the statements in a token: who issued it (`iss`), who
  it is about (`sub`), who it is for (`aud`), when it expires (`exp`),
  its id (`jti`) and anything the application adds.
- **Rules** are what the verifier expects: the issuer and audience it
  accepts, how much clock skew it allows, whether it checks for replays.
  cb2 refuses to open a token until the rules name the issuer and
  audience they accept, or say on purpose that any will do.
- The **implicit assertion** is context the token is bound to but does
  not carry, for example a request id; a token presented in another
  context fails to verify.
- **Key strings** (`kcb2.local...`, `kcb2.public...`) are the text form
  of keys and key ids, shaped like PASETO's PASERK.

## cb2, JWT and PASETO

JWT (JSON Web Token, RFC 7519) is the standard most systems use today.
PASETO version 4 is a newer format that removed JWT's algorithm choice.
cb2 starts from PASETO v4 and changes what its rationale (docs/SPEC.md
section 9) lists, each change closing a named attack.

### At a glance

| | JWT (JWS and JWE) | PASETO v4 | cb2 |
|---|---|---|---|
| who picks the algorithm | the token, in its `alg` header; a safe verifier must pin it | the version in the header | the header; one spelling per kind |
| tokens with a shared secret | HS256 signs but anyone can read the claims; JWE encrypts | `v4.local`: encrypted, authenticated, key-committing | `cb2.local`: the same, with a single-call key split and the key id bound in |
| tokens with a key pair | RSA, ECDSA or EdDSA | Ed25519 | Ed25519 and ML-DSA-65 together; both must verify |
| safe against a future quantum computer | no | no | yes, for signatures and for sealing keys |
| claims checks | up to the library and the application | up to the library and the application | in the library: issuer and audience rules required, `exp` required by default, a replay check hook, strict JSON, an identifier policy for international text |
| key ids | `kid` in the header; matching it to a key is the application's job | in the footer by convention | bound into the footer by the library and compared in constant time |
| tying a token to its client | DPoP (RFC 9449), a separate specification | not defined | built in, in two modes |
| standard and ecosystem | IETF standards, OAuth and OpenID Connect, libraries in every language, support in gateways and identity providers | a published specification with libraries in many languages | one implementation, in C++, used from other languages through its C interface; no other implementation exists |

### Speed and size

Measured with `cb2_bench` on one core of an Apple silicon Mac (M3 Max).
The PASETO and JWT rows are reference implementations written from
their specifications on the same libraries, checked against the official
test vectors; the JWT rows skip header parsing, which flatters JWT. The
full tables and how they were taken are under "Benchmark in detail".

Shared-key tokens, a 64-byte payload:

| | open (verify) | create | token size | opens per second per core |
|---|---:|---:|---:|---:|
| cb2.local | 1.3 us | 2.7 us | 246 | about 750,000 |
| PASETO v4.local | 2.4 us | 3.8 us | 245 | about 420,000 |
| JWE dir A256GCM | 0.8 us | 2.7 us | 167 | about 1,300,000 |
| JWS HS256 (readable, not encrypted) | 1.1 us | 1.2 us | 167 | about 870,000 |

Through the claims layer, opening a typical cb2.local token and checking
every rule takes about 2.8 us, about 350,000 tokens per second per core.

Key-pair tokens, a 64-byte payload:

| | verify | sign | token size | verifications per second per core |
|---|---:|---:|---:|---:|
| cb2.public (Ed25519 + ML-DSA-65) | 113 us | 167 us | 4,659 | about 8,900 |
| PASETO v4.public (Ed25519) | 50 us | 17 us | 246 | about 20,000 |
| JWS EdDSA (Ed25519) | 47 us | 17 us | 210 | about 21,000 |
| JWS ES256 (ECDSA P-256) | 58 us | 22 us | 210 | about 17,000 |
| JWS RS256 (RSA-2048) | 17 us | 593 us | 466 | about 58,000 |

One request with a token tied to its client (the client makes a proof
for `GET https://api.example/v1/me`, the server checks token and proof):

| | bytes on the wire | client: make proof | server: check | checks per second per core |
|---|---:|---:|---:|---:|
| cb2.local bearer token, no proof | 321 | - | 2.7 us | about 370,000 |
| cb2.local + local proof | 762 | 5.8 us | 7.3 us | about 137,000 |
| JWT RS256 + DPoP ES256 | 1,061 | 25.9 us | 79 us | about 12,600 |
| JWT ES256 + DPoP ES256 | 805 | 23.1 us | 120 us | about 8,400 |
| cb2.local + public proof | 8,647 | 215 us | 167 us | about 6,000 |
| cb2.public + public proof | 13,060 | 244 us | 313 us | about 3,200 |

### Where cb2 is ahead

- **Post-quantum.** `cb2.public` signatures need both Ed25519 and
  ML-DSA-65 to verify, so a token stays unforgeable if either scheme is
  broken, including by a quantum computer. `kcb2.seal` delivers keys
  over X-Wing (ML-KEM-768 with X25519). Neither JWT nor PASETO v4 has a
  post-quantum option in common use.
- **Nothing to choose wrongly.** There is no algorithm field to attack,
  key types cannot be swapped (a public key cannot be used as a shared
  secret), and the library binds the key id itself. The JWT bugs where
  `alg: none` or an RS256 key used as an HS256 secret is accepted cannot
  happen.
- **The common mistakes are refused by default.** The verifier must
  name the issuer and audience it accepts, `exp` is required unless the
  rules say otherwise, tokens longer than 16 KiB are refused before they
  are read, the JSON reader is strict, and identifiers that hide
  invisible or right-to-left characters are refused on both ends.
- **Faster shared-key tokens than PASETO.** `cb2.local` opens a small
  token in 1.3 us against 2.4 us for `v4.local` written the same way,
  and at 64 KiB it is twice as fast.
- **Stolen tokens can be made worthless, cheaply.** In the local holder
  mode a request carries a 762-byte token and proof, smaller than JWT
  with DPoP, and the server checks both in 7.3 us, 11 to 16 times
  faster than the DPoP rows.
- **Encrypted by default.** A `cb2.local` token hides its claims; a JWT
  signed with HS256 shows them to anyone who sees the token.

### Where cb2 is behind

- **No ecosystem.** JWT is what OAuth, OpenID Connect, API gateways and
  identity providers speak; none of them accept cb2. PASETO has
  libraries in many languages. cb2 has one implementation, used from
  other languages through its C interface, and there is no second
  implementation to check it against.
- **Not reviewed yet.** Version 0.1.0 has been tested, fuzzed and
  checked against an independent Python implementation of the
  specification, but nobody other than its author has reviewed it.
  JWT and PASETO libraries have years of use and review behind them.
- **Post-quantum tokens are big and slower.** A `cb2.public` token is
  about 4,700 characters against 210 to 250 for an Ed25519 JWT or
  PASETO, and verifying it takes 113 us against about 50 us. A
  `cb2.public` token tied to a client key is 8,290 characters, more
  than the 8 KB nginx allows for one header line by default.
- **Some JWT forms are faster on small tokens.** JWE with AES-GCM and
  HS256 open a 64-byte token in 0.8 and 1.1 us against 1.3 us for
  `cb2.local`, because they do less (no key split, and HS256 does not
  encrypt). RSA verifies in 17 us, much faster than any other signature
  here, though it signs 35 times slower than Ed25519.
- **More dependencies.** cb2 needs libsodium, BLAKE3, OpenSSL's
  libcrypto and, for the post-quantum parts, liboqs.
- **The local holder mode trusts every verifier.** Its proof key is
  shared by the issuer, the client and every verifier that can open the
  token, so it protects against a token that leaks without its key, not
  against a verifier that turns on its clients. The public holder mode
  covers that case at the size and cost shown above.

### Which one to use

- Use **JWT** when you need to interoperate: OAuth and OpenID Connect,
  third-party identity providers, gateways, or clients you do not
  control.
- Use **PASETO v4** when you control both ends, want a mature library in
  your language, and do not need post-quantum security yet.
- Use **cb2** when you control both ends and want post-quantum
  signatures now, claims checks you cannot forget, or cheap
  sender-constrained tokens between your own services, and you can
  accept a young, single implementation.

## Install

cb2 is header-only C++20. It needs:

- libsodium 1.0.18 or later, BLAKE3 (libblake3) and OpenSSL's libcrypto
  3.0 or later, always;
- liboqs, for `cb2.public`, the public holder mode and `kcb2.seal`.
  Without it the library builds with `cb2.local`, the claims layer, key
  wrapping and the local holder mode only.

On macOS:

```bash
brew install cmake ninja libsodium blake3 liboqs openssl@3
```

On Linux, take libsodium and libcrypto from the distribution and build
BLAKE3 and liboqs from pinned sources with `scripts/ci/linux_deps.sh`,
as the CI job does. Everything is found through pkg-config.

Build and run the tests:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/cb2_tests
```

To use the library in a project, add this repository with
`add_subdirectory` or `FetchContent` and link `cb2::cb2`. Without CMake,
add the `include` directory, define `CB2_HAS_PQ` when liboqs is linked,
and link libsodium, libblake3, libcrypto and, for the post-quantum
parts, liboqs.

Build options, all CMake booleans:

| option | default | what it does |
|---|---|---|
| `CB2_PQ` | ON | the post-quantum parts, with liboqs; OFF builds without them |
| `CB2_OPENSSL_CHACHA` | ON | messages of 512 bytes or more go through OpenSSL's vectorised ChaCha20 after libsodium's HChaCha20, the same keystream; OFF keeps every byte on libsodium |
| `CB2_BUILD_TESTS` | ON | the test runner and the vector generator |
| `CB2_BUILD_EXAMPLES` | ON | the runnable examples under `examples/` |
| `CB2_BUILD_PLAYGROUND` | ON | the interactive playground |
| `CB2_BUILD_BINDINGS` | ON | the C interface the language bridges use |
| `CB2_BUILD_BENCH` | ON | the benchmark; `CB2_CRYPTOLIB_INCLUDE` (default `../cryptolib/include`) adds CipherBird's own rows when present |
| `CB2_FUZZ` | OFF | the libFuzzer targets (LLVM clang only) |
| `CB2_SANITIZE` | OFF | AddressSanitizer and UBSan on tests and benchmark |
| `CB2_CT_PROBE` | OFF | the constant-time probe, to run under Valgrind |

The test suite compares cb2's base64url decoder with libsodium's. That
reference misreads bytes above 0x7f before libsodium 1.0.21 on platforms
where `char` is signed, so the test feeds those bytes only to 1.0.21 or
later; the library itself does not use libsodium's codec.

## Quick start

Issue a token and check it:

```cpp
#include <cb2/cb2.hpp>

#include <ctime>
#include <set>
#include <string>

const int64_t now = std::time(nullptr);
std::set<std::string> seen;

auto key = cb2::LocalKey::generate().value();

cb2::Claims claims;
claims.iss = "https://issuer.example";
claims.aud = "api";
claims.sub = "user-1";
claims.iat = now;
claims.exp = now + 3600;
claims.jti = "token-1";
(void)claims.set("role", "admin");

auto token = cb2::Token::seal(key, claims).value();

auto rules = cb2::ValidationRules()
    .expect_issuer("https://issuer.example")
    .expect_audience("api")
    .with_replay_check([&](std::string_view jti) { return seen.insert(std::string(jti)).second; });

auto opened = cb2::Token::open(token, key, rules);
if (opened.is_ok()) std::printf("hello, %s\n", opened.value().sub->c_str());
else std::printf("refused: %s\n", cb2::error_name(opened.error()));
```

This prints `hello, user-1`; opening the same token a second time
prints `refused: replayed`, because the replay check has seen its `jti`.

The token carries the key's id in its footer, and `Token::open` rebuilds
that footer from the key and refuses any other. `exp` is required unless
the rules say `allow_missing_exp()`. An expected audience and issuer are
required unless the rules say `allow_any_audience()` and
`allow_any_issuer()`; rules that say neither are refused as
`rules_incomplete` before the token is read. The replay check is
optional; when installed, it receives the `jti` of every token that
passed every other rule and may refuse it. A token longer than 16 KiB is
refused before it is read.

Tie a token to its client, so that a stolen copy is useless:

```cpp
auto proof_key = cb2::HolderProof::bind_local(claims).value();
auto bound = cb2::Token::seal(key, claims).value();
```

The issuer sends `bound` and `proof_key` to the client. For each request
the client makes a proof, a few hundred bytes:

```cpp
cb2::HolderRequest request{"GET", "https://api.example/v1/me", std::nullopt};
auto proof = cb2::HolderProof::make_local(proof_key, request, bound, "proof-1", now).value();
```

and the server checks the token and the proof together:

```cpp
std::set<std::string> seen_proofs;
auto server_rules = cb2::ValidationRules()
    .expect_issuer("https://issuer.example")
    .expect_audience("api")
    .with_holder_proof(proof, request)
    .with_proof_replay_check([&](std::string_view jti) { return seen_proofs.insert(std::string(jti)).second; });
auto checked = cb2::Token::open(bound, key, server_rules);
```

Without a proof the bound token is refused as `missing_proof`; a proof
for another method or address is `proof_mismatch`, and the same proof
twice is `proof_replayed`.

For signed tokens, `SecretKey::generate()`, `Token::sign(secret_key,
claims)` and `Token::verify(token, secret_key.public_key(), rules)`.

## Try it

### In the browser

https://crdzbird.github.io/cb2/ runs the library compiled to
WebAssembly, and nothing typed into the page leaves it. The page walks
through the library in numbered cards:

1. keys: generate local keys and signing pairs;
2. issue a token: registered claims, custom claims of any JSON type, a
   footer and an implicit assertion, or a raw message;
3. the token: its header, body and footer in colour, read without
   verifying, and for a public token the claims in clear with a warning
   that nothing in them is trusted yet;
4. verify, with every rule;
5. key lookup by the footer's kid, with a forged kid to follow;
6. key wrapping and unwrapping;
7. import and export of keys as kcb2 strings, or of every key as a
   script that restores the ids too;
8. an international-text checker;
9. heavy load: up to a million requests in a row, with every answer
   checked and the time per request charted, to show that the speed
   holds steady.

A row of scenarios fills the forms and runs them. Every button runs a
playground command, and the transcript beside the forms shows the
command and the library's answer, so anything the page does can be
repeated in `cb2_playground` by pasting the transcript.

The page is `web/`: the module (`web/dist/cb2.js` and `cb2.wasm`) is
built by `web/build.sh` with Emscripten against wasm32 builds of the
pinned dependencies from `web/build_deps.sh`, and drives the
interpreter of `playground/session.hpp` through a small C shim. The
Pages workflow publishes it on every push that touches `web/`. To run it
locally, serve the directory with any static server, for example
`python3 -m http.server -d web`. `node web/smoke.cjs` runs the demo
scripts and a short load run through the built module, and the `web` CI
job rebuilds the module from source and runs the same smoke test.

### The playground

`cb2_playground` is a line-oriented session with the library: generate
and import keys, seal and open, sign and verify, build claims and check
them under rules, wrap keys, peek at a footer, tamper with a token and
watch the verdict change. Run it with no arguments for a prompt, or give
it a script; `help` lists the commands and `$` stands for the last token.
`--fast-random` before the script selects libsodium's userspace random
generator for the nonces (the opt-in described under API reference below); `time`
reports which source is in use.

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
example, as a session), `playground/demo_holder_local.cb2` (a cb2.local
token bound to a proof key, and its holder proofs), and
`playground/demo_public.cb2`, `demo_holder.cb2` and `demo_seal.cb2`
(with liboqs) are scripted sessions whose `assert` lines make them
tests; CTest and the web smoke test run them.

### The international text example

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

## API reference

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
- `RecipientKey` and `RecipientPublicKey` (with liboqs ML-KEM-768): an
  X-Wing pair, on liboqs's ML-KEM-768, libsodium's X25519 and cb2's own
  SHA3-256 and SHAKE256 (liboqs keeps its SHA3 internal, so a shared
  liboqs such as Homebrew's does not export it), `generate()`, `from_bytes`, `from_paserk`, `to_paserk`
  (`kcb2.recipient-secret`, `kcb2.recipient`), `public_key()`,
  `paserk_id()` (`kcb2.rid`). `Seal::seal(recipient_public, key)` returns
  the `kcb2.seal` string of a local key sealed to that recipient and
  `Seal::unseal(text, recipient)` recovers the key.

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

Nonce source

- Every seal takes 32 fresh bytes from `randombytes_buf`, which by
  default is the kernel (getentropy or getrandom), about 1.6 us per call
  on this Mac and the larger part of a 64 B seal. An application that
  wants that time back calls, once and before any cb2 function,
  `randombytes_set_implementation(&randombytes_internal_implementation)`:
  libsodium's own ChaCha20-based generator, seeded from the kernel,
  reseeded on a schedule and after a fork, about 0.3 us per call. cb2
  itself keeps no nonce state and makes no such choice; the trade, a
  generator state in process memory maintained by libsodium instead of a
  kernel call per token, belongs to the application. `cb2_playground
  --fast-random` and `cb2_bench --fast-random` show both.

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
- `HolderProof`, local mode (every build): `bind_local(claims)`
  generates a fresh proof key, writes its `kcb2.local` string into
  `cnf` and returns the key for the client; `make_local(proof_key,
  request, access_token, jti, now, lifetime)` makes the
  `cb2.holder-local.` proof the client presents with a request;
  `check_local(proof_key, access_token, rules)` verifies one. Public
  mode (with liboqs): `make(client_secret_key, ...)` makes the
  `cb2.holder-public.` proof and `check(client_public_key, ...)`
  verifies one. `claims_for` builds the claims of either. `Token::open`
  and `Token::verify` run the check as the last step whenever the token
  carries `cnf`, in the mode `cnf` names. `Holder::normalize_target` is
  the RFC 9449 target normalisation both ends apply. `Claims::cnf` holds
  the client's `kcb2.public` string or, in a cb2.local token only, the
  proof key's `kcb2.local` string.
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

## Other languages

Every language bridge sits on one C ABI, `bindings/c`: opaque key
handles, malloc'd results, integer verdicts with their names, claims
and rules as JSON text, and replay checks as callbacks (or a list of
seen ids for simple cases). `bindings/c/include/cb2_c.h` is the whole
surface and `bindings/c/test/test_c.c` exercises every call and
verdict; `-DCB2_BUILD_BINDINGS=ON` (the default) builds `libcb2_c` as a
shared and a static library and runs the test. It is a C library in its
own right: `cmake --install` puts the header, both libraries, a CMake
package (`find_package(cb2_c)`) and a pkg-config file under the prefix,
the shared library exports only the `cb2_` functions, and
`bindings/c/README.md` states the ownership rules, the ABI promise and an
example program built against the install. Each bridge has its own
README with the build and loading steps and one example, and its own
tests mirroring the C test.

| language | where | mechanism | verified here |
|---|---|---|---|
| C | `bindings/c` | the ABI itself, installable with CMake and pkg-config | `cb2_c_test`, and the example built against an install through both |
| Python | `bindings/python` | a typed package over `libcb2_c` through ctypes, built as a platform wheel that bundles the library (scikit-build-core), with an http.server example | 41 pytest cases, the example and `mypy --strict` against the wheel installed in a fresh environment; ruff |
| Go | `bindings/go` | a cgo module, `github.com/Crdzbird/cb2/bindings/go`, callbacks through exported trampolines; an HTTP service with holder proofs and a CLI as examples | `go vet`, staticcheck, `go test -race` with runnable examples, the example service driven with curl |
| JavaScript and Node | `bindings/js` | the npm package `cb2`: the C ABI compiled to WebAssembly with Emscripten, one module for Node and browsers, ES module and CommonJS entries with TypeScript declarations, callbacks through the wasm table; a Node login server and a browser page as examples | `node --test`, `tsc` over typed consumers, arethetypeswrong, the packed tarball from ES modules and CommonJS, the examples with curl and headless Chrome |
| Java | `bindings/java` | JNI glue over the C ABI, classes in `com.cipherbird.cb2` | a Java test program |
| Kotlin | `bindings/java/src/main/kotlin` | a DSL and extensions over the Java classes | a Kotlin test program |
| Swift | `bindings/swift` | a Swift package with a system library target for the C ABI | 9 XCTest cases |
| Dart | `bindings/dart` | dart:ffi, callbacks through NativeCallable | `dart test` |
| Flutter | `bindings/flutter/cb2_flutter` | an FFI plugin over the Dart package, native library per platform | `flutter analyze`; the mobile native builds are not verified here |

CI runs the Swift, Python, Node and Go tests on macOS and the Python,
Node and Go tests on Linux after building the C ABI; the Java, Kotlin,
Dart and Flutter tests run locally with their build scripts, since those
toolchains are not on the runners. A separate job checks the JavaScript
package on Node 22.12 and 24 as npm would ship it.

## Repository layout

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
include/cb2/seal.hpp           X-Wing recipient keys and kcb2.seal
include/cb2/detail/            base64url, PAE, BLAKE3 and liboqs wrappers, SHA3-256 and SHAKE256, the local core, secure memory
tests/                             runner, cases, gen_vectors.cpp, vectors/*.json, vectors/paseto-v1 to v4 (the official PASETO vectors, ISC)
tests/ct/                          ct_probe.cpp, the Valgrind constant-time probe, and its one suppression with the reason
examples/international_text.cpp    the text policy against a legacy check, eight scenarios, self-checking
playground/                        cb2_playground and the two scripted, self-checking demo sessions
web/                               the browser playground: page, C shim, Emscripten build, the built module, node smoke test
fuzz/                              fuzz_local, fuzz_public, fuzz_claims, fuzz_seal, fuzz_holder, fuzz_sha3 (cb2's SHA3 against OpenSSL)
bench/                             bench_main.cpp; reference.hpp, PASETO v1 to v4, JWS and JWE from their specifications, checked by tests/test_reference.cpp against the official vectors; bench_ref.cpp, CipherBird's v4.local and cb1.local when cryptolib is present
docs/PROTOCOL.md                   the normative format for implementers, the vector file format, worked examples
tools/check_vectors.py             an independent Python implementation that checks tests/vectors against docs/PROTOCOL.md alone
bindings/c                         the C ABI (cb2_c.h, cb2_c.cpp) and its test; what every bridge below uses
bindings/python, go, js, java, swift, dart, flutter   the language bridges, each with a README and tests
docs/SPEC.md                       wire format, rationale, threat model
docs/SECURITY.md                   claims and limits
docs/SENDER_CONSTRAINT.md          sender-constrained tokens: the design of both modes, its decisions, how it was built
docs/MIGRATION.md                  moving a cb1 or PASETO v4 deployment to cb2
docs/VERIFICATION.md               the dated record of every verification run
```

## Benchmark in detail

`cb2_bench` (`-DCB2_BUILD_BENCH=ON`), Release build, Apple clang 21,
this Mac (Apple silicon), macOS 26.6, idle machine, 2026-11-04, after
the ChaCha20 backend and the footer cache described below. Each
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
| cb2.local | 246 | 2713 ns | 5261 ns | 121.2 us | 1328 ns | 4280 ns | 128.0 us |
| PASETO v4.local | 245 | 3779 ns | 7758 ns | 266.9 us | 2386 ns | 6364 ns | 266.8 us |
| PASETO v3.local | 266 | 8995 ns | 10.6 us | 113.1 us | 7499 ns | 9095 ns | 114.2 us |
| PASETO v2.local | 213 | 2926 ns | 7016 ns | 300.3 us | 972 ns | 3972 ns | 214.5 us |
| PASETO v1.local | 266 | 10.2 us | 12.5 us | 172.2 us | 7559 ns | 9002 ns | 118.3 us |
| JWE dir A256GCM | 167 | 2656 ns | 3339 ns | 45.4 us | 751 ns | 1463 ns | 44.6 us |
| cb2.public (Ed25519 + ML-DSA-65) | 4659 | 166.7 us | 174.2 us | 623.3 us | 112.6 us | 116.2 us | 441.3 us |
| PASETO v4.public (Ed25519) | 246 | 17.3 us | 23.2 us | 334.6 us | 50.3 us | 51.3 us | 230.3 us |
| PASETO v3.public (ECDSA P-384) | 289 | 195.8 us | 196.3 us | 296.7 us | 396.6 us | 394.0 us | 503.7 us |
| PASETO v2.public (Ed25519) | 246 | 18.5 us | 23.5 us | 333.1 us | 50.3 us | 53.1 us | 235.8 us |
| PASETO v1.public (RSA-2048 PSS) | 502 | 639.6 us | 640.7 us | 739.8 us | 21.8 us | 23.0 us | 124.4 us |
| JWS EdDSA (Ed25519) | 210 | 17.4 us | 23.0 us | 399.3 us | 47.1 us | 50.5 us | 252.8 us |
| JWS ES256 (ECDSA P-256) | 210 | 21.5 us | 22.5 us | 97.8 us | 58.1 us | 59.8 us | 135.5 us |
| JWS RS256 (RSA-2048) | 466 | 593.2 us | 595.6 us | 710.6 us | 17.3 us | 18.6 us | 98.8 us |
| JWS HS256 (HMAC-SHA256) | 167 | 1191 ns | 2348 ns | 81.8 us | 1145 ns | 2324 ns | 81.4 us |
| cryptolib v4.local | 245 | 2015 ns | 5849 ns | 259.6 us | 2020 ns | 6034 ns | 265.9 us |
| cryptolib cb1.local | 246 | 1299 ns | 5365 ns | 213.2 us | 1272 ns | 5435 ns | 227.7 us |

64 KiB throughput, seal / open, in MB/s:

| implementation | seal | open |
|---|---:|---:|
| cb2.local | 516 | 488 |
| PASETO v4.local | 234 | 234 |
| PASETO v3.local | 553 | 547 |
| PASETO v2.local | 208 | 291 |
| PASETO v1.local | 363 | 528 |
| JWE dir A256GCM | 1377 | 1401 |
| cb2.public | 100 | 142 |
| PASETO v4.public | 187 | 271 |
| PASETO v3.public | 211 | 124 |
| PASETO v2.public | 188 | 265 |
| PASETO v1.public | 84 | 502 |
| JWS EdDSA | 157 | 247 |
| JWS ES256 | 639 | 461 |
| JWS RS256 | 88 | 632 |
| JWS HS256 | 764 | 768 |
| cryptolib v4.local | 241 | 235 |
| cryptolib cb1.local | 293 | 274 |

Reading, local tokens. At the sizes tokens actually have, cb2.local
sits with the fastest of the family: opening a 64 B token costs 1.3 us,
against 2.4 us for v4.local written the same plain way, 2.0 us for the
tuned v4.local, 1.0 us for v2.local (one AEAD call, no key split, and no
key commitment) and about 7.5 us for v1.local and v3.local, whose
HKDF-SHA384 split and HMAC-SHA384 tag cost more than the cipher at that
size. HS256 and JWE A256GCM are cheaper still at 64 B because they do
less: no key split, and for HS256 no encryption. Of the 1.3 us, the
three primitive calls (the keyed BLAKE3 split, the keyed BLAKE3 tag over
the 198-byte encoding, XChaCha20) are 1.0 us; the decoder, the footer
compare and the buffers are the rest. At 64 KiB cb2 is the fastest of
the XChaCha20 family: a message of 512 bytes or more goes through
OpenSSL's vectorised ChaCha20 under libsodium's HChaCha20 subkey, the
same keystream, which halves the bulk cost against libsodium's plain C
ChaCha20 on this CPU (v2 and v4 in the table still use it). AES-CTR in
v1 and v3 and AES-GCM in JWE stay ahead because this CPU has AES in
hardware; that is a choice of cipher, not of construction, and a 64 KiB
token is not what the format is for. Seal costs 1.4 us more than open at
64 B on the cb2 row, which is the per-token `randombytes_buf` call
the design requires in place of a nonce batch (docs/SPEC.md section
12, question 5); cb1.local shows the same construction with the batch.
Through the claims layer, `Token::open` of a typical token costs
about 2.8 us, of which the strict JSON parse is 0.8; the footer the key
id is bound into is kept with the key, which took 0.3 us off that path,
and the JSON reader and the text checks copy and skip runs of plain
ASCII in one step, which took 0.5 us off it and 17 us off a bound
request whose cnf carries a 2.6 KB key.
With `cb2_bench --fast-random`, the application opt-in for libsodium's
own generator described under API reference, the same cb2.local row seals a 64 B
token in 1489 ns and a 1 KiB one in 4136 ns, against 2736 and 5332 with
the kernel source in the same session; open does not change.

Reading, public tokens. The post-quantum half is the whole difference:
cb2.public signs in 167 us and verifies in 113 us where Ed25519 alone
signs in 17 us and verifies in 50 us, and the token is 4659 bytes
against 246. Against the rest of the field the hybrid is ordinary:
signing is about 3.6 times cheaper than RSA-2048 (v1.public and RS256,
around 600 us) and a little cheaper than ECDSA P-384 (v3.public, 196
us), and verifying is 3.5 times cheaper than ECDSA P-384 and about five
times slower than RSA, which verifies fast and signs slowly. A
cb2.public verification costs about what two ECDSA P-256 verifications
cost. The size is the price that
matters: it is paid once per token in a service to service call, and
it is why the local purpose is the one for sessions.

### One sender-constrained request

The second table of `cb2_bench` measures one request to a resource that
requires a bound token: the client makes a holder proof for
`GET https://api.example/v1/me`, and the server checks the access token
and that proof under the rules a resource sets (issuer, audience, the
proof for this request, a proof replay check). The access token carries
iss, aud, sub, exp and jti, plus cnf when it is bound: a fresh
`kcb2.local` proof key in the local mode row, the client's `kcb2.public`
key in the two holder proof rows. The DPoP rows are
a JWT access token with `cnf.jkt` and an RFC 9449 proof signed with
ES256, on the same reference code as the JWS rows: the server does the
two signature checks, the `ath` hash and the `jkt` thumbprint, no JSON
claim checks, and takes the client key as known instead of reading it
from the proof header. They are a lower bound for JWT, as the JWS rows
are. Same machine and libraries, 2026-11-06, after the ASCII fast path
of the claims layer; in the same run the first table agreed with the
one above within 8 percent in 101 of its 102 cells and within 9 percent
in all.

| request | token | proof | on the wire | client: make proof | server: check token and proof |
|---|---:|---:|---:|---:|---:|
| cb2.local bearer, no proof | 321 | 0 | 321 | - | 2670 ns |
| cb2.local bound + local proof | 405 | 357 | 762 | 5812 ns | 7325 ns |
| cb2.local bound + holder proof | 3877 | 4770 | 8647 | 215.2 us | 166.7 us |
| cb2.public bound + holder proof | 8290 | 4770 | 13060 | 244.3 us | 313.0 us |
| JWT RS256 + DPoP ES256 | 582 | 479 | 1061 | 25.9 us | 79.2 us |
| JWT ES256 + DPoP ES256 | 326 | 479 | 805 | 23.1 us | 119.6 us |

Reading, the local mode. A cb2.local token bound to a proof key is 84
characters longer than the bearer token (the cnf claim, inside the
encryption) and its proof is 357: 762 on the wire, less than either
DPoP row. The client makes a proof in 5.8 us, a quarter of a DPoP
proof; the server checks token and proof in 7.3 us, 4.7 us more than
the bearer token and 11 to 16 times less than the DPoP rows. One core
checks about 137,000 such requests a second, and a million cost about
7 core-seconds and 0.8 GB of headers. The proof is a keyed BLAKE3
derivation and tag over the request claims and the access token text,
with no signature, and the price is the one the local mode states: the
proof key is shared by the issuer, the client and every verifier that
can open the token, so it protects against a token that leaks without
its key, which covers most of the ways tokens leak, and not against a verifier
that turns on its clients. For service to service traffic on cb2.local
tokens it is the mode to use.

Reading, tokens bound to a client key pair. The binding costs what the
client's hybrid key costs. The cnf claim carries the whole kcb2.public
key, which takes the local token from 321 to 3877 characters, and the
proof is a hybrid signature over the request, 4770 more. On the server
a bound request costs 167 us against 2.7 us for the bearer token, 1.4
times the ES256 + DPoP row and 2.1 times the RS256 + DPoP row; on the
client the proof costs 215 us against 23 to 26 us for a DPoP proof; on
the wire it is 8 to 11 times the bytes. At scale, one core checks about
6,000 such requests a second against 8,400 to 12,600 for DPoP, and a
million requests cost about 2.8 core-minutes of checking against 1.3 to
2.0, and 8.6 GB of headers against about 1 GB. The proof changes on every
request, so HTTP/2 header compression cannot shrink it, and on a slow
uplink the bytes cost more time than the checks. A bound cb2.public
token is 8290 characters, more than the 8 KB nginx allows for one header
line by default; with its proof it is close to the 16 KB Node allows for
all headers. The local purpose is therefore the one for bound tokens as
well. The size comes from the post-quantum client key, not from the
format, and the local mode above, which has no such key, is the answer
where the client key need not be asymmetric.

## Testing and verification

What is checked, on every push and pull request, by CI:

- **macos job:** the release build with `cb2.public`, the tests under
  AddressSanitizer and UBSan, a build without liboqs, the Swift, Python,
  Node and Go bridges, and one minute of each of the six fuzz targets.
- **linux job** (Ubuntu 24.04, gcc, BLAKE3 and liboqs built from pinned
  sources): the release build, a build without liboqs, ASan and UBSan,
  the Python, Node and Go bridges, and the constant-time probe under
  Valgrind, which marks keys and secrets as undefined and requires that
  no branch or memory address depends on them.
- **web job:** the WebAssembly module rebuilt from source and the
  playground demos run through it under Node.
- **vectors job:** `tools/check_vectors.py`, an independent Python
  implementation written from docs/PROTOCOL.md alone, checks every test
  vector, so the library and the specification cannot drift apart
  unnoticed.

What the tests cover: `cb2.local`, `cb2.public`, the claims layer, key
types and ids, `kcb2.local-wrap`, international text in claims, footers
and key ids, the hardening from the adversarial review (rules that must
declare their audience and issuer, the size limit, the replay check,
the weak-key and secret-key import checks, the ML-DSA context string),
sender-constrained tokens in both holder modes, `kcb2.seal` on X-Wing
with the draft's test vectors, cb2's own SHA3-256 and SHAKE256 against
FIPS 202 outputs, the C interface and every language bridge, the
official PASETO v4 vectors for the building blocks cb2 shares with v4,
and six fuzz targets, one of them comparing cb2's SHA3 with OpenSSL's.

What is not covered: interoperability with another implementation (there
is none); in the constant-time probe, the ML-DSA-65 secret (FIPS 204
signing rejection-samples on it by design and liboqs does not mark that
verdict public), key generation, and the holder proof paths; review by a
second person; and the open questions in docs/SPEC.md section 12. One
known secret-dependent memory access is accepted, not fixed: the
`kcb2.local` text of a secret key, and so its `kcb2.lid`, is written by
the table-driven base64url encoder (tests/ct/ct_probe.supp gives the
reason and the bound).

The dated record of every local run, with case counts, fuzz runs and
what each one found, is docs/VERIFICATION.md.
