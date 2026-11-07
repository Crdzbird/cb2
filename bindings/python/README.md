# cb2 for Python

cb2 is a format and a library for security tokens: the short strings a
server hands out after a login and later accepts as proof of who is
calling and what they may do. It does the job of JWT and PASETO, with
the claim checks built into the library, post-quantum signatures, and
tokens that can be tied to the client they were issued to. This package
is the Python interface to it.

The format, its security argument and the C++ library are described in
the [main README](https://github.com/Crdzbird/cb2#readme), the
[specification](https://github.com/Crdzbird/cb2/blob/main/docs/SPEC.md)
and the [wire protocol](https://github.com/Crdzbird/cb2/blob/main/docs/PROTOCOL.md).
cb2 is version 0.1.0 and has not yet been reviewed by anyone but its
author.

The package calls the cb2 C library (`libcb2_c`) through `ctypes`. It
has no Python dependencies, is fully typed (`py.typed`, checked with
`mypy --strict`) and supports Python 3.10 and later on macOS and Linux.

## Install

The package is a platform wheel that carries `libcb2_c` inside it. It is
not on PyPI; build the wheel from a checkout of the repository. The
build needs CMake 3.20 or later, a C++20 compiler, pkg-config and the
libraries the root `CMakeLists.txt` needs: libsodium, BLAKE3, OpenSSL's
libcrypto and, for cb2.public and kcb2.seal, liboqs.

    python -m pip install build
    python -m build --wheel --outdir dist bindings/python
    python -m pip install dist/cb2-*.whl

That wheel links to libsodium, BLAKE3 and libcrypto where the build
machine has them. To ship it to machines without them, copy them into
the wheel with the standard repair tools, as CI does:

    delocate-wheel -w wheelhouse dist/cb2-*.whl            # macOS
    auditwheel repair -w wheelhouse dist/cb2-*.whl         # Linux

The wheel is tagged `py3-none-<platform>`: one build serves every Python
3.10 or later on that platform, since `ctypes` has no ABI of its own. A
source distribution is not supported, because the C++ sources live
outside `bindings/python`. For development, `pip install -e
bindings/python` builds the library once and links the Python sources
in place.

## Quick start

```python
from datetime import datetime, timedelta, timezone

import cb2
from cb2 import LocalKey, PublicKey, Rules, SecretKey, Token

key = LocalKey.generate()
expires = datetime.now(timezone.utc) + timedelta(minutes=15)
claims = {
    "iss": "https://issuer.example",
    "aud": "api",
    "sub": "user-1",
    "exp": expires.isoformat(timespec="seconds"),
    "role": "admin",
}
token = Token.seal(key, claims)
print(token[:16], len(token))

rules = Rules(issuer="https://issuer.example", audience="api")
opened = Token.open(token, key, rules)
print(opened["sub"], opened["role"])

try:
    Token.open(token, key, Rules(issuer="https://issuer.example", audience="billing"))
except cb2.Cb2Error as e:
    print(e.name, e.code)

if cb2.has_public():
    secret = SecretKey.generate()
    published = secret.public_key().to_paserk()
    signed = Token.sign(secret, claims)
    verified = Token.verify(signed, PublicKey.from_paserk(published), rules)
    print(signed[:16], len(signed), verified["sub"])
```

prints (the token text differs on every run):

    cb2.local.nJGg8G 325
    user-1 admin
    audience_mismatch 14
    cb2.public.eyJpc 4738 user-1

The registered times (`exp`, `nbf`, `iat`) are RFC 3339 text, not Unix
numbers; a number there is refused when the token is made. `Token.open`
and `Token.verify` return the claims only after the tag or signature,
the times, the issuer and the audience all pass. An issuer and an
audience are required in the rules (or `allow_any_issuer` and
`allow_any_audience`), and a token without `exp` is refused unless
`require_exp=False`.

## Token kinds and when to use each

| kind | use it when | keys in this package |
|---|---|---|
| `cb2.local` | the same system issues and checks the token: sessions, service to service calls. The claims are encrypted (XChaCha20 with keyed BLAKE3), so only key holders can read them | `LocalKey`, one 32-byte secret shared by issuer and verifier |
| `cb2.public` | many parties must verify tokens they cannot issue. The claims are signed and readable; every token carries an Ed25519 and an ML-DSA-65 signature and both must verify | `SecretKey` signs, its `PublicKey` verifies |
| `cb2.holder-local`, `cb2.holder-public` | a stolen access token must be useless on its own. The issuer puts a client key in `cnf` and the client signs a short proof for every request with `Holder.prove_local` or `Holder.prove` | the `LocalKey` in `cnf`, or the client's `SecretKey` |
| `kcb2.local-wrap` | storing or moving a local key under another local key | `KeyWrap` with two `LocalKey`s |
| `kcb2.seal` | delivering a local key to a recipient, safe against a future quantum computer (X-Wing) | `RecipientKey` and its `RecipientPublicKey` |

cb2.public, its holder proofs and kcb2.seal need a library built with
liboqs. `cb2.has_public()` and `cb2.has_seal()` say whether the loaded
one has them; without them those calls raise `Cb2Error` with the name
`unavailable`. `Holder.prove_local` is in every build.

## Compact claims tokens (experimental)

`Compact` makes the experimental compact formats of
[section 15 of the protocol](https://github.com/Crdzbird/cb2/blob/main/docs/PROTOCOL.md),
`cb3.local.` and `cb3.public.`. The cryptography is that of cb2.local
and cb2.public (the same keys, the same 32-byte nonce and tag, the same
Ed25519 and ML-DSA-65 pair), but the claims travel as strict canonical
CBOR instead of JSON, and the footer is a 16-byte BLAKE3 digest of the
key id instead of its text. A cb3.local token of typical claims is 40
to 50 percent shorter than the cb2.local token of the same claims. The
header name is a placeholder and the format may still change before it
is released.

`Compact` takes the same claims, the same `Rules` (replay callbacks
included) and gives the same verdicts and claims back as `Token`:

```python
from cb2 import Compact, LocalKey, Rules, Token

key = LocalKey.generate()
claims = {
    "iss": "https://issuer.example",
    "aud": "api",
    "sub": "user-1",
    "exp": "2099-01-01T00:00:00+00:00",
    "role": "admin",
}
token = Compact.seal(key, claims)
print(token[:16], len(token), len(Token.seal(key, claims)))

rules = Rules(issuer="https://issuer.example", audience="api")
print(Compact.open(token, key, rules)["role"])
print(Compact.peek_key_digest(token) == Compact.key_digest(key.paserk_id()))
```

prints (the token text differs on every run):

    cb3.local.9mKC7Q 192 325
    admin
    True

The differences from `Token`:

- the two formats never cross: a cb2 token given to `Compact.open` or
  `Compact.verify`, and a compact token given to `Token.open` or
  `Token.verify`, are `invalid`;
- a custom number must be an integer in int64, so `Compact.seal` and
  `Compact.sign` refuse with `argument` what `Token` accepts: `1.5`,
  `1000.0`, `-0.0` or `2**63`. Booleans, `None`, strings, lists and
  objects carry over unchanged. Times must lie in years 0000 to 9999,
  and `cnf` must be a `kcb2.local` or `kcb2.public` key;
- the footer names the key by digest only. `Compact.peek_key_digest`
  returns those 16 bytes unverified (`None` for a key without an id),
  and `Compact.key_digest(key_id)` computes them for each key a
  verifier holds, to pick the one that matches;
- holder proofs bind a compact access token exactly as a cb2 one:
  `Holder.prove_local` and `Holder.prove` take the compact token text
  as `access_token`.

## API overview

Every class and function below is exported from `cb2`. A token or key
text argument (`BytesLike`) may be `str`, `bytes`, `bytearray` or
`memoryview`; claims come back as `dict[str, Any]` (`cb2.Claims`).

Keys (`generate` exists on `LocalKey`, `SecretKey` and `RecipientKey`):

| call | returns |
|---|---|
| `LocalKey.generate()` | `LocalKey` |
| `Key.from_paserk(text: BytesLike)`, `Key.from_bytes(data: bytes)` | the key; every key class has both |
| `key.to_paserk()` | `str`, `kcb2.local.`, `kcb2.secret.`, `kcb2.public.` and so on |
| `key.paserk_id()` | `str`, the key's id, `kcb2.lid.` or `kcb2.pid.` |
| `key.key_id` | `str or None`, the id written into the footer of claims tokens; settable, `clear_key_id()` drops it |
| `SecretKey.public_key()` | `PublicKey` |
| `RecipientKey.public_key()` | `RecipientPublicKey` |

Claims tokens:

| call | returns |
|---|---|
| `Token.seal(key: LocalKey, claims: Mapping[str, Any], implicit: bytes = b"")` | `str` |
| `Token.open(token: BytesLike, key: LocalKey, rules: RulesLike, implicit: bytes = b"")` | `Claims` |
| `Token.sign(secret: SecretKey, claims: Mapping[str, Any], implicit: bytes = b"")` | `str` |
| `Token.verify(token: BytesLike, public: PublicKey, rules: RulesLike, implicit: bytes = b"")` | `Claims` |
| `Token.peek_key_id(token: BytesLike)` | `str or None`, the key id in the footer, unverified, to pick a key |
| `Compact.seal`, `Compact.open`, `Compact.sign`, `Compact.verify` | as the `Token` call of the same name, for the compact formats |
| `Compact.peek_key_digest(token: BytesLike)` | `bytes or None`, the 16-byte key digest in the footer, unverified |
| `Compact.key_digest(key_id: BytesLike)` | `bytes`, the digest of a key id; `Compact.KEY_DIGEST_BYTES` is 16 |

Raw tokens, any bytes in and out with an optional footer, and no claim
checks: `Local.seal(key, msg, footer=b"", implicit=b"") -> str`,
`Local.open(token, key, footer=b"", implicit=b"", max_token_bytes=0) ->
bytes`, and `Public.sign` and `Public.verify` with the same shapes.

Holder proofs, key wrapping and sealing:

| call | returns |
|---|---|
| `Holder.prove(client_secret: SecretKey, htm: str, htu: str, access_token: str, jti: str, now: int, lifetime: int = 60, nonce: str or None = None)` | `str`, a `cb2.holder-public` proof |
| `Holder.prove_local(proof_key: LocalKey, ...)` with the same arguments | `str`, a `cb2.holder-local` proof |
| `Holder.normalize_target(uri: str)` | `str`, the target as a proof binds it |
| `KeyWrap.wrap(wrapping: LocalKey, key: LocalKey)` | `str` |
| `KeyWrap.unwrap(text: BytesLike, wrapping: LocalKey)` | `LocalKey` |
| `Seal.seal(recipient_public: RecipientPublicKey, key: LocalKey)` | `str` |
| `Seal.unseal(text: BytesLike, recipient: RecipientKey)` | `LocalKey` |

Module functions: `version() -> str` (the library's version),
`has_public() -> bool`, `has_seal() -> bool`, `library_path() -> str`
(the file that was opened), `error_name(code: int) -> str`, and
`__version__`.

### Rules

`Rules` is a frozen dataclass; a plain mapping with the same keys works
too (`RulesLike = Rules | Mapping[str, Any]`). Every field is optional
and left out when `None`.

| field | type | meaning |
|---|---|---|
| `issuer`, `audience`, `subject` | `str` | the expected values; issuer and audience are required unless allowed to be anything |
| `allow_any_issuer`, `allow_any_audience` | `bool` | accept any issuer or audience |
| `now` | `int` | the clock in Unix seconds; the system clock when absent |
| `clock_skew` | `int` | seconds of leeway on the times, default 0 |
| `require_exp` | `bool` | default true |
| `max_lifetime` | `int` | the longest `exp` from now, in seconds |
| `max_token_bytes` | `int` | default 16384 |
| `replay` | `Callable[[str], bool]` | called with the `jti`; return True to accept it, False to refuse it as `replayed` |
| `seen_jti` | `list[str]` | a built-in replay check for tests and simple stores |
| `require_cnf` | `bool` | refuse a token without `cnf` (`missing_cnf`) |
| `ignore_cnf` | `bool` | skip the `cnf` check, so no proof is needed; must be said explicitly |
| `proof`, `request` | `str`, `dict[str, str]` | the holder proof sent with the request, and the request's `htm`, `htu` and optional `nonce` |
| `proof_lifetime` | `int` | seconds, default 60 |
| `proof_replay`, `proof_seen_jti` | as `replay` and `seen_jti` | the replay check for proof ids; one of them is required with a proof |

A replay check refuses a token whose `jti` it has seen:

```python
seen: set[str] = set()


def first_time(jti: str) -> bool:
    if jti in seen:
        return False
    seen.add(jti)
    return True


rules = Rules(issuer="https://issuer.example", audience="api", replay=first_time)
```

A callback that raises refuses the token.

## Errors

Every verdict of the library is a `cb2.Cb2Error` with `.code` (an `int`
equal to a `cb2.Code` member) and `.name`, a stable text such as
`"invalid"`, `"expired"`, `"audience_mismatch"`, `"replayed"` or
`"proof_mismatch"`. A token that fails its tag or signature, has the
wrong header, or was made by another key is `invalid`; the claim checks
only run after that. Malformed arguments are `argument`, missing rules
are `rules_incomplete`, a build without liboqs answers `unavailable`.
`Cb2Error` pickles, so it crosses process pools.

`cb2.LibraryNotFound`, an `OSError`, is raised on the first call when no
usable `libcb2_c` can be opened; its message lists what was tried.

```python
try:
    claims = Token.open(token, key, rules)
except cb2.Cb2Error as e:
    if e.code == cb2.Code.EXPIRED:
        ...
```

## Where the shared library comes from

The library is opened on first use, from the first of these that loads:

1. the path in the `CB2_C_LIBRARY` environment variable. When it is set
   it is the only candidate, so a wrong path fails instead of quietly
   loading another copy;
2. the copy inside the installed `cb2` package, which every wheel has;
3. whatever `ctypes.util.find_library("cb2_c")` finds: the system
   library path, `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`.

A candidate whose `cb2_abi_version()` is not the ABI version this
package was written for (0), or that lacks a function, does not load.
`cb2.library_path()` says which file was opened. The environment
variable is how to use a library from a CMake build without a wheel,
for example a build without liboqs:

    export CB2_C_LIBRARY=$PWD/build/bindings/c/libcb2_c.dylib

The wheel's library comes from `bindings/python/CMakeLists.txt`, which
includes the repository's root `CMakeLists.txt` through
[scikit-build-core](https://scikit-build-core.readthedocs.io), builds
its `cb2_c` target (the same shared library, with the same export list,
as `bindings/c`) and installs it into the `cb2` package under its
unversioned name, since a wheel cannot hold the symlinks of a versioned
library.

## Example

`examples/token_service.py` is a token service on the standard
library's `http.server`. It issues cb2.local and cb2.public access
tokens, and compact cb3.local ones, and serves `GET /me`, which opens or verifies the token and, for
a token bound to a client key, checks the holder proof in the
`CB2-Proof` header. Run without arguments it starts the service on a
free port, drives it with a `urllib` client and prints each step:

    $ python examples/token_service.py
    cb2 0.1.0 from .../site-packages/cb2/libcb2_c.dylib
    ok   cb2.local token opens: 200 sub=alice
    ok   tampered cb2.local token is refused: 401 invalid
    ok   request without a token is refused: 401 missing_token
    ok   compact token opens, 207 chars against 409: 200 sub=dave
    ok   tampered compact token is refused: 401 invalid
    ok   cb2.public token verifies: 200 sub=bob
    ok   cb2.public token from another key is refused: 401 invalid
    ok   bound token without a proof is refused (public): 401 missing_proof
    ok   bound token with its proof opens (public): 200 sub=carol
    ok   the same proof again is refused (public): 401 proof_replayed
    ok   a proof for another target is refused (public): 401 proof_mismatch
    all steps behaved as expected

Against a library without liboqs it skips cb2.public and binds the
token to a kcb2.local proof key instead. `python
examples/token_service.py serve --port 8080` keeps the service running.

## Benchmarks

`bench/bench_tokens.py` compares cb2 with PyJWT and pyseto, the usual
JWT and PASETO libraries for Python, on one claims payload: `iss`,
`sub`, `aud`, `exp`, `iat`, `jti` and one short custom claim (`role`).
JWT carries its times as NumericDate integers, PASETO and cb2 as RFC
3339 text, as each format requires. "create" makes a token from the
claims. "validating decode" checks the tag or signature, `exp`, the
issuer and the audience and returns the claims; pyseto checks `exp` and
the audience itself and the benchmark compares `iss` after it. No row
runs a replay check. Keys are made once, outside the timed calls, and
every library runs with its defaults. pyperf runs each benchmark in 20
worker processes; each cell is the median time per operation.

    python -m pip install --group bench      # from bindings/python, with cb2 installed
    python bench/bench_tokens.py

2026-11-07, Apple M3 Max, macOS 26.6.2, Python 3.12.1, the cb2 0.1.0
wheel after `delocate-wheel`, PyJWT 2.15.1, pyseto 1.10.0, cryptography
50.0.2, pyperf 2.10.0, an otherwise idle machine. A first run with other
work on the machine was discarded; the next two agree within 6 percent
in every cell, and the table is the second of them:

| token | create | validating decode | size |
|---|---:|---:|---:|
| cb2.local | 10.4 us | 12.7 us | 403 B |
| cb3.local (compact) | 9.6 us | 11.9 us | 224 B |
| JWT HS256 (PyJWT) | 12.2 us | 29.8 us | 259 B |
| PASETO v4.local (pyseto) | 18.0 us | 26.9 us | 335 B |
| cb2.public | 183.8 us | 131.3 us | 4816 B |
| cb3.public (compact) | 191.3 us | 131.5 us | 4637 B |
| JWT EdDSA (PyJWT) | 41.8 us | 132.8 us | 302 B |
| JWT ES256 (PyJWT) | 32.4 us | 88.3 us | 302 B |
| PASETO v4.public (pyseto) | 42.0 us | 119.4 us | 336 B |

The two compact rows come from a later run on the same machine with the
same versions, while other work was running on it; that run's cb2.local
and cb2.public cells were within 7 percent of the ones above.

What to read into it:

- cb2.public is slower and far larger than every classical row, and
  that is expected: each cb2.public token carries a post-quantum
  ML-DSA-65 signature (3,309 bytes) next to its Ed25519 one, and both
  are made and both are checked. The JWT and PASETO rows sign with
  Ed25519 or ECDSA P-256 alone, which a future quantum computer could
  forge.
- Every cb2 cell includes the cost of calling C from Python through
  `ctypes`: the claims and the rules are encoded as JSON, the arguments
  are marshalled, the result is copied back and the claims JSON is
  decoded. That overhead is part of what is measured. For scale: the
  C++ benchmark in the main README seals a 64-byte raw cb2.local
  message in 2.7 us and opens it in 1.3 us; the same calls through this
  package (`Local.seal`, `Local.open`) took 5.0 us and 3.5 us on this
  machine (timeit, median of seven), so one trip through `ctypes` costs
  about 2 us, and the rest of the cb2.local cells is the claims path:
  JSON both ways, the rules and the checks. PyJWT and pyseto pay their
  own Python overhead around the C underneath them (`hmac`, `hashlib`,
  cryptography, pycryptodomex).
- cb2 claims tokens carry the key id in a footer by default, 85 bytes
  of the sizes above, so a verifier can pick its key with
  `Token.peek_key_id`; `key.clear_key_id()` leaves it out. None of the
  JWT or PASETO rows carries a key id. pyseto writes JSON with a space
  after each separator; cb2 and PyJWT write compact JSON.
- The compact rows carry the same claims as CBOR with a 16-byte key
  digest for a footer: cb3.local is 179 bytes shorter than cb2.local
  and about as fast, since the cryptography is the same and the CBOR
  is encoded and decoded in C++ from the same claims JSON. cb3.public
  saves the same 179 bytes, which barely shows next to its signatures.
- These are one machine's numbers; run the script on yours. CI only
  runs it once with `--debug-single-value` to check that it works.

## Development and checks

The tests are pytest; `tests/test_example.py` runs the example too.
They run against the installed package, so install it first (a wheel or
`pip install -e .`), then from `bindings/python`, with pip 25.1 or later
for dependency groups:

    python -m pip install --group dev
    python -m pytest
    python -m mypy
    ruff check . && ruff format --check .

`mypy` covers `src`, `tests`, `examples` and `bench`; for `bench` it
needs the `bench` group installed as well.

`scripts/check_wheel.sh <wheel>` installs a wheel into a fresh virtual
environment in a temporary directory, then runs the tests,
`mypy --strict` and the example against it; with `CB2_NOPQ_LIBRARY`
set to a library built with `-DCB2_PQ=OFF` it runs them once more
against that library. CI runs it on macOS (after `delocate-wheel`) and
Linux (after `auditwheel repair`), runs ruff and mypy on Linux, and runs
the benchmark once with a single value as a smoke test.
