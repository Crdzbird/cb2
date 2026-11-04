# cb2 specification

Version 0.1.0. This document defines the cb2.local and cb2.public token
formats, the kcb2 key strings and the claims layer, byte for byte, with the
rationale for each decision and the threat model. It describes this
implementation and why it is the way it is. The normative statement of
the formats for an implementer in any language, with the test vector
file format and worked examples with every intermediate value, is
docs/PROTOCOL.md; where the two differ, PROTOCOL.md is the one to fix
or to follow.

## 1. Status: a CipherBird proposal, not a PASETO version

There is no PASETO version 5. The paseto-standard specification repository
(github.com/paseto-standard/paseto-spec, checked on 2026-11-02) documents
versions 1 to 4 only. Its protocol-versions page says, in its rules for
implementations, "If a future post-quantum `Version 5` (NIST) and/or
`Version 6` (Sodium) is defined" versions 1 and 2 should no longer be
accepted, and that "New versions will be decided and formalized by the
PASETO developers", with version identifiers matching `v[0-9]+` reserved
by the PASETO development team.

cb2 is therefore CipherBird's proposal for what a successor to v4
should look like. It is not a paseto-standard version and makes no claim
to be one. Its headers are `cb2.local.` and `cb2.public.`, continuing
CipherBird's own cb1 identifier instead of a reserved `v5`, so an
official Version 5, should one be defined, cannot collide with it. Key
strings carry `kcb2.` in the same way PASERK pairs `k4.` with `v4.`.

Where the v4 specification sets a direction (versioned protocol, no
algorithm agility, PAE, implicit assertions, footer, key ids in the
footer, the shape of PASERK) cb2 follows it. Where it improves on v4
the change is justified in section 9.

## 2. Notation

- `||` is byte concatenation.
- `LE64(n)` is the 8-byte little-endian encoding of n with the most
  significant bit cleared.
- `PAE(p1, ..., pk)` is PASETO's pre-authentication encoding:
  `LE64(k) || LE64(len(p1)) || p1 || ... || LE64(len(pk)) || pk`.
- `b64(x)` is unpadded base64url (RFC 4648 section 5) of x.
- `BLAKE3-keyed(K, m, n)` is the keyed mode of BLAKE3 with 32-byte key K
  over m, with n bytes of extendable output.
- `BLAKE3(m, n)` is unkeyed BLAKE3 with n bytes of output.
- `XChaCha20(k, n2, m)` is libsodium's `crypto_stream_xchacha20_xor` of m
  under 32-byte key k and 24-byte nonce n2, with the block counter at 0.
- `Ed25519-sign`, `Ed25519-verify` are libsodium's `crypto_sign_detached`
  and `crypto_sign_verify_detached`.
- `ML-DSA-65-sign`, `ML-DSA-65-verify` are liboqs's `OQS_SIG_sign` and
  `OQS_SIG_verify` for `OQS_SIG_alg_ml_dsa_65` (FIPS 204, pure mode, no
  context string).

Every primitive above is a vetted library call. cb2 defines no
primitive of its own.

## 3. Common rules

### 3.1 Grammar

```
token   = header payload [ "." footer ]
header  = "cb2.local." | "cb2.public."
payload = b64(body)
footer  = b64(f)                   ; present if and only if f is not empty
```

A token is a byte string; every byte outside the header is a base64url
character or the single footer separator. The body is defined per
purpose below.

### 3.2 base64url

Encoding is unpadded. Decoding is strict: only the 64 characters
`A-Z a-z 0-9 - _`; no `=`; a length that is 1 modulo 4 is invalid; the
unused low bits of the final character must be zero. Hence every byte
string has exactly one accepted encoding, and no two distinct token texts
decode to one body. This is the same acceptance set as libsodium's
`sodium_base642bin` with `sodium_base64_VARIANT_URLSAFE_NO_PADDING` and
no ignored characters; the test suite checks the two agree on random and
malformed inputs.

### 3.3 Footer

The footer is authenticated (local: under the tag; public: under the
signature) but sent in clear. A verifier states the footer it expects.
A token that carries a footer when none is expected, or none when one is,
or a different one, is invalid. The comparison is constant time for
equal lengths; the lengths are public.

### 3.4 Implicit assertion

The implicit assertion i is authenticated like the footer but never
transmitted. Both ends must agree on it out of band. It binds a token to
a context (a service, a session, a request parameter) without carrying
that context in the token.

### 3.5 Limits

The message, the footer and the implicit assertion are each at most 2^26
bytes. A token whose text implies an input beyond that is invalid by its
length alone, before decoding.

The allocating `open` and `verify` functions also refuse, with
`too_large` and before reading a byte, any token longer than
`max_token_bytes`, which defaults to 2^20 (1 MiB) and which the caller
may raise up to the 2^26 ceiling. Without it a token of 2^26 characters
of garbage costs the verifier a 48 MiB buffer and the decoding and
hashing of it before the verdict; with it the cost is one comparison.
The caller-buffer functions have no such limit, because there the caller
sized the buffer and has already paid. The claims layer applies its own,
smaller limit first (8.3).

### 3.6 One verdict

Every failure that depends on the bytes of an unverified token is the
single verdict `invalid`: wrong header, non-canonical encoding, body too
short, footer presence or content, key id, tag, signature. Caller errors
that do not depend on the token (`argument`: wrong buffer size,
overlapping buffers, oversize inputs) and backend failures (`internal`)
are distinct because they carry no information about the token. The
claims layer adds `too_large`, decided on the length alone before any
parsing, and the claim errors, which are reported only after the token
has been authenticated.

## 4. cb2.local

### 4.1 Inputs

- K: 32-byte key.
- n: 32-byte nonce, fresh from the operating system CSPRNG via
  libsodium's `randombytes_buf`.
- m: message, 0 to 2^26 bytes.
- f: footer, 0 to 2^26 bytes.
- i: implicit assertion, 0 to 2^26 bytes.

### 4.2 Seal

```
h              = "cb2.local."                                   (10 bytes)
Ek || n2 || Ak = BLAKE3-keyed(K, h || n, 88)
                 Ek = bytes 0..31, n2 = bytes 32..55, Ak = bytes 56..87
c              = XChaCha20(Ek, n2, m)
t              = BLAKE3-keyed(Ak, PAE(h, n, c, f, i), 32)
body           = n || c || t
token          = h || b64(body) [ || "." || b64(f) ]
```

Body layout, by offset:

| offset | length | content |
|---|---|---|
| 0 | 32 | n, the nonce |
| 32 | len(m) | c, the ciphertext |
| 32 + len(m) | 32 | t, the tag |

Token text length: `10 + b64len(64 + len(m)) + (len(f) == 0 ? 0 : 1 + b64len(len(f)))`
where `b64len(x) = x / 3 * 4 + (x % 3 == 0 ? 0 : x % 3 + 1)`.

The PAE fed to the tag is, byte for byte:

```
LE64(5)
LE64(10)      "cb2.local."
LE64(32)      n
LE64(len(c))  c
LE64(len(f))  f
LE64(len(i))  i
```

### 4.3 Open

1. Check the header is exactly `cb2.local.`; else invalid.
2. Split the rest at the first `.`; a dot followed by nothing is invalid;
   a footer present when none is expected, or absent when one is, is
   invalid.
3. Decode the body (strict). A body shorter than 64 bytes is invalid.
4. Decode the footer (strict) and compare it with the expected footer in
   constant time; a mismatch is invalid.
5. Derive Ek, n2, Ak from K and the token's n as in 4.2.
6. Recompute t over PAE(h, n, c, f, i) with the expected f and the
   caller's i and compare with the token's t in constant time
   (`crypto_verify_32`); a mismatch is invalid. Nothing has been
   decrypted yet.
7. m = XChaCha20(Ek, n2, c).
8. Wipe Ek, n2, Ak and the hasher states. On any failure also wipe the
   whole output region.

### 4.4 Worked example

Vector cb2-E-11 from tests/vectors/cb2_local.json, produced by this
implementation with the deterministic-nonce test hook:

```
K   = 707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f
n   = 26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2
m   = "x"     f = "f"     i = "i"
token (100 bytes) =
cb2.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_KI7EWlZq44gJBpDJftI7jUKqAqzQ1hXF_mnsanxnzuvrg.Zg
```

The 65-byte body decodes to n (32), one ciphertext byte, and t (32); the
footer `Zg` is `f`. Vector cb2-E-10 is the empty message under the same
key and nonce (96 bytes of token text, the shortest possible):

```
cb2.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LGrO_H8wxM8Dj6C62SC7LfKrsjDn1mk1_e8KyPNi0-Wg
```

## 5. cb2.public

cb2.public exists only in builds with liboqs (macro `CB2_HAS_PQ`). A
build without it has no cb2.public purpose: the classes are absent and
`cb2::has_public()` is false. There is no Ed25519-only fallback.

### 5.1 Keys

```
public key pk = ed_pk (32) || ml_pk (1952)                       = 1984 bytes
secret key sk = ed_sk (64) || ml_sk (4032) || ml_pk (1952)       = 6048 bytes
```

`ed_sk` is libsodium's Ed25519 secret key (seed || ed_pk). The secret key
carries the ML-DSA public key so that a stored secret key restores the
pair and so that signing knows the key id it binds. The sizes are pinned;
at first use the library checks that liboqs reports exactly these sizes
for ML-DSA-65, and that it supports the FIPS 204 context string, and
refuses to operate otherwise.

Importing a secret key (`from_bytes`, `from_paserk`) checks that the
public halves it carries belong to its secret halves: `ed_pk` must equal
the public key derived from the seed, and `ml_pk` must verify a signature
made with `ml_sk` over a fixed probe under the context string
`kcb2.secret.self-test`, which no token uses. A key that fails either check
is `argument`. The check catches a corrupted or tampered key file and any
corruption of the ML-DSA secret half that changes what it signs; it does
not claim to detect every possible change to the secret halves.

### 5.2 Sign

```
h     = "cb2.public."                                                   (11 bytes)
m2    = PAE(h, m, f, i)
sig   = Ed25519-sign(ed_sk, m2) || ML-DSA-65-sign(ml_sk, m2, ctx = h)  (64 + 3309 = 3373 bytes)
body  = m || sig
token = h || b64(body) [ || "." || b64(f) ]
```

The ML-DSA half is the FIPS 204 signature with the header as its context
string (ML-DSA.Sign(sk, M, ctx) with ctx = "cb2.public.", 11 bytes; the
ctx of the pure signing interface, so the signed message is
`0 || 11 || ctx || m2` inside the algorithm). A signature the same key
made over the same m2 for any other purpose, under an empty or another
context, is not a cb2.public signature. Ed25519 as libsodium provides it
has no context parameter; its half is separated by the header inside m2
only, and the hybrid requires both halves.

Body layout:

| offset | length | content |
|---|---|---|
| 0 | len(m) | m, the message in clear |
| len(m) | 64 | Ed25519 signature |
| len(m) + 64 | 3309 | ML-DSA-65 signature |

The PAE, byte for byte: `LE64(4) || LE64(11) || "cb2.public." || LE64(len(m)) || m || LE64(len(f)) || f || LE64(len(i)) || i`.

### 5.3 Verify

1. Header check, split, strict decode, footer comparison as in 4.3. A
   body shorter than 3373 bytes is invalid.
2. m is the body less its last 3373 bytes; sig is those bytes.
3. Rebuild m2 = PAE(h, m, f, i) with the expected f and the caller's i.
4. Ed25519-verify(ed_pk, m2, sig[0..64)) and ML-DSA-65-verify(ml_pk, m2,
   sig[64..3373), ctx = h); both are evaluated and both must succeed.
   One failure is invalid.

ML-DSA-65 signing is randomised (FIPS 204 hedged signing as liboqs
implements it), so a cb2.public token is not reproducible byte for byte;
the vectors record tokens that must verify and keys under which signing
must round trip. The Ed25519 half is deterministic.

## 6. Key ids and the footer binding

Every key carries an optional key id. By default it is the key's PASERK
id (section 7). The claims layer binds the id into the footer as the JSON
object

```
{"kid":"<id>"}
```

with the id JSON-escaped, and nothing else in the footer. A key with no id
produces a token with no footer. On the verifying side the footer is
rebuilt from the verifier's key and compared in constant time, so a token
opens only under a key with the same id, even if two keys share bytes.
The id may be read from a token without verification (`peek_key_id`),
which returns an `UnverifiedKeyId` good only for selecting a candidate
key; the binding is then checked during authentication.

## 7. kcb2 key strings (PASERK-shaped)

| type | form | length |
|---|---|---|
| kcb2.local | `kcb2.local.` \|\| b64(K) | 11 + 43 = 54 |
| kcb2.public | `kcb2.public.` \|\| b64(pk) | 12 + 2646 = 2658 |
| kcb2.secret | `kcb2.secret.` \|\| b64(sk) | 12 + 8064 = 8076 |
| kcb2.lid | `kcb2.lid.` \|\| b64(BLAKE3(`kcb2.lid.` \|\| kcb2.local-string, 33)) | 9 + 44 = 53 |
| kcb2.pid | `kcb2.pid.` \|\| b64(BLAKE3(`kcb2.pid.` \|\| kcb2.public-string, 33)) | 9 + 44 = 53 |
| kcb2.local-wrap | `kcb2.local-wrap.` \|\| b64(n \|\| c \|\| t) | 16 + 128 = 144 |

The ids follow PASERK's shape (an id header, then the hash of the id
header and the key string, 33 bytes) with BLAKE3 in place of BLAKE2b.

kcb2.local-wrap is the cb2.local construction of section 4 with the header
`kcb2.local-wrap.` in place of `cb2.local.` everywhere (the key derivation
input, the PAE, the token text), the 32-byte key to wrap as the message,
an empty footer and an empty implicit assertion. Because the header is
different in the derivation and the PAE, a wrapped key is not a cb2.local
token of the key bytes and cannot be opened as one, and the other way
round. Example from tests/vectors/paserk.json:

```
wrapping key = 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
key          = 707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f
nonce        = df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8
kcb2.local-wrap.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtglFt_HVImGkJytBCsR_wRmZJksaMsZPWtbKSs7ESd-tGHeiV53g-P9-9OBKH_ECdlifNY7TiALS3EWC03Gma82
kcb2.local = kcb2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8
kcb2.lid   = kcb2.lid.1aEqnqYMImOxxw-gsD1cek4Y7mdyCF9Qh7Mq_Q976E01
```

## 8. Claims layer

### 8.1 Payload

The payload of a claims token is one JSON object. Registered claims, all
strings:

| claim | meaning | format |
|---|---|---|
| iss | issuer | string |
| sub | subject | string |
| aud | audience | string |
| exp | expiration | RFC 3339 |
| nbf | not before | RFC 3339 |
| iat | issued at | RFC 3339 |
| jti | token id | string |

Any other member is a custom claim and may be any JSON value. The writer
emits the registered claims in the order above, then custom claims in
insertion order, with no whitespace; strings are escaped per RFC 8259
with control characters as `\u00XX`.

RFC 3339 accepted on input: `YYYY-MM-DDTHH:MM:SS`, optional `.fraction`
(ignored), then `Z` or `+HH:MM` or `-HH:MM`; `T` and `Z` in either case.
Produced: `YYYY-MM-DDTHH:MM:SS+00:00`, the form the PASETO vectors use.

### 8.2 JSON reader

Exactly RFC 8259 and nothing more: the four JSON whitespace characters;
strings with the seven named escapes and `\uXXXX` with surrogate pairs
validated; raw UTF-8 validated (no overlong forms, no surrogates, nothing
above U+10FFFF); numbers by the grammar and kept as text, never
converted; no duplicate member names; nesting at most 16 deep counting
the payload object itself, so a custom claim value may nest at most 15
deep and `set_json` refuses a deeper one on the issuing side; the whole
input is one value. A registered claim that is not a string, or a time
claim that is not valid RFC 3339, makes the payload `claims_malformed`.

### 8.3 Validation order

`Token::open` and `Token::verify` perform, in this order and stopping at
the first failure:

0. The rules must be complete: they name an expected audience or allow
   any audience explicitly, and the same for the issuer; else
   `rules_incomplete`. Then the verifier's own key id, if any, and every
   expected issuer, audience and subject must satisfy the identifier
   policy of 8.4; else `argument`. An expectation the policy refuses
   could never equal a claim the policy accepts, so a verifier configured
   with an invisible character in its issuer would otherwise refuse every
   token with a misleading `issuer_mismatch`. All of this depends on the
   verifier alone, so a token minted for one service is never accepted
   by another through a verifier that forgot to say which audience it
   serves.
1. Length: `len(token) > max_token_bytes` is `too_large`. Nothing in the
   token has been read. The same limit is passed down to the raw layer.
2. Authentication: section 4.3 or 5.3 with the footer rebuilt from the
   key id. Any failure is `invalid`.
3. Parsing: 8.2, then the identifier policy of 8.4 on iss, sub, aud, jti
   and every custom claim name. Failure is `claims_malformed`.
4. Validation with the verifier's rules and clock `now`:
   - `exp` absent and `require_exp` (the default): `missing_exp`
   - `exp <= now - skew`: `expired`
   - `nbf > now + skew`: `not_yet_valid`
   - `iat > now + skew`: `issued_in_future`
   - with a maximum lifetime set: `exp > now + max_lifetime`:
     `lifetime_exceeded`
   - expected issuer, audience or subject absent or different (constant
     time): `issuer_mismatch`, `audience_mismatch`, `subject_mismatch`
   - with a replay check installed: `jti` absent is `missing_jti`; the
     check receives `jti` and refuses it: `replayed`. The check runs last,
     so it only ever sees tokens that passed every other rule and a
     denylist behind it never records a token refused for another
     reason. An exception out of the check is `internal`.
5. Only then are the claims returned.

`skew` defaults to 0. `max_token_bytes` defaults to 16384. `max_lifetime`
is unset by default; a verifier that sets it bounds how long any token it
accepts stays usable from now, whatever expiry the issuer wrote, which is
the usual issuer mistake. The audience
and issuer expectations are required unless `allow_any_audience()` and
`allow_any_issuer()` say otherwise; `exp` is required unless
`allow_missing_exp()`.

### 8.4 Text

Every string in a token is UTF-8. The claims writer emits it raw and
escapes only `"`, `\` and the control characters, so a payload reads as
written in any script: Latin with diacritics, Cyrillic, Greek, Arabic,
Hebrew, the CJK scripts, emoji, anything Unicode encodes. The reader
resolves escapes before anything is compared, so `"Pe\u00f1a"` and the
raw two-byte form of U+00F1 are the same claim. The token text itself
stays ASCII: the body and the footer are base64url, which survives HTTP
headers, cookies, URLs and every transport that would otherwise
normalise, re-encode or reject non-ASCII bytes and so break the tag.

Comparison is byte for byte, in constant time, with no normalisation.
U+00F1 (one code point) and U+006E U+0303 (n plus a combining tilde) are
different identifiers. An issuer must emit one form consistently; NFC is
the usual choice. The library does not normalise because a normaliser is
a large table that would have to be identical on both ends, and because
folding two spellings into one is exactly what an impersonation needs.

Identifiers are the claims that are compared for equality (iss, sub, aud,
jti), custom claim names, and key ids. An identifier must be well-formed
UTF-8 and must contain none of:

| class | code points |
|---|---|
| C0 and C1 controls | U+0000..U+001F, U+007F..U+009F |
| Default_Ignorable_Code_Point (Unicode 15.1) | U+00AD, U+034F, U+061C, U+115F..U+1160, U+17B4..U+17B5, U+180B..U+180F, U+200B..U+200F, U+202A..U+202E, U+2060..U+206F, U+3164, U+FE00..U+FE0F, U+FEFF, U+FFA0, U+FFF0..U+FFF8, U+1BCA0..U+1BCA3, U+1D173..U+1D17A, U+E0000..U+E0FFF |
| noncharacters | U+FDD0..U+FDEF and U+xxFFFE, U+xxFFFF in every plane |
| private use | U+E000..U+F8FF, U+F0000..U+10FFFF |

These are the characters that are invisible or that change how their
neighbours are displayed (zero-width spaces and joiners, bidi overrides,
soft hyphens, variation selectors, tags) or that have no agreed meaning
(noncharacters, private use). Two issuer strings that differ only by one
of them look identical to a reviewer and compare different, or the other
way round after a careless cleanup; a bidi override can make a subject
display reversed in a log. Every letter, digit, mark and symbol of every
script is accepted, including combining sequences. The policy is
checked on both sides: `Token::seal` and `Token::sign` return `argument`
for claims or a key id that break it, before anything is encrypted or
signed, and `Claims::from_json` returns `claims_malformed` after
authentication. `peek_key_id` returns nothing for such a key id. Custom
claim values are data, not identifiers, and may hold any valid UTF-8.

Lengths and limits count bytes, not characters.

## 9. Rationale: what changes from v4 and from cb1, and the attack each closes

| decision | v4.local / v4.public | cb1 | cb2 | closes |
|---|---|---|---|---|
| hash | BLAKE2b, two keyed calls per token | BLAKE3, two keyed calls | BLAKE3, one keyed XOF call for Ek, n2 and Ak | nothing new in security; halves the derivation cost and removes a second domain string that could be mis-set |
| derivation input | domain string plus nonce | domain string plus nonce | header plus nonce | binds the derived keys to the version and purpose: a cb2.local key schedule cannot be reproduced for another header, so a cross-purpose or cross-version key reuse yields unrelated keys |
| key commitment | Ak derived from K, committing | same | same, documented with its 2^128 bound | partitioning-oracle and multi-key attacks on non-committing AEAD |
| tag check before decrypt | yes | yes | yes, with the output region wiped on failure | chosen-ciphertext and decryption-oracle attacks; plaintext never exists on a failed path |
| one verdict | yes | yes | yes, plus `too_large` decided on length only | error oracles |
| public signature | Ed25519 | Ed25519 + ML-DSA-65 | Ed25519 + ML-DSA-65, both required | quantum forgery; the hybrid also survives a classical break of either scheme |
| PQ availability | n/a | compile-time option | compile-time option; the purpose is absent without it | silent downgrade to Ed25519-only |
| secret key form | 64 bytes | 4096 bytes without ml_pk | 6048 bytes carrying ml_pk | a secret key that cannot name its own public key, so a signer could bind the wrong key id |
| key types | raw byte spans | raw byte spans | LocalKey, PublicKey, SecretKey; no byte spans in the token API | algorithm and purpose confusion by passing one key to the other function |
| key id | footer by convention | footer by convention | bound by the library into `{"kid":...}` and compared in constant time | tokens accepted under a rotated or mis-selected key; timing on the id comparison |
| claims | none in the token layer | none | typed claims with a validator that requires exp by default | missing-expiry and missing-audience bugs, the most common real token failures |
| size limit | caller's problem | caller's problem | before any parsing | decompression-style and parser-cost denial of service |
| JSON | caller's problem | caller's problem | strict reader, numbers never converted | duplicate-key and coercion ambiguities between issuer and verifier |
| international text | UTF-8 accepted by the JSON grammar, nothing more | same | UTF-8 raw on the wire, escapes resolved before comparison, an identifier policy on both sides, no normalisation | identifiers that differ by an invisible or bidi character; tokens minted with text the verifier will refuse |
| nonce source | batched per-thread CSPRNG | same | `randombytes_buf` per token, no batch | the batch is a public buffer held for a long time; one call per token keeps no nonce state at all. Measured cost on this Mac: about 1.4 us per seal (README benchmark), which is the whole difference between cb2 and cb1 at seal time; open is at parity or faster |
| PAE | materialised head of 73 bytes | streamed | streamed through a 128-byte buffered sink; never materialised for the MAC | nothing new in security; one or two hasher updates instead of eleven |
| allocation | caller buffers | caller buffers | caller buffers plus convenience functions that allocate once | a convenience API that does not tempt callers into copying secrets |

## 10. Threat model

### Parties and trust

- Issuer: holds K or sk. Trusted.
- Verifier: holds K or pk, knows the expected footer, the implicit
  assertion and the validation rules. Trusted.
- Network and client: untrusted. Everything between issuer and verifier
  is attacker controlled, including the token text, its length and its
  timing of arrival.

### Attacker capabilities

The attacker sees every token, can submit any byte string to the
verifier any number of times, and can measure the verifier's response
code and wall-clock time. The attacker may hold other keys of the same
system (a tenant in a multi-tenant deployment) and may try to make one
token valid under two keys. The attacker may be a future adversary with a
cryptographically relevant quantum computer against tokens recorded now.

### AI-assisted attacker

The attacker is assumed to have language-model tooling that reads this
specification and the source, enumerates every parser branch, generates
malformed inputs at scale, and proposes side channels. The consequences
drawn for the design:

- Nothing is security-by-obscurity: the format, the order of checks and
  the single-verdict rule are published here so that automated review
  finds nothing a reviewer did not intend.
- The parsing surface before authentication is minimal and fuzzed: a
  header compare, a dot search, a strict table-driven decoder, a
  constant-time footer compare, a constant-time tag compare. The JSON
  reader never runs before authentication.
- Every comparison of secret-derived or key-identifying bytes is
  constant time by construction and reviewed as a list: tag
  (`crypto_verify_32`), footer and key id (`sodium_memcmp`), issuer,
  audience and subject (`sodium_memcmp`). Everything else compared is
  public token structure.
- Every failure path wipes; an attacker who provokes a failure cannot
  retrieve partial plaintext from the output buffer.
- No branch depends on secret data in cb2's own code; the primitives
  are libsodium's and BLAKE3's.

### Out of scope

Compromise of the verifier's host, a malicious build, a broken primitive
library, side channels inside libsodium, BLAKE3 or liboqs, physical
attacks, and the application's own authorisation logic.

## 11. Test hook

When `CB2_TEST_NONCE` is defined, `Local::seal_with_nonce_for_testing`
and `KeyWrap::wrap_with_nonce_for_testing` accept a caller-chosen nonce.
They exist to produce the known-answer vectors and must not be compiled
into a shipping build; the CMake target defines the macro for the test
and generator executables only, never for the library interface.

## 12. Open questions for the owner

1. Resolved: the headers are `cb2.local.` and `cb2.public.` and the key
   strings `kcb2.*`. The `v5` identifier the library first used is
   reserved by the PASETO developers for a future official version, and
   continuing CipherBird's own cb1 identifier removes the collision.
2. Whether cb2 should replace cb1 in the repository, sit beside it, or
   move to its own repository with its own release cadence.
3. Resolved: the ML-DSA half uses the FIPS 204 context string with the
   header `cb2.public.` as the context (section 5.2), through liboqs
   `OQS_SIG_sign_with_ctx_str`, which requires a liboqs that reports
   `sig_with_ctx_support` for ML-DSA-65 (0.12 and later).
4. Whether a `kcb2.seal` (local key sealed to a public key) should be added
   on top of the existing hybrid KEM of the repository.
5. Whether to batch nonces per thread as cb1 does. The benchmark shows
   the per-token `randombytes_buf` costs about 1.4 us per seal, so cb1
   seals a 64-byte token in 1.2 us and cb2 in 2.7 us; at 1 KiB the
   gap is the same 1.4 us and at 64 KiB it vanishes. Batching would
   close the gap at the price of a nonce buffer that lives in process
   memory and a fork handler. This implementation follows the owner's
   instruction to use `randombytes_buf` only.
6. Sender-constrained tokens: a `cnf` claim bound to a client key and a
   per-request proof of a new purpose, so that a stolen token is useless
   without the key. The design draft is docs/SENDER_CONSTRAINT.md; it is
   not implemented and nothing in the format changes until it is.
