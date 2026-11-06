# cb2 token protocol

Version 0.1.0. Status: a CipherBird proposal, not a standard.

cb2 stands for Cryptographically Bound tokens, version 2. The format is
also called BRACE (Bound, Rule-checked, Authenticated, Committing
Envelope). BRACE is a name, not an identifier: every header and key
string in this document is spelled with cb2 or kcb2, and an
implementation MUST NOT accept any other spelling.

This document is the normative definition of the cb2.local and cb2.public
token formats, the kcb2 key strings, the claims layer and the holder
proofs of sender-constrained tokens (section 13). It is written
for an implementer in any language who has not read the reference
implementation and does not intend to. Everything an implementation needs
to produce tokens the reference accepts, and to accept the tokens it
produces, is here or in a standard this document cites.

The rationale for each decision, the comparison with PASETO v4 and the
threat model are in SPEC.md. The guarantees and their assumptions are in
SECURITY.md. Neither is needed to implement the protocol. The test
vectors under tests/vectors are part of this specification; appendix A
defines their file format and appendix B walks through three of them
with every intermediate value.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read
as RFC 2119 and RFC 8174 describe when they appear in capitals.

A token, a message, a footer, an implicit assertion and a key are byte
strings. Lengths and limits count bytes, never characters. `a || b` is
concatenation. `len(x)` is the length of x in bytes. Hexadecimal in this
document and in the vectors is lowercase with no prefix.

The word invalid names one verdict. Every rejection that depends on the
bytes of a token that has not yet been authenticated MUST be reported as
that one verdict, with no further detail, to any party that could have
produced the token.

## 2. Primitives

cb2 defines no primitive of its own. Each one below is used exactly as
its cited definition states, with the parameters given.

| name | definition | parameters |
|---|---|---|
| BLAKE3-keyed(K, m, n) | BLAKE3 (Aumasson, Neves, O'Hearn, Wilcox-O'Hearn, specification version 1), keyed mode | 32-byte key K, n bytes of extendable output |
| BLAKE3(m, n) | BLAKE3, hash mode | n bytes of output |
| XChaCha20(k, n2, m) | draft-irtf-cfrg-xchacha: HChaCha20 of k and the first 16 bytes of n2, then ChaCha20 under the derived key with the last 8 bytes of n2 as nonce, block counter starting at 0 | 32-byte key k, 24-byte nonce n2; the output is m XOR keystream |
| Ed25519-sign, Ed25519-verify | RFC 8032 section 5.1, pure Ed25519 (no prehash, no context) | 32-byte public key, 64-byte signature |
| ML-DSA-65-sign(sk, m, ctx), ML-DSA-65-verify(pk, m, sig, ctx) | FIPS 204, ML-DSA-65, the external functions ML-DSA.Sign and ML-DSA.Verify with a context string | 1952-byte public key, 4032-byte private key, 3309-byte signature, ctx of at most 255 bytes |
| base64url | RFC 4648 section 5, no padding; see 3.3 for the decoding rules | |
| JSON | RFC 8259; see 9.2 for the reader rules | |
| RFC 3339 | RFC 3339 section 5.6; see 9.3 for the accepted and produced forms | |
| X-Wing (kcb2.seal only) | draft-connolly-cfrg-xwing-kem, on ML-KEM-768 (FIPS 203), X25519 (RFC 7748), SHA3-256 and SHAKE256 (FIPS 202); see 14.1 | 32-byte decapsulation key, 1216-byte encapsulation key, 1120-byte ciphertext, 32-byte shared secret |

Two notes on XChaCha20. The ChaCha20 step MAY be the original 64-bit
counter form or the RFC 8439 form with a 96-bit nonce whose first four
bytes are zero: for every message this protocol permits (at most 2^26
bytes, 2^20 blocks) the two produce the same keystream. The block
counter MUST start at 0.

ML-DSA-65 signing MAY be hedged (randomised) or deterministic; the
verifier does not distinguish them. A cb2.public token is therefore not
reproducible byte for byte, and the vectors record tokens that MUST
verify rather than tokens that MUST be reproduced.

## 3. Encodings

### 3.1 LE64

`LE64(n)` is the 8-byte little-endian encoding of the unsigned integer n
with the most significant bit of the last byte cleared. n is always below
2^63 in this protocol, so the clearing changes nothing; it is kept so
that the encoding is the one PASETO defines.

### 3.2 PAE

`PAE(p1, ..., pk)`, the pre-authentication encoding, is

```
LE64(k) || LE64(len(p1)) || p1 || ... || LE64(len(pk)) || pk
```

It is injective: no two different sequences of byte strings have the same
encoding, so a MAC or signature over PAE(...) binds every piece and the
boundaries between them.

### 3.3 base64url

Encoding is RFC 4648 section 5 without padding.

Decoding MUST be strict. A decoder MUST accept only the 64 characters
`A-Z`, `a-z`, `0-9`, `-` and `_`. It MUST reject `=`, whitespace, line
breaks and every other character. It MUST reject an input whose length is
1 modulo 4. It MUST reject an input whose final character sets bits that
the encoded byte string does not use (the low 2 bits of the last
character when the length is 3 modulo 4, the low 4 bits when it is 2
modulo 4). Under these rules every byte string has exactly one accepted
encoding.

`b64len(x)`, the length of the encoding of x bytes, is
`4 * floor(x / 3) + (x mod 3 == 0 ? 0 : x mod 3 + 1)`.

## 4. Token grammar and limits

```
token   = header body-text [ "." footer-text ]
header  = "cb2.local." | "cb2.public." | "cb2.holder-public."
body-text   = base64url(body)
footer-text = base64url(f)      ; present if and only if len(f) > 0
```

The header `cb2.local.` is 10 bytes, `cb2.public.` is 11 bytes and
`cb2.holder-public.` is 18 bytes. The body is defined per purpose in
sections 5, 6 and 13. The footer f is
authenticated but transmitted in clear. Every byte of a token after the
header is a base64url character or the single `.` that separates the
body from the footer.

A verifier is given the footer it expects and the implicit assertion i
it expects, both possibly empty. A token that carries a footer when the
expected footer is empty, that carries none when it is not, or that
carries a different one, is invalid. A verifier MUST NOT read the footer
out of the token and use it as the expected footer; the expected value
comes from the verifier's own configuration or from a key it has
selected (section 8).

The implicit assertion is never transmitted. Both ends agree on it out of
band. It is bound into the tag or signature exactly like the footer.

Limits. The message, the footer and the implicit assertion are each at
most 2^26 bytes. A token whose text implies a body or footer beyond that
is invalid by its length alone. An implementation that allocates on
behalf of the caller SHOULD refuse, before reading any byte, any token
longer than a configurable limit whose default is 2^20 bytes, with a
verdict (`too_large`) that depends on the length only. The claims layer
applies its own, smaller default of 16384 bytes (section 9.5).

## 5. cb2.local

### 5.1 Parameters

- K: a 32-byte key, uniformly random. An implementation MUST refuse to
  import a key whose 32 bytes are all equal; it is the one low-entropy
  key that can be recognised without knowing where the key came from.
- n: a 32-byte nonce, fresh from the operating system CSPRNG for every
  token. An implementation MUST NOT reuse a nonce under a key, MUST NOT
  derive it from a counter or a clock, and MUST fail rather than fall
  back to a weaker source.
- m: the message, 0 to 2^26 bytes.
- f: the footer, 0 to 2^26 bytes.
- i: the implicit assertion, 0 to 2^26 bytes.

### 5.2 Seal

```
h              = "cb2.local."
Ek || n2 || Ak = BLAKE3-keyed(K, h || n, 88)
                 Ek = bytes 0..31, n2 = bytes 32..55, Ak = bytes 56..87
c              = XChaCha20(Ek, n2, m)
t              = BLAKE3-keyed(Ak, PAE(h, n, c, f, i), 32)
body           = n || c || t
token          = h || base64url(body) [ || "." || base64url(f) ]
```

The PAE fed to the tag, byte for byte:

```
LE64(5)
LE64(10)      "cb2.local."
LE64(32)      n
LE64(len(c))  c
LE64(len(f))  f
LE64(len(i))  i
```

Body layout:

| offset | length | content |
|---|---|---|
| 0 | 32 | n |
| 32 | len(m) | c |
| 32 + len(m) | 32 | t |

The token text is `10 + b64len(64 + len(m))` bytes, plus
`1 + b64len(len(f))` when f is not empty. The shortest cb2.local token is
96 bytes (an empty message, no footer).

Ek, n2, Ak and the hasher states MUST be wiped after use.

### 5.3 Open

Given a token, K, the expected footer f and the implicit assertion i, in
this order, stopping at the first failure, every failure being invalid:

1. The token MUST begin with the 10 bytes `cb2.local.` and be longer than
   the header.
2. Split the rest at the first `.`. A `.` followed by nothing is invalid.
   The presence of a footer MUST agree with whether f is empty.
3. Decode the body with the strict decoder (3.3). A body shorter than 64
   bytes is invalid. n is the first 32 bytes, t the last 32, c the rest.
4. Decode the footer text with the strict decoder and compare it with f.
   The comparison MUST be constant time for equal lengths; a length
   difference MAY be decided at once, the lengths being public.
5. Derive Ek, n2 and Ak from K and the token's n as in 5.2.
6. Compute t' = BLAKE3-keyed(Ak, PAE(h, n, c, f, i), 32) with the expected
   f and i, and compare t' with t in constant time. A mismatch is invalid.
   Nothing has been decrypted at this point and nothing MUST be.
7. m = XChaCha20(Ek, n2, c).
8. Wipe Ek, n2, Ak and the hasher states. On any failure after step 6
   the implementation MUST also wipe any region that held plaintext.

An implementation MUST NOT expose a function that returns any part of the
message before step 6 has succeeded.

## 6. cb2.public

### 6.1 Keys

```
public key pk = ed_pk (32) || ml_pk (1952)                       = 1984 bytes
secret key sk = ed_sk (64) || ml_sk (4032) || ml_pk (1952)       = 6048 bytes
```

`ed_pk` and `ed_sk` are RFC 8032 Ed25519 keys, `ed_sk` being the 32-byte
seed followed by `ed_pk` (the form libsodium stores). `ml_pk` and `ml_sk`
are FIPS 204 ML-DSA-65 keys. The secret key carries `ml_pk` so that it
alone restores the pair and names its own key id.

An implementation that imports a secret key from bytes SHOULD check that
the public halves it carries belong to the secret halves: that `ed_pk`
equals the public key derived from the seed, and that `ml_pk` verifies a
signature `ml_sk` makes. The reference makes that ML-DSA probe signature
under the context string `kcb2.secret.self-test`, which no token uses, so
that the probe can never be mistaken for a token signature. The probe
message itself is not part of the protocol. A key that fails the check
MUST be refused.

There is no Ed25519-only form of any key and no Ed25519-only token. An
implementation without ML-DSA-65 has no cb2.public purpose.

### 6.2 Sign

```
h     = "cb2.public."
m2    = PAE(h, m, f, i)
sig   = Ed25519-sign(ed_sk, m2) || ML-DSA-65-sign(ml_sk, m2, ctx = h)
body  = m || sig
token = h || base64url(body) [ || "." || base64url(f) ]
```

The PAE, byte for byte:

```
LE64(4)
LE64(11)      "cb2.public."
LE64(len(m))  m
LE64(len(f))  f
LE64(len(i))  i
```

The ML-DSA half is ML-DSA.Sign(ml_sk, m2, ctx) with ctx the 11 header
bytes. Inside FIPS 204 the bytes that reach the lattice signature are
therefore `0x00 || 0x0b || "cb2.public." || m2`. A signature the same key
made over the same m2 under an empty or any other context is not a
cb2.public signature. Ed25519 has no context parameter; its half is bound
to the purpose by the header inside m2.

The signature is 64 + 3309 = 3373 bytes. Body layout:

| offset | length | content |
|---|---|---|
| 0 | len(m) | m, in clear |
| len(m) | 64 | Ed25519 signature |
| len(m) + 64 | 3309 | ML-DSA-65 signature |

The token text is `11 + b64len(len(m) + 3373)` bytes, plus
`1 + b64len(len(f))` when f is not empty. The shortest cb2.public token is
4509 bytes.

### 6.3 Verify

Given a token, pk, the expected footer f and the implicit assertion i:

1. The token MUST begin with the 11 bytes `cb2.public.`. Split, decode
   and compare the footer exactly as in 5.3 steps 2 to 4. A body shorter
   than 3373 bytes is invalid.
2. m is the body less its last 3373 bytes; sig is those bytes.
3. m2 = PAE(h, m, f, i) with the expected f and i.
4. Check Ed25519-verify(ed_pk, m2, sig[0..64)) and
   ML-DSA-65-verify(ml_pk, m2, sig[64..3373), ctx = h). Both MUST be
   evaluated and both MUST succeed. Any failure is invalid.

An implementation MUST NOT accept a token on the strength of one half,
whatever the other half's state, and MUST NOT offer a mode that skips
either half. An implementation MAY evaluate the halves in either order or
in parallel; it SHOULD NOT let the outcome of one half change whether the
other is evaluated if that difference is observable, since it reveals
which half failed.

The Ed25519 verifier MUST reject a signature whose S component is not
reduced modulo the group order, as RFC 8032 requires. It MAY apply
further checks such as rejecting small-order points; honest signatures
never trigger them, so interoperability is unaffected.

### 6.4 Why both halves are one signature

The key id of a public key (section 7) is a hash of the whole key, both
halves. A token is accepted only under the key whose id it was bound to,
and only when both halves verify under the matching halves of that key.
Replacing either half of the public key therefore changes the key id and
breaks one half of the signature; the vectors cb2-P-2 and cb2-P-3 record
both cases. An attacker who breaks one scheme still has to forge the
other over the same m2.

## 7. kcb2 key strings and key ids

| type | form | length |
|---|---|---|
| kcb2.local | `kcb2.local.` \|\| base64url(K) | 11 + 43 = 54 |
| kcb2.public | `kcb2.public.` \|\| base64url(pk) | 12 + 2646 = 2658 |
| kcb2.secret | `kcb2.secret.` \|\| base64url(sk) | 12 + 8064 = 8076 |
| kcb2.lid | `kcb2.lid.` \|\| base64url(BLAKE3(`kcb2.lid.` \|\| kcb2.local-string, 33)) | 9 + 44 = 53 |
| kcb2.pid | `kcb2.pid.` \|\| base64url(BLAKE3(`kcb2.pid.` \|\| kcb2.public-string, 33)) | 9 + 44 = 53 |
| kcb2.local-wrap | `kcb2.local-wrap.` \|\| base64url(n \|\| c \|\| t) | 16 + 128 = 144 |
| kcb2.recipient | `kcb2.recipient.` \|\| base64url(X-Wing encapsulation key, 1216 bytes) | 15 + 1622 = 1637 |
| kcb2.recipient-secret | `kcb2.recipient-secret.` \|\| base64url(X-Wing decapsulation key, 32 bytes) | 22 + 43 = 65 |
| kcb2.rid | `kcb2.rid.` \|\| base64url(BLAKE3(`kcb2.rid.` \|\| kcb2.recipient-string, 33)) | 9 + 44 = 53 |
| kcb2.seal | `kcb2.seal.` \|\| base64url(ct \|\| n \|\| c \|\| t), section 14 | 10 + 1622 = 1632 |

A key string MUST be decoded with the strict decoder and MUST have
exactly the length in the table. The id of a key is the hash of the id
header followed by the full key string, text included, not of the raw
key bytes. A secret key's id is the id of its public key.

kcb2.local-wrap is the cb2.local construction of section 5 with the
16-byte header `kcb2.local-wrap.` in place of `cb2.local.` in the key
derivation input, in the PAE and in the text, the 32-byte key to wrap as
the message, an empty footer and an empty implicit assertion. The PAE
begins `LE64(5) || LE64(16) || "kcb2.local-wrap."`. A wrapped key is not
a cb2.local token of the key bytes and cannot be opened as one, nor the
other way round, because the header differs in the derivation.

## 8. Key ids and the footer

Every key MAY carry a key id, a UTF-8 string that satisfies the
identifier policy of 9.4. When nothing else is set, the id is the key's
kcb2.lid or kcb2.pid.

The claims layer (section 9) binds the key id into the footer as the
JSON object `{"kid":"<id>"}` with the id written as a JSON string (see
9.1 for the escaping) and nothing else in the footer. A key with no id
produces a token with no footer.

On the verifying side the footer is rebuilt from the verifier's own key
and compared as in 5.3 step 4. A token therefore opens only under a key
with the same id, even when two keys share bytes, and a token minted
under a key with an id does not open under the same bytes with no id.

An implementation MAY read the id out of a token before verifying it, to
choose a candidate key. It MUST treat that value as unverified: it is
good for selecting a key and for nothing else, and the binding is checked
during authentication. The reference bounds the token by the claims
layer's size limit, splits at the first `.`, decodes the footer strictly,
parses it as JSON, and returns the `kid` member only when it is a string
that satisfies 9.4.

## 9. Claims layer

The claims layer defines what the message of a token is when the token
carries claims, and how a verifier validates them. It is built on
sections 5 and 6 without changing them: a claims token is a cb2.local or
cb2.public token whose message is the payload of 9.1 and whose footer is
the key id binding of section 8.

### 9.1 Payload

The payload is one JSON object (RFC 8259) encoded in UTF-8. The
registered claims are all strings:

| claim | meaning | format |
|---|---|---|
| iss | issuer | identifier (9.4) |
| sub | subject | identifier |
| aud | audience | identifier |
| exp | expiration | RFC 3339 (9.3) |
| nbf | not before | RFC 3339 |
| iat | issued at | RFC 3339 |
| jti | token id | identifier |
| cnf | the key this token is bound to (section 13) | identifier |

Every other member is a custom claim. Its name is an identifier (9.4) and
its value MAY be any JSON value, nested at most 15 levels deep (9.2). An
issuer MUST NOT write a custom claim whose name is empty or is one of the
registered names.

An issuer MUST write the payload with no whitespace outside strings, the
registered claims first in the order of the table above (absent ones
omitted, cnf last of them), then the custom claims in insertion order. A string is written
with `"` as `\"`, `\` as `\\`, U+0008, U+000C, U+000A, U+000D and U+0009
as `\b`, `\f`, `\n`, `\r` and `\t`, every other code point below U+0020
as `\u00XX` with lowercase hex, and everything else, including U+007F and
every non-ASCII code point, as raw UTF-8. A verifier MUST accept any
RFC 8259 spelling of the same object (whitespace, member order, escapes),
and MUST compare claims after escapes are resolved; `"Pe\u00f1a"` and the
raw two-byte form of U+00F1 are the same claim. The ordering and escaping
rules bind the issuer so that the vectors are reproducible.

### 9.2 Reader

A verifier's JSON reader MUST accept exactly RFC 8259 and nothing more,
and MUST reject:

- any byte outside a string that is not JSON syntax or one of the four
  JSON whitespace characters;
- a string with an invalid escape, an unpaired surrogate escape, a raw
  control character, or raw bytes that are not well-formed UTF-8 (overlong
  forms, surrogates, values above U+10FFFF);
- a number that does not match the RFC 8259 grammar (a leading `+`, a
  leading zero before another digit, a trailing `.`, a missing fraction
  digit, a hex literal). Numbers MUST be kept as text; a verifier MUST
  NOT convert them, so no coercion is possible;
- an object with two members of the same name;
- nesting deeper than 16 levels counting the payload object itself, so
  that a custom claim value nests at most 15 deep;
- anything before or after the one value.

A registered claim that is not a string, or a time claim that is not
valid RFC 3339, makes the payload malformed.

### 9.3 Time

A time claim is an RFC 3339 date-time. Accepted:
`YYYY-MM-DDTHH:MM:SS`, an optional `.` followed by one or more fraction
digits (ignored), then `Z` or `+HH:MM` or `-HH:MM`; `T` and `Z` MAY be
lowercase. The year is four digits; the month, day, hour and minute MUST
be in range (the day against the month and leap years); the second MAY
be 60. The offset hours MUST be at most 23 and the minutes at most 59.
Nothing else is accepted: no date without time, no missing offset, no
space in place of `T`.

Produced: `YYYY-MM-DDTHH:MM:SS+00:00`, the form the PASETO vectors use.
Comparison is on the instant: `2023-11-14T23:13:20+00:00` and
`2023-11-15T01:13:20+02:00` are the same time.

### 9.4 Identifiers

An identifier is one of: the claims iss, sub, aud and jti; a custom claim
name; a key id. An identifier MUST be well-formed UTF-8 and MUST contain
none of these code points:

| class | code points |
|---|---|
| C0 and C1 controls | U+0000..U+001F, U+007F..U+009F |
| Default_Ignorable_Code_Point (Unicode 15.1) | U+00AD, U+034F, U+061C, U+115F..U+1160, U+17B4..U+17B5, U+180B..U+180F, U+200B..U+200F, U+202A..U+202E, U+2060..U+206F, U+3164, U+FE00..U+FE0F, U+FEFF, U+FFA0, U+FFF0..U+FFF8, U+1BCA0..U+1BCA3, U+1D173..U+1D17A, U+E0000..U+E0FFF |
| noncharacters | U+FDD0..U+FDEF and U+xxFFFE, U+xxFFFF in every plane |
| private use | U+E000..U+F8FF, U+F0000..U+10FFFF |

Every letter, digit, mark and symbol of every script is accepted,
including combining sequences. The policy MUST be applied on both sides:
an issuer MUST refuse to mint a token whose identifiers or key id break
it, and a verifier MUST treat a payload that breaks it as malformed, after
authentication. A custom claim's value is data, not an identifier, and
MAY hold any well-formed UTF-8.

Identifiers are compared byte for byte, with no Unicode normalisation,
in constant time for equal lengths. U+00F1 and U+006E U+0303 are
different identifiers. An issuer SHOULD emit one form consistently; NFC
is the usual choice.

### 9.5 Verifier rules

A verifier holds a set of rules. The rules carry:

| rule | default | meaning |
|---|---|---|
| now | the verifier's clock | the instant validation is performed at |
| clock skew | 0 | tolerance in seconds on exp, nbf and iat |
| require exp | true | a token without exp is refused |
| expected audience | required | aud MUST equal it, or the rules say explicitly that any audience is accepted |
| expected issuer | required | iss MUST equal it, or the rules say explicitly that any issuer is accepted |
| expected subject | none | when set, sub MUST equal it |
| max lifetime | none | when set, exp MUST NOT lie more than this many seconds after now |
| replay check | none | when installed, receives jti and may refuse it |
| max token bytes | 16384 | tokens longer than this are refused unread |

Rules that neither name an expected audience nor say explicitly that any
audience is accepted are incomplete; the same for the issuer. A verifier
MUST refuse to validate with incomplete rules, before reading the token.
This is the one bypass a correctly built token offers, a verifier that
never said which service it is, and it is closed by default.

### 9.6 Validation order

Opening a claims token performs, in this order, stopping at the first
failure:

0. The rules MUST be complete (9.5); otherwise `rules_incomplete`. The
   verifier's own key id, if any, and every expected issuer, audience and
   subject MUST satisfy 9.4; otherwise `argument`. Both verdicts depend on
   the verifier alone.
1. A token longer than max token bytes is `too_large`. Nothing in it has
   been read.
2. Authentication: section 5.3 or 6.3 with the footer rebuilt from the
   key id (section 8). Any failure is `invalid`.
3. Parsing: 9.2, then the identifier policy of 9.4 on iss, sub, aud, jti
   and every custom claim name. Any failure is `claims_malformed`.
4. Validation against the rules, with t = now and s = clock skew:
   - exp absent and exp required: `missing_exp`
   - exp present and exp <= t - s: `expired`
   - nbf present and nbf > t + s: `not_yet_valid`
   - iat present and iat > t + s: `issued_in_future`
   - a maximum lifetime L set, exp present and exp > t + L:
     `lifetime_exceeded`
   - an expected issuer, audience or subject absent from the token or
     different from the expectation: `issuer_mismatch`,
     `audience_mismatch`, `subject_mismatch`, in that order
   - with a replay check installed: jti absent is `missing_jti`; the check
     receives jti and refuses it: `replayed`. The check runs after the
     bindings, so it sees only tokens that passed every other rule.
5. The sender constraint of section 13.5: nothing for a token without
   cnf unless the rules require one, otherwise the holder proof is
   checked under the key cnf carries.
6. Only then are the claims released to the caller.

An implementation MUST NOT offer a function that returns claims from a
token that has not been authenticated.

## 10. Verdicts

The names below are the ones the vectors use. An implementation MAY name
its errors differently but MUST preserve the distinctions and, above all,
MUST NOT split `invalid`.

| verdict | depends on | meaning |
|---|---|---|
| invalid | the token | any failure of 5.3, 6.3 or the footer and key id binding |
| too_large | the token's length only | longer than the limit in force |
| argument | the caller | wrong key size, weak key, inconsistent secret key, an identifier or key id that breaks 9.4 on the issuing side, a verifier expectation that breaks 9.4, oversize inputs, a bad buffer |
| rules_incomplete | the verifier | no audience or issuer expectation and no explicit allowance |
| internal | the implementation | a primitive failed |
| unavailable | the build | ML-DSA-65 is not present |
| claims_malformed | the authenticated payload | 9.2 or 9.4 failed after authentication |
| missing_exp, expired, not_yet_valid, issued_in_future, lifetime_exceeded, issuer_mismatch, audience_mismatch, subject_mismatch, missing_jti, replayed | the authenticated claims and the rules | 9.6 step 4 |
| missing_cnf, missing_proof | the authenticated claims and the rules | 13.5 step 1 |
| proof_invalid | the proof | any failure before the proof authenticates, 13.5 step 3 |
| proof_malformed, proof_expired, proof_mismatch, proof_replayed | the authenticated proof and the rules | 13.5 step 4 |

## 11. Versioning

Nothing about the algorithms is negotiated in a token. The header is the
whole description of how a token was made. A change to any primitive,
parameter, derivation, encoding or layout in sections 2 to 7 MUST produce
a new header (cb3 and kcb3), never a new field, flag or claim inside a
cb2 token. A verifier MUST reject a header it does not implement with the
verdict invalid, and MUST NOT accept a cb2 token under the rules of any
other header, including PASETO's v3 and v4 and CipherBird's cb1.

## 12. Security considerations

The threat model is SPEC.md section 10 and the claims are SECURITY.md;
this section only lists what an implementer MUST get right beyond the
steps above.

- Constant time. The tag comparison (5.3 step 6), the footer comparison,
  and the comparison of key ids, issuer, audience and subject MUST not
  leak, through timing, how many bytes matched. Lengths are public.
- Order. The tag MUST be checked before anything is decrypted; the
  payload MUST be parsed only after authentication; the size limit MUST
  be applied before anything is read.
- Wiping. Derived keys, hasher states, secret keys and any plaintext
  produced on a path that then fails MUST be wiped. Key material SHOULD
  also be locked against swapping and excluded from core dumps where the
  platform allows. Claims handed to the application are the
  application's data; an implementation need not wipe them, and MUST say
  so if it does not.
- Nonces. 32 random bytes per token from the operating system. No
  counters, no batching that keeps a nonce buffer in process memory, no
  fallback.
- Key commitment. Ak is a pseudorandom function of K and n, so a tag
  commits a token to one key; an implementation MUST NOT replace the
  keyed BLAKE3 tag with a polynomial MAC such as Poly1305, which would
  lose this.
- Key ids are public. A key with little entropy can be tested against one
  token at the cost of one short hash per guess; keys MUST be uniformly
  random, and a key that for some reason is not SHOULD carry an opaque
  explicit id instead of its kcb2.lid.
- Sizes. A cb2.public token is at least 4509 bytes before any claims and
  does not fit a browser cookie with room to spare. The local purpose is
  the one for session tokens; the public purpose is for service to
  service use and for anything whose verifier must not hold the issuing
  key.

## 13. Holder proofs: sender-constrained tokens

A token whose payload carries the registered claim `cnf` is
sender-constrained: a verifier accepts it only together with a holder
proof, a token of purpose `cb2.holder-public.` that the presenter made
under the key `cnf` names, for this request and for this very access
token. The token alone is then no more useful to a thief than a public
key. The design and its rationale are in SENDER_CONSTRAINT.md; this
section is the normative part.

### 13.1 The cnf claim

`cnf` is a registered claim, a string subject to 9.4, written after jti.
Its value is a key string:

- `kcb2.public.` followed by 2646 base64url characters: the client's
  whole hybrid public key, as section 7 writes it. The token carries the
  key, not its id, so a verifier needs no key store and consults nothing
  the client presents: the key arrives under the issuer's tag or
  signature.
- `kcb2.local.` followed by 43 base64url characters: reserved for the
  symmetric holder mode, which this version does not define. A verifier
  MUST treat it as `claims_malformed` in a cb2.public token, where the
  key would be in clear, and as `unavailable` in a cb2.local token.

Any other value is `claims_malformed` when the constraint is checked.

### 13.2 The request and the target

A proof names the request it is for: `htm`, the HTTP method, compared
byte for byte and uppercase by convention; `htu`, the request target
after the normalisation below; and `nonce`, present only when the
verifier handed one out. The names are those of RFC 9449 so that their
meaning needs no new definition. A verifier that is not an HTTP resource
defines what `htm` and `htu` mean for it and says so; both are required
all the same, since a proof that does not say what it is for can be
replayed against anything.

Target normalisation, applied by the client before writing `htu` and by
the verifier to its own request before comparing: the query and the
fragment are removed; the scheme and the host are lowercased; a port
that is the scheme's default (80 for http, 443 for https) is removed; an
empty path is written as `/`; the path is otherwise kept exactly as
sent, percent-encoding included; nothing else changes. A URI without a
scheme and a host, with userinfo, or with a port that is not all digits
has no normal form and MUST be refused: by the client as `argument`, by
the verifier as `argument` before the proof is read. The result is
compared byte for byte in constant time.

### 13.3 Proof claims

The payload of a proof is a claims object under 9.1 and 9.2:

| claim | required | meaning |
|---|---|---|
| jti | yes | a fresh id per proof, for the proof replay check |
| iat | yes | when the proof was made |
| exp | yes | when it stops being valid; the client writes iat plus a lifetime of at most the verifier's proof lifetime, 60 seconds by default |
| htm | yes | the method, as a custom string claim |
| htu | yes | the normalised target, as a custom string claim |
| nonce | when the verifier uses nonces | the verifier's nonce, as a custom string claim |

The client writes the registered claims in the order of 9.1 and then
htm, htu and nonce in that order, so that a proof's payload is
reproducible.

### 13.4 Making a proof

```
h      = "cb2.holder-public."
f      = {"kid":"<kcb2.pid of the client key>"}        (section 8, the key's default id)
i      = the complete text of the access token
proof  = the construction of section 6.2 with header h, message = the payload of 13.3, footer f, implicit assertion i
```

The header is the domain string everywhere section 6 uses the header:
in the PAE, in the ML-DSA context string and in the text. A proof
therefore never verifies as a cb2.public token and a cb2.public token
never verifies as a proof, under the same key. The implicit assertion
ties the proof to one access token without carrying a hash of it; the
verifier holds that text and nothing is sent twice.

### 13.5 Verifying

The verifier's rules gain:

| rule | default | meaning |
|---|---|---|
| holder proof | none | the proof presented with the request, together with the request's method, target and nonce |
| proof lifetime | 60 seconds | the most exp - iat a proof may claim, and the most exp may lie after now plus the clock skew |
| proof replay check | none; REQUIRED when a proof is given | receives the proof's jti and refuses one it has seen within the proof lifetime |
| require sender constraint | false | a token without cnf is refused |
| ignore sender constraint | false | cnf is not checked and no proof is needed; MUST be said explicitly |

Rules that carry a proof without a proof replay check, or that both
require and ignore the constraint, are incomplete (`rules_incomplete`,
9.6 step 0).

Step 5 of 9.6, stopping at the first failure:

1. If the rules ignore the constraint, release. Otherwise cnf absent:
   `missing_cnf` when required, else release as a bearer token. cnf
   present and no proof in the rules: `missing_proof`.
2. Classify cnf as 13.1 says; import the `kcb2.public` key; a string of
   the wrong length or encoding is `claims_malformed`.
3. Verify the proof as a `cb2.holder-public.` token under that key with
   the footer rebuilt from the key's default id and the implicit
   assertion set to the access token text, bounded first by the same
   size limit as the access token. Every failure that depends on the
   proof's bytes, the size included, is `proof_invalid`, one verdict.
4. Parse the proof claims under 9.2 and 9.4; failure, or jti, iat, exp,
   htm or htu absent or not strings: `proof_malformed`. Then, with
   t = now, s = the clock skew and L = the proof lifetime:
   - exp <= t - s, or iat > t + s, or exp - iat > L, or exp > t + s + L:
     `proof_expired`
   - htm different from the request's method, or htu different from
     the request's normalised target, or, when the verifier has a nonce,
     nonce absent or different: `proof_mismatch`, compared in constant
     time
   - the proof replay check refuses jti: `proof_replayed`
5. Release the claims of the access token.

A verifier MUST NOT accept a proof whose implicit assertion is anything
but the access token it arrived with, MUST NOT accept a proof under a key
other than the one cnf carries, and MUST NOT skip the replay check: the
proof lifetime is the only thing that bounds the replay store, and
without the store a captured request can be replayed for that long.

### 13.6 Issuance

How the client's key reaches the issuer is outside the token format, as
key distribution is for the rest of cb2. The shape is: the client sends
its `kcb2.public` string with the token request together with a proof
over that request, a `cb2.holder-public.` token with the token
endpoint's htm and htu, a fresh jti and an empty implicit assertion, so
that the issuer binds only a key the client demonstrably holds. The
issuer writes the whole key string into cnf. A new token means a new
binding; a client key is never carried from one token to the next.

## 14. kcb2.seal: a local key sealed to a recipient

A kcb2.seal string carries a 32-byte local key to one recipient: whoever
holds the recipient's secret recovers the key, nobody else does, and the
string may travel over any channel. It is the post-quantum counterpart
of PASERK's k4.seal.

### 14.1 Recipient keys

The recipient key pair is X-Wing (draft-connolly-cfrg-xwing-kem), the
hybrid of ML-KEM-768 and X25519, used exactly as that document defines
it and nothing else: the 32-byte decapsulation key expands through
SHAKE256 to the ML-KEM-768 seed and the X25519 secret; the
encapsulation key is pk_M (1184 bytes) || pk_X (32); a ciphertext is
ct_M (1088) || ct_X (32); the shared secret is SHA3-256 of ss_M, ss_X,
ct_X, pk_X and the six-byte X-Wing label. An implementation MUST
reproduce the draft's test vectors (tests/vectors/xwing) before anything
below means anything. Only the 32-byte decapsulation key is ever
serialised (kcb2.recipient-secret); the expanded form MUST NOT be
transmitted, as the draft says.

An X25519 result of all zero bytes (a low-order peer point) MUST be
refused, on both sides.

### 14.2 Sealing

```
(ss, ct) = X-Wing.Encapsulate(pk)                       ct 1120 bytes, ss 32 bytes
h        = "kcb2.seal."                                  (10 bytes)
n        = 32 random bytes
body     = the cb2.local construction of section 5.2 with header h, key ss,
           message = the 32 key bytes, footer empty, implicit assertion ct:
           n || c || t                                   96 bytes
string   = h || base64url(ct || n || c || t)             1632 characters
```

The header is the domain string in the key derivation and the PAE, so
the body is not a cb2.local token of the key bytes nor a kcb2.local-wrap
string, and the KEM ciphertext is the implicit assertion, so the tag
covers it as well as the key. The PAE begins
`LE64(5) || LE64(10) || "kcb2.seal." || LE64(32) || n || LE64(32) || c || LE64(0) || LE64(1120) || ct`.

### 14.3 Unsealing

1. The string MUST be exactly 1632 characters and begin with
   `kcb2.seal.`; its remainder MUST decode strictly to 1216 bytes.
   Otherwise invalid.
2. ct is the first 1120 bytes; ss = X-Wing.Decapsulate(ct, sk). A
   decapsulation failure is invalid.
3. Open the 96-byte body as section 5.3 steps 5 to 8 with header h, key
   ss, footer empty and implicit assertion ct. A tag mismatch is
   invalid; nothing is decrypted before it.
4. The 32 bytes are the local key; an all-equal key is refused as
   invalid, as section 5.1 requires of any import. The key carries its
   default id.

Every failure that depends on the string's bytes is the single verdict
invalid. ML-KEM decapsulation never fails on a malformed ciphertext, by
its construction; it returns an implicit-rejection secret and the tag
check refuses the result, which is what makes the single verdict hold.

## Appendix A. Test vector files

The files under tests/vectors are JSON, UTF-8 encoded, written by the
reference's `cb2_gen_vectors` program and checked by its test suite on
every build. A string field whose value is a byte string (payload,
footer, implicit assertion, key id) is the UTF-8 of that byte string after
JSON unescaping. A field named as hex holds lowercase hexadecimal.

Three files hold tokens that an implementation MUST reproduce or accept;
the fourth holds key strings. Every file has `name` and `generator`
members and the members below.

### A.1 cb2_local.json

`tests`: an array of objects. Each has `name`, `expect-fail` (boolean),
`key` (hex, 32 bytes), `token`, `footer` and `implicit-assertion`.

A success vector (`expect-fail` false) adds `nonce` (hex, 32 bytes),
`payload`, and the intermediate values `ek`, `n2`, `ak` (hex, 32, 24 and
32 bytes), `ciphertext` (hex), `pae` (hex, the bytes the tag is computed
over) and `tag` (hex, 32 bytes). An implementation MUST reproduce `token`
byte for byte from `key`, `nonce`, `payload`, `footer` and
`implicit-assertion`, MUST open it to `payload`, and SHOULD check each
intermediate value in order (key split, ciphertext, PAE, tag) to locate a
divergence.

A failure vector (`expect-fail` true) adds `reason`. Opening `token`
under `key` with the given footer and implicit assertion MUST yield
invalid.

`tamper`: an object with `key`, `footer`, `implicit-assertion`, a `token`
that opens, and `cases`, an array of `{position, token}` in which one
character of the token at `position` was changed. Every case MUST yield
invalid.

`weak-keys`: an array of `{key, expect, reason}`. Importing `key` MUST
fail with the verdict `expect`.

### A.2 cb2_public.json

`note` records that tokens are checked, not reproduced.

`tests`: an array of objects with `name`, `expect-fail`, `public-key`
(hex, 1984 bytes), `token`, `footer` and `implicit-assertion`.

A success vector adds `secret-key` (hex, 6048 bytes), `payload`, `pae`
(hex, the m2 of 6.2) and `ed25519-signature` (hex, 64 bytes). An
implementation MUST verify `token` under `public-key` to `payload`. It
SHOULD recompute `pae`, check that the 64 bytes after the message in the
decoded body equal `ed25519-signature`, and check that this half verifies
over `pae` under the first 32 bytes of `public-key`. Ed25519 is
deterministic, so an implementation that signs `pae` with the first 64
bytes of `secret-key` MUST produce that same half. It SHOULD also sign
`payload` with `secret-key` and verify the result under `public-key`.

A failure vector adds `reason`; verifying `token` under `public-key` MUST
yield invalid. Two of them, cb2-P-2 and cb2-P-3, carry a public key with
one half replaced.

`tamper`: as in A.1 with `public-key` in place of `key`; `note` says
which positions are sampled.

`rejected-secret-keys`: an array of `{name, secret-key, expect, reason}`
in which one bit of a valid secret key was flipped. Importing
`secret-key` MUST fail with the verdict `expect`.

### A.3 claims.json

`tests`: an array of objects with `name`, `purpose` (`local` or
`public`), `payload` (the exact text the issuer wrote), `token`,
`implicit-assertion`, `rules` and `expect` (a verdict name of section
10, or `ok`).

A `local` vector has `key` (hex) and `nonce` (hex) and MAY have `key-id`,
the issuer's explicit key id; without it the issuer's id is the key's
kcb2.lid. The footer of the token is the section 8 binding of that id.
An implementation MUST reproduce `token` from `key`, `nonce`, `payload`,
that footer and `implicit-assertion`.

A `public` vector has `public-key` (hex) and no nonce; the token is
verified, not reproduced.

`verifier-key-id`, when present, is the key id the verifier's key
carries; without it the verifier uses the default id of the same key.
A vector whose verifier id differs from the issuer's expects `invalid`.

`payload-canonical`, when present, is the text a conforming issuer writes
for the same claims; it is what the verifier's claims serialise back to
after a successful open. Without it the canonical text is `payload`.

`rules` is an object with `now` (Unix seconds), `require-exp`,
`require-audience`, `require-issuer` (booleans), `clock-skew` (seconds)
and optionally `issuer`, `audience`, `subject`, `max-token-bytes` and
`seen-jti` (an array of ids a replay check refuses; an empty array
installs a check that accepts every id). A false `require-audience` or
`require-issuer` is the explicit allowance of 9.5.

Opening `token` under the verifier's key with `rules` and
`implicit-assertion` MUST yield `expect`; on `ok` the claims MUST
serialise to the canonical text.

### A.4 paserk.json

`local`: `key` (hex), `kcb2.local` and `kcb2.lid`.
`local-wrap`: `wrapping-key` (hex), `key` (hex), `nonce` (hex) and
`kcb2.local-wrap`, which MUST be reproduced from those and MUST unwrap to
`key`.
`public`: `public-key` (hex), `secret-key` (hex), `kcb2.public`,
`kcb2.pid` and `kcb2.secret`, all of which MUST be reproduced from the
hex.

### A.5 proofs.json

`issuer` and `audience` are the expectations every test's rules carry.
`client-public-key` and `stranger-public-key` are hex.

`access-tokens`: an object with `local`, `bearer` and `public`. A local
entry has `purpose` `local`, `key` (hex), `nonce` (hex), `payload` and
`token`, and MUST be reproduced from them with the footer of section 8
for the key's default id; `local` carries cnf and `bearer` does not. The
`public` entry has `purpose` `public`, `issuer-public-key` (hex),
`payload` and `token`, verified not reproduced.

`tests`: objects with `name`, `access-token` (a key of `access-tokens`),
`proof` (the proof text, or empty for none), `request` (`htm`, `htu` and
optionally `nonce`), `rules` (`now`, `clock-skew`, `proof-lifetime`,
`seen-jti`, `require-cnf`, `ignore-cnf`) and `expect`. Opening the
access token under its key with rules that expect `issuer` and
`audience`, carry the proof and the request when `proof` is not empty,
and refuse the ids in `seen-jti`, MUST yield `expect`.

`intermediates`: for the proof of cb2-H-1, `claims` (its payload),
`footer`, `implicit-assertion` (the local access token), `pae` (hex)
and `ed25519-signature` (hex), checked as A.2 describes with the
`cb2.holder-public.` header.

`normalisation`: objects with `input` and `output`, the latter null when
the input has no normal form (13.2).

### A.6 seal.json

`recipient`: `secret` (hex, the 32-byte X-Wing decapsulation key, the
first vector of tests/vectors/xwing), `public-key` (hex, 1216 bytes),
and the strings `kcb2.recipient-secret`, `kcb2.recipient` and
`kcb2.rid`, all of which MUST be reproduced.

`sealed`: `key` (hex, the local key), `eseed` (hex, the 64-byte X-Wing
encapsulation randomness), `nonce` (hex), `ct` (hex, the ciphertext
Encapsulate produces from `eseed`), `ss` (hex, the shared secret) and
`kcb2.seal`, which MUST be reproduced byte for byte from `key`,
`eseed` and `nonce` under the recipient, and MUST unseal to `key`.

`failures`: objects with `name`, `recipient-secret` (hex), `kcb2.seal`
and `reason`; unsealing MUST yield invalid.

## Appendix B. Worked examples

### B.1 cb2-E-10: the shortest cb2.local token

```
K  = 707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f
n  = 26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2
m  = (empty)   f = (empty)   i = (empty)

BLAKE3-keyed(K, "cb2.local." || n, 88) =
Ek = 27a7279024d2c5d25eea2474126148a08409634a60348e1887561ea49a051f5a
n2 = 5a84ee0e8d6661110ea68949399c3a382968bf03c7fd9e38
Ak = 65e4d7c4c176cb1e1cc956b5659a919bb8049b882d4e1981a5ddc98cb9629721

c  = (empty)

PAE("cb2.local.", n, c, f, i) =
0500000000000000                   LE64(5)
0a00000000000000 6362322e6c6f63616c2e   LE64(10) "cb2.local."
2000000000000000 26f7...f7f2       LE64(32) n
0000000000000000                   LE64(0)  c
0000000000000000                   LE64(0)  f
0000000000000000                   LE64(0)  i

t  = BLAKE3-keyed(Ak, PAE, 32)
   = c6acefc7f30c4cf038fa0bad920bb2df2abb230e7d66935fdef0ac8f362d3e5a

body  = n || t   (64 bytes)
token = cb2.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LGrO_H8wxM8Dj6C62SC7LfKrsjDn1mk1_e8KyPNi0-Wg
        (96 bytes)
```

### B.2 cb2-E-11: one byte of message, footer and implicit assertion

Same K and n as B.1, so the same Ek, n2 and Ak.

```
m  = "x" (78)   f = "f" (66)   i = "i" (69)

c  = XChaCha20(Ek, n2, m) = 88

PAE("cb2.local.", n, c, f, i) =
0500000000000000
0a00000000000000 6362322e6c6f63616c2e
2000000000000000 26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2
0100000000000000 88
0100000000000000 66
0100000000000000 69

t  = ec45a566ae388090690c97ed23b8d42aa02acd0d615c5fe69ec6a7c67ceebeb8

body  = n || 88 || t   (65 bytes)
token = cb2.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_KI7EWlZq44gJBpDJftI7jUKqAqzQ1hXF_mnsanxnzuvrg.Zg
        (100 bytes: 10 header, 87 body text, 1 dot, 2 footer text)
```

The first 42 characters of the body text are the same in both tokens:
they encode the shared nonce; the 43rd mixes its last bits with the
first byte after it.

### B.3 cb2-S-5: the Ed25519 half of a cb2.public signature

The keys are in cb2_public.json; the message, footer and implicit
assertion are the same one-byte strings as B.2.

```
m2 = PAE("cb2.public.", m, f, i) =
0400000000000000
0b00000000000000 6362322e7075626c69632e      LE64(11) "cb2.public."
0100000000000000 78
0100000000000000 66
0100000000000000 69

Ed25519-sign(ed_sk, m2) =
335f3068427625a618a621c6d823c7e8bc1f71383ebb995c3a0373587e9d56c8
9ccbeee0607208ef5dc835c7e957bf7aea06d197a8ed9d7d233b97e59bb95c05

ML-DSA-65-sign(ml_sk, m2, ctx = "cb2.public.") = 3309 bytes, randomised

body  = 78 || ed_sig || ml_sig   (3374 bytes)
token = cb2.public.eDNf...   (4513 bytes: 11 header, 4499 body text, ".Zg")
```

The ML-DSA half in the file verifies under the ML-DSA half of
`public-key` with the 11 header bytes as context; a fresh signing
produces a different ML-DSA half that verifies equally.

## Appendix C. Conformance checklist

An implementation conforms when all of the following hold. A second
implementation of this document exists for that purpose:
`tools/check_vectors.py`, written in Python from this document alone,
without reading the reference, runs items 1 to 7 and 10 to 12 against
the vectors with the blake3 and pynacl packages, the ML-DSA-65 half
with dilithium-py and X-Wing's ML-KEM-768 with kyber-py when they are
installed. The repository's CI runs it on every push with all four
packages pinned, and fails when any check
fails or is skipped, so the reference and this document cannot drift
apart unnoticed.

1. Every success vector in cb2_local.json and every local vector in
   claims.json is reproduced byte for byte and opens to its payload;
   every intermediate value matches.
2. Every success vector in cb2_public.json and every public vector in
   claims.json verifies to its payload; the Ed25519 half matches and
   verifies over the recorded PAE; signing the payload again produces a
   token that verifies.
3. Every failure vector, every tamper case, every weak key and every
   rejected secret key is refused with the recorded verdict, and every
   token-dependent refusal is the single verdict invalid.
4. Every claims vector yields its recorded verdict in the order of 9.6,
   and an `ok` vector's claims serialise to the canonical text.
5. Every key string in paserk.json is reproduced, and the wrapped key
   unwraps.
6. The decoder rejects padding, whitespace, a length of 1 modulo 4 and
   non-zero unused bits, and the tamper sweep of cb2_local.json (every
   position of a 100-byte token) yields invalid at every position.
7. Rules without an audience and issuer expectation or allowance are
   refused before the token is read; a token over the size limit is
   refused before the token is read.
8. Nothing is decrypted before the tag is checked, nothing is parsed
   before authentication, and no function returns claims from an
   unauthenticated token.
9. Tag, footer, key id and identifier comparisons are constant time for
   equal lengths.
10. The header of a token the implementation does not implement yields
    invalid.
11. Every vector in proofs.json yields its recorded verdict: a bound
    token is refused without a proof, a proof verifies only under the
    key cnf carries and only with the access token it was made for, the
    request and the times are checked as 13.5 says, a proof is never
    accepted as a cb2.public token nor a cb2.public token as a proof,
    and every target normalises as 13.2 says.
12. X-Wing reproduces the draft's vectors, seal.json is reproduced byte
    for byte and unseals, and every failure in it is invalid.
