# paseto5 security: claims and limits

This document states what paseto5 guarantees, under which assumptions, and
what it does not do. The wire format and the rationale for each decision
are in SPEC.md. The verification that was actually performed on this code
is listed in README.md.

## What is claimed

### v5.local

A v5.local token is an authenticated encryption of the message under a
32-byte key, bound to the header, the nonce, the footer and the implicit
assertion.

1. Confidentiality of the message. The message is encrypted with XChaCha20
   under a key and nonce derived per token from the 32-byte key and a
   32-byte random nonce by keyed BLAKE3. Nothing about the message but
   its length is visible in the token.
2. Integrity and authenticity. The 32-byte tag is keyed BLAKE3 over the
   pre-authentication encoding of the header, nonce, ciphertext, footer
   and implicit assertion under an authentication key derived from the
   token key. A token that differs in any byte, that carries a different
   footer or that is presented with a different implicit assertion is
   rejected before anything is decrypted.
3. Key commitment. The authentication key is a pseudorandom function of
   the token key and the nonce, so a valid tag commits the token to one
   key: finding two keys under which one token opens costs a collision in
   a 256-bit keyed hash, about 2^128 work. There is no partitioning
   oracle.
4. Nonce safety. Nonces are 32 random bytes from the operating system
   through libsodium; the keystream is derived from key and nonce, so a
   repeat requires a 256-bit collision. The process aborts if the system
   random device is unavailable; it never falls back to anything weaker.
5. No oracle. Every failure that depends on the token (header, encoding,
   footer, key id, tag) is reported as one verdict, invalid, and the tag
   comparison is constant time (libsodium crypto_verify_32). Footer and
   key-id comparisons are constant time for equal lengths; the lengths
   are already public in the token text.
6. Wiping. Derived keys, hasher states and the plaintext on any failed
   path are wiped with sodium_memzero. Plaintext returned to the caller
   lives in memory that is wiped when freed.

### v5.public

A v5.public token is the message in clear with a hybrid signature over
the pre-authentication encoding of the header, message, footer and
implicit assertion.

1. Unforgeability. The signature is Ed25519 and ML-DSA-65 (FIPS 204) over
   the same bytes; verification requires both. A forger must break both
   schemes. If a large quantum computer breaks Ed25519, ML-DSA-65 holds;
   if a lattice break defeats ML-DSA-65, Ed25519 holds.
2. Binding. The header, footer and implicit assertion are signed, so a
   token cannot be moved to another purpose, another footer (another key
   id) or another context.
3. No downgrade. There is no Ed25519-only mode. A build without liboqs has
   no v5.public purpose at all, and a token is never accepted on the
   strength of one half.
4. No oracle. Every token-dependent failure is the single verdict invalid.

### Keys

1. Purpose separation by type. LocalKey, PublicKey and SecretKey are
   distinct C++ types; the token functions accept only the type their
   purpose needs. Raw key bytes are never an argument of the token API.
2. Key ids. Every key carries an optional id, by default its PASERK id
   (k5.lid or k5.pid: 33 bytes of BLAKE3 over the id header and the
   PASERK string). The claims layer binds the id into the footer as
   {"kid":"..."} and compares it in constant time; a token minted under a
   key with one id does not open under a key with another, even if the
   key bytes are equal.
3. k5.local-wrap. A local key wrapped under another local key is the
   v5.local construction with its own header, so a wrapped key is not a
   token and a token is not a wrapped key.

### Claims layer

1. Validate before trust. Claims are returned only by Token::open and
   Token::verify, which authenticate first and parse second. There is no
   function that returns claims from an unverified token. peek_key_id
   returns a value whose type name says it is unverified and which is good
   only for choosing a candidate key.
2. Expiry is required unless the verifier opts out explicitly with
   allow_missing_exp(). nbf and iat are checked against the verifier's
   clock with a skew that defaults to zero. Issuer, audience and subject
   are bound when the verifier expects them, compared in constant time.
3. Size limit before parsing. A token longer than max_token_bytes
   (default 16384) is refused before any byte of it is examined.
4. Strict JSON. Duplicate member names, invalid escapes, invalid UTF-8,
   control characters, non-canonical numbers and nesting deeper than 16
   are all rejected. Numbers are never converted, so there is no
   coercion; registered claims must be strings and the three time claims
   must be RFC 3339.
5. International text, byte for byte. Every string is UTF-8 and may hold
   any script; escapes are resolved before comparison and nothing is
   normalised, so composed and decomposed spellings are different
   identifiers. The identifier claims, custom claim names and key ids are
   checked against a policy that refuses controls, the Unicode
   Default_Ignorable_Code_Point set (zero-width and bidi characters,
   variation selectors, tags), noncharacters and private-use code points,
   on the issuing side (argument) and on the verifying side
   (claims_malformed). See docs/SPEC.md section 8.4.

## Assumptions

- libsodium, BLAKE3 and liboqs are correct and their constant-time
  properties hold on the target. paseto5 composes them and adds no
  primitive of its own.
- The caller keeps the LocalKey and SecretKey secret and the PublicKey
  authentic. A key id is not a secret and not a proof of key possession.
- The verifier's clock is correct to within the configured skew.
- The implicit assertion is agreed out of band; it is never sent.
- The process memory is not readable by the attacker while a key is in
  use. Wiping limits exposure after use; it is not a defence against a
  live memory read.

## What is not claimed

- Replay protection. A valid token is valid until it expires. Callers who
  need single use must track jti themselves.
- Revocation. Tokens carry no revocation state. Use short lifetimes and
  key rotation (the key id makes rotation routine).
- Forward secrecy. Compromise of a local key exposes every token made
  under it, past and future, until it is rotated.
- Hiding the message length. A v5.local token reveals the message length
  exactly. Pad the message before sealing if that matters.
- Hiding the footer. The footer, including the key id, is authenticated
  but sent in clear.
- Interoperability with PASETO. v5.local and v5.public are CipherBird
  constructions; a PASETO v4 implementation will reject them by header
  and paseto5 rejects v3 and v4 tokens the same way. The PASERK-shaped
  key strings are likewise CipherBird's, not the PASERK standard's.
- FIPS validation. BLAKE3, XChaCha20 and Ed25519 are not FIPS algorithms
  and liboqs is not a validated module.
- Resistance to a hostile build. A build that defines PASETO5_TEST_NONCE
  exposes the deterministic-nonce functions; such a build must not ship.
- Protection of the SecretKey's ML-DSA half against fault attacks or
  against a compromised liboqs.

## Limits

| Quantity | Limit |
|---|---|
| message, footer, implicit assertion | each at most 2^26 bytes (67,108,864) |
| token accepted by the claims layer | max_token_bytes, default 16,384 |
| JSON nesting | 16 levels |
| local key | exactly 32 bytes |
| public key | exactly 1,984 bytes |
| secret key | exactly 6,048 bytes |
| wrapped local key | exactly 142 characters |

## Reporting

Report a weakness to the repository owner privately, as SECURITY.md at
the repository root describes. Do not open a public issue for a
cryptographic finding.
