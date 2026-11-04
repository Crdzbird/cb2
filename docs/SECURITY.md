# cb2 security: claims and limits

This document states what cb2 guarantees, under which assumptions, and
what it does not do. The wire format and the rationale for each decision
are in SPEC.md. The verification that was actually performed on this code
is listed in README.md.

## What is claimed

### cb2.local

A cb2.local token is an authenticated encryption of the message under a
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
   path are wiped with sodium_memzero. The message Local::open returns
   lives in memory that is wiped when freed. The claims layer parses
   that buffer into ordinary strings and hands them to the caller: they
   are the application's data, not key material, and are not wiped.
   An application that treats a claim as a secret must wipe it itself.

### cb2.public

A cb2.public token is the message in clear with a hybrid signature over
the pre-authentication encoding of the header, message, footer and
implicit assertion.

1. Unforgeability. The signature is Ed25519 and ML-DSA-65 (FIPS 204) over
   the same bytes; verification requires both. A forger must break both
   schemes. If a large quantum computer breaks Ed25519, ML-DSA-65 holds;
   if a lattice break defeats ML-DSA-65, Ed25519 holds.
2. Binding. The header, footer and implicit assertion are signed, so a
   token cannot be moved to another purpose, another footer (another key
   id) or another context. The ML-DSA half also carries the header as
   its FIPS 204 context string, so a signature the same key made for any
   other purpose, even over these very bytes under another context, is
   not a cb2.public signature.
3. No downgrade. There is no Ed25519-only mode. A build without liboqs has
   no cb2.public purpose at all, and a token is never accepted on the
   strength of one half.
4. No oracle. Every token-dependent failure is the single verdict invalid.

### Keys

1. Purpose separation by type. LocalKey, PublicKey and SecretKey are
   distinct C++ types; the token functions accept only the type their
   purpose needs. Raw key bytes are never an argument of the token API.
2. Key ids. Every key carries an optional id, by default its PASERK id
   (kcb2.lid or kcb2.pid: 33 bytes of BLAKE3 over the id header and the
   PASERK string). The claims layer binds the id into the footer as
   {"kid":"..."} and compares it in constant time; a token minted under a
   key with one id does not open under a key with another, even if the
   key bytes are equal.
3. kcb2.local-wrap. A local key wrapped under another local key is the
   cb2.local construction with its own header, so a wrapped key is not a
   token and a token is not a wrapped key.
4. Key entropy. A local key must be 32 uniformly random bytes. Its
   default key id is a fast hash of the key that travels in clear in
   every footer, so a key with little entropy can be tested against one
   token at the cost of one short hash per guess, cheaper than the AEAD.
   The importers refuse the one weak key they can recognise (every byte
   equal); a key derived from a password or any other low-entropy source
   is the caller's error, and such a key should at least carry an
   explicit opaque key id instead of the default.
5. Locked memory. The bytes of a LocalKey and a SecretKey are locked
   with sodium_mlock for the life of the object, so they are not swapped
   out and, where the platform supports it, not written to a core dump,
   and are wiped and unlocked when the object dies. The lock is best
   effort: a platform or a resource limit that refuses it leaves the key
   wiped on release but swappable in between, and unlocking one key
   unlocks the whole page it shares with any other. Exported key strings
   (to_paserk) are wiped but not locked.
6. Secret key import. A secret key imported from bytes or from its
   kcb2.secret form is checked before use: its Ed25519 public half must be
   the one its seed derives and its ML-DSA public half must verify a
   signature its secret half makes. A corrupted or tampered key file is
   refused with argument instead of producing tokens nothing verifies.

### Claims layer

1. Validate before trust. Claims are returned only by Token::open and
   Token::verify, which authenticate first and parse second. There is no
   function that returns claims from an unverified token. peek_key_id
   returns a value whose type name says it is unverified and which is good
   only for choosing a candidate key.
2. Expiry is required unless the verifier opts out explicitly with
   allow_missing_exp(). nbf and iat are checked against the verifier's
   clock with a skew that defaults to zero. A maximum lifetime, when the
   verifier sets one, refuses a token whose exp lies further ahead than
   that, so an issuer's over-long expiry is worth no more than the
   verifier allows. Issuer, audience and subject are bound when the
   verifier expects them, compared in constant time; an expectation that
   breaks the identifier policy is refused as argument before the token
   is read, since it could never match.
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
   (claims_malformed). See docs/SPEC.md section 8.4;
   examples/international_text.cpp runs the spoofs the policy exists
   for (invisible and bidi characters in identifiers, escaped
   smuggling, a look-alike key id, overlong UTF-8) through a check
   without the policy and through Token::open, side by side.

6. Audience and issuer by declaration. A verifier's rules must name the
   audience and the issuer they accept, or say explicitly that any will
   do (allow_any_audience, allow_any_issuer). Rules that say neither are
   rules_incomplete before the token is read. This is the one bypass a
   correctly built token offers, a verifier that never said which
   service it is, and the default now refuses it.
7. Replay. A valid token is valid until it expires; cb2 tracks no
   jti by itself. Three measures limit what a stolen token is worth:
   a short exp; the implicit assertion bound to the request (a session
   or channel id, a request hash), which makes the token worthless
   outside that context; and the replay check of ValidationRules, which
   receives the jti of every token that passed every other rule and may
   refuse it against a store of seen ids. A token without a jti is
   missing_jti once a check is installed.
8. Raw-layer size. The allocating open and verify functions refuse any
   token longer than 1 MiB before reading it, unless the caller raises
   the limit; the claims layer applies its 16 KiB limit first. A flood
   of oversize garbage therefore costs a length comparison, not a 48 MiB
   buffer and the hashing of it.

### Sender-constrained tokens (holder proofs)

1. A token that carries cnf is accepted only with a holder proof that
   authenticates under the key cnf carries, for this very access token
   (its text is the proof's implicit assertion), for this method and
   target, within the proof lifetime, once per jti. A token read from a
   log, a proxy, a cache, a crash dump or a capture is useless without
   the client's secret key.
2. A captured request, proof included, replays only against the same
   method and target, with the same token, within the proof lifetime
   (60 seconds by default), and only once past the proof replay check,
   which is required whenever a proof is checked.
3. The verifier trusts nothing the client presents about the key: cnf
   carries the whole public key under the issuer's own tag or signature,
   and the proof's footer binds that key's id. A proof under any other
   key fails closed.
4. Domain separation: the holder header is the ML-DSA context string
   and the first PAE piece, so a signature the client made as a
   cb2.public token is never a proof and a proof is never a cb2.public
   token, under the same key.
5. Safe by default: a token that carries cnf is refused without a proof
   unless the verifier says ignore_sender_constraint() on purpose; a
   verifier may also require cnf of every token.

Not claimed: protection when the client's secret key is stolen together
with the token (malware on the client), or when the verifier is
compromised; a browser client cannot hold a post-quantum key
non-extractably today. The symmetric holder mode designed for that case
in docs/SENDER_CONSTRAINT.md is not yet implemented.

## Assumptions

- libsodium, BLAKE3 and liboqs are correct and their constant-time
  properties hold on the target. cb2 composes them and adds no
  primitive of its own.
- The caller keeps the LocalKey and SecretKey secret and the PublicKey
  authentic. A key id is not a secret and not a proof of key possession.
- The verifier's clock is correct to within the configured skew.
- The implicit assertion is agreed out of band; it is never sent.
- The process memory is not readable by the attacker while a key is in
  use. Wiping limits exposure after use; it is not a defence against a
  live memory read.

## What is not claimed

- Replay protection by itself. A valid token is valid until it expires.
  The replay check hands the caller every accepted jti at the right
  moment; the store behind it, and its consistency across verifiers, is
  the caller's.
- Revocation. Tokens carry no revocation state. Use short lifetimes and
  key rotation (the key id makes rotation routine).
- Forward secrecy. Compromise of a local key exposes every token made
  under it, past and future, until it is rotated.
- Hiding the message length. A cb2.local token reveals the message length
  exactly. Pad the message before sealing if that matters.
- Hiding the footer. The footer, including the key id, is authenticated
  but sent in clear.
- Interoperability with PASETO. cb2.local and cb2.public are CipherBird
  constructions; a PASETO v4 implementation will reject them by header
  and cb2 rejects v3 and v4 tokens the same way. The PASERK-shaped
  key strings are likewise CipherBird's, not the PASERK standard's.
- FIPS validation. BLAKE3, XChaCha20 and Ed25519 are not FIPS algorithms
  and liboqs is not a validated module.
- Resistance to a hostile build. A build that defines CB2_TEST_NONCE
  exposes the deterministic-nonce functions; such a build must not ship.
- Protection of the SecretKey's ML-DSA half against fault attacks or
  against a compromised liboqs. The import check catches a key whose
  public halves do not match its secret halves; it does not claim to
  detect every change to the secret halves.

## Limits

| Quantity | Limit |
|---|---|
| message, footer, implicit assertion | each at most 2^26 bytes (67,108,864) |
| token accepted by the allocating raw open and verify | max_token_bytes, default 1,048,576 (1 MiB), raisable to the ceiling |
| token accepted by the claims layer | max_token_bytes, default 16,384 |
| ML-DSA context string | the 11-byte header; FIPS 204 allows up to 255 |
| JSON nesting | 16 levels |
| local key | exactly 32 bytes |
| public key | exactly 1,984 bytes |
| secret key | exactly 6,048 bytes |
| wrapped local key | exactly 144 characters |

## Reporting

Report a weakness to the repository owner privately, as SECURITY.md at
the repository root describes. Do not open a public issue for a
cryptographic finding.
