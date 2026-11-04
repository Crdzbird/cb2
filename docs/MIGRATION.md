# Moving to cb2

cb2 supersedes cb1, CipherBird's first token format, and is the
successor this repository proposes to PASETO v4. This note says what a
deployment of either changes to move, and what it must not expect.

## What stays the same

- The token shape: `header || base64url(body) [ || "." || base64url(footer) ]`,
  the pre-authentication encoding, the strict base64url, the footer and
  the implicit assertion. A parser written for v4 or cb1 needs the
  header string changed and nothing else to split a cb2 token.
- The local key: 32 uniformly random bytes. A cb1 or v4 local key can be
  reused as a cb2 local key as it is; only its PASERK string changes
  form (`kcb2.local.` in place of `k4.local.` or cb1's string).
- The claims: iss, sub, aud, exp, nbf, iat and jti with RFC 3339 times,
  as PASETO registers them. cb2 adds cnf (PROTOCOL.md section 13) and
  requires the verifier to say which audience and issuer it accepts.

## What changes on the wire

Tokens are not interchangeable in either direction. A cb2 verifier
refuses a cb1 or v4 token by its header and a cb1 or v4 verifier refuses
a cb2 token the same way; no token of one format passes for the other,
by design (PROTOCOL.md section 11). A migration therefore runs two
verifiers for the overlap period, keyed by the header, and stops issuing
the old format once no token of it can still be alive.

| | PASETO v4 | cb1 | cb2 |
|---|---|---|---|
| local header | `v4.local.` | `cb1.local.` | `cb2.local.` |
| public header | `v4.public.` | `cb1.public.` | `cb2.public.` |
| local key split | BLAKE2b, two keyed calls, domain strings | BLAKE3, two keyed calls, domain strings | BLAKE3, one keyed XOF call over the header and the nonce |
| local tag | BLAKE2b-256 keyed | BLAKE3 keyed | BLAKE3 keyed, the same |
| public signature | Ed25519 | Ed25519 + ML-DSA-65 | Ed25519 + ML-DSA-65 with the header as the ML-DSA context string |
| secret key form | 64 bytes | Ed25519 sk + ML-DSA sk | the same plus the ML-DSA public key, 6048 bytes |
| key strings | k4.local, k4.public, k4.secret, k4.lid, k4.pid, k4.local-wrap, k4.seal | cb1's | kcb2.local, kcb2.public, kcb2.secret, kcb2.lid, kcb2.pid, kcb2.local-wrap, kcb2.seal, kcb2.recipient |
| key id in the footer | by convention | by convention | bound by the library as `{"kid":...}` and compared in constant time |
| claims validation | the application's | the application's | the library's, with mandatory audience and issuer rules |
| sender constraint | none | none | cnf and holder proofs |
| sealing a key to a recipient | k4.seal on X25519 | none | kcb2.seal on X-Wing (ML-KEM-768 + X25519) |

## Moving from cb1

cb1 and cb2 share every primitive. The differences are the header, the
single-call key split and, on the public side, the ML-DSA context string
and the secret key carrying its public half. In code:

1. Replace `crypto::cb1::Local` and `Public` with `cb2::Local` and
   `cb2::Public`; the caller-buffer functions have the same shape, the
   allocating ones return `Result<T>`.
2. Import existing local keys with `LocalKey::from_bytes`; they are the
   same 32 bytes. Regenerate signing pairs with `SecretKey::generate`,
   or rebuild a cb1 pair as `ed_sk || ml_sk || ml_pk` and import it with
   `SecretKey::from_bytes`, which checks that the halves belong together.
3. If the application put a key id in the footer by hand, stop: give
   the key its id with `set_key_id` and let the claims layer bind it.
4. If the application validated claims itself, replace that with
   `ValidationRules`, which refuses to run until told the expected
   audience and issuer, and requires exp unless told otherwise.
5. If cb1's per-thread nonce batch mattered for throughput, read the
   nonce source note in README.md under API: the same effect is one
   libsodium call at process start, by the application's choice.

## Moving from PASETO v4

Everything above, plus:

1. Local keys carry over as bytes. v4 public keys do not: a v4 signing
   key is Ed25519 only and cb2.public requires the hybrid pair, so
   signing pairs are regenerated and verifiers receive the new
   `kcb2.public` string.
2. k4.seal recipients do not carry over either: kcb2.seal recipients are
   X-Wing pairs, generated with `RecipientKey::generate`.
3. The claims layer's JSON reader is stricter than most: numbers are
   kept as text, member names may not repeat, nesting is bounded, and
   the identifier claims may not contain invisible or formatting code
   points (PROTOCOL.md section 9). An issuer that relied on looser
   parsing finds out at `Token::seal`, with `argument`, before anything
   is minted.
4. Verifiers that accepted any audience or issuer must now say so with
   `allow_any_audience` and `allow_any_issuer`, on purpose.

## What a migration must not expect

- No interoperability with PASETO implementations in other languages
  until one implements cb2; docs/PROTOCOL.md and tools/check_vectors.py
  are what such an implementation is written from.
- No in-band negotiation. A verifier accepts the headers it implements
  and nothing else; a future change of primitive is cb3, not a flag.
