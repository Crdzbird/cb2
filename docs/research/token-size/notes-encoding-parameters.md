# Encoding-level and cryptographic-parameter techniques to shrink cb2 tokens

Scope: every encoding and parameter choice in cb2.local that affects size, and the security margin each change gives up. Researched 2026-11-07. Numbers marked "computed" were calculated locally by the researcher from the cited tables and grammars (script: HPACK code lengths parsed from RFC 7541 Appendix B; sizes from field lengths); they are not quoted from a source.

Baseline (computed from the field layout in the brief): body = 32 B nonce + |m| + 32 B tag, footer JSON `{"kid":"kcb2.lid.<44 chars>"}` is 63 bytes, which base64url-encodes to 84 chars. Total length = 10 ("cb2.local.") + ceil(4(64+|m|)/3) + 1 (".") + 84.

| plaintext | current cb2 | kid as 8 raw bytes in body, no footer | + nonce 24 B | + tag 16 B | + 3-char prefix "c2." | nonce 16, tag 16, kid 4, prefix 3 |
|---|---|---|---|---|---|---|
| 0 B | 181 | 106 | 96 | 74 | 67 | 51 |
| 100 B | 314 | 240 | 229 | 208 | 201 | 185 |
| 200 B | 447 | 373 | 362 | 341 | 334 | 318 |

(Each column is cumulative left to right, all base64url, computed.) The footer is the single largest fixed cost: 85 of 181 chars for an empty payload.

## Text encodings for binary data in HTTP headers and cookies

### Takeaway
Nothing denser than base64url is legal in `Authorization: Bearer` (token68/b64token admits only 66 characters plus trailing `=`), and on HTTP/2 and HTTP/3 the HPACK/QPACK Huffman code makes base64url the cheapest on-the-wire alphabet of all those tested: about 1.065 wire bits per payload bit, versus 1.166 for Z85 and 1.182 for base91, because punctuation has long Huffman codes. Z85 is cookie-octet safe and saves 6.25 percent of characters on HTTP/1.1, but it is not token68-safe, not URL-safe, and costs more bytes than base64url once Huffman-coded.

### Cited Findings
- RFC 9110 defines `token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="` and says it "allows the 66 unreserved URI characters ... plus a few others, so that it can hold a base64, base64url ..., base32, or base16 (hex) encoding, with or without padding" - [RFC 9110 Section 11.2](https://www.rfc-editor.org/rfc/rfc9110#section-11.2)
- `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, so a single opaque Authorization value must match token68 (the auth-param alternative would require `name=value` syntax, and quoted-string values) - [RFC 9110 Section 11.4](https://www.rfc-editor.org/rfc/rfc9110#section-11.4)
- The Bearer scheme's `b64token` uses the same character set as token68 - [RFC 6750 Section 2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1)
- RFC 6265 `cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E`, i.e. "US-ASCII characters excluding CTLs, whitespace DQUOTE, comma, semicolon, and backslash" (90 usable characters) - [RFC 6265 Section 4.1.1](https://www.rfc-editor.org/rfc/rfc6265#section-4.1.1)
- User agents SHOULD support "At least 4096 bytes per cookie (as measured by the sum of the length of the cookie's name, value, and attributes)" - [RFC 6265 Section 6.1](https://www.rfc-editor.org/rfc/rfc6265#section-6.1)
- base64url (RFC 4648 Section 5) is the URL and filename safe alphabet (`-` and `_` replace `+` and `/`); padding may be omitted only when the referring specification says so (Section 3.2) - [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648)
- Z85 spec: frames "SHALL have a length that is divisible by 4" and strings "divisible by 5"; it is designed to be "safe for strings" (usable in source code in double or single quotes) and states the goal "To provide the most efficient textual representation possible"; it calls Ascii85 "not string-safe" - [ZeroMQ RFC 32/Z85](https://rfc.zeromq.org/spec/32/)
- Base122 is about 14.3 percent overhead measured in UTF-8 bytes, defined by a reference implementation only, and safe only on fully UTF-8 channels (secondary sources) - [MojoAuth Base64 vs Base122](https://mojoauth.com/dev-guides/base64-vs-base122.md); [base122-fast crate](https://docs.rs/base122-fast)
- Branca mandates base62 (`0-9A-Za-z`) for the string form; the spec gives no rationale - [Branca spec](https://github.com/tuupola/branca-spec)
- HPACK Huffman coding applies to string literals with the H flag; the code table is RFC 7541 Appendix B - [RFC 7541 Section 5.2 and Appendix B](https://www.rfc-editor.org/rfc/rfc7541#appendix-B). QPACK (HTTP/3) reuses the same Huffman code - [RFC 9204 Section 4.1.2](https://www.rfc-editor.org/rfc/rfc9204#section-4.1.2)
- RFC 7541 notes "an encoder might also choose not to index values for header fields that are considered to be highly valuable or sensitive to recovery, such as the Cookie or Authorization header fields" (never-indexed literals); this disables dynamic-table reuse but Huffman coding of the literal still applies - [RFC 7541 Section 7.1.3](https://www.rfc-editor.org/rfc/rfc7541#section-7.1.3)

Computed table (alphabet safety from the RFC 9110 and RFC 6265 grammars above; Huffman lengths parsed from RFC 7541 Appendix B, averaged over a uniform symbol distribution, which holds for encoded random ciphertext):

| encoding | chars per byte (HTTP/1.1) | bits/char | mean HPACK code length | wire bits per payload bit (HTTP/2,3) | chars outside token68 | chars outside cookie-octet |
|---|---|---|---|---|---|---|
| hex | 2.000 | 4.000 | 5.625 | 1.406 | none | none |
| base32 | 1.600 | 5.000 | 6.812 | 1.363 | none | none |
| base62 | ~1.344 | 5.954 | 6.403 | 1.075 | none | none |
| base64url | 1.333 | 6.000 | 6.391 | 1.065 | none | none |
| base64 std | 1.333 | 6.000 | 6.469 (`+`/`/` cost 11 and 6 bits) | 1.078 | none | none |
| Z85 | 1.250 | 6.409 | 7.471 | 1.166 | `! # $ % & ( ) * : < = > ? @ [ ] ^ { }` | none |
| Ascii85 | 1.250 | 6.409 | 7.624 | 1.189 | 23 chars | `" , ; \` |
| base91 | ~1.231 | 6.508 | 7.692 | 1.182 | 24 chars | `" , ;` |
| base122 | ~1.143 (UTF-8 bytes) | n/a | n/a | n/a | non-ASCII | non-ASCII |

- Computed: base64url characters have HPACK codes of 5 bits (`a c e i o s t 0 1 2`), 6 bits (e.g. `A b d f ... - _`), 7 bits (most uppercase) and 8 bits (`X Z`); `.` is 6 bits. Z85/base91 punctuation reaches 15 bits (base91) and 19 bits (Ascii85).
- Computed body sizes, current parameters, empty payload (64 raw bytes): base64url 86, Z85 80, base62 ~86, base91 ~79 chars. Savings from Z85 over base64url are 6.25 percent of the encoded part (1.25/1.333).

### Inferences
- In `Authorization: Bearer`, base64url is already optimal among token68-legal alphabets (token68 has 66 symbols plus `=`; a base66 encoding would gain at most log2(66)/6 = 0.75 percent and is non-standard).
- For cookies, Z85 is grammatically legal but `=` inside values and `%` can trip ad hoc cookie parsers and URL-decoding frameworks; and many deployments copy cookie values into URLs or headers, so a cookie-only alphabet would fork the token format. Not worth 6 percent.
- On HTTP/2/3 (the common case for browsers and gRPC), a denser punctuation-heavy alphabet is a net loss on the wire. Base64url's Huffman cost (6.39 bits per 6 payload bits) is within 6.5 percent of raw binary, so encoding-level tricks have almost no remaining headroom there; byte reductions must come from fewer raw bytes (footer, nonce, tag, prefix).
- base64 standard is slightly worse than base64url under Huffman because `+` has an 11-bit code.

### Gaps
- No primary source found for Branca's rationale for base62 (likely "URL safe with no special characters"); not confirmed.
- No measurement found of how many production HTTP/2 encoders actually set the Huffman flag for Authorization or Cookie values (nghttp2, hyper/h2, Go net/http); RFC 7541 leaves it to the encoder.
- Did not verify server-side header-size limits (nginx, Envoy, Node) as part of this question.

## Nonce size: 32 vs 24 vs 16 bytes for random nonces

### Takeaway
Because cb2 derives (Ek, n2) from the random nonce n through keyed BLAKE3, the only thing that matters is that n never repeats under one key; the collision probability after q tokens is about q^2 / 2^(b+1) for a b-bit nonce. 24 bytes (192 bits, Branca, libsodium/NaCl secretbox, XChaCha20) is ample for any realistic issuance volume; 16 bytes (128 bits) is acceptable only with bounded per-key issuance (for example 2^32 tokens gives about 2^-65). The 32-byte nonce in PASETO v4 comes from reusing the whole random value as KDF salt, not from a stated birthday requirement.

### Cited Findings
- PASETO v4.local: "Generate 32 random bytes from the OS's CSPRNG, n"; keyed BLAKE2b over `"paseto-encryption-key" || n` with length 56 gives Ek (32 bytes) and n2 (24 bytes); Ak from `"paseto-auth-key-for-aead" || n`, length 32; tag is BLAKE2b-MAC length 32; token is `h || base64url(n || c || t) || "." || base64url(f)` - [PASETO Version4.md](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md)
- PASETO rationale: "With v1.local, half of the 32-byte random value was used as an HKDF salt and half was used as an AES-CTR nonce"; now "we now use the entire 32-byte random value in the HKDF step"; "neither v3.local nor v4.local will pre-hash the message and random value to derive a nonce" (v2 did, to resist RNG failure); "A single key can be used for 2^112 PASETOs before rotation is necessary" - [PASETO Rationale-V3-V4.md](https://github.com/paseto-standard/paseto-spec/blob/master/docs/Rationale-V3-V4.md)
- Branca: "Version (1B) || Timestamp (4B) || Nonce (24B) || Ciphertext (*B) || Tag (16B)", XChaCha20-Poly1305, nonce from a CSPRNG, user-supplied nonces are "a foot gun" - [Branca spec](https://github.com/tuupola/branca-spec)
- XChaCha draft: with a secure RNG, random 192-bit nonces reach a 50 percent single-collision chance after roughly 2^96 messages; HChaCha20 uses the first 128 bits of the nonce to derive a subkey - [draft-arciszewski-xchacha-03](https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03)
- Go `nacl/secretbox`: 24-byte nonces "are long enough that randomly generated nonces have negligible risk of collision" - [pkg.go.dev secretbox](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox)
- RbNaCl SimpleBox: after 2^64 messages the chance of a repeated 24-byte nonce is approximately 2^-64 (the exact birthday bound gives about 2^-65) - [RbNaCl SimpleBox](https://rubydoc.info/gems/rbnacl/RbNaCl/SimpleBox)
- Some secondary documentation misstates the bound (e.g. 2^64 for 24-byte nonces); the correct 50 percent point is 2^96 - contradicted by [Crypto++ XChaCha20-Poly1305 docs](https://cryptopp-modern-com.pages.dev/docs/api/symmetric/xchacha20-poly1305) versus the [XChaCha draft](https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03)

Computed collision probabilities, p ~ q^2 / 2^(b+1):

| nonce | q = 2^32 tokens/key | q = 2^48 | q = 2^64 | q at p = 2^-32 |
|---|---|---|---|---|
| 128-bit (16 B) | 2^-65 | 2^-33 | 2^-1 | 2^48 |
| 192-bit (24 B) | 2^-129 | 2^-97 | 2^-65 | 2^80 |
| 256-bit (32 B) | 2^-193 | 2^-161 | 2^-129 | 2^112 |

- The 2^112 figure in the PASETO rationale matches the q at which a 256-bit random value reaches about 2^-33 collision probability (computed), so PASETO's own budget implies roughly a 2^-32 acceptable-collision threshold.

### Inferences
- In cb2 a nonce repeat gives the same (Ek, n2, Ak): XChaCha20 keystream reuse leaks the XOR of two plaintexts. Unlike Poly1305 (a one-time MAC, where nonce reuse enables forgery), the keyed BLAKE3 tag stays a PRF, so reuse does not give forgeries. That makes the failure mode confidentiality-only, which is milder than Branca's.
- 24 bytes is the natural cut: it is XChaCha20's native nonce length, it is Branca's and libsodium's choice, and at 2^48 tokens per key the collision chance is 2^-97. Saving: 8 bytes, about 10.7 base64url chars (computed).
- 16 bytes saves 16 bytes (21.3 chars) but caps safe issuance at about 2^48 per key at 2^-32 risk; a high-volume issuer rotating keys yearly would be well inside that, yet the margin depends on key rotation discipline rather than on the format. A shorter nonce also weakens multi-key/multi-target arguments when the nonce is used as KDF salt.
- PASETO's 32 bytes buys RNG-misuse margin and a 2^112 budget, not a requirement for the AEAD itself.

### Gaps
- No PASETO document found that states why 32 rather than 24 bytes beyond the v1 history quoted above; no crypto.stackexchange answer specifically on 16-byte random-salt KDF-derived nonces was retrieved.

## Tag length: truncating the 32-byte keyed BLAKE3 tag to 16 bytes

### Takeaway
A 128-bit tag keeps online forgery resistance far beyond anything an attacker can submit (same as Poly1305 and full-length GCM), but it halves key-commitment security from about 128 to about 64 bits, because commitment attacks are offline collision searches subject to the birthday bound. The literature (Bellare, Hoang, Wu) argues committing security should target 128 bits because attacks are offline; so a 16-byte tag gives up cb2's key-committing claim at the 128-bit level.

### Cited Findings
- SP 800-107r1 5.3.3: truncated HMAC uses the leftmost bits and "the output length, lambda, shall be no less than 32 bits" - [NIST SP 800-107r1](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf)
- SP 800-107r1 5.3.5: forgery likelihood with 2^t allowed failed verifications is 2^-(lambda - t); Table 2 gives, for lambda = 64, 2^-44 / 2^-34 / 2^-29 at 2^20 / 2^30 / 2^35 failed verifications; "A commonly acceptable length for the MacTag is 64 bits; MacTags with lengths shorter than 64 bits are discouraged." - [NIST SP 800-107r1](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf). Note: NIST has announced withdrawal of SP 800-107r1 and released SP 800-224 ipd (June 2024) covering truncated HMAC - [NIST CSRC SP 800-107r1 page](https://csrc.nist.gov/pubs/sp/800/107/r1/final); [NIST MAC project news](https://csrc.nist.gov/Projects/message-authentication-codes/news)
- SP 800-38D 5.2.1.2: GCM tag length t "may be any one of the following five values: 128, 120, 112, 104, or 96. For certain applications, t may be 64 or 32"; Appendix C restricts 32- and 64-bit tags (e.g. 32-bit tags with 25-byte packets allow 2^22 decryption invocations per key) and names SRTP voice as the model use case - [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- SP 800-38D Appendix B: for GCM, a targeted forgery succeeds with probability about n/2^t for n-block inputs, and successful forgeries leak the hash subkey H (polynomial MAC weakness that does not apply to a PRF-based MAC like keyed BLAKE3) - [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- Branca's Poly1305 tag is 16 bytes ("The authentication tag is 128 bits ie. 16 bytes") - [Branca spec](https://github.com/tuupola/branca-spec)
- BLAKE3 "targets 128-bit security for all of its security goals ... (second-)preimage, collision, or differentiability"; key length is 256 bits "as an extra defense layer against weakly chosen keys, key material leaks, and potentially multi-target attacks"; and "BLAKE3 does not domain separate outputs of different lengths. Shorter outputs are prefixes of longer ones." - [BLAKE3 specification paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
- Bellare, Hoang, Wu: "committing security can be achieved quite cheaply if one is content with 64-bit security, but ... due to offline attacks, standards should target 128-bit security"; "The prevailing understanding is that CMT-security is subject to birthday attacks, and thus 128-bit security requires a 256-bit ciphertext expansion"; CAU-C1 with 128-bit expansion "has only 64-bits of committing security"; CTX "For 128-bit security, the hash function needs to have a 256-bit output"; GCM, XSalsa20/Poly1305, ChaCha20/Poly1305 and OCB are all CMT-1-insecure - [The Landscape of Committing Authenticated Encryption, NIST 3rd Modes Workshop 2023](https://csrc.nist.gov/csrc/media/Events/2023/third-workshop-on-block-cipher-modes-of-operation/documents/accepted-papers/The%20Landscape%20of%20Committing%20Authenticated%20Encryption.pdf)
- The same paper shows the birthday barrier is on total ciphertext length, not expansion: with new constructions (NC1, EwC) expansion can be max(128, 256 - |M|) bits while keeping about 128-bit commitment, but these are new, specialised schemes - [same source](https://csrc.nist.gov/csrc/media/Events/2023/third-workshop-on-block-cipher-modes-of-operation/documents/accepted-papers/The%20Landscape%20of%20Committing%20Authenticated%20Encryption.pdf)
- Albertini, Duong, Gueron, Koelbl, Luykx, Schmieg (USENIX Security 2022): AE schemes generally do not guarantee key commitment; built AES-GCM ciphertexts that decrypt validly under two keys; propose a simple fix for AES-GCM and ChaCha20Poly1305 - [ePrint 2020/1456](https://eprint.iacr.org/2020/1456)
- PASETO rationale: key- and message-commitment are "an important security property in systems with multiple possible symmetric keys"; "we MUST take attacks that depend on random-key robustness seriously"; "GMAC is neither message-committing nor key-committing" - [PASETO Rationale-V3-V4.md](https://github.com/paseto-standard/paseto-spec/blob/master/docs/Rationale-V3-V4.md)

### Inferences
- Online forgery with a 128-bit PRF tag: even 2^40 rejected attempts per key leave 2^-88 success (computed from the SP 800-107 formula 2^-(lambda - t)). Truncating to 16 bytes is safe for authenticity; 64 bits would also meet NIST's "commonly acceptable" bar but drops below Poly1305/GCM norms.
- Key commitment: in cb2 a CMT-1 attacker picks K1 != K2 and searches for a ciphertext whose tag verifies under both derived Ak values. With a t-bit tag the generic cost is about 2^(t/2): 2^128 for 32 bytes, 2^64 for 16 bytes. 2^64 offline BLAKE3 evaluations is within reach of well-funded attackers, which is why the cited authors set 128 bits as the target. So a 16-byte tag keeps commitment only at the 64-bit level.
- Whether that matters depends on cb2's threat model: commitment attacks need an attacker who can choose or knows multiple keys (multi-tenant, partitioning-oracle, or key-rotation scenarios where verifiers try several keys). If cb2 always selects exactly one key by authenticated kid and never trial-decrypts, the practical exposure is small, but cb2 would no longer be able to advertise 128-bit key commitment.
- Because BLAKE3 outputs of different lengths are prefixes of each other, a 16-byte-tag variant under the same key would produce tags that are prefixes of the 32-byte variant's tags. The version/header must be inside the MAC input (and ideally the derived Ak should be domain-separated by version) so the two lengths cannot be cross-accepted.
- Middle ground: 24-byte tag gives about 96-bit commitment (computed) and saves 8 bytes (about 10.7 chars).

### Gaps
- Could not retrieve SP 800-224 final text (status as of November 2026 not confirmed) to quote its current truncated-HMAC minimums.
- No published analysis specific to truncated keyed BLAKE3 commitment found; the 2^(t/2) bound is the generic birthday argument from the literature above applied by inference.
- Bellare-Hoang "Efficient Schemes for Committing Authenticated Encryption" (Eurocrypt 2022) primary text was not fetched; the claims above come from the 2023 NIST workshop paper by the same authors.

## Key id length

### Takeaway
A key id only has to select a key among the issuer's live keys; with the footer authenticated by the MAC (as in PASETO), any kid tampering just causes verification failure. Tink uses a 4-byte key hint in a 5-byte prefix and explicitly treats it as unauthenticated; PASERK's 33-byte lid is a collision-resistant fingerprint, which is far more than selection needs. Replacing the 63-byte JSON footer with a raw 4 to 8 byte kid inside the body saves about 74 to 80 chars per token, the largest single saving available.

### Cited Findings
- PASERK ID: `d = crypto_generichash(h || p, 33)` (BLAKE2b-264 over the header and the entire PASERK string); "When base64url-encoded, d will produce an unpadded 44-byte string"; no rationale for 33 bytes is given in the document - [PASERK operations/ID.md](https://github.com/paseto-standard/paserk/blob/master/operations/ID.md)
- k4.lid "serves as a pointer to another PASERK, which is in turn intended for local PASETOs" - [PASERK types/lid.md](https://github.com/paseto-standard/paserk/blob/master/types/lid.md)
- Tink: "Most Tink primitives support a 5 byte output prefix" = 1 version byte 0x01 plus "4 bytes key hint: This is the key ID of the key used"; legacy keys may use 0x00; "these prefixes are not authenticated and cannot be relied on for" security, they are a hint to speed up decryption - [Tink wire format](https://developers.google.com/tink/wire-format)
- PASETO footers exist "to support key-ids and key rotation strategies" - [PASETO Rationale-V3-V4.md](https://github.com/paseto-standard/paseto-spec/blob/master/docs/Rationale-V3-V4.md)
- PASETO implicit assertions: data "that IS NOT stored in the token but IS USED to calculate the authentication tag", e.g. account ID binding - [PASETO Rationale-V3-V4.md](https://github.com/paseto-standard/paseto-spec/blob/master/docs/Rationale-V3-V4.md)

Computed: random kid collision among k live keys ~ k^2 / 2^(b+1). 32-bit kid: 1,000 keys gives about 1.2e-4; 64-bit kid: 10^6 keys gives about 2.7e-8. Size: 33-byte lid in JSON = 85 chars (63 B footer + dot); raw 8 B kid inside body ~ 10.7 chars; raw 4 B ~ 5.3 chars.

### Inferences
- Collisions are not a security problem if the kid is authenticated and the verifier tries only the selected key: a collision causes a failed verification, not acceptance. The issuer can also reject a newly generated key whose short kid collides with a live key, making 4 bytes sufficient for any realistic key ring.
- Enumeration/oracle concerns: a full 264-bit hash of the key is a public fingerprint; a short kid leaks less. If the kid is a truncated hash of the key, it should still be a domain-separated hash (as PASERK does with the header) so it cannot be confused with other key-derived values. Alternatively, a random or sequential kid assigned at key creation avoids deriving anything from key material.
- Keeping PASERK-compatible lids in the token is an interoperability choice, not a security one; the full lid can stay in the key store while the token carries a short handle.
- If the kid is placed in the body (or in an authenticated header), it must remain in the MAC input to keep the PASETO-style footer binding.
- The JSON wrapper (`{"kid":"..."}`, 8 + 2 bytes) plus the `kcb2.lid.` prefix (9 bytes) adds 19 bytes of syntax before encoding (computed).

### Gaps
- No primary rationale found for PASERK's 33-byte (264-bit) length; the 33 is plausibly chosen to avoid base64 padding (33 is divisible by 3), but that is unconfirmed.
- No Tink document found that explains how 4-byte key ids are chosen or whether collisions are checked.

## Header/version prefix length

### Takeaway
The readable "cb2.local." prefix costs 10 chars; a one-byte binary version inside the body (Branca's 0xBA, Fernet's 0x80, Tink's 0x01) costs about 1.3 chars. Misuse resistance comes from the version being bound into the MAC/KDF input and from versioned, non-negotiable protocols, not from readability; the readable prefix mainly helps humans, log scanners and secret detectors.

### Cited Findings
- PASETO v4.local uses header `h = "v4.local."` (9 chars) which is part of the authenticated input - [PASETO Version4.md](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md)
- PASETO: version-tag suffixes for other encodings (e.g. `v4c`), and "tokens MUST NOT be transmutable between encodings without access to the symmetric key" - [PASETO Rationale-V3-V4.md](https://github.com/paseto-standard/paseto-spec/blob/master/docs/Rationale-V3-V4.md)
- Branca uses a single version byte 0xBA as the first byte, authenticated as AEAD additional data - [Branca spec](https://github.com/tuupola/branca-spec)
- Tink prefix version byte 0x01 (0x00 legacy) - [Tink wire format](https://developers.google.com/tink/wire-format)
- Fernet: version byte 0x80, 8-byte timestamp, 16-byte IV, ciphertext, 32-byte HMAC-SHA256 - [Fernet spec](https://github.com/fernet/spec/blob/master/Spec.md)

### Inferences
- Shrink options, computed: "cb2.local." (10) to "c2l." or "c2." (3 to 4 chars) saves 6 to 7 chars; dropping the text prefix entirely for a body-internal version byte saves about 8.7 chars.
- The "local" vs "public" purpose word protects against key-type confusion only if the purpose is cryptographically bound (header in MAC input and different KDF labels). A one-byte version enum that encodes both version and purpose gives the same binding.
- A recognisable text prefix has operational value: GitHub-style secret scanning and log redaction typically key on fixed prefixes. A short but distinctive prefix (3 to 4 chars) keeps most of that.

### Gaps
- Did not retrieve a primary PASETO or Paragon document arguing specifically for human-readable prefixes over binary version bytes; the transmutability statement above is the closest.

## Published "token diet" write-ups that measured savings

### Takeaway
No published write-up was found that measures savings from the specific parameter changes (nonce, tag, kid, prefix) or from alternative alphabets; the existing material is about JWT claim compression or replacing tokens with references.

### Cited Findings
- Apigee community: estimate that compressing a JWT reduces it to "maybe 50%" because the signature is incompressible; a follow-up reported up to 70 percent reduction on claims in testing and then abandoned compression - [Apigee community thread](https://community.apigee.com/questions/65207/configure-gateway-to-accept-header-with-compressed.html?sort=votes); [Google Cloud Community follow-up](https://www.googlecloudcommunity.com/gc/Apigee/Configure-gateway-to-accept-header-with-compressed-JWT-token/td-p/58310/page/2)
- Omnissa engineering (2025-07-21): gzipping the JWT payload reduced cookie size significantly; they then moved to a small reference cookie pointing to a stored token - [Omnissa engineering blog](https://engineering.omnissa.com/story/2025-07-21-taming-oversized-oauth2-token)

### Inferences
- Measured numbers for cb2 should come from the computed table at the top of this note (and the sibling local_measurements note), since no external benchmark exists for these exact knobs. Combined, the parameter changes take an empty-payload cb2.local from 181 to 51 to 96 chars depending on how much margin is surrendered.

### Gaps
- No Medium/dev.to/engineering write-up found that compared base64url against Z85/base91 for tokens in real HTTP/2 traffic.
