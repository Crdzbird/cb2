# Compact claim and payload encodings for authentication tokens

Research date: 2026-11-07. Byte counts marked "computed" come from a local script (hand-written CBOR encoder following RFC 8949 preferred serialization, Python json with no whitespace) run on the cb2 example claims given in the brief. They are arithmetic, not quotes from a source; method is described inline so the report writer can reproduce them.

Baseline (computed): example claims JSON = 217 bytes; JSON footer {"kid":"kcb2.lid.<44>"} = 63 bytes (84 base64url chars); token = 10 ("cb2.local.") + 382 (base64url of 32 + 217 + 32 = 281 bytes) + 1 + 84 = 470 chars, matching the brief.

## 1. CWT (RFC 8392) and COSE (RFC 9052/9053): integer keys, epoch times, sizes, overheads, deterministic CBOR

### Takeaway
CWT replaces JSON claim names with small integers (iss=1 ... cti=7) and times with untagged CBOR integers; the RFC 8392 example claims set is 80 bytes and full COSE envelopes add roughly 34 to 95 bytes depending on MAC/signature/encryption. Applied to the cb2 example, CWT-style CBOR shrinks the 217-byte claims to 106 bytes, and with a shared-registry interning scheme to 49 to 59 bytes. COSE avoids canonicalisation problems by signing the exact bstr-wrapped bytes, not a re-encoded map.

### Cited Findings
- CWT registered claim keys: iss=1, sub=2, aud=3, exp=4, nbf=5, iat=6, cti=7 (cti is a byte string); key 0 reserved - [RFC 8392 sec 4](https://www.rfc-editor.org/rfc/rfc8392.html)
- NumericDate in CWT is a CBOR number with "the leading tag 1 (epoch-based date/time) MUST be omitted"; claim values "MUST NOT be prefixed with any CBOR tag" - [RFC 8392 sec 2, 5](https://www.rfc-editor.org/rfc/rfc8392.html)
- CWT CBOR tag is 61 and is optional; CoAP content-format application/cwt is also 61 - [RFC 8392 sec 6, 9.4](https://www.rfc-editor.org/rfc/rfc8392.html)
- RFC 8392 Appendix A sizes: example claims set (iss, sub, aud, exp, nbf, iat, cti) = 80 bytes; signed CWT (COSE_Sign1, ES256, 64-byte sig, kid in unprotected) = 175 bytes; MACed CWT (COSE_Mac0, HMAC 256/64, 8-byte tag, with tag 61) = 114 bytes; encrypted CWT (COSE_Encrypt0, AES-CCM-16-64-128, 13-byte IV, 8-byte tag) = 127 bytes. Breakdown for Encrypt0: tag+array 2, protected header 4, unprotected (kid + 13-byte iv) 31, ciphertext 90 - [RFC 8392 Appendix A](https://www.rfc-editor.org/rfc/rfc8392.html)
- Same-claims comparison from a demo script: JWT 215 bytes vs bare CBOR claims 57 bytes vs full CWT 78 bytes (single small example, not a benchmark) - [generalzero notes, CWT](https://notes.generalzero.org/Web%20Exploitation/Auth/CWT.html)
- A Japanese wiki estimates CWT at roughly 1/2 to 1/3 of JWT size, noting JWT inflates twice (JSON text then base64url); no measurement given - [NetDevInfraWiki MS_CWT](https://github.com/NetDevInfraWGinOSSConsortium/NetDevInfraWiki/wiki/MS_CWT)
- RFC 8392's stated motivation: JSON "is considered inefficient for some Internet of Things (IoT) systems"; CWT is "a compact means of representing secured claims" - [RFC 8392 sec 1](https://www.rfc-editor.org/rfc/rfc8392.html)
- COSE structures: COSE_Encrypt0 = [protected bstr, unprotected map, ciphertext], tag 16; COSE_Sign1 = [protected, unprotected, payload, signature], tag 18; COSE_Mac0 tag 17 - [RFC 9052 sec 4.2, 5.2, 6.2](https://www.rfc-editor.org/rfc/rfc9052.html)
- The protected header is CBOR-encoded then wrapped in a bstr, which "avoids the problem of all parties needing to be able to do a common canonical encoding"; Sig_structure context "Signature1", Enc_structure context "Encrypt0" - [RFC 9052 sec 3, 4.4, 5.3](https://www.rfc-editor.org/rfc/rfc9052.html)
- Senders "SHOULD encode a zero-length map as a zero-length byte string" (protected header), recipients must accept both - [RFC 9052 sec 3](https://www.rfc-editor.org/rfc/rfc9052.html)
- Header labels in each map "MUST be unique", duplicates "MUST be rejected as malformed"; protected value wins if a label is in both buckets - [RFC 9052 sec 3](https://www.rfc-editor.org/rfc/rfc9052.html)
- Deterministic CBOR (RFC 8949 sec 4.2.1): shortest-form integers, lengths and tags; "Indefinite-length items MUST NOT appear"; map keys sorted by "bytewise lexicographic order of their deterministic encodings". This differs from the RFC 7049 "Canonical CBOR" length-first order, kept as an alternative in sec 4.2.3 - [RFC 8949 sec 4.2](https://www.rfc-editor.org/rfc/rfc8949.html)
- RFC 8949 sec 4.2.2: protocols must define their own deterministic profile, including float rules (negative zero, single NaN form 0xf97e00, integral floats vs integers) - [RFC 8949 sec 4.2.2](https://www.rfc-editor.org/rfc/rfc8949.html)
- Gordian dCBOR application profile, draft-mcnally-deterministic-cbor-17 (Feb 2026, still an Internet-Draft, not an RFC), adds "numeric reduction" so 2 and 2.0 encode identically and rejects maps with both 10 and 10.0 as keys - [datatracker draft-mcnally-deterministic-cbor-17](https://datatracker.ietf.org/doc/html/draft-mcnally-deterministic-cbor-17); [draft -03](https://datatracker.ietf.org/doc/html/draft-mcnally-deterministic-cbor-03)
- IANA CWT registry (last updated 2026-07-20) now assigns 8=cnf, 9=scope, 10=eat_nonce, 11=vct (temporary until 2026-12-02), 38=ace_profile, 39=cnonce, 40=exi, 256 to 275 EAT claims, 65533 to 65535 status list claims. Ranges: -256..255 Standards Action; -65536..-257 and 256..65535 Specification Required; >65535 Expert Review; less than -65536 Private Use - [IANA CWT Claims registry](https://www.iana.org/assignments/cwt/cwt.xhtml)

### Inferences
- Computed cb2 example sizes (claims payload only):
  - JSON as today: 217 bytes.
  - JSON with exp/iat as epoch integers instead of RFC 3339 strings: 183 bytes (34 saved).
  - CBOR map, string keys kept, epoch times, 16-byte binary jti: 124 bytes.
  - CWT-style integer keys for iss/sub/aud/exp/iat/cti, custom claims "role"/"tenant" as text keys: 106 bytes.
  - Same, custom claims under private-use integer keys (less than -65536, each costs a 5-byte key): 104 bytes. Private-use keys save almost nothing because they need a 4-byte integer argument.
  - All keys small integers 1..9 (only legal in a private cb2 claim registry; in CWT 8 and 9 are already cnf and scope): 96 bytes.
  - Plus interning iss, aud, role to small integers via a registry both sides know: 59 bytes.
  - Plus exp stored as a delta from iat (900 s): 57 bytes.
  - Positional CBOR array [iss, sub, aud, iat, ttl, jti, role, tenant] with interned values: 49 bytes.
- Computed whole-token chars with today's 32-byte nonce + 32-byte tag + JSON footer: JSON 470; CWT-int 322; interned+delta 257; positional array 246. Dropping the JSON footer (kid moved inside or shortened) removes 85 chars: 385 / 237 / 172 / 161.
- Computed COSE_Encrypt0 envelope for ChaCha20-Poly1305 (protected {1:24} = 5 bytes, unprotected {4: kid, 5: 12-byte iv}, 16-byte tag, tag 16): overhead 40 bytes with no kid, 43 with a 1-byte kid, 46 with a 4-byte kid, 50 with an 8-byte kid. For the 106-byte CWT claims that is 152 bytes / 203 base64url chars with a 4-byte kid. cb2's own envelope today costs 64 bytes (32 nonce + 32 tag) plus the footer, so cb2's crypto overhead, not the encoding, becomes the dominant cost once claims are binary.
- If cb2 MACs/encrypts the exact transmitted bytes (as it does now, and as COSE does with bstr wrapping), deterministic encoding is not needed for verification; it only matters if a verifier ever re-encodes claims and compares, or if equal claims must produce equal tokens (caching, dedup).

### Gaps
- No rigorous, multi-token published benchmark of CWT vs JWT sizes was found; the 215 vs 78 byte example is from a personal notes site.
- RFC 9052 section 9 ("CBOR Encoding Restrictions") body was not read in full (fetch truncated); the claim that COSE requires deterministic encoding only for the Sig/MAC/Enc structures is based on cross-references in sec 4.4 and 6.3.
- RFC 9053 algorithm identifiers (e.g. ChaCha20/Poly1305 = 24) were used from memory in the computed envelope and not re-fetched.

## 2. Other token formats: structure, encoding, sizes

### Takeaway
Fixed-overhead symmetric formats range from 45 bytes (Branca) to 57+ bytes (Fernet) to 64 bytes (PASETO v4.local, current cb2); none of Branca/Fernet carries a key id. Capability formats (Biscuit, macaroons v2, UCAN 1.0) all moved to binary encodings (protobuf, varint TLV, DAG-CBOR) with string interning or varints to control size. SAML assertions are several KB vs roughly 1 KB JWTs.

### Cited Findings
- Branca: Version (1, 0xBA) || Timestamp (4, big-endian uint32, overflows 2106) || Nonce (24) || Ciphertext || Poly1305 tag (16); XChaCha20-Poly1305 IETF; header authenticated not encrypted; base62 encoding; 45 bytes fixed overhead; no footer or key id; payload is arbitrary bytes (JSON, MessagePack, Protocol Buffers suggested) - [Branca spec](https://github.com/tuupola/branca-spec)
- Fernet: Version 0x80 (1) || Timestamp (8) || IV (16) || AES-128-CBC ciphertext with PKCS#7 padding (1 to 16 bytes added) || HMAC-SHA256 (32); base64url; 57 bytes fixed overhead, minimum raw token 73 bytes; no key id field - [Fernet spec](https://github.com/fernet/spec/blob/master/Spec.md)
- PASETO v4.local: header "v4.local.", 32-byte random nonce, keys and 24-byte XChaCha20 nonce derived with keyed BLAKE2b, 32-byte BLAKE2b-MAC tag over PAE(h, n, c, f, i), output h || base64url(n || c || t) [|| "." || base64url(f)]; v4.public appends a 64-byte Ed25519 signature - [PASETO Version4.md](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md)
- PASETO guidance: "users should store Key-ID claims (kid) in the unencrypted footer"; "PASERK is the RECOMMENDED way to serialize Key IDs"; footer JSON safety checks recommended: maximum length (no default given), maximum depth "Only 1-dimensional objects", maximum keys (no default) - [PASETO Payload Processing](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md)
- Macaroons v2 binary: fields are <type varuint64><length varuint64><content>; LOCATION=1, IDENTIFIER=2, VID=4, SIGNATURE=6; EOS is one 0x00 byte; version byte 2; signature 32 bytes - [libmacaroons format.txt](https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt)
- Macaroons v1 was "quite verbose and inflates the size"; v2 "can easily be 50% smaller" in the designer's testing; v1 required UTF-8 ids/caveats and parts under about 64K, v2 allows binary blobs - [macaroons mailing list, New Macaroons Binary Format](https://groups.google.com/g/macaroons/c/EIDUZQoelq8)
- Biscuit: protobuf; Biscuit{rootKeyId optional uint32, authority, blocks, proof}; SignedBlock{block bytes, nextKey, signature, externalSignature, version}; Ed25519 default, secp256r1 optional; strings interned into a symbol table (28 default symbols, indexes 0 to 1023 reserved, token symbols from 1024); public keys also tabled "to reduce size"; format version integers 3 to 6 (v3.0 to v3.3), implementations must refuse newer or older block versions; designed "small enough for storage in HTTP cookies"; no typical sizes given - [Biscuit SPECIFICATIONS.md](https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md)
- Biscuit's rootKeyId is "a hint to decide which root public key should be used" (a 32-bit integer key id, not a hash) - [Biscuit SPECIFICATIONS.md](https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md)
- UCAN: v1 (core spec at v1.0.0-rc.1 per a 2026 overview) replaces the earlier JWT form with DAG-CBOR envelopes addressed by CID; signatures encoded as varsig (varint algorithm code, varint size, signature bytes); DAG-CBOR recommended - [UCAN specs overview (2026)](https://cdn.jsdelivr.net/npm/@wovin/core@0.3.3/src/pubsub/UCAN%20Specs%20Overview.md); [ucan-ipld README](https://github.com/ucan-wg/ucan-ipld/blob/main/README.md); [ucan-wg receipt](https://github.com/ucan-wg/receipt); [go-ucan](https://beta.pkg.go.dev/github.com/ucan-wg/go-ucan@v1.0.0)
- Discord user tokens (community reverse engineering, not an official spec): three dot-separated base64 parts, user id (snowflake), creation timestamp, and an HMAC; algorithm and key unknown - [serenity token.rs](https://docs.rs/crate/serenity/0.11.7/source/src/utils/token.rs); [darksunlight gist](https://gist.github.com/darksunlight/8e8db86794a88e0f3f80408970fc94e5)
- Discord snowflakes are 64-bit ids whose top 42 bits are ms since the Discord epoch 1420070400000, so an id also carries a timestamp - [discord-user-rs utils.rs](https://docs.rs/crate/discord-user-rs/latest/source/src/utils.rs)
- SAML vs JWT: vendor/blog estimates put SAML assertions at 2 to 8 KB (over 8 KB with extra certs and encrypted attributes) vs JWT ID tokens around 0.8 to 1.5 KB, roughly 4 to 5x; SAML can exceed URL limits in HTTP-Redirect binding - [ssojet OIDC vs SAML](https://ssojet.com/blog/oidc-vs-saml-hybrid-cloud-when-to-use-each); [tech-insider OIDC vs SAML 2026](https://tech-insider.org/oidc-vs-saml-2026/); [Apigee SAML2 vs JWT](https://community.apigee.com/articles/44556/saml2-vs-jwt-a-comparison.html)

### Inferences
- Computed Branca-like layout (1 + 4 + 24 + payload + 16) for the cb2 claims: JSON 217 bytes gives 262 raw / 353 base62 / 350 base64url chars; CWT-int 106 bytes gives 151 raw / 203 base62; interned 57 bytes gives 102 raw / 138 base62. Base62 is about 0.8% larger than base64url (log2(62) = 5.954 bits per char vs 6) and needs bignum-style conversion, so it buys no size, only a URL-safe alphabet without "-" and "_".
- Computed Fernet for the 217-byte JSON: 281 raw bytes (224-byte padded CBC ciphertext), 376 base64 chars.
- Moving cb2 from a 32-byte nonce + 32-byte tag to a 24-byte nonce + 16-byte tag (XChaCha20-Poly1305 or Branca-like) saves 24 bytes raw (32 chars); computed: JSON 470 to 353 chars without footer; interned binary claims 140 chars. A 32-byte keyed-BLAKE3 tag truncated to 16 bytes saves 16 bytes (about 21 chars). Whether truncation is acceptable for cb2's post-quantum goals is a crypto question outside this note (Grover does not meaningfully weaken MAC forgery the way it weakens key search, but this was not researched here).
- Formats that put a timestamp in a fixed header (Branca 4 bytes, Fernet 8 bytes) avoid paying for a time claim inside the payload; cb2 could do the same for exp/iat.

### Gaps
- No public, citable documentation was found on Google ALTS tokens, Google internal macaroon-like tokens, Facebook, Dropbox, or Cloudflare Access token encodings in this pass; treat any claim about them as unverified.
- No measured size for a typical Biscuit, UCAN 1.0 delegation, or macaroon v2 was found.
- AWS KMS key id and ciphertext-blob overhead were not researched (search budget).

## 3. Binary encodings of common values

### Takeaway
The biggest single savings in the cb2 example are: claim names to integers (about 25 bytes), two RFC 3339 times to epoch integers (40 bytes in CBOR), jti UUID text to 16 binary bytes (20 bytes), and interning the issuer URL and audience (about 30 bytes). Varints and CBOR use the same 5 bytes for a current epoch second.

### Cited Findings
- ULID: 128 bits = 48-bit ms timestamp + 80-bit randomness; 26 chars Crockford base32 or 16 binary bytes; monotonic mode increments the random part within a millisecond - [ULID spec](https://github.com/ulid/spec)
- CBOR preferred serialization encodes integers in the shortest of 1, 2, 3, 5 or 9 bytes - [RFC 8949 sec 4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html)
- CWT forbids tag 1 on NumericDate, so an epoch time is a bare uint (saves the 1-byte tag) - [RFC 8392 sec 2](https://www.rfc-editor.org/rfc/rfc8392.html)
- CWT cti is a byte string, so a UUID can be carried as 16 raw bytes - [RFC 8392 sec 4](https://www.rfc-editor.org/rfc/rfc8392.html)
- Macaroons v2 uses LEB128-style varuint64 (7 bits per byte, LSB first) for type and length fields - [libmacaroons format.txt](https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt)
- Biscuit interns strings via a default symbol table plus per-token symbols, and tables public keys, explicitly to reduce size - [Biscuit SPECIFICATIONS.md](https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md)
- Branca carries the issue time as a 4-byte header field instead of a claim - [Branca spec](https://github.com/tuupola/branca-spec)

### Inferences
- Computed per-value costs for the cb2 example:
  - Time: RFC 3339 string "2026-11-07T15:23:30+00:00" is 25 chars (27 with JSON quotes); epoch 1794065010 is 10 JSON digits, 5 CBOR bytes, 5 LEB128 bytes, 6 CBOR bytes with tag 1. Two times: 54 JSON bytes vs 10 CBOR bytes. As a delta (exp = iat + 900) exp costs 3 CBOR bytes. A 4-byte fixed uint32 (Branca) overflows in 2106; a 5-byte CBOR uint does not.
  - UUID: 36 text chars (38 in JSON) vs 16 raw bytes (17 as CBOR bstr), 22 chars if base64url'd inside JSON.
  - Claim names: "iss","sub","aud","exp","iat","jti" each cost 5 JSON bytes plus ":" and ","; an integer key 1 to 23 costs 1 CBOR byte.
  - Interning "https://auth.example.com" (24 bytes) and "mobile" (6) and "viewer" (6) to small ints saves about 37 bytes but requires a registry shared and versioned between issuer and verifier; a wrong or stale registry silently changes meaning, so the registry version must be bound into the authenticated data (e.g. a version byte or registry id in the header).
- Positional arrays (49 bytes) beat maps (57 bytes) by 8 bytes but make optional and custom claims awkward; a map with small integer keys is the usual compromise (CWT, Biscuit, COSE).
- iss is redundant when the key id already identifies the issuer's key; dropping it entirely (verifier derives issuer from the key) saves its whole cost. This is a design inference, not a sourced practice.

### Gaps
- No source quantifying general-purpose compression (deflate/zstd) on short tokens was gathered; for 200-byte inputs compression usually does little, but this was not verified here. JWE "zip":"DEF" history and its compression-oracle concerns were not researched.

## 4. Key id size

### Takeaway
Key ids are hints, not security: COSE says applications "MUST NOT assume that kid values are unique", Tink uses a 5-byte unauthenticated prefix (1 version + 4-byte id) and falls back to trial decryption. PASERK lid/pid is 33 bytes (44 base64url chars + 7-char prefix = 51 chars) and JWK thumbprints are 43 chars, both sized for global collision resistance rather than key selection. If the MAC/AEAD authenticates the kid and the verifier only uses it to pick among its own keys, 1 to 8 bytes is enough; collisions only cost an extra trial verification.

### Cited Findings
- PASERK ID: v2/v4 d = BLAKE2b(h || p, 33 bytes) ("BLAKE2b-264"), v1/v3 SHA-384 truncated to 33 bytes; result h || base64url(d); 33 bytes chosen so it "will encode evenly" to 44 chars with no padding; no collision discussion in the spec. With prefix "k4.lid." the string is 51 chars - [PASERK ID.md](https://github.com/paseto-standard/paserk/blob/master/operations/ID.md)
- JWK thumbprint (RFC 7638): SHA-256 over required members in lexicographic order, no whitespace; example "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" (43 chars); may be used as a "kid" which the consumer "treats ... as an opaque value that it uses to select the key"; no text on truncation or collisions - [RFC 7638 sec 3, 3.1, 3.4](https://www.rfc-editor.org/rfc/rfc7638.html)
- COSE kid: label 4, bstr; "Applications MUST NOT assume that kid values are unique"; kid is a hint and "not a security-critical field", may sit in the unprotected bucket; its internal structure "cannot be relied on" - [RFC 9052 sec 3.1](https://www.rfc-editor.org/rfc/rfc9052.html)
- RFC 8392 examples use kid in unprotected headers of 15 to 21 bytes encoded (e.g. a short ASCII kid) - [RFC 8392 Appendix A](https://www.rfc-editor.org/rfc/rfc8392.html)
- Tink output prefix: 5 bytes = 1 version byte (0x01, legacy 0x00, prehash 0xff) + 4-byte key id; "not authenticated", "anyone can rewrite it", used only as a hint to speed up decryption/verification; RAW keys have no prefix - [Tink wire format](https://developers.google.com/tink/wire-format)
- Tink decrypts with the hinted key first, then tries all RAW-prefix keys; ids are meant to be unique within a keyset, though repeated ids are tolerated for compatibility with a Google internal library, with removal planned - [Tink keysets design](https://developers.google.com/tink/design/keysets); [Tink WIRE-FORMAT mirror](https://fuchsia.googlesource.com/third_party/tink/+/983c21e0916aee37aa32e4b37486768d1233e0a5/docs/WIRE-FORMAT.md)
- Biscuit uses an optional uint32 rootKeyId as a hint - [Biscuit SPECIFICATIONS.md](https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md)
- Branca and Fernet carry no key id at all; key rotation is done by trying keys - [Branca spec](https://github.com/tuupola/branca-spec); [Fernet spec](https://github.com/fernet/spec/blob/master/Spec.md)
- OSCORE (RFC 8613) uses the sender id as "kid", always present in requests and typically absent in responses (from a 2025/2026 draft describing RFC 8613 behaviour; RFC text itself not fetched) - [draft-tiloca-core-oscore-piv-enc](https://datatracker.ietf.org/doc/draft-tiloca-core-oscore-piv-enc/03/)

### Inferences
- Computed birthday bound for randomly chosen key ids, P(any collision) about n^2 / 2^(b+1): 32-bit ids, 1,000 keys: 1.2e-4; 100,000 keys: near certain. 48-bit, 100,000 keys: 1.8e-5. 64-bit, 100,000 keys: 2.7e-10. If the issuer assigns ids (counter or checked-unique random), collisions are zero by construction and 1 to 2 bytes suffice.
- When the kid is inside the authenticated data (cb2's footer is already MAC-bound like PASETO's), a short or colliding kid cannot cause acceptance under the wrong key; worst case is an extra trial decryption, which is a DoS amplification factor equal to the number of colliding keys.
- A hash-derived kid (PASERK lid) lets any party compute the id from the key without coordination and avoids leaking key material, which is why it is 33 bytes. cb2 could keep a long canonical PASERK-style id for key management and send only a short prefix (e.g. first 4 to 8 bytes) in tokens, as Tink effectively does with 4 bytes.
- Computed savings: the current JSON footer is 63 bytes (85 chars with the dot). A 4-byte binary kid inside the binary header costs about 5 bytes (7 chars). A 1-byte issuer-assigned kid costs 2 bytes.
- A kid that is a truncated hash of the key acts as a weak key-confirmation oracle; with the kid authenticated and keys secret this leaks only which key is in use, which the full PASERK id already leaks.

### Gaps
- PASERK spec gives no rationale or collision analysis beyond the encoding argument; no PASETO/PASERK GitHub discussion on short ids was found.
- AWS KMS key id formats (UUID, ARN) and how KMS ciphertext blobs embed key identity were not researched.
- RFC 8613 text on zero-length Sender IDs was not directly fetched.

## 5. Pitfalls: parser differentials, CBOR canonicalisation, type confusion, extensibility, versioning

### Takeaway
Binary formats remove some JSON hazards (number precision, Unicode escapes) but bring their own: duplicate map keys, non-preferred encodings, float vs int, tags and indefinite lengths. The safe pattern is authenticate exact bytes (COSE style), parse with a strict decoder that rejects duplicates and non-deterministic forms, keep a version byte inside the authenticated header, and reserve a key range or nested map for custom claims.

### Cited Findings
- JSON parser differentials: Bishop Fox tested 49 parsers and found risky behaviour in every language; categories include inconsistent duplicate-key precedence (Python last-wins vs a Go parser first-wins enabling a quantity bypass) and large numbers decoded as 0 by one service - [Bishop Fox, JSON Interoperability Vulnerabilities](https://bishopfox.com/blog/json-interoperability-vulnerabilities); [PortSwigger coverage](https://portswigger.net/daily-swig/research-how-json-parsers-can-create-security-risks-when-it-comes-to-interoperability); [json-interop-vuln-labs](https://uithub.com/BishopFox/json-interop-vuln-labs)
- Recommendation from that research: parsers should raise fatal errors on duplicate keys - [PortSwigger coverage](https://portswigger.net/daily-swig/research-how-json-parsers-can-create-security-risks-when-it-comes-to-interoperability)
- Differential testing for JSON parsers (ASIA CCS 2024) - [TU Berlin 2024b-asiaccs.pdf](https://www.mlsec.tu-berlin.de/docs/2024b-asiaccs.pdf)
- CBOR: a map with duplicate keys "may be well-formed, but it is not valid"; generic decoders may reject, pass through, or drop entries; dropping is unsafe when "the data source and transfer can be attacked"; protocols "MUST define what to do" - [RFC 8949 sec 5.6](https://www.rfc-editor.org/rfc/rfc8949.html)
- CBOR distinguishes well-formed (syntax) from valid (semantics) - [RFC 8949 sec 1.2, 5](https://www.rfc-editor.org/rfc/rfc8949.html)
- Deterministic CBOR has two incompatible key orders (bytewise in RFC 8949 vs length-first in RFC 7049), and floats need extra rules (negative zero, NaN, 2 vs 2.0) - [RFC 8949 sec 4.2](https://www.rfc-editor.org/rfc/rfc8949.html); [dCBOR draft -17](https://datatracker.ietf.org/doc/html/draft-mcnally-deterministic-cbor-17)
- COSE sidesteps canonicalisation by authenticating bstr-wrapped bytes - [RFC 9052 sec 3](https://www.rfc-editor.org/rfc/rfc9052.html)
- COSE rejects duplicate header labels as malformed and gives protected headers precedence - [RFC 9052 sec 3](https://www.rfc-editor.org/rfc/rfc9052.html)
- CWT forbids tags on claim values (no tag 1 times, etc.), reducing type confusion between tagged and untagged forms - [RFC 8392 sec 5](https://www.rfc-editor.org/rfc/rfc8392.html)
- RFC 7638 notes thumbprints only identify keys uniquely if the JWK representation is canonical and validated (non-canonical RSA exponent gives a different thumbprint) - [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html)
- Biscuit versioning: integer format version per block, implementations must refuse blocks outside their known range - [Biscuit SPECIFICATIONS.md](https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md)
- Macaroons v2 was introduced as a new format alongside v1; Go's macaroon.v2 binary unmarshal accepts both v1 and v2 and base64 decoding accepts standard and URL alphabets, padded or not (a liberal-acceptance example) - [macaroons mailing list](https://groups.google.com/g/macaroons/c/EIDUZQoelq8); [macaroon.v2 vendored source](https://grok.dragonflybsd.org/xref/dports/net-im/dendrite/dendrite-0.5.1/vendor/gopkg.in/macaroon.v2/)
- CWT registry ranges give a standards-track path for new claims and a private range (less than -65536) for custom ones; registrations change over time (vct is temporary until 2026-12-02) - [IANA CWT registry](https://www.iana.org/assignments/cwt/cwt.xhtml)
- PASETO recommends footer JSON depth and size limits and that footer contents be distrusted until the payload verifies - [PASETO Payload Processing](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md)

### Inferences
- For cb2, a new binary payload should be a new token version/purpose header (e.g. "cb2.local." to a new prefix or a version byte inside the authenticated data), not content-sniffed; verifiers that accept both JSON and binary under the same header invite type confusion.
- Strict decoding rules worth fixing in a cb2 spec: reject duplicate keys, reject non-preferred (non-shortest) integer and length encodings, reject indefinite lengths, reject tags and floats where not expected, reject unknown critical claims, require exp/iat as unsigned integers. These make the encoding canonical so that every claims set has exactly one byte form, which helps cross-language bindings (cb2 has Java, Go, JS, Swift bindings per recent commits) agree.
- Custom claims: reserve a small-integer range for cb2-defined claims and put application claims either as text-keyed entries or in a nested map under one key, so private integer assignments by different apps cannot collide silently.
- Mixing CWT's public integer keys with cb2-private small integers (e.g. using 8 or 9) would collide with registered cnf and scope; either adopt the IANA table exactly or declare the map cb2-private and not CWT.
- Interned values (issuer, audience, role) need the registry version authenticated with the token; otherwise a verifier with a newer table could map the same integer to a different string.

### Gaps
- No documented real-world CVE about CBOR duplicate-key or non-canonical-encoding confusion in a token library was gathered in this pass (searches focused on JSON); the CBOR risk is argued from RFC 8949 text.
- No PASETO/PASERK or biscuit GitHub issue threads on token size were fetched.
