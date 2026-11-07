# Post-quantum signature schemes by size and status (input to shrinking cb2.public)

Baseline: cb2.public = Ed25519 (64 B) + ML-DSA-65 (3309 B) = 3373 B of signature, 4498 base64url chars of a 4883-char token. Everything that is not signature is therefore about 385 chars. All "token chars" figures below are inferences computed as ceil(sig_bytes * 4 / 3) + 385, unpadded base64url, assuming the rest of the token is unchanged.

Research date: 2026-11-07. Items older than 2026 are marked "(older)".

## Q1. ML-DSA-44/65/87 sizes, categories, agency positions, and is ML-DSA-44 acceptable for short-lived auth tokens?

### Takeaway
ML-DSA-44 (NIST category 2) cuts the PQ signature from 3309 to 2420 B (token about 3697 chars, -24 percent) and is fully FIPS 204 and RFC 9964 compliant, but it is the one ML-DSA level that BSI reportedly does not recommend and CNSA 2.0 does not allow (CNSA 2.0 is ML-DSA-87 only). For short-lived auth tokens with no long-term confidentiality, a forgery must happen before expiry, so category 2 is technically defensible; the barrier is policy, not cryptanalysis.

### Cited Findings
- liboqs datasheet: ML-DSA-44 level 2, pk 1312 B, sk 2560 B, sig 2420 B; ML-DSA-65 level 3, pk 1952 B, sk 4032 B, sig 3309 B; ML-DSA-87 level 5, pk 2592 B, sk 4896 B, sig 4627 B - [liboqs ml_dsa.yml](https://raw.githubusercontent.com/open-quantum-safe/liboqs/main/docs/algorithms/sig/ml_dsa.yml)
- Relative CPU (Cloudflare, ML-DSA-44 = 1): Ed25519 sign 0.15, verify 1.3; ML-DSA-44 baseline (older, Nov 2024) - [Cloudflare, Another look at PQ signatures](https://blog.cloudflare.com/another-look-at-pq-signatures/)
- RFC 9964 "ML-DSA for JOSE and COSE" (Prorock, Steele), Proposed Standard, registers JOSE alg names ML-DSA-44, ML-DSA-65, ML-DSA-87 and COSE algs -48, -49, -50; it registers all three levels without preferring one - [RFC Editor, RFC 9964](https://www.rfc-editor.org/info/rfc9964); draft history at [datatracker draft-ietf-cose-dilithium](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/). Publication month reported as May 2026 by a secondary source only (unverified).
- CNSA 2.0 (NSA) approves only ML-DSA-87 for signatures (and ML-KEM-1024); ML-DSA-44/65 are not CNSA 2.0 options; NSA does not require hybrids - [postquantum.com, CNSA 2.0 vs global requirements](https://postquantum.com/cnsa-2-0/global-pqc-requirements/); [Encryption Consulting, ML-DSA-44 vs 65 vs 87](https://www.encryptionconsulting.com/ml-dsa-44-vs-65-vs-87-enterprise-pki/) (secondary; the primary NSA CNSA 2.0 advisory was not fetched)
- BSI TR-02102-1 version 2026-01 (published 23 Jan 2026): lists ML-DSA, SLH-DSA, LMS/HSS, XMSS/XMSS-MT for signatures; a comparison table marks ML-DSA-44 as not recommended by BSI, ML-DSA-65 and -87 accepted; hybrid with a classical signature is the recommended mode - [postquantum.com, BSI TR-02102-1 2026](https://postquantum.com/security-pqc/bsi-tr-02102-cryptographic-guideline-update/); [duokey, BSI TR-02102](https://duokey.com/en/resources/germany-post-quantum-cryptography-regulation-bsi-tr-02102); [BSI TR-02102 PDF](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102.pdf?__blob=publicationFile&v=10) (PDF not fully read; a GitHub issue quotes section 5.3.4 recommending PQ signatures only in combination with a classical one - [maknae issue 575](https://github.com/darkhonor/maknae/issues/575), secondhand)
- ANSSI: sources conflict. One says ANSSI accepts ML-DSA at levels 2, 3 and 5 with hybrid supported; others say ANSSI aligns with BSI on hybrid deployment and accepts ML-DSA/FN-DSA at levels 3 and 5 - [pqshield, regional regulations](https://pqshield.com/regional-regulations-for-cryptography-algorithm-selection/); [postquantum.com](https://postquantum.com/cnsa-2-0/global-pqc-requirements/)
- NIST IR 8547: classical quantum-vulnerable signatures (ECDSA, EdDSA, RSA) deprecated after 2030 and disallowed after 2035; the final version is reported (secondary) as published 27 Oct 2026 and as tightening the draft so Ed25519/P-256 are also deprecated after 2030 - [Quantum Computing Report, final IR 8547](https://quantumcomputingreport.com/nist-releases-final-ir-8547-establishing-definitive-post-quantum-cryptography-transition-timeline-and-deprecation-schedules/); [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-ir8547-pqc-transition-20261030-csa-st/); [pqshield on the draft (older)](https://pqshield.com/nist-recommends-timelines-for-transitioning-cryptographic-algorithms/)
- Measured (from the brief, M3 Max, liboqs 0.16): ML-DSA-65 sign about 150 us / verify about 65 us; ML-DSA-44 sign 93 us / verify 37 us.

### Inferences
- Token sizes: Ed25519 + ML-DSA-44 = 2484 B sig, about 3697 chars (-24 percent); ML-DSA-44 alone 2420 B, about 3612 chars (-26 percent); Ed25519 + ML-DSA-87 = 4691 B, about 6640 chars (+36 percent).
- Dropping Ed25519 saves only 64 B (85 chars); it is not where the size is.
- ML-DSA-44 is acceptable for short-lived tokens if cb2 does not target CNSA 2.0 or BSI-qualified deployments. A sensible design is a header/version that names the level, so an "ML-DSA-44 compact" profile and an "ML-DSA-65/87 compliance" profile can coexist.
- The ML-DSA-44 move also speeds verify by about 43 percent (65 to 37 us).

### Gaps
- Primary NSA CNSA 2.0 text and the ANSSI 2024/2025 PQC position paper were not fetched; the ANSSI level-2 position is unresolved.
- Final IR 8547 publication date not confirmed on csrc.nist.gov.

## Q2. FN-DSA (Falcon, FIPS 206): status, sizes, implementation concerns, library support

### Takeaway
As of Nov 2026 FIPS 206 is still not published even as an initial public draft on csrc (NIST sent it for approval 28 Aug 2025); it would cut the PQ signature to 666 B (token about 1359 chars with Ed25519, -72 percent) but signing needs floating point that is hard to make constant time, and it is not yet usable for FIPS validation.

### Cited Findings
- Falcon-512: pk 897 B, sig 666 B, sign about 3x and verify about 0.7x ML-DSA-44 CPU; Cloudflare flags signing as hard to implement securely; emulated floating point is roughly 20x slower; no middle security level, next size up doubles sizes (older, Nov 2024) - [Cloudflare](https://blog.cloudflare.com/another-look-at-pq-signatures/)
- Falcon-1024 signature about 1280 B (figure from the brief; consistent with secondary FN-DSA summaries) - [Encryption Consulting, FN-DSA](https://www.encryptionconsulting.com/education-center/fn-dsa-fips-206/); [shattered.io, FN-DSA vs ML-DSA](https://shattered.io/fn-dsa-vs-ml-dsa-falcon-dilithium-2026/)
- Status: NIST submitted the FIPS 206 draft for approval on 28 Aug 2025; as of Sept 30, 2026 no public draft and no Federal Register notice; a Nov 2026 review also found none; final widely expected late 2026 or early 2027 (estimates, not NIST commitments) - [DigiCert, FN-DSA nears draft approval](https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist); [arcqubit guide](https://www.arcqubit.ai/blog/nist-pqc-standards-guide); [quantumsecuritydefence.com](https://quantumsecuritydefence.com/insights/nist-fips-standards/). Direct fetches of csrc.nist.gov/pubs/fips/206/ipd and /final returned HTTP 404 on 2026-11-07, consistent with nothing published.
- FN-DSA is not yet eligible for CNSA 2.0 or most federal mandates until FIPS 206 is final - [Encryption Consulting](https://www.encryptionconsulting.com/education-center/fn-dsa-fips-206/)
- NIST itself, in IR 8610, contrasts HAWK with Falcon's "complicated floating-point operations" - [NIST IR 8610](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8610.pdf)
- Library support: liboqs ships Falcon (4 variants: 512, 1024, padded-512, padded-1024) through 0.15; liboqs 0.16.0 (9 Jul 2026) notes mention ML-DSA test additions, SPHINCS+ removal, MQOM integration, but no FN-DSA - [liboqs releases](https://github.com/open-quantum-safe/liboqs/releases); [LibOQS.NET 0.3.0](https://www.strathweb.com/2026/01/liboqs-net-0-3-0-liboqs-0-15-0-full-suite-of-algorithms-and-other-new-features/). wolfCrypt has native Falcon, marked experimental until FIPS 206 - [wolfSSL](https://www.wolfssl.com/wolfcrypt-now-supports-native-falcon-anticipating-fn-dsa-standardization/)

### Inferences
- Ed25519 + Falcon-512: 730 B, about 1359 chars (-72 percent). Falcon-512 alone: about 1273 chars. Ed25519 + Falcon-1024: 1344 B, about 2177 chars (-55 percent).
- Speed at cb2 scale (scaling Cloudflare ratios by the brief's ML-DSA-44 numbers): Falcon-512 sign roughly 280 us, verify roughly 26 us. Rough estimate only.
- Falcon-512 is category 1, below ML-DSA-65's category 3; for compliance parity, Falcon-1024 (category 5) is the like-for-like option.
- Practical risk: shipping a token format on Falcon before FIPS 206 final means the wire encoding may need to change (FIPS 206 may differ in details from round-3 Falcon, as FIPS 204 did from Dilithium).

### Gaps
- BoringSSL, AWS-LC, Bouncy Castle, PQClean FN-DSA status not confirmed this session.
- No FIPS 206 draft text available, so final sizes and the exact encoding (compressed vs padded) are not confirmed.

## Q3. SLH-DSA sizes and stateful LMS/XMSS

### Takeaway
SLH-DSA is a poor fit: even the smallest set (SLH-DSA-128s, 7856 B) is more than 2x ML-DSA-65 and slow to sign; stateful LMS is smaller (about 1112 B) but needs signer state management, which is dangerous for a horizontally scaled token issuer.

### Cited Findings
- SLH-DSA 128s: pk 32 B, sig 7856 B, sign 14000x and verify 40x ML-DSA-44; 128f: sig 17088 B, sign 720x, verify 110x (older, Nov 2024) - [Cloudflare](https://blog.cloudflare.com/another-look-at-pq-signatures/)
- SLH-DSA range 7856 to 49856 B across the 12 FIPS 205 sets (192s 16224, 192f 35664, 256s 29792, 256f 49856) - [FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) (Table 2; not re-fetched this session)
- LMS M4_H20_W8: pk 48 B, sig 1112 B, sign 2.9x (flagged "requires state"), verify 8.4x - [Cloudflare](https://blog.cloudflare.com/another-look-at-pq-signatures/)
- Paragon's draft PASETO v6 uses SLH-DSA-SHA2-128s for public tokens - [Paragon Initiative blog](https://paragonie.com/b/KdUgiEnDfzKMfImK)
- liboqs 0.16.0 fixed an out-of-bounds read in XMSS/XMSS^MT verification - [liboqs releases](https://github.com/open-quantum-safe/liboqs/releases)

### Inferences
- Ed25519 + SLH-DSA-128s: 7920 B, about 10945 chars (+124 percent). Ed25519 + LMS: 1176 B, about 1953 chars (-60 percent), but a token issuer signing millions of tokens with multiple replicas cannot safely share one-time-key state; LMS is for firmware/roots, not tokens.

### Gaps
- None material.

## Q4. NIST additional signatures on-ramp: candidates, sizes, speeds, maturity

### Takeaway
On 14 May 2026 NIST advanced 9 schemes to round 3 (FAEST, HAWK, MAYO, MQOM, QR-UOV, SDitH, SNOVA, SQIsign, UOV) in NIST IR 8610; HAWK was withdrawn on 28 Jul 2026 after a key-recovery improvement, leaving 8. Round 3 is expected to take about two years and NIST says it is "unlikely" to standardize multivariate schemes without a further round, so no on-ramp scheme will be a FIPS before roughly 2028-2029. The tiny-signature options (UOV 96 B, SQIsign 148 B, MAYO-2 about 186 B, SNOVA) are all either attacked-and-reparameterized or slow.

### Cited Findings
- Timeline: July 2023 40 round-1 candidates; Oct 2024 14 round-2 (NIST IR 8528); May 2026 round 3 announced with NIST IR 8610 - [NIST IR 8610](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8610.pdf); [NIST pqc-forum announcement](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/LXoTAe5AN78/m/ZXgBCNlgDAAJ); round 3 "expected to last about two years" - [The Quantum Insider](https://thequantuminsider.com/2026/05/21/nist-advances-nine-post-quantum-signature-algorithms-to-third-round/)
- NIST round 3 page lists the 9 and states "The submission team has withdrawn HAWK" (page updated 13 Oct 2026) - [NIST CSRC round 3](https://csrc.nist.gov/projects/pqc-dig-sig/round-3-additional-signatures)
- Eliminated in round 2: CROSS (SPHINCS+-like sizes, attack forced reparameterization), LESS (cat-1 sig 2625 B with 13940 B pk up to 1329 B sig with 97484 B pk; attack cost 12 to 24 bits), Mirath, PERK, RYDE (MPCitH crowding; RYDE/MQOM/Mirath cat-1 sigs 3 to 3.5 KB) - [NIST IR 8610](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8610.pdf)
- UOV: sig as small as 96 B at cat 1, verify tens of thousands of cycles, pk over 200 KB expanded; wedge attack cut security a few bits (cat 1) to about 20 bits (cat 5), and a follow-up attack put uov-Ip, uov-III, uov-V below target; NIST sees UOV for specific applications, not general purpose - [NIST IR 8610](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8610.pdf)
- MAYO: wedge attack left MAYO2 (cat 1) about 30 bits short; MAYO1/3/5 have the largest sigs among multivariate candidates; NIST views it as a reasonable general-purpose candidate - [NIST IR 8610](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8610.pdf). Round-2 sizes: MAYO-1 pk 1420 B / sig 454 B, MAYO-2 pk 4912 B / sig 186 B - [arXiv survey 2510.10436](https://arxiv.org/pdf/2510.10436) (secondary)
- QR-UOV: pk 15 to 50 percent of UOV, odd characteristic, unaffected by wedge attack; signing 3 to 5x faster than compressed UOV, verify half as fast - [NIST IR 8610](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8610.pdf)
- SNOVA: "concerning history of cryptanalysis", a wedge variant "broke most of SNOVA's proposed parameter sets"; new odd-characteristic cat-1 set has pk and sig both smaller than Falcon; NIST "does not see SNOVA as having reached a stable form" - [NIST IR 8610](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8610.pdf)
- SQIsign: smallest combined pk+sig; round 2 moved to higher-dimensional isogenies, signing about 20x faster and verify 6x faster than round 1, sig as low as 148 B at cat 1; fully constant-time signing still an open problem - [NIST IR 8610](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8610.pdf); pk 65 B at level I per [pqc-forum thread](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/LXoTAe5AN78/m/ZXgBCNlgDAAJ) (via search snippet)
- HAWK: 555 B sig at cat 1, integer-only arithmetic - [NIST IR 8610](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8610.pdf). Withdrawn 28 Jul 2026 after an attack (credited to Anthropic's Claude Mythos Preview) that roughly halves the lattice-reduction block size: HAWK-512 estimate from about 2^150 to 2^108, HAWK-1024 from 2^288 to 2^182; still exponential; ePrint 2026/1628 - [The Hacker News](https://thehackernews.com/2026/07/claude-ai-just-cracked-post-quantum.html); [smartscope analysis](https://smartscope.blog/en/blog/claude-mythos-hawk-cryptanalysis-2026/) (secondary)
- MPCitH: FAEST most trusted (AES-only), MQOM best performance (smallest pk+sig of the six), SDitH most conservative assumption but slower - [NIST IR 8610](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8610.pdf). FAEST EM-128f: pk 32 B, sig 5696 B (older round-1/2 transition numbers) - [Cloudflare](https://blog.cloudflare.com/another-look-at-pq-signatures/)
- Cloudflare table (older, Nov 2024; relative CPU vs ML-DSA-44 sign/verify): MAYO one pk 1168 / sig 321, 1.4/1.4; MAYO two pk 5488 / sig 180, 1.7/0.8; SNOVA (24,5,4) pk 1016 / sig 248, 0.9/1.4; SNOVA (37,17,2) pk 9842 / sig 106; UOV Is-pkc pk 66576 / sig 96, 0.3/2.3; UOV Ip-pkc pk 43576 / sig 128, 0.3/0.8; QR-UOV I pk 23657 / sig 157, 75/125; SQIsign I pk 64 / sig 177, 17000/900; HAWK 512 pk 1024 / sig 555, 0.25/1.2; MQOM L1 pk 59 / sig 7850; SDitH L1 pk 132 / sig 8496 - [Cloudflare](https://blog.cloudflare.com/another-look-at-pq-signatures/). Cloudflare's view: UOV suits cases where the pk is known in advance and works best as a complement to another scheme.
- Library support: liboqs 0.15 added UOV and updated MAYO and CROSS; 0.16.0 added MQOM - [liboqs releases](https://github.com/open-quantum-safe/liboqs/releases); [newreleases 0.16.0](https://newreleases.io/project/github/open-quantum-safe/liboqs/release/0.16.0)

### Inferences
- Token size if paired with Ed25519 (and keeping the rest at 385 chars): UOV 96 B about 599 chars (-88 percent); SQIsign 148 B about 668 (-86 percent); MAYO-2 186 B about 719 (-85 percent); SNOVA 248 B about 801 (-84 percent); MAYO-1 454 B about 1076 (-78 percent); FAEST-128f about 8065 (+65 percent); MQOM about 3.2 KB is no better than ML-DSA-65.
- cb2 verifiers cache issuer keys, so UOV's 44 to 270 KB public key is a key-distribution cost (JWKS-style fetch) rather than a per-token cost; UOV (or QR-UOV) is the strongest size-per-verify-speed candidate for a key-cached verifier, but the round-3 parameter sets are being reworked (odd characteristic) so wire sizes are not frozen.
- SQIsign verify, scaling Cloudflare round-1 numbers by IR 8610's 6x improvement and the brief's ML-DSA-44 verify of 37 us, would be around 5 ms per verify and signing tens of ms; too slow for high-rate token verification. Rough estimate.
- Any on-ramp scheme should only be considered as an extra component in a hybrid, never as the sole PQ component, until standardized.

### Gaps
- Exact round-3 parameter tables (bytes and cycles for every set) were not in IR 8610 text; per-candidate round-3 spec documents were not fetched.
- No independent benchmark for round-2/3 SQIsign on Apple M-series found.

## Q5. Hybrid and composite designs, when the classical part can be dropped, and how others did it

### Takeaway
IETF LAMPS composite ML-DSA is now RFC 10073 (Proposed Standard, Nov 2026) and defines exactly cb2's pair (id-MLDSA65-Ed25519-SHA512, 3373 B) plus id-MLDSA44-Ed25519-SHA512 (2484 B), with a prefix-label-ctx-prehash combiner; BSI (and likely ANSSI) want hybrids, NSA does not, and NIST IR 8547 deprecates Ed25519 after 2030 and disallows it after 2035. Messaging deployments (Signal, Apple PQ3) kept authentication classical and only made key agreement PQ; the web (Chrome, Cloudflare) is avoiding per-certificate PQ signatures via Merkle Tree Certificates.

### Cited Findings
- RFC 10073 "Composite ML-DSA for Use in X.509 PKI", Proposed Standard, November 2026, from draft-ietf-lamps-pq-composite-sigs-19 (datatracker page last updated 2026-11-06) - [datatracker](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
- Ed25519 composites: id-MLDSA44-Ed25519-SHA512 (OID 1.3.6.1.5.5.7.6.39) and id-MLDSA65-Ed25519-SHA512 (OID 1.3.6.1.5.5.7.6.48); no ML-DSA-87 + Ed25519 pairing - [datatracker](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
- Combiner: M' = Prefix || Label || len(ctx) || ctx || PH(M), Prefix = "CompositeAlgorithmSignatures2025", PH = SHA-512; ML-DSA signs M' with the Label as its FIPS 204 context; Ed25519 (pure, not Ed25519ph) signs M'; signature = ML-DSA sig || Ed25519 sig; both must verify - [datatracker](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/); [LAMPS GitHub](https://github.com/lamps-wg/draft-composite-sigs/blob/main/draft-ietf-lamps-pq-composite-sigs.md)
- CNSA 2.0 guidance favors a parallel ML-DSA-87 PKI and not putting more than one algorithm in a certificate - [postquantum.com](https://postquantum.com/cnsa-2-0/global-pqc-requirements/)
- BSI recommends PQ signatures in combination with classical ones - see Q1 sources.
- NIST IR 8547: EdDSA and ECDSA deprecated after 2030, disallowed after 2035 - [Quantum Computing Report](https://quantumcomputingreport.com/nist-releases-final-ir-8547-establishing-definitive-post-quantum-cryptography-transition-timeline-and-deprecation-schedules/)
- Signal: PQXDH only covers initial key agreement; SPQR adds a PQ ratchet with keys over 1 KB spread across messages; authentication remains classical - [heise](https://heise.de/-10725380); [PQShield on SPQR](https://pqshield.com/?p=9081)
- Apple PQ3: PQ rekeying is periodic "to meet our message size requirement"; impersonation would require breaking authentication keys at the time of communication, i.e., authentication keys are classical; PQShield notes Apple could swap in PQ signatures - [Apple security blog](https://apple.co/4bKuUFI); [PQShield on PQ3](https://pqshield.com/?p=3206)
- Chrome/Cloudflare: Merkle Tree Certificates move the ML-DSA signature to a tree head and ship small inclusion proofs (one source cites 736 B for a batch of about 4.4M certs); about 1000 sites in a live test; Chrome says no plan to add traditional PQ X.509 certs to its current root store, PQ root store slated for Q3 2027; Let's Encrypt targeting MTC staging late 2026 - [postquantum.com on Google MTC](https://postquantum.com/security-pqc/googles-merkle-tree-mtc-https/); [postquantum.com on Let's Encrypt MTC](https://postquantum.com/security-pqc/lets-encrypt-merkle-tree-mtc-post-quantum/); [LWN](https://lwn.net/Articles/1060941/) (secondary; primary Cloudflare/Chrome posts not fetched)
- Cloudflare recommends a "plan B" of reducing the number of signatures sent while on-ramp schemes mature (older, Nov 2024) - [Cloudflare](https://blog.cloudflare.com/another-look-at-pq-signatures/)

### Inferences
- cb2.public is already equivalent in size to RFC 10073 id-MLDSA65-Ed25519-SHA512. Adopting the RFC 10073 message construction (or citing it) gives cb2 a standards story; switching to id-MLDSA44-Ed25519-SHA512 is the only standards-backed size cut available today (-24 percent).
- Dropping Ed25519 saves only 85 chars and loses the hedge against an ML-DSA break; the hedge is cheap and BSI wants it. The real lever is the PQ component.
- The MTC lesson for tokens: amortize the PQ signature. A batch issuer could sign a Merkle root of many tokens (one ML-DSA signature per batch, published out of band) and each token carries Ed25519 + an inclusion path (about 32 B x log2(batch); 20 levels = 640 B). That trades online verification for a fetched/cached batch root and adds issuance latency; it is a design idea, not something found deployed for tokens.

### Gaps
- No primary statement from Signal or Apple explaining why authentication stayed classical; size is the inferred reason.
- ANSSI primary text not fetched.

## Q6. PQ signatures in token formats (JOSE/COSE, PASETO, deployments)

### Takeaway
JOSE/COSE have standardized ML-DSA (RFC 9964), so a PQ JWT with ML-DSA-44 has a roughly 3.3 KB base64url signature; PASETO has only a Paragon draft (v5 = ML-DSA-87, v6 = SLH-DSA-128s), both larger than cb2 today. No deployed PQ token format smaller than ML-DSA-44 was found.

### Cited Findings
- RFC 9964 registers ML-DSA-44/65/87 for JOSE and COSE and introduces the AKP key type - [RFC Editor](https://www.rfc-editor.org/info/rfc9964); [draft-ietf-cose-dilithium-11](https://www.ietf.org/archive/id/draft-ietf-cose-dilithium-11.html)
- Paragon draft PASETO v5 (FIPS/CNSA 2.0 target) uses ML-DSA-87 for public tokens; v6 uses SLH-DSA-SHA256-128s; local modes unchanged - [Paragon Initiative](https://paragonie.com/b/KdUgiEnDfzKMfImK) (date not stated; status of draft unknown)
- Unofficial Rust crate paseto-pq uses a paseto.pq1 header, ML-DSA-44 by default (-65/-87 optional), explicitly not compatible with standard PASETO - [docs.rs paseto-pq](https://docs.rs/paseto-pq)

### Inferences
- Paragon v5 public token signature alone: 4627 B, about 6170 base64url chars, larger than cb2's current 4883-char token; v6 about 10475 chars. cb2 with Ed25519 + ML-DSA-44 would be smaller than any standards-track PQ token found.
- A PQ JWT with RFC 9964 ML-DSA-44 has a 3227-char signature segment plus JSON header/claims; cb2's binary claims encoding is already the smaller format, so the signature choice dominates.

### Gaps
- No real-world deployment of PQ-signed bearer tokens (e.g., an IdP issuing ML-DSA JWTs in production) with published sizes was found.
- Composite JOSE/COSE (ML-DSA + Ed25519) drafts were not checked this session.

## Summary table (sig bytes, token chars at 385 non-signature chars)

| Option | Status Nov 2026 | Sig B | Token chars | vs today |
|---|---|---|---|---|
| Ed25519 + ML-DSA-65 (today) | FIPS 204, RFC 10073 | 3373 | 4883 | 0 |
| Ed25519 + ML-DSA-44 | FIPS 204, RFC 10073, RFC 9964 | 2484 | 3697 | -24% |
| ML-DSA-44 only | FIPS 204, RFC 9964 | 2420 | 3612 | -26% |
| Ed25519 + ML-DSA-87 | FIPS 204, CNSA 2.0 | 4691 | 6640 | +36% |
| Ed25519 + Falcon-1024 | FIPS 206 not published | 1344 | 2177 | -55% |
| Ed25519 + Falcon-512 | FIPS 206 not published | 730 | 1359 | -72% |
| Ed25519 + LMS H20 | SP 800-208, stateful | 1176 | 1953 | -60% |
| Ed25519 + MAYO-1 (r2) | round 3 | 518 | 1076 | -78% |
| Ed25519 + SNOVA ~248 | round 3, unstable | 312 | 801 | -84% |
| Ed25519 + MAYO-2 (r2) | round 3, cat-1 set attacked | 250 | 719 | -85% |
| Ed25519 + SQIsign I | round 3, slow | 212 | 668 | -86% |
| Ed25519 + UOV 96 | round 3, reparameterizing, pk >200 KB | 160 | 599 | -88% |
| Ed25519 + FAEST-128f | round 3 | 5760 | 8065 | +65% |
| Ed25519 + SLH-DSA-128s | FIPS 205 | 7920 | 10945 | +124% |
