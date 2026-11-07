## Unreleased

- `CompactToken`: the experimental compact claims tokens cb3.local and
  cb3.public of docs/PROTOCOL.md section 15, over `cb2_compact_seal`,
  `cb2_compact_open`, `cb2_compact_sign` and `cb2_compact_verify`. They
  take the same claims, `Rules`, replay checks and holder proofs as
  `Token` and give the same verdicts, with tokens about half the size.
  The issuer refuses with `argument` a custom number that is not a
  canonical int64 integer (1.5, 1e3, -0), which `Token` accepts.
- `CompactToken.peekKeyDigest` and `CompactToken.keyDigest`: the 16-byte
  key digest a compact footer carries in place of the key id, and the
  digest of a key id to compare it with.
- The benchmark times cb3.local and cb3.public next to cb2.local and
  cb2.public, and the example opens a cb3.local token.

## 0.2.0

- Shaped as a library: README, LICENSE, an example CLI, dartdoc on every
  public member, and `very_good_analysis` with strict casts, inference
  and raw types.
- The FFI bindings are split by area under `lib/src/ffi` and no longer
  reachable from the public API; `Cb2Library.bindings` is gone.
- The holder proof members of `Rules` (`proof`, `request`,
  `proofLifetime`, `proofSeenJti`, `proofReplay`) move to `HolderRules`,
  given as `Rules(holder: ...)`.
- `Cb2Library.preferBundled` tries the bundled library before
  `CB2_C_LIBRARY`, so an app's environment cannot swap it.

## 0.1.0

- First bindings over the cb2 C ABI: cb2.local and cb2.public tokens,
  raw and claims, holder proofs, key wrapping and kcb2.seal.
