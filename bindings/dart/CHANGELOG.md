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
- `ClaimTable`: the claim table of docs/PROTOCOL.md section 15.5 over
  `cb2_claim_table_from_json`, `cb2_claim_table_digest` and
  `cb2_claim_table_free`. `ClaimTable.fromEntries` takes 1 to 256
  distinct, non-empty strings, `digest` gives its 32-byte digest, and the
  handle is released by `dispose` or a finalizer, like the keys.
- `CompactToken.seal`, `open`, `sign` and `verify` take an optional
  `table:`, over the `cb2_compact_*_with_table` functions. A token opens
  only under the table it was made under; without a table nothing
  changes, except that an implicit assertion beginning with `kcb3.table.`
  is refused with `argument`.
- The benchmark times cb3.local and cb3.public next to cb2.local and
  cb2.public, and cb3.local under a claim table; the example opens a
  cb3.local token alone and under a table.

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
