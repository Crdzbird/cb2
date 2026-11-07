## 0.2.0

- Shaped as a library: README, LICENSE, an example CLI, dartdoc on every
  public member, and `very_good_analysis` with strict casts, inference
  and raw types.
- The FFI bindings are split by area under `lib/src/ffi` and no longer
  reachable from the public API; `Cb2Library.bindings` is gone.
- The holder proof members of `Rules` (`proof`, `request`,
  `proofLifetime`, `proofSeenJti`, `proofReplay`) move to `HolderRules`,
  given as `Rules(holder: ...)`.

## 0.1.0

- First bindings over the cb2 C ABI: cb2.local and cb2.public tokens,
  raw and claims, holder proofs, key wrapping and kcb2.seal.
