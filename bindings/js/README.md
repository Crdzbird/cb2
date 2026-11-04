# cb2 for JavaScript

The C ABI of cb2 (`bindings/c`) compiled to WebAssembly with Emscripten,
with a small JavaScript bridge over it. One build serves Node (22.12 and
later) and browsers; the same `cb2_core.wasm` runs in both. The build has
cb2.public (ML-DSA-65) and kcb2.seal (X-Wing) through liboqs, and uses
libsodium's XChaCha20 for cb2.local; it has no OpenSSL and no dependencies.

## Layout

    build.sh          compiles bindings/c/src/cb2_c.cpp to dist/
    dist/cb2_core.js  the Emscripten module (ES module, committed)
    dist/cb2_core.wasm
    src/cb2.js        the ES module entry: load() and Cb2Error
    cb2.cjs           the CommonJS entry, the same two exports
    test/test.mjs     node --test, mirrors bindings/c/test/test_c.c

## Building

The wasm32 dependencies (libsodium, BLAKE3, liboqs) come from
`web/deps/wasm32`, built by `web/build_deps.sh` when they are missing.
With Emscripten on the PATH:

    bash bindings/js/build.sh
    node --test bindings/js/test/

`build.sh` exports every `cb2_*` function of `cb2_c.h` plus `malloc` and
`free`, with table growth enabled for the replay callbacks. The dist files
are committed, like `web/dist`, so users of the package do not need
Emscripten.

## Use

Node, as an ES module:

```js
import { load, Cb2Error } from "cb2";

const cb2 = await load();
```

Node, from CommonJS:

```js
const { load, Cb2Error } = require("cb2");

load().then((cb2) => { /* ... */ });
```

A browser, from a module script. The core finds `cb2_core.wasm` next to
`cb2_core.js` through `import.meta.url`; pass `locateFile` when it is
served from somewhere else, or `wasmBinary` with the bytes already
fetched:

```html
<script type="module">
import { load } from "./node_modules/cb2/src/cb2.js";

const cb2 = await load({ locateFile: (name) => "/static/" + name });
</script>
```

Every call to `load()` instantiates an independent core.

## Example

An access token sealed by an issuer, opened by a service with the rules
it requires, with a replay store as a function:

```js
import { load, Cb2Error } from "cb2";

const cb2 = await load();
const key = cb2.LocalKey.generate();

const token = cb2.Token.seal(key, {
    iss: "https://issuer.example",
    aud: "api",
    sub: "user-1",
    exp: "2099-01-01T00:00:00+00:00",
    jti: "7f2a",
    role: "admin",
});

const seen = new Set();
const rules = {
    issuer: "https://issuer.example",
    audience: "api",
    replay: (jti) => (seen.has(jti) ? false : (seen.add(jti), true)),
};

const claims = cb2.Token.open(token, key, rules);
console.log(claims.role);

try {
    cb2.Token.open(token, key, rules);
} catch (e) {
    if (e instanceof Cb2Error) console.log(e.name, e.code);
}

key.free();
```

The second open prints `replayed 17`.

## API

`load(options)` resolves to an object with:

- Key classes `LocalKey`, `SecretKey`, `PublicKey`, `RecipientKey`,
  `RecipientPublicKey`. Each offers what its ABI type offers: `generate()`
  (not the public halves), `fromBytes(Uint8Array)`, `fromPaserk(text)`,
  `toPaserk()`, `paserkId()` (not `SecretKey`, whose id is its public
  key's), the `keyId` getter with `setKeyId(id)` and `clearKeyId()` (the
  three signing and local types), `publicKey()` (the two secret pairs),
  and `free()`. A freed key throws when used; `freed` says whether it was.
- `Local.seal(key, msg, footer, implicit)` and
  `Local.open(key, token, footer, implicit, maxTokenBytes)`;
  `Public.sign` and `Public.verify` with the same shapes. `msg`, `footer`
  and `implicit` are a `Uint8Array` or a string (UTF-8); a token is a
  string; an opened message is a `Uint8Array`.
- `Token.seal(key, claims, implicit)`, `Token.sign(secretKey, claims,
  implicit)`, `Token.open(token, key, rules, implicit)`,
  `Token.verify(token, publicKey, rules, implicit)` and
  `Token.peekKeyId(token)`. Claims are a plain object, serialized with
  `JSON.stringify`, with the registered claims as strings (times as RFC
  3339); the opened claims come back as a plain object.
- `Holder.prove(clientSecret, { htm, htu, nonce }, accessToken, jti, now,
  lifetime)` and `Holder.normalizeTarget(uri)`. `now` defaults to the
  clock and `lifetime` to 60 seconds.
- `KeyWrap.wrap(wrapping, key)`, `KeyWrap.unwrap(text, wrapping)`,
  `Seal.seal(recipientPublic, key)`, `Seal.unseal(text, recipient)`.
- `hasPublic()`, `hasSeal()`, `version()`, `errorName(code)`, the
  `Cb2Error` class, and `core`, the Emscripten module itself.

### Rules

The rules object mirrors the rules JSON described in
`bindings/c/include/cb2_c.h`, member for member: `now`, `clock_skew`,
`require_exp`, `allow_any_audience`, `allow_any_issuer`, `issuer`,
`audience`, `subject`, `max_token_bytes`, `max_lifetime`, `seen_jti`,
`require_cnf`, `ignore_cnf`, `proof`, `request`, `proof_lifetime`,
`proof_seen_jti`. Two members may be functions:

- `replay: (jti) => boolean` runs as the replay check; the token is
  `replayed` when it returns false.
- `proofReplay: (jti) => boolean` runs as the proof replay check when a
  `proof` is given; a proof with neither `proofReplay` nor
  `proof_seen_jti` is `rules_incomplete`, as the library requires.

Both run inside the call only: they are installed in the wasm table for
the duration of `open` or `verify` and removed afterwards. An exception
thrown inside one refuses the id.

### Errors

Every refusal is a `Cb2Error` with `code` (the `cb2_code` value) and
`name`, the stable verdict name ("invalid", "expired", "replayed",
"proof_mismatch", ...). Nothing else is thrown for a refused token.

### Memory

Keys are handles into the wasm heap: call `free()` when done. Every other
result is copied out and released inside the call; key material in
transit (the bytes and PASERK text given to the secret constructors, the
PASERK text of a secret) is wiped before release.
