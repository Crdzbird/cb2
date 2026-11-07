# cb2 for JavaScript

The C ABI of cb2 (`bindings/c`) compiled to WebAssembly with Emscripten,
with a small JavaScript API over it, packaged for npm. One build serves
Node (22.12 and later) and browsers; the same `cb2_core.wasm` runs in
both. The build has cb2.public (Ed25519 and ML-DSA-65) and kcb2.seal
(X-Wing) through liboqs, and uses libsodium's XChaCha20 for cb2.local. It
has no runtime dependencies, and TypeScript declarations ship with it.

## Install

The package is not on the npm registry. Install it from a checkout, or
from a tarball made with `npm pack`:

    npm install /path/to/cb2/bindings/js
    npm install ./cb2-0.1.0.tgz

## Use

As an ES module:

```js
import { load, Cb2Error } from "cb2";

const cb2 = await load();
```

From CommonJS, through the `require` condition of the exports map:

```js
const { load, Cb2Error } = require("cb2");

load().then((cb2) => { /* ... */ });
```

The CommonJS entry loads the ES module with `require()`, which Node
supports from 22.12; Node 22.12 prints an ExperimentalWarning for it and
22.13 and later do not.

From TypeScript, with `module` set to `nodenext`, `node16` or `bundler`,
the declarations come from the `types` condition of whichever entry is
resolved (`types/cb2.d.ts` for import, `types/cb2.d.cts` for require):

```ts
import { load, Cb2Error, type LocalKey, type Rules } from "cb2";
```

Every call to `load()` instantiates an independent core, with its own
heap and its own key classes.

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

## Browsers and bundlers

`dist/cb2_core.js` finds the wasm with
`new URL("cb2_core.wasm", import.meta.url)`, so by default the wasm is
fetched from next to the module. With a plain static server that means
serving the package directory as it is (the server must send `.wasm` as
`application/wasm`), and mapping the bare name with an import map:

```html
<script type="importmap">
  { "imports": { "cb2": "./node_modules/cb2/src/cb2.js" } }
</script>
<script type="module">
  import { load } from "cb2";
  const cb2 = await load();
</script>
```

Bundlers that understand the `new URL(..., import.meta.url)` pattern emit
the wasm as an asset and rewrite the URL. Checked here with the packed
tarball, a page that seals, opens and refuses a token, in a browser:

| bundler | what it takes |
|---|---|
| Vite 8.3 | nothing, in `vite build` and in the dev server |
| webpack 5.112 | `new webpack.IgnorePlugin({ resourceRegExp: /^node:/ })` in the plugins; the core imports `node:module` only when it runs under Node, and webpack refuses the `node:` scheme in a browser build |
| esbuild 0.28 | `--external:node:*`, and a copy of `cb2_core.wasm` next to the output, since esbuild leaves the URL as it is |

Any other setup can place the wasm itself: copy it from
`node_modules/cb2/dist/cb2_core.wasm` (also exported as `cb2/core.wasm`)
and pass `locateFile`:

```js
const cb2 = await load({ locateFile: (name) => "/static/" + name });
```

or fetch the bytes and pass `wasmBinary`:

```js
const response = await fetch("/static/cb2_core.wasm");
const cb2 = await load({ wasmBinary: new Uint8Array(await response.arrayBuffer()) });
```

## Example apps

- `examples/node`: a `node:http` server with no other dependency. `POST
  /login` checks a demo password and issues a cb2.local access token,
  `GET /me` opens the bearer token under the server's rules, and every
  refusal is a 401 naming the verdict (`invalid`, `expired`, ...). `npm
  install && npm start` runs it; `npm test` drives it over HTTP, and
  `bash smoke.sh` starts it and drives it with curl. The key
  comes from `CB2_LOCAL_KEY` (a kcb2.local PASERK) or is generated at
  start; `PORT` and `TOKEN_TTL_SECONDS` set the port and the lifetime.

      curl -s -X POST localhost:3000/login -d '{"user":"ada","password":"lovelace"}'
      curl -s localhost:3000/me -H "authorization: Bearer $TOKEN"

- `examples/browser`: a static page that seals, opens, signs and verifies
  claims tokens with keys that live only in the page, and shows the
  verdict for a token with one character changed. `npm install && npm
  start` serves it on http://localhost:8080/ with the dependency-free
  `serve.mjs`. With `?selftest` in the URL the page presses its own
  buttons and writes the outcome to `data-selftest` on the body, which CI
  reads from headless Chrome.

Both depend on the package as `"cb2": "file:../.."`, so they run against
the sources in this directory.

## API

`load(options)` resolves to an object with:

- Key classes `LocalKey`, `SecretKey`, `PublicKey`, `RecipientKey`,
  `RecipientPublicKey`. Each offers what its ABI type offers: `generate()`
  (not the public halves), `fromBytes(Uint8Array)`, `fromPaserk(text)`,
  `toPaserk()`, `paserkId()` (not `SecretKey`, whose id is its public
  key's), the `keyId` getter with `setKeyId(id)` and `clearKeyId()` (the
  three signing and local types), `publicKey()` (the two secret pairs),
  and `free()`. A freed key throws when used; `freed` says whether it was.
  The declarations make the five key types distinct, so a `PublicKey`
  cannot be passed where a `LocalKey` is expected.
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
  lifetime)`, the public mode, `Holder.proveLocal(proofKey, { htm, htu,
  nonce }, accessToken, jti, now, lifetime)`, the local mode under the
  `kcb2.local` proof key the issuer put in `cnf` of a cb2.local token, and
  `Holder.normalizeTarget(uri)`. `now` defaults to the clock and
  `lifetime` to 60 seconds.
- `KeyWrap.wrap(wrapping, key)`, `KeyWrap.unwrap(text, wrapping)`,
  `Seal.seal(recipientPublic, key)`, `Seal.unseal(text, recipient)`.
- `hasPublic()`, `hasSeal()`, `version()`, `errorName(code)`, the
  `Cb2Error` class, and `core`, the Emscripten module itself, with every
  function of `cb2_c.h` declared as `_cb2_*`.

The options of `load` are `locateFile(path, prefix)`, `wasmBinary` (an
`ArrayBuffer` or `Uint8Array`), and any other Emscripten module option,
such as `instantiateWasm`. `cb2/core` exports the bare Emscripten factory.

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
"proof_mismatch", ...), typed as the union `Cb2ErrorName`. Nothing else
is thrown for a refused token.

### Memory

Keys are handles into the wasm heap: call `free()` when done. Every other
result is copied out and released inside the call; key material in
transit (the bytes and PASERK text given to the secret constructors, the
PASERK text of a secret) is wiped before release.

## Developing

    npm ci                 the dev tools: TypeScript and arethetypeswrong
    npm test               node --test: the API, the package, CommonJS
    npm run typecheck      tsc over the typed consumers in test/consumer
    npm run attw           arethetypeswrong over the packed package
    npm run check:pack     npm pack, install the tarball in a scratch
                           project, run the ES module and CommonJS
                           consumers there and tsc over the typed ones
    npm run types:sync     copy types/cb2.d.ts to types/cb2.d.cts

`types/cb2.d.ts` is the source of the declarations; the CommonJS copy
must stay identical, and a test says so when it is not. Another test
compares the `_cb2_*` functions declared on `Cb2Core` with `cb2_c.h`,
and the members of the runtime API with the ones declared.

### Building the core

The wasm32 dependencies (libsodium, BLAKE3, liboqs) come from
`web/deps/wasm32`, built by `web/build_deps.sh` when they are missing.
With Emscripten on the PATH:

    bash bindings/js/build.sh

`build.sh` exports every `cb2_*` function of `cb2_c.h` plus `malloc` and
`free`, with table growth enabled for the replay callbacks. The dist
files are committed, like `web/dist`, so users of the package do not need
Emscripten.

## Layout

    package.json          exports map, files, engines; no dependencies
    build.sh              compiles bindings/c/src/cb2_c.cpp to dist/
    dist/cb2_core.js      the Emscripten module (ES module, committed)
    dist/cb2_core.wasm
    src/cb2.js            the ES module entry: load() and Cb2Error
    cb2.cjs               the CommonJS entry, the same two exports
    types/                cb2.d.ts, its CommonJS copy cb2.d.cts, core.d.ts
    test/test.mjs         the API, mirroring bindings/c/test/test_c.c
    test/package.test.mjs the packed files, exports map and API shape
    test/cjs.test.cjs     the CommonJS entry
    test/consumer/        consumers by package name: esm.mjs, cjs.cjs,
                          and types.ts and types.cts for tsc
    scripts/check-pack.mjs
    examples/node         the node:http login server
    examples/browser      the static page
