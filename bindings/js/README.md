# cb2 for JavaScript

cb2 is a format for security tokens, the strings a server hands out
after a login and later accepts as proof of who is calling. It does the
job of JWT and PASETO with the checks built in: the verifier must say
which issuer and audience it accepts, expiry is required by default, and
signed tokens carry a post-quantum signature (ML-DSA-65) next to
Ed25519. This package is the cb2 C++ library compiled to WebAssembly,
one build for Node and browsers, with TypeScript declarations and no
runtime dependencies.

The format, its rationale and its limits are described in the
[main README](https://github.com/Crdzbird/cb2#readme),
[docs/SPEC.md](https://github.com/Crdzbird/cb2/blob/main/docs/SPEC.md),
[docs/PROTOCOL.md](https://github.com/Crdzbird/cb2/blob/main/docs/PROTOCOL.md)
and [docs/SECURITY.md](https://github.com/Crdzbird/cb2/blob/main/docs/SECURITY.md).
cb2 is version 0.1.0 and has not been reviewed by anyone but its author.

## Install

The package is not on the npm registry yet. Install it from a checkout
of the repository, or from a tarball made there with `npm pack`:

    npm install /path/to/cb2/bindings/js
    npm install ./cb2-0.1.0.tgz

It needs Node 22.12 or later, or any current browser.

## Quick start in Node

An issuer seals a token under a shared key; a service opens it with the
rules it requires, and a token for another audience is refused:

```js
import { load, Cb2Error } from "cb2";

const cb2 = await load();
const key = cb2.LocalKey.generate();

const token = cb2.Token.seal(key, {
    iss: "https://auth.example",
    aud: "api",
    sub: "user-1",
    exp: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    role: "admin",
});

const claims = cb2.Token.open(token, key, { issuer: "https://auth.example", audience: "api" });
console.log(claims.sub, claims.role);

try {
    cb2.Token.open(token, key, { issuer: "https://auth.example", audience: "billing" });
} catch (e) {
    if (e instanceof Cb2Error) console.log("refused:", e.name);
}

key.free();
```

It prints `user-1 admin` and then `refused: audience_mismatch`. In a
real service the key comes from a secret store: `key.toPaserk()` gives
its text form (`kcb2.local....`), and `cb2.LocalKey.fromPaserk(text)`
reads it back.

From CommonJS the same API comes through `require`:

```js
const { load, Cb2Error } = require("cb2");
```

## Quick start in a browser

With a static server that serves the package directory (and sends `.wasm`
as `application/wasm`), an import map is all a page needs:

```html
<script type="importmap">
  { "imports": { "cb2": "./node_modules/cb2/src/cb2.js" } }
</script>
<script type="module">
  import { load } from "cb2";

  const cb2 = await load();
  const signer = cb2.SecretKey.generate();
  const token = cb2.Token.sign(signer, { iss: "https://auth.example", aud: "web", exp: "2099-01-01T00:00:00Z" });
  const verifier = cb2.PublicKey.fromPaserk(signer.publicKey().toPaserk());
  const claims = cb2.Token.verify(token, verifier, { issuer: "https://auth.example", audience: "web" });
  document.body.textContent = `verified a ${token.length}-character token for ${claims.aud}`;
</script>
```

The page shows `verified a 4695-character token for web` (the length
depends on the claims). The core finds `cb2_core.wasm` next to
`cb2_core.js`; with a bundler, see "Browsers and bundlers" below.

## Token kinds and when to use each

| kind | use it when | key | typical size |
|---|---|---|---|
| `cb2.local` (`Token.seal`, `Token.open`) | the party that issues the token is the one that checks it, or shares a key with it: sessions, service to service calls inside one system. The claims are encrypted. | `LocalKey`, 32 bytes, shared | 250 to 450 characters |
| `cb2.public` (`Token.sign`, `Token.verify`) | many parties must check tokens they cannot issue. The claims are signed, not encrypted. Ed25519 and ML-DSA-65 must both verify. | `SecretKey` signs, `PublicKey` verifies | about 4,800 characters |
| holder proofs (`Holder.prove`, `Holder.proveLocal`) | a stolen token must be useless: the issuer puts a key in the token's `cnf` claim and the client proves it holds that key on every request | the proof key in `cnf`, or the client's `SecretKey` | about 360 (local) or 4,800 (public) characters |
| `kcb2.local-wrap` (`KeyWrap`) | storing local keys encrypted under another local key | two `LocalKey`s | 144 characters |
| `kcb2.seal` (`Seal`) | handing a local key to a recipient, safe against a future quantum computer (X-Wing) | the recipient's `RecipientKey` pair | about 1,600 characters |

`Local` and `Public` are the same formats with any bytes as the message
instead of claims, for callers who check the content themselves.

## API overview

`load(options?)` instantiates the WebAssembly core and resolves to the
API. Each call builds an independent core. The declarations ship in
`types/` and are picked by the exports map for import and require alike.

```ts
type Opt = Bytes | null | undefined;

declare function load(options?: LoadOptions): Promise<Cb2>;

interface Cb2 {
    LocalKey: { generate(): LocalKey; fromBytes(bytes: Uint8Array): LocalKey; fromPaserk(text: string): LocalKey };
    SecretKey: { generate(): SecretKey; fromBytes(bytes: Uint8Array): SecretKey; fromPaserk(text: string): SecretKey };
    PublicKey: { fromBytes(bytes: Uint8Array): PublicKey; fromPaserk(text: string): PublicKey };
    RecipientKey: { generate(): RecipientKey; fromBytes(bytes: Uint8Array): RecipientKey; fromPaserk(text: string): RecipientKey };
    RecipientPublicKey: { fromBytes(bytes: Uint8Array): RecipientPublicKey; fromPaserk(text: string): RecipientPublicKey };
    Token: {
        seal(key: LocalKey, claims: Claims, implicit?: Opt): string;
        open(token: string, key: LocalKey, rules: Rules, implicit?: Opt): Claims;
        sign(key: SecretKey, claims: Claims, implicit?: Opt): string;
        verify(token: string, key: PublicKey, rules: Rules, implicit?: Opt): Claims;
        peekKeyId(token: string): string | null;
    };
    Local: {
        seal(key: LocalKey, msg: Bytes, footer?: Opt, implicit?: Opt): string;
        open(key: LocalKey, token: string, footer?: Opt, implicit?: Opt, maxTokenBytes?: number): Uint8Array;
    };
    Public: {
        sign(key: SecretKey, msg: Bytes, footer?: Opt, implicit?: Opt): string;
        verify(key: PublicKey, token: string, footer?: Opt, implicit?: Opt, maxTokenBytes?: number): Uint8Array;
    };
    Holder: {
        prove(clientSecret: SecretKey, request: HolderRequest, accessToken: string, jti: string, now?: number, lifetime?: number): string;
        proveLocal(proofKey: LocalKey, request: HolderRequest, accessToken: string, jti: string, now?: number, lifetime?: number): string;
        normalizeTarget(uri: string): string;
    };
    KeyWrap: { wrap(wrapping: LocalKey, key: LocalKey): string; unwrap(text: string, wrapping: LocalKey): LocalKey };
    Seal: { seal(to: RecipientPublicKey, key: LocalKey): string; unseal(text: string, by: RecipientKey): LocalKey };
    hasPublic(): boolean;
    hasSeal(): boolean;
    version(): string;
    errorName(code: number): string;
    Cb2Error: typeof Cb2Error;
    core: Cb2Core;
}
```

That is a summary; `types/cb2.d.ts` has the exact signatures with their
documentation. In short:

- **Keys.** Every key has `toPaserk()` and `free()`; local and public
  keys have `paserkId()`; the signing and local keys have a `keyId` that
  is written into each token's footer (by default the PASERK id), with
  `setKeyId(id)` and `clearKeyId()`; the two secret pairs have
  `publicKey()`. The declarations make the five key types distinct, so a
  `PublicKey` cannot be passed where a `LocalKey` is expected.
- **Claims** are a plain object. The registered claims are strings:
  `iss`, `sub`, `aud` (one audience), `jti`, `cnf`, and the times `exp`,
  `nbf`, `iat` in RFC 3339 (`new Date(...).toISOString()` works). Any
  other member is a custom claim with any JSON value.
- **Rules** mirror the rules JSON of the C library member for member:
  `issuer` (or `allow_any_issuer`) and `audience` (or
  `allow_any_audience`) are required, then `subject`, `now`,
  `clock_skew` (default 0), `require_exp` (default true),
  `max_lifetime`, `max_token_bytes`, `seen_jti`, `require_cnf`,
  `ignore_cnf`, and for holder proofs `proof`, `request`,
  `proof_lifetime`, `proof_seen_jti`. Two members may be functions:
  `replay: (jti) => boolean` and `proofReplay: (jti) => boolean`, run
  inside the call as replay checks; returning false refuses the token
  as `replayed` (or the proof as `proof_replayed`), and so does throwing.
- **Holder proofs.** `Holder.prove(clientSecret, { htm, htu, nonce },
  accessToken, jti, now?, lifetime?)` is the public mode,
  `Holder.proveLocal(proofKey, ...)` the local mode; the server passes
  the proof and the request in the rules of `Token.open` or
  `Token.verify`.
- **Options of `load`**: `locateFile(path, prefix)` to say where
  `cb2_core.wasm` is served from, `wasmBinary` with its bytes, or any
  other Emscripten module option such as `instantiateWasm`.
- **`cb2/core`** exports the bare Emscripten factory, and `core` on the
  API is the module itself, with every function of the C ABI declared as
  `_cb2_*`.

## Errors

Every refusal throws a `Cb2Error`, and nothing else is thrown for a
refused token. It has `code` (1 to 24) and `name`, the stable verdict
name, typed as the union `Cb2ErrorName`: `invalid` (wrong key, changed
token, wrong footer or implicit assertion), `expired`, `not_yet_valid`,
`issuer_mismatch`, `audience_mismatch`, `subject_mismatch`, `replayed`,
`rules_incomplete` (the rules name no issuer or audience),
`claims_malformed`, `missing_proof`, `proof_mismatch`, `proof_replayed`
and the others listed in docs/PROTOCOL.md. A web service usually maps
all of them to 401 and logs the name.

## Memory

Keys are handles into the wasm heap and are not collected by the garbage
collector: call `free()` when a key is no longer needed (using a freed
key throws). Everything else is copied out and released inside the
call, and key material in transit (the bytes and PASERK text given to
the secret constructors, the PASERK text of a secret) is wiped before it
is released.

## Browsers and bundlers

`dist/cb2_core.js` finds the wasm with
`new URL("cb2_core.wasm", import.meta.url)`, so by default the wasm is
fetched from next to the module. Bundlers that understand that pattern
emit the wasm as an asset and rewrite the URL. Checked with the packed
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

In Node 22.12 loading the package from CommonJS prints an
ExperimentalWarning, because the CommonJS entry loads the ES module with
`require()`; Node 22.13 and later print nothing.

## Example apps

- `examples/node`: a `node:http` server with no other dependency. `POST
  /login` checks a demo password and issues a cb2.local access token,
  `GET /me` opens the bearer token under the server's rules, and every
  refusal is a 401 naming the verdict (`invalid`, `expired`, ...). `npm
  install && npm start` runs it; `npm test` drives it over HTTP, and
  `bash smoke.sh` starts it and drives it with curl. The key comes from
  `CB2_LOCAL_KEY` (a kcb2.local PASERK) or is generated at start; `PORT`
  and `TOKEN_TTL_SECONDS` set the port and the lifetime.

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

## Benchmarks

`bench/` times cb2 against the JavaScript libraries most used for JWT
and PASETO v4, on one claims payload: `iss`, `sub`, `aud`, `exp`,
`iat`, `jti` and one custom claim (`role`). JWT carries the times as
numbers, as its standard says; cb2 and PASETO carry them as RFC 3339
text. "Issue" makes one token. "Verify" checks it the way a service
would and returns the claims: the signature or tag, the expiry, the
issuer and the audience. Every case is run once and its claims checked
before it is timed.

- **jose** 6.2.15 (panva), the most used JWT library: HS256 with a
  shared key, EdDSA (Ed25519) and ES256 with a key pair, verified with
  `jwtVerify` and the issuer, audience and algorithm pinned.
- **paseto** 4.0.1 (panva) for PASETO v4.public, verified with the issuer
  and audience options. Its v4.local needs the caller to supply
  XChaCha20 and BLAKE2b through an extension API, so it is not used for
  v4.local.
- **paseto-ts** 2.0.7 for PASETO v4.local, the most downloaded
  maintained package with v4.local built in (pure TypeScript over
  @stablelib). Its v4.public is shown as well. It checks the time claims
  itself; it has no issuer or audience option, so the benchmark compares
  `iss` and `aud` after it.

The runtimes differ, and that shapes the numbers: jose and panva's
paseto call WebCrypto (`crypto.subtle`), which in Node is native code
reached through asynchronous calls, while cb2 is the C++ library
compiled to WebAssembly and runs synchronously, and paseto-ts is plain
JavaScript. The harness warms each operation up, times it in batches of
at least 10 ms, and reports the median of 21 batches, taken in 5
interleaved rounds as the median of the round medians.

Apple M3 Max, macOS 26.6.2 (Darwin 25.6.0), Node 26.12.1, 2026-11-07, with
other work running on the machine (load average about 4 to 5). Times in
microseconds per token, lower is better; a second run agreed within 14%.

| key | token | issue (us) | verify (us) | token bytes |
|---|---|--:|--:|--:|
| shared | cb2.local (cb2, wasm) | 25.1 | 7.1 | 430 |
| shared | JWT HS256 (jose) | 15.9 | 15.0 | 285 |
| shared | PASETO v4.local (paseto-ts) | 44.5 | 38.4 | 331 |
| pair | cb2.public, Ed25519 + ML-DSA-65 (cb2, wasm) | 470 | 217 | 4843 |
| pair | JWT EdDSA, Ed25519 (jose) | 54.9 | 123 | 328 |
| pair | JWT ES256 (jose) | 40.6 | 75.8 | 328 |
| pair | PASETO v4.public (paseto) | 56.1 | 122 | 332 |
| pair | PASETO v4.public (paseto-ts) | 2903 | 5754 | 332 |

The same benchmark in the browser pane of the Claude desktop app
(Chromium 152, not cross-origin isolated), same machine and day. A
second run was up to 37% slower on the fastest operations, so read these
as rough:

| key | token | issue (us) | verify (us) | token bytes |
|---|---|--:|--:|--:|
| shared | cb2.local (cb2, wasm) | 32.2 | 8.1 | 430 |
| shared | JWT HS256 (jose) | 9.3 | 8.8 | 285 |
| shared | PASETO v4.local (paseto-ts) | 48.0 | 41.4 | 331 |
| pair | cb2.public, Ed25519 + ML-DSA-65 (cb2, wasm) | 491 | 220 | 4843 |
| pair | JWT EdDSA, Ed25519 (jose) | 30.3 | 54.3 | 328 |
| pair | JWT ES256 (jose) | 55.5 | 106 | 328 |
| pair | PASETO v4.public (paseto) | 31.3 | 57.4 | 332 |
| pair | PASETO v4.public (paseto-ts) | 2175 | 4625 | 332 |

What the tables say:

- With a shared key, cb2.local verifies faster than the other two in
  both runtimes and issues slower than HS256. The three do not do the
  same thing: HS256 only authenticates and anyone can read its claims,
  while cb2.local and v4.local encrypt them.
- cb2.public is the slowest key-pair token apart from pure-JavaScript
  paseto-ts, and by far the largest, by design. It carries an ML-DSA-65
  signature (3,309 bytes) next to the Ed25519 one and both must verify,
  so it stays secure if Ed25519 is broken by a quantum computer; the
  classical formats carry one 64-byte signature and do not. Against
  jose's EdDSA and ES256, issuing costs 9 to 12 times as much in Node
  and 9 to 16 times in the browser, where WebCrypto is faster;
  verifying costs 2 to 3 times as much in Node and 2 to 4 times in the
  browser. The token is about 15 times the size.
- cb2 tokens name the key in a footer by default, which is 85 of the
  bytes above; after `clearKeyId()` the two cb2 tokens are 345 and 4,758
  bytes. The JWT and PASETO tokens here carry no key id.

To run it: `cd bench && npm install && npm run bench` for Node (`npm run
smoke` is the short run CI uses), and for the browser serve `bench/`
with any static server, such as `python3 -m http.server`, and open
`/browser/index.html`.

## Development

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
compares the `_cb2_*` functions declared on `Cb2Core` with `cb2_c.h`
and with the exports of the wasm, and the members of the runtime API
with the ones declared.

### Building the core

The wasm32 dependencies (libsodium, BLAKE3, liboqs) come from
`web/deps/wasm32`, built by `web/build_deps.sh` when they are missing.
With Emscripten on the PATH, from the repository root:

    bash bindings/js/build.sh

`build.sh` compiles `bindings/c/src/cb2_c.cpp` and exports every `cb2_*`
function of `cb2_c.h` plus `malloc` and `free`, with table growth
enabled for the replay callbacks. The build has cb2.public and kcb2.seal
through liboqs and uses libsodium's XChaCha20 for cb2.local; it has no
OpenSSL. The dist files are committed, like `web/dist`, so users of the
package do not need Emscripten.

### Layout

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
    bench/                the benchmark against jose and PASETO v4,
                          with its own package.json
