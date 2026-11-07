# cb2 example: a static page

A page that loads cb2 in the browser through an import map, seals and
opens a claims token under a cb2.local key, signs and verifies one under a
cb2.public pair, and shows the verdict for a token with one character
changed. The keys are generated in the page and never leave it.

    npm install
    npm start

then open http://localhost:8080/. `serve.mjs` is a static server with no
dependencies that sends `.wasm` as `application/wasm`; any static server
that serves this directory, `node_modules/cb2` included, works as well.
The core fetches `cb2_core.wasm` from next to `cb2_core.js`.

Open http://localhost:8080/?selftest and the page presses its own
buttons and sets `data-selftest` on the body to `pass`, or to the step
that went wrong.
