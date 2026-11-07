# cb2 example: a Node login server

A `node:http` server with no dependency besides cb2. `POST /login` checks
a demo password and answers with a cb2.local access token; `GET /me`
opens the bearer token under the server's rules (issuer, audience, the
longest lifetime) and answers with its claims. A refused token is a 401
whose body and `WWW-Authenticate` header name the library's verdict.

    npm install
    npm start
    npm test

The demo accounts are `ada` / `lovelace` (admin) and `alan` / `turing`
(reader). `CB2_LOCAL_KEY` gives the key as kcb2.local PASERK text;
without it a key is generated at start and tokens do not survive a
restart. `PORT` defaults to 3000 and `TOKEN_TTL_SECONDS` to 600.

    curl -s -X POST localhost:3000/login -d '{"user":"ada","password":"lovelace"}'
    curl -s localhost:3000/me -H "authorization: Bearer $TOKEN"

`app.mjs` is the handler, `server.mjs` starts it, and `test.mjs` drives
it over HTTP with a clock it moves: a good token, a wrong password, a
tampered token, an expired one, one under another key, and none.
`smoke.sh` starts the server with a two-second token lifetime and goes
through the same cases with curl.
