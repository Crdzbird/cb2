/**
 * The example end to end over HTTP on a free port, with a clock the test
 * moves: login, the protected route, and the refusals of a tampered, an
 * expired, a foreign and a missing token.
 */
import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { after, before, test } from "node:test";
import { load } from "cb2";
import { createApp } from "./app.mjs";

const cb2 = await load();
const key = cb2.LocalKey.generate();
let now = 1_800_000_000;
const server = createServer(createApp({ cb2, key, issuer: "https://test", audience: "api", ttl: 60, clock: () => now }));
let base = "";

before(async () => {
    server.listen(0);
    await once(server, "listening");
    base = `http://localhost:${server.address().port}`;
});

after(() => {
    server.close();
    key.free();
});

async function call(path, { token, body } = {}) {
    const headers = token ? { authorization: `Bearer ${token}` } : {};
    const init = body ? { method: "POST", body: JSON.stringify(body), headers } : { headers };
    const res = await fetch(base + path, init);
    return { status: res.status, body: await res.json(), auth: res.headers.get("www-authenticate") };
}

async function login(user = "ada", password = "lovelace") {
    return (await call("/login", { body: { user, password } })).body.access_token;
}

test("login issues a token the protected route accepts", async () => {
    const token = await login();
    assert.ok(token.startsWith("cb2.local."));
    const me = await call("/me", { token });
    assert.equal(me.status, 200);
    assert.deepEqual(me.body, { sub: "ada", role: "admin", exp: "2027-01-15T08:01:00+00:00" });
});

test("a wrong password or a malformed body is refused", async () => {
    assert.equal((await call("/login", { body: { user: "ada", password: "nope" } })).status, 401);
    assert.equal((await call("/login", { body: { user: "nobody", password: "lovelace" } })).status, 401);
    assert.equal((await call("/login", { body: { user: 1 } })).status, 400);
});

test("a tampered token is refused as invalid", async () => {
    const token = await login();
    const flipped = token.slice(0, 20) + (token[20] === "A" ? "B" : "A") + token.slice(21);
    const me = await call("/me", { token: flipped });
    assert.equal(me.status, 401);
    assert.equal(me.body.reason, "invalid");
    assert.match(me.auth, /error="invalid_token", error_description="invalid"/);
});

test("an expired token is refused as expired", async () => {
    const token = await login("alan", "turing");
    now += 61;
    const me = await call("/me", { token });
    now -= 61;
    assert.equal(me.status, 401);
    assert.equal(me.body.reason, "expired");
});

test("a token under another key, or none, is refused", async () => {
    const other = cb2.LocalKey.generate();
    const foreign = cb2.Token.seal(other, { iss: "https://test", aud: "api", exp: "2099-01-01T00:00:00Z" });
    other.free();
    assert.equal((await call("/me", { token: foreign })).body.reason, "unknown_key");
    const none = await call("/me");
    assert.equal(none.status, 401);
    assert.equal(none.body.error, "missing_token");
    assert.equal((await call("/me", { token: "cb2.local.garbage" })).body.reason, "invalid");
});
