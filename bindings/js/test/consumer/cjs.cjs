/**
 * A consumer of the package from CommonJS: requires cb2 by name, seals and
 * opens a claims token, and checks a tampered one is refused. Run from a
 * project that installed the package.
 */
"use strict";

const assert = require("node:assert/strict");
const { Cb2Error, load } = require("cb2");
const { version } = require("cb2/package.json");

load().then((cb2) => {
    assert.equal(cb2.version(), version);
    const key = cb2.LocalKey.generate();
    const token = cb2.Token.seal(key, { iss: "https://issuer.example", aud: "api", sub: "cjs", exp: "2099-01-01T00:00:00Z" });
    const claims = cb2.Token.open(token, key, { issuer: "https://issuer.example", audience: "api" });
    assert.equal(claims.sub, "cjs");
    const tampered = token.slice(0, -2) + (token.at(-2) === "A" ? "B" : "A") + token.at(-1);
    assert.throws(() => cb2.Token.open(tampered, key, { issuer: "https://issuer.example", audience: "api" }),
        (e) => e instanceof Cb2Error && e.name === "invalid" && e.code === 1);
    key.free();
    console.log(`cjs: cb2 ${cb2.version()} from ${require.resolve("cb2")}, sealed, opened and refused a tampered token`);
}).catch((e) => {
    console.error(e);
    process.exitCode = 1;
});
