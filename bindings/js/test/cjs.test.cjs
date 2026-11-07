/**
 * The CommonJS entry: require("cb2") through the exports map gives the
 * same load() and Cb2Error as the ES module entry. Run with npm test.
 */
"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");

const cjs = require("cb2");

test("require gives the ES module's exports", async () => {
    const esm = await import("cb2");
    assert.equal(typeof cjs.load, "function");
    assert.equal(cjs.load, esm.load);
    assert.equal(cjs.Cb2Error, esm.Cb2Error);
    assert.equal(require.resolve("cb2"), require.resolve("../cb2.cjs"));
    assert.equal(require("cb2/package.json").name, "cb2");
});

test("a token round trip from CommonJS", async () => {
    const cb2 = await cjs.load();
    const key = cb2.LocalKey.generate();
    const token = cb2.Token.seal(key, { iss: "i", aud: "a", sub: "cjs", exp: "2099-01-01T00:00:00Z" });
    assert.equal(cb2.Token.open(token, key, { issuer: "i", audience: "a" }).sub, "cjs");
    assert.throws(() => cb2.Token.open(token, key, { issuer: "i", audience: "b" }),
        (e) => e instanceof cjs.Cb2Error && e.name === "audience_mismatch" && e.code === 14);
    key.free();
});
