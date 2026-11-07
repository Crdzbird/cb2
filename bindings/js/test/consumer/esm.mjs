/**
 * A consumer of the package as an ES module: imports cb2 and cb2/core by
 * name, seals and opens a claims token, and checks a tampered one is
 * refused. Run from a project that installed the package.
 */
import assert from "node:assert/strict";
import createCb2Core from "cb2/core";
import { Cb2Error, load } from "cb2";

const cb2 = await load();
const key = cb2.LocalKey.generate();
const token = cb2.Token.seal(key, { iss: "https://issuer.example", aud: "api", sub: "esm", exp: "2099-01-01T00:00:00Z" });
const claims = cb2.Token.open(token, key, { issuer: "https://issuer.example", audience: "api" });
assert.equal(claims.sub, "esm");
const tampered = token.slice(0, -2) + (token.at(-2) === "A" ? "B" : "A") + token.at(-1);
assert.throws(() => cb2.Token.open(tampered, key, { issuer: "https://issuer.example", audience: "api" }),
    (e) => e instanceof Cb2Error && e.name === "invalid" && e.code === 1);
key.free();
const core = await createCb2Core();
assert.equal(core.UTF8ToString(core._cb2_version()), cb2.version());
console.log(`esm: cb2 ${cb2.version()} from ${import.meta.resolve("cb2")}, sealed, opened and refused a tampered token`);
