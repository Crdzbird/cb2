/**
 * The package as published: the file list npm would pack, the exports map,
 * the two copies of the declarations, and the runtime shape of the API
 * against what types/cb2.d.ts declares. Run with npm test.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { load } from "../src/cb2.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const pkg = JSON.parse(read("package.json"));

const PACKED = [
    "LICENSE",
    "README.md",
    "cb2.cjs",
    "dist/cb2_core.js",
    "dist/cb2_core.wasm",
    "package.json",
    "src/cb2.js",
    "src/error.js",
    "src/heap.js",
    "src/keys.js",
    "src/tokens.js",
    "types/cb2.d.cts",
    "types/cb2.d.ts",
    "types/core.d.ts",
];

test("npm pack lists exactly the intended files", () => {
    const npm = process.platform === "win32" ? "npm.cmd" : "npm";
    const out = execFileSync(npm, ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: root, encoding: "utf8" });
    const files = JSON.parse(out)[0].files.map((f) => f.path).sort();
    assert.deepEqual(files, PACKED);
});

test("every target of the exports map exists and is packed", () => {
    const targets = [];
    const walk = (node) => {
        if (typeof node === "string") targets.push(node.replace(/^\.\//, ""));
        if (node && typeof node === "object") Object.values(node).forEach(walk);
    };
    walk(pkg.exports);
    walk({ main: pkg.main, module: pkg.module, types: pkg.types });
    assert.ok(targets.length >= 9);
    for (const t of targets) {
        assert.ok(existsSync(new URL(`../${t}`, import.meta.url)), `${t} exists`);
        assert.ok(PACKED.includes(t), `${t} is packed`);
    }
    for (const entry of [pkg.exports["."].import, pkg.exports["."].require, pkg.exports["./core"]]) {
        assert.equal(Object.keys(entry)[0], "types", "types comes first in each condition");
    }
});

test("the CommonJS declarations are a copy of the ES module ones", () => {
    assert.equal(read("types/cb2.d.cts"), read("types/cb2.d.ts"), "run npm run types:sync");
});

test("Cb2Core declares every function of cb2_c.h and the core exports each", async () => {
    const header = read("../c/include/cb2_c.h").replace(/\/\*[\s\S]*?\*\//g, "");
    const names = [...header.matchAll(/CB2_API[^;]*?\b(cb2_\w+)\s*\(/g)].map((m) => m[1]);
    assert.ok(names.length >= 60);
    const types = read("types/cb2.d.ts");
    const declared = [...types.matchAll(/^\s+_(cb2_\w+)\(/gm)].map((m) => m[1]);
    assert.deepEqual([...declared].sort(), [...names].sort());
    const { core } = await load();
    for (const name of names) assert.equal(typeof core[`_${name}`], "function", name);
});

test("the runtime API has the members the declarations name", async () => {
    const cb2 = await load();
    assert.deepEqual(Object.keys(cb2).sort(), [
        "Cb2Error", "Holder", "KeyWrap", "Local", "LocalKey", "Public", "PublicKey", "RecipientKey",
        "RecipientPublicKey", "Seal", "SecretKey", "Token", "core", "errorName", "hasPublic", "hasSeal", "version",
    ]);
    const methods = (o) => Object.keys(o).filter((k) => typeof o[k] === "function").sort();
    assert.deepEqual(methods(cb2.Local), ["open", "seal"]);
    assert.deepEqual(methods(cb2.Public), ["sign", "verify"]);
    assert.deepEqual(methods(cb2.Token), ["open", "peekKeyId", "seal", "sign", "verify"]);
    assert.deepEqual(methods(cb2.Holder), ["normalizeTarget", "prove", "proveLocal"]);
    assert.deepEqual(methods(cb2.KeyWrap), ["unwrap", "wrap"]);
    assert.deepEqual(methods(cb2.Seal), ["seal", "unseal"]);

    const statics = (C) => ["fromBytes", "fromPaserk", "generate"].filter((k) => typeof C[k] === "function");
    const proto = (C) => Object.getOwnPropertyNames(Object.getPrototypeOf(C.prototype) === Object.prototype
        ? C.prototype : C.prototype).filter((k) => k !== "constructor").sort();
    const common = ["free", "freed", "ptr", "toPaserk"];
    const keyId = ["clearKeyId", "keyId", "setKeyId"];
    const expect = {
        LocalKey: { statics: ["fromBytes", "fromPaserk", "generate"], proto: [...common, ...keyId, "paserkId"] },
        SecretKey: { statics: ["fromBytes", "fromPaserk", "generate"], proto: [...common, ...keyId, "publicKey"] },
        PublicKey: { statics: ["fromBytes", "fromPaserk"], proto: [...common, ...keyId, "paserkId"] },
        RecipientKey: { statics: ["fromBytes", "fromPaserk", "generate"], proto: [...common, "paserkId", "publicKey"] },
        RecipientPublicKey: { statics: ["fromBytes", "fromPaserk"], proto: [...common, "paserkId"] },
    };
    for (const [name, want] of Object.entries(expect)) {
        assert.equal(cb2[name].name, name);
        assert.deepEqual(statics(cb2[name]), want.statics, `${name} statics`);
        assert.deepEqual(proto(cb2[name]), want.proto.sort(), `${name} members`);
    }
});

test("load copies its options, so one object serves two cores", async () => {
    const options = {};
    const a = await load(options);
    const b = await load(options);
    assert.deepEqual(Object.keys(options), []);
    assert.notEqual(a.core, b.core);
    const k = a.LocalKey.generate();
    const token = a.Token.seal(k, { iss: "i", aud: "a", exp: "2099-01-01T00:00:00Z" });
    const same = b.LocalKey.fromPaserk(k.toPaserk());
    assert.equal(b.Token.open(token, same, { issuer: "i", audience: "a" }).iss, "i");
    k.free();
    same.free();
});

test("locateFile and wasmBinary place the wasm", async () => {
    const asked = [];
    const viaLocate = await load({
        locateFile: (path, prefix) => {
            asked.push(path);
            return prefix + path;
        },
    });
    assert.deepEqual(asked, ["cb2_core.wasm"]);
    assert.equal(viaLocate.version(), pkg.version);
    const wasmBinary = readFileSync(new URL("../dist/cb2_core.wasm", import.meta.url));
    const viaBytes = await load({ wasmBinary, locateFile: () => "/nowhere/cb2_core.wasm" });
    assert.equal(viaBytes.version(), pkg.version);
});

test("wasmBinary that is not wasm rejects", async () => {
    await assert.rejects(load({ wasmBinary: new Uint8Array([0, 1, 2, 3]) }), WebAssembly.CompileError);
});
