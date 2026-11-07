/**
 * The JavaScript bridge exercised from Node, mirroring bindings/c/test/test_c.c:
 * keys, raw tokens, claims tokens with rules and both replay callbacks,
 * compact claims tokens, holder proofs of both modes, key wrapping and sealing, and every verdict the bridge
 * relies on. Run from the repository root: node --test bindings/js/test/
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { Cb2Error, load } from "../src/cb2.js";

const cb2 = await load();

const CLAIMS = {
    iss: "https://issuer.example",
    sub: "user-1",
    aud: "api",
    exp: "2099-01-01T00:00:00+00:00",
    jti: "id-1",
    role: "admin",
};
const RULES = { issuer: "https://issuer.example", audience: "api", now: 1700000000 };

function refused(fn, name) {
    let error = null;
    try {
        fn();
    } catch (e) {
        error = e;
    }
    assert.ok(error instanceof Cb2Error, `expected a Cb2Error named ${name}`);
    assert.equal(error.name, name);
    assert.equal(cb2.errorName(error.code), name);
}

test("library", () => {
    assert.equal(cb2.version(), "0.1.0");
    assert.equal(cb2.hasPublic(), true);
    assert.equal(cb2.hasSeal(), true);
    assert.equal(cb2.errorName(0), "ok");
    assert.equal(cb2.errorName(3), "argument");
    assert.equal(cb2.errorName(24), "proof_replayed");
    assert.equal(cb2.errorName(99), "unknown");
});

test("local keys and raw tokens", () => {
    const { LocalKey, Local } = cb2;
    const k = LocalKey.generate();
    const paserk = k.toPaserk();
    assert.ok(paserk.startsWith("kcb2.local."));
    assert.equal(paserk.length, 54);
    const id = k.paserkId();
    assert.ok(id.startsWith("kcb2.lid."));
    assert.equal(k.keyId, id);
    const same = LocalKey.fromPaserk(paserk);
    assert.equal(same.paserkId(), id);

    const footer = '{"kid":"x"}';
    const token = Local.seal(k, "hello", footer);
    assert.ok(token.startsWith("cb2.local."));
    const opened = Local.open(same, token, footer);
    assert.deepEqual(opened, new TextEncoder().encode("hello"));
    refused(() => Local.open(same, token), "invalid");
    const last = token.at(-1) === "A" ? "B" : "A";
    refused(() => Local.open(same, token.slice(0, -1) + last, footer), "invalid");

    const bytes = new Uint8Array([0, 1, 2, 255]);
    assert.deepEqual(Local.open(k, Local.seal(k, bytes, new Uint8Array([9]), "imp"), new Uint8Array([9]), "imp"), bytes);

    assert.equal(k.setKeyId("rotation-1").keyId, "rotation-1");
    refused(() => k.setKeyId("a\u200b"), "argument");
    assert.equal(k.clearKeyId().keyId, null);
    same.free();
    k.free();
    assert.equal(k.freed, true);
    assert.throws(() => k.paserkId(), /freed/);
    refused(() => LocalKey.fromBytes(new Uint8Array(32).fill(7)), "argument");
});

test("claims tokens and verdicts", () => {
    const { LocalKey, Token } = cb2;
    const k = LocalKey.generate();
    const token = Token.seal(k, CLAIMS);
    const claims = Token.open(token, k, RULES);
    assert.equal(claims.role, "admin");
    assert.equal(claims.jti, "id-1");
    assert.equal(Token.peekKeyId(token), k.paserkId());

    refused(() => Token.open(token, k, {}), "rules_incomplete");
    refused(() => Token.open(token, k, { ...RULES, audience: "other" }), "audience_mismatch");
    refused(() => Token.open(token, k, { ...RULES, now: 4102444801 }), "expired");

    const seen = new Set();
    const remember = (jti) => {
        if (seen.has(jti)) return false;
        seen.add(jti);
        return true;
    };
    assert.equal(Token.open(token, k, { ...RULES, replay: remember }).jti, "id-1");
    refused(() => Token.open(token, k, { ...RULES, replay: remember }), "replayed");
    assert.deepEqual([...seen], ["id-1"]);
    refused(() => Token.open(token, k, { ...RULES, seen_jti: ["id-1"] }), "replayed");
    refused(() => Token.open(token, k, { ...RULES, replay: () => { throw new Error("store down"); } }), "replayed");
    refused(() => Token.open(token, k, { ...RULES, max_lifetime: 60 }), "lifetime_exceeded");
    refused(() => Token.seal(k, { sub: "a\u200bb", exp: "2099-01-01T00:00:00+00:00" }), "argument");
    refused(() => Token.open(token, LocalKey.generate(), RULES), "invalid");
    k.free();
});

test("compact claims tokens and verdicts", () => {
    const { LocalKey, Token, Compact } = cb2;
    const k = LocalKey.generate();
    const compact = Compact.seal(k, CLAIMS);
    const full = Token.seal(k, CLAIMS);
    assert.ok(compact.startsWith("cb3.local."));
    assert.ok(compact.length < full.length, `${compact.length} < ${full.length}`);
    assert.deepEqual(Compact.open(compact, k, RULES), Token.open(full, k, RULES));
    refused(() => Token.open(compact, k, RULES), "invalid");
    refused(() => Compact.open(full, k, RULES), "invalid");
    refused(() => Compact.open(compact, k, {}), "rules_incomplete");
    refused(() => Compact.open(compact, k, { ...RULES, audience: "web" }), "audience_mismatch");
    refused(() => Compact.open(compact, k, { ...RULES, now: 4102444800 }), "expired");
    refused(() => Compact.open(compact, k, { ...RULES, seen_jti: ["id-1"] }), "replayed");
    refused(() => Compact.open(compact, k, RULES, "x"), "invalid");
    refused(() => Compact.open(compact, LocalKey.generate(), RULES), "invalid");

    const seen = new Set();
    const remember = (jti) => {
        if (seen.has(jti)) return false;
        seen.add(jti);
        return true;
    };
    assert.equal(Compact.open(compact, k, { ...RULES, replay: remember }).jti, "id-1");
    refused(() => Compact.open(compact, k, { ...RULES, replay: remember }), "replayed");
    refused(() => Compact.open(compact, k, { ...RULES, replay: () => { throw new Error("store down"); } }), "replayed");
    assert.equal(Compact.open(Compact.seal(k, CLAIMS, "imp"), k, RULES, "imp").role, "admin");

    const peeked = Compact.peekKeyDigest(compact);
    assert.ok(peeked instanceof Uint8Array);
    assert.equal(peeked.length, Compact.keyDigestBytes);
    assert.equal(Compact.keyDigestBytes, 16);
    assert.deepEqual(peeked, Compact.keyDigest(k.keyId));
    assert.deepEqual(Compact.keyDigest(k.paserkId()), peeked);
    assert.notDeepEqual(Compact.keyDigest("rotation-1"), peeked);
    assert.equal(Compact.peekKeyDigest(full), null);
    assert.equal(Compact.peekKeyDigest(""), null);
    refused(() => Compact.keyDigest("a\nb"), "argument");
    assert.equal(Compact.keyDigest("").length, 16);

    assert.deepEqual(Compact.peekKeyDigest(Compact.seal(k.setKeyId("rotation-1"), CLAIMS)), Compact.keyDigest("rotation-1"));
    k.clearKeyId();
    const bare = Compact.seal(k, CLAIMS);
    assert.equal(Compact.peekKeyDigest(bare), null);
    refused(() => Compact.open(compact, k, RULES), "invalid");
    assert.equal(Compact.open(bare, k, RULES).sub, "user-1");

    const fraction = { iss: "https://issuer.example", aud: "api", exp: "2099-01-01T00:00:00+00:00", n: 1.5 };
    refused(() => Compact.seal(k, fraction), "argument");
    assert.equal(Token.open(Token.seal(k, fraction), k, RULES).n, 1.5);
    refused(() => Compact.seal(k, { ...fraction, n: 1e300 }), "argument");
    assert.equal(Compact.open(Compact.seal(k, { ...fraction, n: -42 }), k, RULES).n, -42);
    k.free();
});

test("compact access tokens with local holder proofs", () => {
    const { LocalKey, Compact, Holder } = cb2;
    const k = LocalKey.generate();
    const proofKey = LocalKey.generate();
    const cnf = proofKey.toPaserk();
    const access = Compact.seal(k, { iss: "https://issuer.example", aud: "api", exp: "2099-01-01T00:00:00+00:00", cnf });
    assert.ok(access.startsWith("cb3.local."));
    refused(() => Compact.open(access, k, RULES), "missing_proof");
    const proof = Holder.proveLocal(proofKey, { htm: "GET", htu: "https://api.example/v1/me" }, access, "p-1", 1700000000, 60);
    const request = { htm: "GET", htu: "https://api.example/v1/me" };
    const proofs = [];
    const claims = Compact.open(access, k, { ...RULES, proof, request, proofReplay: (jti) => { proofs.push(jti); return true; } });
    assert.equal(claims.cnf, cnf);
    assert.deepEqual(proofs, ["p-1"]);
    refused(() => Compact.open(access, k, { ...RULES, proof, request: { htm: "POST", htu: "https://api.example/v1/me" }, proof_seen_jti: [] }), "proof_mismatch");
    refused(() => Compact.open(access, k, { ...RULES, proof, request, proofReplay: () => false }), "proof_replayed");
    const stranger = LocalKey.generate();
    const forged = Holder.proveLocal(stranger, request, access, "p-2", 1700000000, 60);
    refused(() => Compact.open(access, k, { ...RULES, proof: forged, request, proof_seen_jti: [] }), "proof_invalid");
    stranger.free();
    proofKey.free();
    k.free();
});

test("compact public sign and verify", { skip: !cb2.hasPublic() }, () => {
    const { SecretKey, LocalKey, Token, Compact } = cb2;
    const sk = SecretKey.generate();
    const pk = sk.publicKey();
    const signed = Compact.sign(sk, CLAIMS);
    const full = Token.sign(sk, CLAIMS);
    assert.ok(signed.startsWith("cb3.public."));
    assert.ok(signed.length < full.length, `${signed.length} < ${full.length}`);
    assert.deepEqual(Compact.verify(signed, pk, RULES), Token.verify(full, pk, RULES));
    refused(() => Token.verify(signed, pk, RULES), "invalid");
    refused(() => Compact.verify(full, pk, RULES), "invalid");
    refused(() => Compact.verify(signed, pk, { ...RULES, audience: "web" }), "audience_mismatch");
    refused(() => Compact.verify(signed, pk, { ...RULES, now: 4102444800 }), "expired");
    refused(() => Compact.verify(signed, pk, { ...RULES, seen_jti: ["id-1"] }), "replayed");
    const stranger = SecretKey.generate();
    refused(() => Compact.verify(signed, stranger.publicKey(), RULES), "invalid");
    assert.deepEqual(Compact.peekKeyDigest(signed), Compact.keyDigest(sk.keyId));
    const proofKey = LocalKey.generate();
    const bound = { iss: "https://issuer.example", aud: "api", exp: "2099-01-01T00:00:00+00:00", cnf: proofKey.toPaserk() };
    refused(() => Compact.sign(sk, bound), "argument");
    proofKey.free();
    stranger.free();
    pk.free();
    sk.free();
});

test("key wrapping", () => {
    const { LocalKey, KeyWrap } = cb2;
    const k = LocalKey.generate();
    const wrapping = LocalKey.generate();
    const wrapped = KeyWrap.wrap(wrapping, k);
    assert.ok(wrapped.startsWith("kcb2.local-wrap."));
    assert.equal(wrapped.length, 144);
    const unwrapped = KeyWrap.unwrap(wrapped, wrapping);
    assert.equal(unwrapped.paserkId(), k.paserkId());
    refused(() => KeyWrap.unwrap(wrapped, k), "invalid");
    unwrapped.free();
    wrapping.free();
    k.free();
});

test("public sign and verify", () => {
    const { SecretKey, PublicKey, Token, Public } = cb2;
    const sk = SecretKey.generate();
    const pk = sk.publicKey();
    const pub = pk.toPaserk();
    assert.equal(pub.length, 2658);
    assert.ok(pub.startsWith("kcb2.public."));
    const pk2 = PublicKey.fromPaserk(pub);
    assert.equal(pk2.paserkId(), pk.paserkId());
    assert.equal(sk.keyId, pk.paserkId());
    const token = Token.sign(sk, CLAIMS);
    assert.equal(Token.verify(token, pk2, RULES).sub, "user-1");
    const stranger = SecretKey.generate();
    refused(() => Token.verify(token, stranger.publicKey(), RULES), "invalid");

    const raw = Public.sign(sk, "signed bytes", "f");
    assert.ok(raw.startsWith("cb2.public."));
    assert.equal(new TextDecoder().decode(Public.verify(pk, raw, "f")), "signed bytes");
    refused(() => Public.verify(pk, raw), "invalid");
    stranger.free();
    pk2.free();
    pk.free();
    sk.free();
});

test("holder proofs", () => {
    const { SecretKey, LocalKey, Token, Holder } = cb2;
    const client = SecretKey.generate();
    const clientPublic = client.publicKey();
    const k = LocalKey.generate();
    const access = Token.seal(k, { iss: "https://issuer.example", aud: "api", exp: "2099-01-01T00:00:00+00:00", cnf: clientPublic.toPaserk() });
    refused(() => Token.open(access, k, RULES), "missing_proof");

    const proof = Holder.prove(client, { htm: "GET", htu: "https://api.example/v1/me" }, access, "p-1", 1700000000, 60);
    assert.ok(proof.startsWith("cb2.holder-public."));
    const request = { htm: "GET", htu: "HTTPS://API.EXAMPLE:443/v1/me?x=1" };
    refused(() => Token.open(access, k, { ...RULES, proof, request }), "rules_incomplete");
    const proofs = [];
    const claims = Token.open(access, k, { ...RULES, proof, request, proofReplay: (jti) => { proofs.push(jti); return true; } });
    assert.equal(claims.aud, "api");
    assert.deepEqual(proofs, ["p-1"]);
    refused(() => Token.open(access, k, { ...RULES, proof, request: { htm: "POST", htu: "https://api.example/v1/me" }, proof_seen_jti: [] }), "proof_mismatch");
    refused(() => Token.open(access, k, { ...RULES, proof, request, proof_seen_jti: ["p-1"] }), "proof_replayed");
    refused(() => Token.open(access, k, { ...RULES, proof, request, proofReplay: () => false }), "proof_replayed");
    refused(() => Token.open(access, k, { ...RULES, now: 1700000100, proof, request, proof_seen_jti: [] }), "proof_expired");
    assert.equal(Token.open(access, k, { ...RULES, ignore_cnf: true }).aud, "api");

    assert.equal(Holder.normalizeTarget("HTTPS://API.Example:443/a?b#c"), "https://api.example/a");
    refused(() => Holder.normalizeTarget("nope"), "argument");
    k.free();
    clientPublic.free();
    client.free();
});

test("local holder proofs", () => {
    const { LocalKey, Token, Holder } = cb2;
    const k = LocalKey.generate();
    const proofKey = LocalKey.generate();
    const cnf = proofKey.toPaserk();
    const access = Token.seal(k, { iss: "https://issuer.example", aud: "api", exp: "2099-01-01T00:00:00+00:00", cnf });
    refused(() => Token.open(access, k, RULES), "missing_proof");
    const client = LocalKey.fromPaserk(cnf);
    const proof = Holder.proveLocal(client, { htm: "GET", htu: "https://api.example/v1/me" }, access, "p-1", 1700000000, 60);
    assert.ok(proof.startsWith("cb2.holder-local.") && proof.length < 450);
    const request = { htm: "GET", htu: "HTTPS://API.EXAMPLE:443/v1/me?x=1" };
    refused(() => Token.open(access, k, { ...RULES, proof, request }), "rules_incomplete");
    assert.equal(Token.open(access, k, { ...RULES, proof, request, proofReplay: () => true }).aud, "api");
    refused(() => Token.open(access, k, { ...RULES, proof, request: { htm: "POST", htu: "https://api.example/v1/me" }, proof_seen_jti: [] }), "proof_mismatch");
    refused(() => Token.open(access, k, { ...RULES, proof, request, proof_seen_jti: ["p-1"] }), "proof_replayed");
    refused(() => Token.open(access, k, { ...RULES, now: 1700000100, proof, request, proof_seen_jti: [] }), "proof_expired");
    const stranger = LocalKey.generate();
    const forged = Holder.proveLocal(stranger, { htm: "GET", htu: "https://api.example/v1/me" }, access, "p-2", 1700000000, 60);
    refused(() => Token.open(access, k, { ...RULES, proof: forged, request, proof_seen_jti: [] }), "proof_invalid");
    refused(() => Holder.proveLocal(client, { htm: "GET", htu: "nope" }, access, "p-3", 1700000000, 60), "argument");
    stranger.free();
    client.free();
    proofKey.free();
    k.free();
});

test("sealing", () => {
    const { RecipientKey, RecipientPublicKey, LocalKey, Seal } = cb2;
    const r = RecipientKey.generate();
    const rp = r.publicKey();
    const rec = rp.toPaserk();
    assert.equal(rec.length, 1637);
    assert.ok(rec.startsWith("kcb2.recipient."));
    assert.equal(RecipientPublicKey.fromPaserk(rec).paserkId(), rp.paserkId());
    const secret = r.toPaserk();
    assert.equal(secret.length, 65);
    const r2 = RecipientKey.fromPaserk(secret);
    const k = LocalKey.generate();
    const sealed = Seal.seal(rp, k);
    assert.equal(sealed.length, 1632);
    const back = Seal.unseal(sealed, r2);
    assert.equal(back.paserkId(), k.paserkId());
    const other = RecipientKey.generate();
    refused(() => Seal.unseal(sealed, other), "invalid");
    assert.ok(rp.paserkId().startsWith("kcb2.rid."));
    assert.equal(r2.paserkId(), rp.paserkId());
    back.free();
    k.free();
    other.free();
    r2.free();
    rp.free();
    r.free();
});

test("replay callbacks leave the table after the call", () => {
    const { LocalKey, Token, core } = cb2;
    const k = LocalKey.generate();
    const token = Token.seal(k, CLAIMS);
    const probe = core.addFunction(() => 1, "ipii");
    core.removeFunction(probe);
    for (let i = 0; i < 50; i++) Token.open(token, k, { ...RULES, replay: () => true });
    const again = core.addFunction(() => 1, "ipii");
    core.removeFunction(again);
    assert.equal(again, probe);
    k.free();
});
