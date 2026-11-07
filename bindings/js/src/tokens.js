/**
 * The token operations over the C ABI: raw cb2.local and cb2.public
 * tokens, claims tokens with rules in the cb2 and the compact formats,
 * holder proofs, key wrapping and sealing. Claims go in and come out as
 * plain objects through JSON; rules are a plain object mirroring the rules
 * JSON of cb2_c.h, with replay and proofReplay accepted as functions
 * (jti) => boolean that run as the library's replay checks for the length
 * of the call.
 */
import { check, takeBytes, takeText, withArena } from "./heap.js";

/** The bytes of a compact token's key digest, CB2_KEY_DIGEST_BYTES. */
const KEY_DIGEST_BYTES = 16;

function rawSeal(m, fn, key, msg, footer, implicit) {
    return withArena(m, (a) => {
        const message = a.bytes(msg);
        const f = a.bytes(footer);
        const i = a.bytes(implicit);
        const out = a.out();
        const len = a.out();
        check(m, fn(key.ptr, message.ptr, message.len, f.ptr, f.len, i.ptr, i.len, out, len));
        return takeText(m, a.pointerAt(out));
    });
}

function rawOpen(m, fn, key, token, footer, implicit, maxTokenBytes) {
    return withArena(m, (a) => {
        const t = a.bytes(token);
        const f = a.bytes(footer);
        const i = a.bytes(implicit);
        const out = a.out();
        const len = a.out();
        check(m, fn(key.ptr, t.ptr, t.len, f.ptr, f.len, i.ptr, i.len, maxTokenBytes, out, len));
        return takeBytes(m, a.pointerAt(out), a.sizeAt(len));
    });
}

function claimsSeal(m, fn, key, claims, implicit) {
    return withArena(m, (a) => {
        const c = a.bytes(JSON.stringify(claims));
        const i = a.bytes(implicit);
        const out = a.out();
        const len = a.out();
        check(m, fn(key.ptr, c.ptr, c.len, i.ptr, i.len, out, len));
        return takeText(m, a.pointerAt(out));
    });
}

/** A replay check as a wasm table entry; an exception inside it refuses the id. */
function callback(m, fn) {
    return m.addFunction((user, ptr, len) => {
        try {
            return fn(m.UTF8ToString(ptr, len)) ? 1 : 0;
        } catch {
            return 0;
        }
    }, "ipii");
}

function prepareRules(m, rules) {
    const json = { ...rules };
    const installed = [];
    let replay = 0;
    let proofReplay = 0;
    if (typeof json.replay === "function") {
        replay = callback(m, json.replay);
        installed.push(replay);
        json.replay = true;
    }
    if (typeof json.proofReplay === "function") {
        proofReplay = callback(m, json.proofReplay);
        installed.push(proofReplay);
    }
    delete json.proofReplay;
    const release = () => installed.forEach((f) => m.removeFunction(f));
    return { text: JSON.stringify(json), replay, proofReplay, release };
}

function claimsOpen(m, fn, key, token, rules, implicit) {
    const r = prepareRules(m, rules ?? {});
    try {
        return withArena(m, (a) => {
            const t = a.bytes(token);
            const rj = a.bytes(r.text);
            const i = a.bytes(implicit);
            const out = a.out();
            const len = a.out();
            check(m, fn(key.ptr, t.ptr, t.len, rj.ptr, rj.len, i.ptr, i.len, r.replay, r.proofReplay, 0, out, len));
            return JSON.parse(takeText(m, a.pointerAt(out)));
        });
    } finally {
        r.release();
    }
}

function textResult(m, fn, text) {
    return withArena(m, (a) => {
        const t = a.bytes(text);
        const out = a.out();
        check(m, fn(t.ptr, t.len, out));
        return takeText(m, a.pointerAt(out));
    });
}

function digestResult(m, fn, text) {
    return withArena(m, (a) => {
        const t = a.bytes(text);
        const out = a.out();
        check(m, fn(t.ptr, t.len, out));
        const ptr = a.pointerAt(out);
        return ptr === 0 ? null : takeBytes(m, ptr, KEY_DIGEST_BYTES);
    });
}

function keyResult(m, fn, Cls, text, by) {
    return new Cls(withArena(m, (a) => {
        const t = a.bytes(text);
        const slot = a.out();
        check(m, fn(t.ptr, t.len, by.ptr, slot));
        return a.pointerAt(slot);
    }));
}

function pairResult(m, fn, first, second) {
    return withArena(m, (a) => {
        const out = a.out();
        check(m, fn(first.ptr, second.ptr, out));
        return takeText(m, a.pointerAt(out));
    });
}

function prove(m, fn, key, request, accessToken, jti, now, lifetime) {
    return withArena(m, (a) => {
        const htm = a.bytes(request.htm);
        const htu = a.bytes(request.htu);
        const nonce = a.bytes(request.nonce);
        const access = a.bytes(accessToken);
        const id = a.bytes(jti);
        const out = a.out();
        const len = a.out();
        const at = BigInt(now ?? Math.floor(Date.now() / 1000));
        check(m, fn(key.ptr, htm.ptr, htm.len, htu.ptr, htu.len, nonce.ptr, nonce.len,
            access.ptr, access.len, id.ptr, id.len, at, BigInt(lifetime ?? 60), out, len));
        return takeText(m, a.pointerAt(out));
    });
}

/**
 * Builds Local, Public, Token, Compact, Holder, KeyWrap and Seal over a
 * core module.
 * @param {import("../types/cb2.js").Cb2Core} m the core module
 * @param {object} keys the classes from makeKeys
 * @returns {Pick<import("../types/cb2.js").Cb2, "Local" | "Public" | "Token" | "Compact" | "Holder" | "KeyWrap" | "Seal">}
 */
export function makeTokens(m, keys) {
    const Local = {
        /** Seals msg (bytes or text) under a LocalKey; the token text. */
        seal: (key, msg, footer, implicit) => rawSeal(m, m._cb2_local_seal, key, msg, footer, implicit),
        /** Opens a cb2.local token; the message bytes. */
        open: (key, token, footer, implicit, maxTokenBytes = 0) =>
            rawOpen(m, m._cb2_local_open, key, token, footer, implicit, maxTokenBytes),
    };
    const Public = {
        /** Signs msg under a SecretKey; the token text. */
        sign: (key, msg, footer, implicit) => rawSeal(m, m._cb2_public_sign, key, msg, footer, implicit),
        /** Verifies a cb2.public token under a PublicKey; the message bytes. */
        verify: (key, token, footer, implicit, maxTokenBytes = 0) =>
            rawOpen(m, m._cb2_public_verify, key, token, footer, implicit, maxTokenBytes),
    };
    const Token = {
        /** Seals a claims object under a LocalKey. */
        seal: (key, claims, implicit) => claimsSeal(m, m._cb2_token_seal, key, claims, implicit),
        /** Signs a claims object under a SecretKey. */
        sign: (key, claims, implicit) => claimsSeal(m, m._cb2_token_sign, key, claims, implicit),
        /** Opens a sealed claims token under the rules; the claims object. */
        open: (token, key, rules, implicit) => claimsOpen(m, m._cb2_token_open, key, token, rules, implicit),
        /** Verifies a signed claims token under the rules; the claims object. */
        verify: (token, key, rules, implicit) => claimsOpen(m, m._cb2_token_verify, key, token, rules, implicit),
        /** The key id a token's footer names, unverified; null when none. */
        peekKeyId: (token) => textResult(m, m._cb2_peek_key_id, token),
    };
    const Compact = {
        /** The bytes of a key digest. */
        keyDigestBytes: KEY_DIGEST_BYTES,
        /** Seals a claims object under a LocalKey as a compact token. */
        seal: (key, claims, implicit) => claimsSeal(m, m._cb2_compact_seal, key, claims, implicit),
        /** Signs a claims object under a SecretKey as a compact token. */
        sign: (key, claims, implicit) => claimsSeal(m, m._cb2_compact_sign, key, claims, implicit),
        /** Opens a sealed compact token under the rules; the claims object. */
        open: (token, key, rules, implicit) => claimsOpen(m, m._cb2_compact_open, key, token, rules, implicit),
        /** Verifies a signed compact token under the rules; the claims object. */
        verify: (token, key, rules, implicit) => claimsOpen(m, m._cb2_compact_verify, key, token, rules, implicit),
        /** The key digest a compact token's footer carries, unverified; null when none. */
        peekKeyDigest: (token) => digestResult(m, m._cb2_compact_peek_key_digest, token),
        /** The key digest of a key id, to match against peekKeyDigest. */
        keyDigest: (id) => digestResult(m, m._cb2_compact_key_digest, id),
    };
    const Holder = {
        /** A public-mode proof by the client's SecretKey for one request and one access token. */
        prove: (clientSecret, request, accessToken, jti, now, lifetime) =>
            prove(m, m._cb2_holder_prove, clientSecret, request, accessToken, jti, now, lifetime),
        /** A local-mode proof under the kcb2.local proof key the issuer put in cnf of a cb2.local access token. */
        proveLocal: (proofKey, request, accessToken, jti, now, lifetime) =>
            prove(m, m._cb2_holder_prove_local, proofKey, request, accessToken, jti, now, lifetime),
        /** The normalized form of a request target (argument when it is not a URI). */
        normalizeTarget: (uri) => textResult(m, m._cb2_holder_normalize_target, uri),
    };
    const KeyWrap = {
        /** Wraps a LocalKey under a wrapping LocalKey; kcb2.local-wrap text. */
        wrap: (wrapping, key) => pairResult(m, m._cb2_wrap, wrapping, key),
        /** Unwraps kcb2.local-wrap text with the wrapping key; a LocalKey. */
        unwrap: (text, wrapping) => keyResult(m, m._cb2_unwrap, keys.LocalKey, text, wrapping),
    };
    const Seal = {
        /** Seals a LocalKey to a RecipientPublicKey; kcb2.seal text. */
        seal: (to, key) => pairResult(m, m._cb2_seal, to, key),
        /** Unseals kcb2.seal text with the RecipientKey; a LocalKey. */
        unseal: (text, by) => keyResult(m, m._cb2_unseal, keys.LocalKey, text, by),
    };
    return { Local, Public, Token, Compact, Holder, KeyWrap, Seal };
}
