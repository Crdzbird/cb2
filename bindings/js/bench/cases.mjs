/**
 * The cases: one claims payload (iss, sub, aud, exp, iat, jti and one
 * short custom claim) issued and verified by cb2 and by the JavaScript
 * JWT and PASETO v4 libraries, each verify checking the signature or tag,
 * the expiry, the issuer and the audience. Every case is run once and its
 * result checked before it is timed. The libraries are passed in, so the
 * Node and browser runners share this file.
 */

const ISSUER = "https://issuer.example";
const AUDIENCE = "api";

function payload(now) {
    return {
        iss: ISSUER,
        sub: "user-1",
        aud: AUDIENCE,
        jti: "4f1c2a9e-6b0d-4e8a-9c3b-2f7d1e5a8b60",
        role: "admin",
        iat: now,
        exp: now + 3600,
    };
}

function rfc3339(seconds) {
    return new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
}

/** The payload with times as RFC 3339 strings, as cb2 and PASETO write them. */
function textTimes(p) {
    return { ...p, iat: rfc3339(p.iat), exp: rfc3339(p.exp) };
}

function checkClaims(claims) {
    if (claims.iss !== ISSUER || claims.aud !== AUDIENCE) throw new Error("issuer or audience refused");
    if (claims.sub !== "user-1" || claims.role !== "admin") throw new Error(`unexpected claims ${JSON.stringify(claims)}`);
    return claims;
}

async function cb2Cases(cb2, claims) {
    const local = cb2.LocalKey.generate();
    const signer = cb2.SecretKey.generate();
    const verifier = signer.publicKey();
    const rules = { issuer: ISSUER, audience: AUDIENCE };
    const sealed = cb2.Token.seal(local, claims);
    const signed = cb2.Token.sign(signer, claims);
    const compactSealed = cb2.Compact.seal(local, claims);
    const compactSigned = cb2.Compact.sign(signer, claims);
    const table = cb2.ClaimTable.fromEntries([ISSUER, AUDIENCE]);
    const tabledSealed = cb2.Compact.seal(local, claims, null, table);
    const tabledSigned = cb2.Compact.sign(signer, claims, null, table);
    return [
        {
            group: "shared",
            name: "cb2.local (cb2, wasm)",
            issue: () => cb2.Token.seal(local, claims),
            verify: () => checkClaims(cb2.Token.open(sealed, local, rules)),
            token: sealed,
        },
        {
            group: "shared",
            name: "cb3.local, compact (cb2, wasm)",
            issue: () => cb2.Compact.seal(local, claims),
            verify: () => checkClaims(cb2.Compact.open(compactSealed, local, rules)),
            token: compactSealed,
        },
        {
            group: "shared",
            name: "cb3.local, compact, claim table (cb2, wasm)",
            issue: () => cb2.Compact.seal(local, claims, null, table),
            verify: () => checkClaims(cb2.Compact.open(tabledSealed, local, rules, null, table)),
            token: tabledSealed,
        },
        {
            group: "pair",
            name: "cb2.public, Ed25519 + ML-DSA-65 (cb2, wasm)",
            issue: () => cb2.Token.sign(signer, claims),
            verify: () => checkClaims(cb2.Token.verify(signed, verifier, rules)),
            token: signed,
        },
        {
            group: "pair",
            name: "cb3.public, compact (cb2, wasm)",
            issue: () => cb2.Compact.sign(signer, claims),
            verify: () => checkClaims(cb2.Compact.verify(compactSigned, verifier, rules)),
            token: compactSigned,
        },
        {
            group: "pair",
            name: "cb3.public, compact, claim table (cb2, wasm)",
            issue: () => cb2.Compact.sign(signer, claims, null, table),
            verify: () => checkClaims(cb2.Compact.verify(tabledSigned, verifier, rules, null, table)),
            token: tabledSigned,
        },
    ];
}

async function joseCase(jose, group, name, alg, sign, verify, claims) {
    const issue = () => new jose.SignJWT(claims).setProtectedHeader({ alg, typ: "JWT" }).sign(sign);
    const token = await issue();
    return {
        group,
        name,
        issue,
        verify: async () => checkClaims((await jose.jwtVerify(token, verify, { issuer: ISSUER, audience: AUDIENCE, algorithms: [alg] })).payload),
        token,
    };
}

async function joseCases(jose, claims) {
    const secret = await jose.generateSecret("HS256");
    const ed = await jose.generateKeyPair("Ed25519");
    const es = await jose.generateKeyPair("ES256");
    return [
        await joseCase(jose, "shared", "JWT HS256 (jose)", "HS256", secret, secret, claims),
        await joseCase(jose, "pair", "JWT EdDSA, Ed25519 (jose)", "EdDSA", ed.privateKey, ed.publicKey, claims),
        await joseCase(jose, "pair", "JWT ES256 (jose)", "ES256", es.privateKey, es.publicKey, claims),
    ];
}

async function pasetoCase(paseto, v4public, claims) {
    const v4 = new paseto.PublicProtocol(v4public.GenerateKeyPairFactory, v4public.SignFactory, v4public.VerifyFactory);
    const { publicKey, secretKey } = await v4.GenerateKeyPair();
    const issue = () => v4.Sign(secretKey, claims);
    const token = await issue();
    return {
        group: "pair",
        name: "PASETO v4.public (paseto)",
        issue,
        verify: async () => checkClaims((await v4.Verify(publicKey, token, { issuer: ISSUER, audience: AUDIENCE })).claims),
        token,
    };
}

function pasetoTsCases(pasetoTs, claims) {
    const local = pasetoTs.generateKeys("local");
    const pair = pasetoTs.generateKeys("public");
    const options = { addIat: false, addExp: false };
    const encrypted = pasetoTs.encrypt(local, claims, options);
    const signed = pasetoTs.sign(pair.secretKey, claims, options);
    return [
        {
            group: "shared",
            name: "PASETO v4.local (paseto-ts)",
            issue: () => pasetoTs.encrypt(local, claims, options),
            verify: () => checkClaims(pasetoTs.decrypt(local, encrypted).payload),
            token: encrypted,
        },
        {
            group: "pair",
            name: "PASETO v4.public (paseto-ts)",
            issue: () => pasetoTs.sign(pair.secretKey, claims, options),
            verify: () => checkClaims(pasetoTs.verify(pair.publicKey, signed).payload),
            token: signed,
        },
    ];
}

/**
 * Builds the cases for the libraries given; a missing library is skipped.
 * @param {{ cb2: object, jose?: object, paseto?: object, v4public?: object, pasetoTs?: object }} libs
 */
export async function makeCases(libs) {
    const now = Math.floor(Date.now() / 1000);
    const jwtClaims = payload(now);
    const textClaims = textTimes(jwtClaims);
    const all = [
        ...(await cb2Cases(libs.cb2, textClaims)),
        ...(libs.jose ? await joseCases(libs.jose, jwtClaims) : []),
        ...(libs.paseto ? [await pasetoCase(libs.paseto, libs.v4public, textClaims)] : []),
        ...(libs.pasetoTs ? pasetoTsCases(libs.pasetoTs, textClaims) : []),
    ];
    for (const c of all) {
        await c.verify();
        c.size = new TextEncoder().encode(c.token).length;
    }
    const order = ["shared", "pair"];
    return all.sort((a, b) => order.indexOf(a.group) - order.indexOf(b.group));
}
