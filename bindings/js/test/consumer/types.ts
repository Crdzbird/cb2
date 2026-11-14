/**
 * A type-level consumer of the ES module declarations: every member of the
 * API used once with the types a caller would write, plus checks that the
 * key types do not stand in for each other. Checked with tsc, never run.
 */
import createCb2Core from "cb2/core";
import {
    Cb2Error,
    load,
    type Bytes,
    type Cb2,
    type Cb2Core,
    type Cb2ErrorName,
    type ClaimTable,
    type Claims,
    type CompactTokens,
    type HolderRequest,
    type LoadOptions,
    type LocalKey,
    type PublicKey,
    type RecipientKey,
    type RecipientPublicKey,
    type Rules,
    type SecretKey,
} from "cb2";

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type Assignable<From, To> = [From] extends [To] ? true : false;
type Assert<T extends true> = T;

export type Checks = [
    Assert<Equal<ReturnType<typeof load>, Promise<Cb2>>>,
    Assert<Equal<Awaited<ReturnType<typeof createCb2Core>>, Cb2Core>>,
    Assert<Equal<Assignable<PublicKey, LocalKey>, false>>,
    Assert<Equal<Assignable<LocalKey, PublicKey>, false>>,
    Assert<Equal<Assignable<SecretKey, LocalKey>, false>>,
    Assert<Equal<Assignable<RecipientPublicKey, PublicKey>, false>>,
    Assert<Equal<Assignable<RecipientKey, RecipientPublicKey>, false>>,
    Assert<Equal<Assignable<"expired", Cb2ErrorName>, true>>,
    Assert<Equal<Assignable<"nope", Cb2ErrorName>, false>>,
    Assert<Equal<Assignable<{ aud: string[] }, Claims>, false>>,
    Assert<Equal<Assignable<{ exp: number }, Claims>, false>>,
    Assert<Equal<Assignable<{ role: { level: number } }, Claims>, true>>,
    Assert<Equal<Assignable<{ replay: (jti: string) => boolean }, Rules>, true>>,
    Assert<Equal<Assignable<{ now: string }, Rules>, false>>,
    Assert<Equal<Cb2["Cb2Error"], typeof Cb2Error>>,
    Assert<Equal<Cb2["Compact"], CompactTokens>>,
    Assert<Equal<ReturnType<CompactTokens["peekKeyDigest"]>, Uint8Array | null>>,
    Assert<Equal<Assignable<ClaimTable, LocalKey>, false>>,
    Assert<Equal<Assignable<LocalKey, ClaimTable>, false>>,
    Assert<Equal<Assignable<string[], Parameters<Cb2["ClaimTable"]["fromEntries"]>[0]>, true>>,
    Assert<Equal<Assignable<Parameters<Cb2["Token"]["open"]>, Parameters<CompactTokens["open"]>>, true>>,
    Assert<Equal<Parameters<CompactTokens["open"]>[4], ClaimTable | null | undefined>>,
];

export async function everything(wasm: Uint8Array): Promise<string[]> {
    const options: LoadOptions = { locateFile: (path, prefix) => prefix + path, wasmBinary: wasm };
    const cb2: Cb2 = await load(options);
    const out: string[] = [cb2.version(), cb2.errorName(9)];
    const flags: boolean[] = [cb2.hasPublic(), cb2.hasSeal()];

    const key: LocalKey = cb2.LocalKey.generate();
    const again: LocalKey = cb2.LocalKey.fromPaserk(key.toPaserk());
    const raw: LocalKey = cb2.LocalKey.fromBytes(new Uint8Array(32));
    const wrapped: LocalKey = new cb2.LocalKey(key.ptr);
    const id: string | null = key.setKeyId("rotation-1").clearKeyId().keyId;
    const freed: boolean = key.freed;
    out.push(key.paserkId(), String(id), String(freed), String(raw instanceof cb2.LocalKey), String(wrapped.ptr));

    const msg: Bytes = new Uint8Array([1, 2, 3]);
    const sealed: string = cb2.Local.seal(key, msg, "footer", null);
    const opened: Uint8Array = cb2.Local.open(again, sealed, "footer", undefined, 4096);
    out.push(String(opened.length));

    const claims: Claims = { iss: "https://issuer.example", aud: "api", exp: "2099-01-01T00:00:00Z", role: ["a", "b"] };
    const rules: Rules = {
        issuer: "https://issuer.example",
        audience: "api",
        clock_skew: 5,
        seen_jti: ["used"],
        replay: (jti) => jti.length > 0,
    };
    const token: string = cb2.Token.seal(key, claims);
    const back: Claims = cb2.Token.open(token, key, rules, "implicit");
    const kid: string | null = cb2.Token.peekKeyId(token);
    out.push(String(back.sub), String(kid));

    const compact: string = cb2.Compact.seal(key, claims, "implicit");
    const compactBack: Claims = cb2.Compact.open(compact, key, rules, "implicit");
    const peeked: Uint8Array | null = cb2.Compact.peekKeyDigest(compact);
    const digest: Uint8Array = cb2.Compact.keyDigest(key.paserkId());
    const digestBytes: number = cb2.Compact.keyDigestBytes;
    out.push(String(compactBack.aud), String(peeked?.length), String(digest.length), String(digestBytes));

    const table: ClaimTable = cb2.ClaimTable.fromEntries(["https://issuer.example", "api"]);
    const tableDigest: Uint8Array = table.digest();
    const tabled: string = cb2.Compact.seal(key, claims, null, table);
    const tabledBack: Claims = cb2.Compact.open(tabled, key, rules, undefined, table);
    const tableFreed: boolean = table.freed;
    out.push(String(tableDigest.length), String(tabledBack.iss), String(tableFreed), String(cb2.ClaimTable.digestBytes));
    table.free();

    const sk: SecretKey = cb2.SecretKey.generate();
    const pk: PublicKey = sk.publicKey();
    const pk2: PublicKey = cb2.PublicKey.fromPaserk(pk.toPaserk());
    const signed: string = cb2.Token.sign(sk, claims);
    const verified: Claims = cb2.Token.verify(signed, pk2, rules);
    const rawSigned: string = cb2.Public.sign(sk, "bytes");
    const rawVerified: Uint8Array = cb2.Public.verify(pk, rawSigned);
    out.push(String(verified.aud), String(rawVerified.length), pk.paserkId(), String(sk.keyId));
    const compactSigned: string = cb2.Compact.sign(sk, claims);
    const compactVerified: Claims = cb2.Compact.verify(compactSigned, pk2, rules);
    out.push(String(compactVerified.iss));

    const request: HolderRequest = { htm: "GET", htu: "https://api.example/v1/me", nonce: "n" };
    const proof: string = cb2.Holder.prove(sk, request, signed, "p-1");
    const proofLocal: string = cb2.Holder.proveLocal(again, request, token, "p-2", 1700000000, 60);
    const target: string = cb2.Holder.normalizeTarget(request.htu);
    const bound: Claims = cb2.Token.open(token, key, { ...rules, proof: proofLocal, request, proofReplay: () => true });
    out.push(proof, target, String(bound.iss));

    const wrap: string = cb2.KeyWrap.wrap(again, key);
    const unwrapped: LocalKey = cb2.KeyWrap.unwrap(wrap, again);
    const recipient: RecipientKey = cb2.RecipientKey.generate();
    const recipientPublic: RecipientPublicKey = recipient.publicKey();
    const fromText: RecipientPublicKey = cb2.RecipientPublicKey.fromPaserk(recipientPublic.toPaserk());
    const sealedKey: string = cb2.Seal.seal(fromText, key);
    const unsealed: LocalKey = cb2.Seal.unseal(sealedKey, recipient);
    out.push(unwrapped.paserkId(), unsealed.paserkId(), recipient.paserkId(), recipientPublic.paserkId());

    try {
        cb2.Token.open(token, key, {});
    } catch (e) {
        if (e instanceof cb2.Cb2Error) {
            const name: Cb2ErrorName = e.name;
            const code: number = e.code;
            out.push(name, String(code));
        }
    }

    const core: Cb2Core = cb2.core;
    const ptr: number = core._malloc(8);
    const version: number = core._cb2_version();
    core.HEAPU8.fill(0, ptr, ptr + 8);
    core._free(ptr);
    out.push(core.UTF8ToString(version), String(flags));

    for (const k of [key, again, raw, sk, pk, pk2, unwrapped, recipient, recipientPublic, fromText, unsealed]) k.free();
    return out;
}
