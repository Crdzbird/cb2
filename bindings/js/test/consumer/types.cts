/**
 * A type-level consumer of the CommonJS declarations, reached through the
 * require condition of the exports map. types/cb2.d.cts is a copy of
 * types/cb2.d.ts, which types.ts covers member by member; this file checks
 * the CommonJS resolution and shape. Checked with tsc, never run.
 */
import cb2Package = require("cb2");
import type { Cb2, Claims, LocalKey, PublicKey } from "cb2";

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type Assert<T extends true> = T;

export type Checks = [
    Assert<Equal<ReturnType<typeof cb2Package.load>, Promise<Cb2>>>,
    Assert<Equal<InstanceType<typeof cb2Package.Cb2Error>["code"], number>>,
    Assert<Equal<[PublicKey] extends [LocalKey] ? true : false, false>>,
];

export async function roundTrip(): Promise<Claims> {
    const cb2 = await cb2Package.load();
    const key = cb2.LocalKey.generate();
    const token = cb2.Token.seal(key, { iss: "https://issuer.example", aud: "api", exp: "2099-01-01T00:00:00Z" });
    try {
        return cb2.Token.open(token, key, { issuer: "https://issuer.example", audience: "api" });
    } catch (e) {
        if (e instanceof cb2Package.Cb2Error) throw new Error(`refused: ${e.name}`);
        throw e;
    } finally {
        key.free();
    }
}
