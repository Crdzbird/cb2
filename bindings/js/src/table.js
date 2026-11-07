/**
 * The claim table of compact tokens (docs/PROTOCOL.md section 15.5) over
 * the opaque cb2_claim_table handle: an ordered list of 1 to 256 distinct,
 * non-empty strings the issuer and its verifiers configure alike, under
 * which an iss or aud equal to an entry travels as its index. A table's
 * handle lives until free(); using a freed table throws.
 */
import { check, takeBytes, withArena } from "./heap.js";

/** The bytes of a claim table digest, CB2_CLAIM_TABLE_DIGEST_BYTES. */
const DIGEST_BYTES = 32;

/**
 * Builds the ClaimTable class over a core module.
 * @param {import("../types/cb2.js").Cb2Core} m the core module
 * @returns {import("../types/cb2.js").Cb2["ClaimTable"]}
 */
export function makeClaimTable(m) {
    class ClaimTable {
        #ptr;

        /** Wraps a handle the ABI returned; fromEntries is the public way in. */
        constructor(ptr) {
            this.#ptr = ptr;
        }

        /** The bytes of a table digest. */
        static digestBytes = DIGEST_BYTES;

        /** A table from its entries, an array of strings (argument for anything the rules refuse). */
        static fromEntries(entries) {
            return new this(withArena(m, (a) => {
                const json = a.bytes(JSON.stringify(entries));
                const slot = a.out();
                check(m, m._cb2_claim_table_from_json(json.ptr, json.len, slot));
                return a.pointerAt(slot);
            }));
        }

        /** The handle; throws once the table is freed. */
        get ptr() {
            if (this.#ptr === 0) throw new Error("ClaimTable was freed");
            return this.#ptr;
        }

        /** True once free() ran. */
        get freed() {
            return this.#ptr === 0;
        }

        /** The 32-byte digest of the table, to compare two parties' tables. */
        digest() {
            return withArena(m, (a) => {
                const out = a.out();
                check(m, m._cb2_claim_table_digest(this.ptr, out));
                return takeBytes(m, a.pointerAt(out), DIGEST_BYTES);
            });
        }

        /** Releases the handle; safe to call twice. */
        free() {
            if (this.#ptr === 0) return;
            m._cb2_claim_table_free(this.#ptr);
            this.#ptr = 0;
        }
    }
    return ClaimTable;
}
