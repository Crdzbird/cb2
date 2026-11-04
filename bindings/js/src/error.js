/**
 * Cb2Error: a refusal from the library. code is the C ABI code (1 and up)
 * and name the stable verdict name the library uses for it ("invalid",
 * "expired", "proof_replayed", ...), exactly the names of docs/PROTOCOL.md.
 */
export class Cb2Error extends Error {
    /**
     * @param {number} code the cb2_code value
     * @param {string} name the verdict name from cb2_error_name
     */
    constructor(code, name) {
        super(`cb2: ${name}`);
        this.code = code;
        this.name = name;
    }
}
