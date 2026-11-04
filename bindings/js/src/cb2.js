/**
 * cb2 for JavaScript: the C ABI of cb2 compiled to WebAssembly, one build
 * for Node and browsers. load() instantiates the core and returns the API:
 * the key classes, Local, Public, Token, Holder, KeyWrap and Seal, plus
 * hasPublic(), hasSeal(), version() and errorName(code).
 */
import createCb2Core from "../dist/cb2_core.js";
import { Cb2Error } from "./error.js";
import { makeKeys } from "./keys.js";
import { makeTokens } from "./tokens.js";

export { Cb2Error };

/**
 * Instantiates the WebAssembly core and returns the API over it. The
 * options go to the Emscripten factory: locateFile(path, prefix) to say
 * where cb2_core.wasm is served from, or wasmBinary with its bytes.
 * Each call builds an independent instance.
 * @param {object} [options]
 * @returns {Promise<object>}
 */
export async function load(options = {}) {
    const m = await createCb2Core(options);
    const keys = makeKeys(m);
    return {
        ...keys,
        ...makeTokens(m, keys),
        Cb2Error,
        /** True when cb2.public (ML-DSA-65) is in this build. */
        hasPublic: () => m._cb2_has_public() === 1,
        /** True when kcb2.seal (X-Wing) is in this build. */
        hasSeal: () => m._cb2_has_seal() === 1,
        /** The library version. */
        version: () => m.UTF8ToString(m._cb2_version()),
        /** The stable name of an error code ("ok", "invalid", ..., "unknown"). */
        errorName: (code) => m.UTF8ToString(m._cb2_error_name(code)),
        /** The Emscripten module itself, for callers who need the raw ABI. */
        core: m,
    };
}
