/**
 * cb2 for JavaScript: the C ABI of cb2 compiled to WebAssembly, one build
 * for Node and browsers. load() instantiates the core and returns the API:
 * the key classes, Local, Public, Token, Compact, Holder, KeyWrap and
 * Seal, plus hasPublic(), hasSeal(), version() and errorName(code). The
 * declarations are in types/cb2.d.ts.
 *
 * @module cb2
 */
import createCb2Core from "../dist/cb2_core.js";
import { Cb2Error } from "./error.js";
import { makeKeys } from "./keys.js";
import { makeTokens } from "./tokens.js";

export { Cb2Error };

/**
 * The core for the options. The Emscripten build does not read wasmBinary
 * itself, so bytes given there are instantiated through instantiateWasm,
 * and a failure to instantiate them rejects instead of leaving the factory
 * waiting.
 */
function instantiate(options) {
    const { wasmBinary, ...rest } = options;
    if (wasmBinary === undefined || rest.instantiateWasm !== undefined) return createCb2Core(rest);
    let fail;
    const failed = new Promise((_, reject) => {
        fail = reject;
    });
    rest.instantiateWasm = (imports, done) => {
        WebAssembly.instantiate(wasmBinary, imports).then((r) => done(r.instance, r.module), fail);
        return {};
    };
    return Promise.race([createCb2Core(rest), failed]);
}

/**
 * Instantiates the WebAssembly core and resolves to the API over it. The
 * options go to the Emscripten factory: locateFile(path, prefix) to say
 * where cb2_core.wasm is served from, wasmBinary with its bytes already
 * fetched, or instantiateWasm to instantiate it yourself. Each call builds
 * an independent core with its own heap and key classes.
 *
 * @param {import("../types/cb2.js").LoadOptions} [options]
 * @returns {Promise<import("../types/cb2.js").Cb2>}
 */
export async function load(options = {}) {
    const m = await instantiate({ ...options });
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
