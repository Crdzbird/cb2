/**
 * Type declarations for cb2/core: the Emscripten factory of the
 * WebAssembly core, without the API over it. Most callers want load()
 * from cb2 instead.
 *
 * @packageDocumentation
 */

import type { Cb2Core, LoadOptions } from "./cb2.js";

/** Instantiates the core and resolves to the Emscripten module. */
declare function createCb2Core(options?: LoadOptions): Promise<Cb2Core>;

export default createCb2Core;
