/**
 * The CommonJS entry: the same load() and Cb2Error as src/cb2.js, loaded
 * with require(esm), which Node 22.12 and later do synchronously. The
 * declarations are in types/cb2.d.cts.
 */
"use strict";

module.exports = require("./src/cb2.js");
