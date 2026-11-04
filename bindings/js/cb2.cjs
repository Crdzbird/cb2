/**
 * The CommonJS entry: the same load() and Cb2Error as src/cb2.js. Node
 * 22.12 and later load the ES module synchronously from require().
 */
"use strict";

module.exports = require("./src/cb2.js");
