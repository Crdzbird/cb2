/**
 * Runs the benchmark under Node and prints the environment and a Markdown
 * table. --quick runs the short profile CI uses as a smoke test.
 */
import { readFileSync } from "node:fs";
import { cpus, release, type } from "node:os";
import * as jose from "jose";
import * as paseto from "paseto";
import * as v4public from "paseto/v4/public";
import * as pasetoTs from "paseto-ts/v4";
import { load } from "cb2";
import { makeCases } from "./cases.mjs";
import { PROFILES, runAll, table } from "./harness.mjs";

const quick = process.argv.includes("--quick");
const version = (name) => JSON.parse(readFileSync(new URL(`./node_modules/${name}/package.json`, import.meta.url), "utf8")).version;
const cb2 = await load();
const cases = await makeCases({ cb2, jose, paseto, v4public, pasetoTs });

console.log(`date: ${new Date().toISOString().slice(0, 10)}`);
console.log(`machine: ${cpus()[0].model}, ${type()} ${release()}, ${process.arch}`);
console.log(`runtime: Node ${process.versions.node} (V8 ${process.versions.v8})`);
console.log(`libraries: cb2 ${cb2.version()} (wasm), jose ${version("jose")}, paseto ${version("paseto")}, paseto-ts ${version("paseto-ts")}`);
const profile = quick ? PROFILES.quick : PROFILES.full;
console.log(`profile: ${quick ? "quick" : "full"}, ${profile.rounds} rounds of ${profile.samples} batches per operation`);
const rows = await runAll(cases, profile, (line) => console.error(line));
console.log("");
console.log(table(rows));
