/**
 * Runs the benchmark in the page and shows the environment and the
 * Markdown table. ?quick runs the short profile. The table is also set as
 * data-table on the body, and data-done when the run is over.
 */
import * as jose from "jose";
import * as paseto from "paseto";
import * as v4public from "paseto/v4/public";
import * as pasetoTs from "paseto-ts/v4";
import { load } from "cb2";
import { makeCases } from "../cases.mjs";
import { PROFILES, runAll, table } from "../harness.mjs";

const out = document.getElementById("out");
const quick = new URLSearchParams(location.search).has("quick");
const profile = quick ? PROFILES.quick : PROFILES.full;
const print = (line) => {
    out.textContent += `${line}\n`;
};

try {
    const cb2 = await load();
    const cases = await makeCases({ cb2, jose, paseto, v4public, pasetoTs });
    print(`date: ${new Date().toISOString().slice(0, 10)}`);
    print(`browser: ${navigator.userAgent}`);
    print(`timer: crossOriginIsolated ${globalThis.crossOriginIsolated === true}`);
    print(`profile: ${quick ? "quick" : "full"}, ${profile.rounds} rounds of ${profile.samples} batches per operation`);
    const rows = await runAll(cases, profile, (line) => {
        document.getElementById("status").textContent = line;
    });
    const result = table(rows);
    print("");
    print(result);
    document.body.dataset.table = result;
    document.getElementById("status").textContent = "Done.";
} catch (e) {
    document.getElementById("status").textContent = `Failed: ${e}`;
    console.error(e);
}
document.body.dataset.done = "true";
