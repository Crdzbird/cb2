/**
 * Node smoke test of the web build: loads dist/cb2.js, runs demo.cb2
 * (and demo_public.cb2, demo_holder.cb2 and demo_seal.cb2 when the build has liboqs) through the same
 * interpreter the page uses, then a short heavy load run of every
 * workload the build has (web/load.hpp) with an attack every tenth
 * request, and exits non-zero on any assert failure, malformed command,
 * wrong load verdict or unrefused attack. Run: node web/smoke.cjs
 */
const fs = require("fs");
const path = require("path");
const createCb2 = require("./dist/cb2.js");

createCb2().then((m) => {
    const run = m.cwrap("cb2_web_run", "string", ["string"]);
    const hasPq = m.ccall("cb2_web_has_pq", "number", [], []) === 1;
    const scripts = ["demo.cb2", "demo_text.cb2"].concat(hasPq ? ["demo_public.cb2", "demo_holder.cb2", "demo_seal.cb2"] : []);
    let asserts = 0;
    for (const name of scripts) {
        const text = fs.readFileSync(path.join(__dirname, "demo", name), "utf8");
        for (const line of text.split("\n")) {
            const reply = run(line);
            if (line.startsWith("assert ")) asserts += 1;
            if (reply.includes("error:")) {
                console.log("> " + line);
                console.log(reply);
            }
        }
    }
    const failures = m.ccall("cb2_web_failures", "number", [], []);
    console.log(`scripts: ${scripts.join(", ")}; asserts: ${asserts}; failures: ${failures}; pq: ${hasPq}`);
    const setup = m.cwrap("cb2_web_load_setup", "string", ["string"]);
    const batch = m.cwrap("cb2_web_load_batch", "string", ["number", "number"]);
    let loadOk = true;
    for (const kind of hasPq ? ["bearer", "bound", "signed"] : ["bearer"]) {
        const info = JSON.parse(setup(kind));
        let b = {error: info.error};
        for (let i = 0; i < 3 && !info.error; i++) b = JSON.parse(batch(41, 10));
        const right = !b.error && b.done === 123 && b.wrong === 0 && b.attacks > 0 && b.refused === b.attacks && b.ok + b.attacks === b.done;
        loadOk = loadOk && right;
        console.log(`load ${kind}: ${b.error || `${b.done} requests, ${b.ok} accepted, ${b.refused} of ${b.attacks} attacks refused, ${b.wrong} wrong`}`);
    }
    process.exit(failures === 0 && asserts > 0 && loadOk ? 0 : 1);
}).catch((e) => {
    console.error(e);
    process.exit(1);
});
