/**
 * Node smoke test of the web build: loads dist/cb2.js, runs demo.cb2
 * (and demo_public.cb2 when the build has liboqs) through the same
 * interpreter the page uses, and exits non-zero on any assert failure
 * or malformed command. Run: node web/smoke.cjs
 */
const fs = require("fs");
const path = require("path");
const createCb2 = require("./dist/cb2.js");

createCb2().then((m) => {
    const run = m.cwrap("cb2_web_run", "string", ["string"]);
    const hasPq = m.ccall("cb2_web_has_pq", "number", [], []) === 1;
    const scripts = ["demo.cb2", "demo_text.cb2"].concat(hasPq ? ["demo_public.cb2"] : []);
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
    process.exit(failures === 0 && asserts > 0 ? 0 : 1);
}).catch((e) => {
    console.error(e);
    process.exit(1);
});
