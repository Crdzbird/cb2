/**
 * Packs the package with npm pack, installs the tarball into a scratch
 * project outside the repository, and runs the consumers of test/consumer
 * there: the ES module and CommonJS programs under node, and tsc over the
 * typed consumers. Usage: npm run check:pack [-- --keep]
 */
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const tsc = join(root, "node_modules", "typescript", "bin", "tsc");
const keep = process.argv.includes("--keep");

function run(cmd, args, cwd) {
    console.log(`$ ${[cmd, ...args].join(" ")}`);
    const shell = cmd === npm && process.platform === "win32";
    return execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"], shell });
}

const scratch = mkdtempSync(join(tmpdir(), "cb2-pack-"));
const project = join(scratch, "consumer");
mkdirSync(project);
const packed = JSON.parse(run(npm, ["pack", "--json", "--pack-destination", scratch], root))[0];
console.log(`packed ${packed.filename}: ${packed.entryCount} files, ${packed.size} bytes`);
writeFileSync(join(project, "package.json"), JSON.stringify({ name: "cb2-consumer", private: true, type: "module" }, null, 2));
run(npm, ["install", "--no-audit", "--no-fund", join(scratch, packed.filename)], project);
for (const file of ["esm.mjs", "cjs.cjs", "types.ts", "types.cts", "tsconfig.json"]) {
    copyFileSync(join(root, "test", "consumer", file), join(project, file));
}
process.stdout.write(run(process.execPath, ["esm.mjs"], project));
process.stdout.write(run(process.execPath, ["cjs.cjs"], project));
const read = run(process.execPath, [tsc, "-p", ".", "--listFilesOnly"], project).split("\n");
for (const file of read.filter((l) => l.includes("node_modules/cb2/"))) {
    console.log(`tsc reads ${file.slice(file.indexOf("node_modules/cb2/"))}`);
}
run(process.execPath, [tsc, "-p", "."], project);
console.log("tsc: the typed ES module and CommonJS consumers check against the installed declarations");
if (keep) console.log(`kept ${scratch}`);
if (!keep) rmSync(scratch, { recursive: true, force: true });
