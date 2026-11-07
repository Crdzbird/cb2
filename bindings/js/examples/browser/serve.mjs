/**
 * A static file server for the example page, with no dependencies: serves
 * this directory, node_modules/cb2 included, with the right content types
 * (application/wasm lets the browser compile the core while it streams).
 * PORT defaults to 8080.
 */
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
const port = Number(process.env.PORT ?? 8080);
const TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".wasm": "application/wasm",
};

const server = createServer(async (req, res) => {
    const { pathname } = new URL(req.url ?? "/", "http://localhost");
    const path = normalize(join(root, decodeURIComponent(pathname.endsWith("/") ? `${pathname}index.html` : pathname)));
    const type = TYPES[extname(path)];
    const inside = path.startsWith(root) && !path.slice(root.length).split(sep).includes("..");
    const info = inside && type ? await stat(path).catch(() => null) : null;
    if (!info?.isFile()) {
        res.writeHead(404, { "content-type": "text/plain" });
        res.end("not found\n");
        return;
    }
    res.writeHead(200, { "content-type": type, "content-length": info.size, "cache-control": "no-cache" });
    createReadStream(path).pipe(res);
});

server.listen(port, () => {
    console.log(`cb2 browser example on http://localhost:${server.address().port}/`);
});
