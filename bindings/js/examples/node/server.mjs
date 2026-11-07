/**
 * Starts the example server. The key comes from CB2_LOCAL_KEY (its
 * kcb2.local PASERK text) or is generated at start, in which case tokens
 * die with the process. PORT (default 3000) and TOKEN_TTL_SECONDS (default
 * 600) are read from the environment.
 */
import { createServer } from "node:http";
import { load } from "cb2";
import { createApp } from "./app.mjs";

const cb2 = await load();
const key = process.env.CB2_LOCAL_KEY ? cb2.LocalKey.fromPaserk(process.env.CB2_LOCAL_KEY) : cb2.LocalKey.generate();
const port = Number(process.env.PORT ?? 3000);
const ttl = Number(process.env.TOKEN_TTL_SECONDS ?? 600);
const handle = createApp({ cb2, key, issuer: "https://cb2-example.local", audience: "example-api", ttl });
const server = createServer(handle);

server.listen(port, () => {
    console.log(`cb2 ${cb2.version()} example on http://localhost:${server.address().port}, key ${key.keyId}, tokens live ${ttl} s`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
    process.once(signal, () => {
        server.close(() => key.free());
        server.closeAllConnections();
    });
}
