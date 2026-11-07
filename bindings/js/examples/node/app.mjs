/**
 * The request handler of the example: POST /login checks a user's password
 * and issues a cb2.local access token, GET /me opens the bearer token under
 * the server's rules and answers with its claims, and every refusal is a
 * 401 that names the library's verdict. Keys are looked up by the key id
 * in the token's footer, so a second key can be added during a rotation.
 */
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";

const MAX_BODY = 4096;

/**
 * Demo accounts. A real server keeps password hashes from a slow KDF such
 * as scrypt or Argon2, never the passwords.
 */
const USERS = new Map([
    ["ada", { password: "lovelace", role: "admin" }],
    ["alan", { password: "turing", role: "reader" }],
]);

const digest = (text) => createHash("sha256").update(text).digest();

function passwordMatches(user, password) {
    const account = USERS.get(user);
    const expected = digest(account ? account.password : "no such user");
    return timingSafeEqual(digest(String(password)), expected) && account !== undefined;
}

function rfc3339(seconds) {
    return new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
}

function send(res, status, body, headers = {}) {
    const text = JSON.stringify(body);
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
    res.end(`${text}\n`);
}

async function readJson(req) {
    let size = 0;
    const chunks = [];
    for await (const chunk of req) {
        size += chunk.length;
        if (size > MAX_BODY) return null;
        chunks.push(chunk);
    }
    try {
        return JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
        return null;
    }
}

/**
 * Builds the handler.
 * @param {object} options
 * @param {import("cb2").Cb2} options.cb2 the loaded library
 * @param {import("cb2").LocalKey} options.key the key tokens are sealed under
 * @param {string} options.issuer the iss of issued tokens and the expected issuer
 * @param {string} options.audience the aud of issued tokens and the expected audience
 * @param {number} options.ttl token lifetime in seconds
 * @param {() => number} [options.clock] the time in Unix seconds
 * @returns {(req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => Promise<void>}
 */
export function createApp({ cb2, key, issuer, audience, ttl, clock = () => Math.floor(Date.now() / 1000) }) {
    const keys = new Map([[key.keyId, key]]);

    async function login(req, res) {
        const body = await readJson(req);
        if (!body || typeof body.user !== "string" || typeof body.password !== "string") {
            return send(res, 400, { error: "invalid_request" });
        }
        if (!passwordMatches(body.user, body.password)) return send(res, 401, { error: "invalid_credentials" });
        const now = clock();
        const token = cb2.Token.seal(key, {
            iss: issuer,
            aud: audience,
            sub: body.user,
            iat: rfc3339(now),
            exp: rfc3339(now + ttl),
            jti: randomUUID(),
            role: USERS.get(body.user).role,
        });
        return send(res, 200, { access_token: token, token_type: "Bearer", expires_in: ttl });
    }

    function refuse(res, reason) {
        const header = `Bearer error="invalid_token", error_description="${reason}"`;
        return send(res, 401, { error: "invalid_token", reason }, { "www-authenticate": header });
    }

    function me(req, res) {
        const match = /^Bearer ([A-Za-z0-9._~+/=-]+)$/.exec(req.headers.authorization ?? "");
        if (!match) return send(res, 401, { error: "missing_token" }, { "www-authenticate": "Bearer" });
        const token = match[1];
        try {
            const kid = cb2.Token.peekKeyId(token);
            const verifier = kid === null ? key : keys.get(kid);
            if (!verifier) return refuse(res, "unknown_key");
            const claims = cb2.Token.open(token, verifier, { issuer, audience, max_lifetime: ttl, now: clock() });
            return send(res, 200, { sub: claims.sub, role: claims.role, exp: claims.exp });
        } catch (e) {
            if (e instanceof cb2.Cb2Error) return refuse(res, e.name);
            throw e;
        }
    }

    return async function handle(req, res) {
        const { pathname } = new URL(req.url ?? "/", "http://localhost");
        try {
            if (pathname === "/login" && req.method === "POST") return await login(req, res);
            if (pathname === "/me" && req.method === "GET") return me(req, res);
            return send(res, 404, { error: "not_found" });
        } catch (e) {
            console.error(e);
            return send(res, 500, { error: "server_error" });
        }
    };
}
