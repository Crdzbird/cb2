/**
 * The example page: loads cb2 through the import map, seals and opens a
 * claims token under a fresh cb2.local key, signs and verifies one under a
 * fresh cb2.public pair, and shows the library's verdict for a token that
 * was changed. The keys live only in this page.
 */
import { Cb2Error, load } from "cb2";

const $ = (id) => document.getElementById(id);
const ISSUER = "https://issuer.example";
const AUDIENCE = "api";

function initialClaims() {
    const exp = new Date(Date.now() + 10 * 60 * 1000).toISOString().replace(/\.\d+Z$/, "Z");
    return JSON.stringify({ iss: ISSUER, aud: AUDIENCE, sub: "user-1", exp, role: "admin" }, null, 2);
}

function show(id, ok, text) {
    const out = $(id);
    out.className = ok ? "ok" : "bad";
    out.textContent = text;
}

function attempt(id, fn) {
    try {
        show(id, true, fn());
    } catch (e) {
        if (e instanceof Cb2Error) return show(id, false, `Refused: ${e.name} (code ${e.code})`);
        if (e instanceof SyntaxError) return show(id, false, `The claims are not JSON: ${e.message}`);
        throw e;
    }
}

const cb2 = await load();
const localKey = cb2.LocalKey.generate();
const signer = cb2.SecretKey.generate();
const verifier = signer.publicKey();
const rules = { issuer: ISSUER, audience: AUDIENCE };

$("claims").value = initialClaims();
$("status").textContent = `cb2 ${cb2.version()} is ready. cb2.public: ${cb2.hasPublic() ? "yes" : "no"}, kcb2.seal: ${cb2.hasSeal() ? "yes" : "no"}. Local key ${localKey.paserkId()}.`;
document.body.dataset.ready = "true";

$("seal").addEventListener("click", () => attempt("local-result", () => {
    const token = cb2.Token.seal(localKey, JSON.parse($("claims").value));
    $("local-token").value = token;
    return `Sealed ${token.length} characters under ${cb2.Token.peekKeyId(token)}.`;
}));

$("open").addEventListener("click", () => attempt("local-result", () => {
    const claims = cb2.Token.open($("local-token").value.trim(), localKey, rules);
    return `Opened:\n${JSON.stringify(claims, null, 2)}`;
}));

$("tamper").addEventListener("click", () => {
    const token = $("local-token").value.trim();
    const at = 12 + Math.floor(Math.random() * 40);
    if (token.length <= at) return show("local-result", false, "Seal a token first.");
    $("local-token").value = token.slice(0, at) + (token[at] === "A" ? "B" : "A") + token.slice(at + 1);
    show("local-result", true, `Changed character ${at}. Open it to see the verdict.`);
});

$("sign").addEventListener("click", () => attempt("public-result", () => {
    const token = cb2.Token.sign(signer, JSON.parse($("claims").value));
    $("public-token").value = token;
    return `Signed: ${token.length} characters, both signatures included.`;
}));

$("verify").addEventListener("click", () => attempt("public-result", () => {
    const claims = cb2.Token.verify($("public-token").value.trim(), verifier, rules);
    return `Verified:\n${JSON.stringify(claims, null, 2)}`;
}));

for (const id of ["seal", "open", "tamper", "sign", "verify"]) $(id).disabled = false;

/**
 * With ?selftest in the URL the page presses its own buttons and records
 * the outcome in data-selftest on the body, "pass" or what went wrong, so
 * a headless browser can check it.
 */
function selftest() {
    const steps = [
        ["seal", "local-result", /^Sealed/],
        ["open", "local-result", /^Opened:[\s\S]*"sub": "user-1"/],
        ["tamper", "local-result", /^Changed character/],
        ["open", "local-result", /^Refused: invalid \(code 1\)$/],
        ["sign", "public-result", /^Signed/],
        ["verify", "public-result", /^Verified:[\s\S]*"role": "admin"/],
    ];
    for (const [button, output, want] of steps) {
        $(button).click();
        const got = $(output).textContent;
        if (!want.test(got)) return `${button}: ${got}`;
    }
    return "pass";
}

if (new URLSearchParams(location.search).has("selftest")) document.body.dataset.selftest = selftest();
