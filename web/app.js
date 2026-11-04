(function () {
    "use strict";

    function $(id) { return document.getElementById(id); }

    var out = $("out");
    var cmd = $("cmd");
    var status = $("status");
    var tokenBox = $("token");
    var history = [];
    var cursor = 0;
    var run = null;
    var reset = null;
    var hasPq = false;
    var keys = [];
    var lastToken = "";

    var EXPLAIN = {
        ok: "The token authenticated and every rule passed.",
        invalid: "Something in the unverified token is wrong: the header, the encoding, the footer, the key id, the tag or the signature. No detail is given on purpose, so the verdict cannot be used as an oracle.",
        too_large: "The token is longer than the verifier's limit; it was refused before being parsed.",
        argument: "The caller's input is wrong: a claim that fails the identifier policy, a key id with invisible characters, a key string that is not a kcb2 key.",
        rules_incomplete: "The rules name no expected issuer and no expected audience, and do not say that any is acceptable. The token was not read.",
        internal: "A backend call failed.",
        unavailable: "This build lacks the backend the operation needs.",
        claims_malformed: "The token authenticated, but its payload is not a valid claims object: bad JSON, a wrong type, or an identifier the policy refuses.",
        missing_exp: "The token authenticated but carries no exp; the rules did not allow that.",
        expired: "The token authenticated but its exp is in the past, beyond any clock skew allowed.",
        not_yet_valid: "The token authenticated but its nbf is still in the future.",
        issued_in_future: "The token authenticated but its iat is in the future.",
        lifetime_exceeded: "The token authenticated but its exp lies further ahead than the maximum lifetime the rules allow.",
        issuer_mismatch: "The token authenticated but its iss is not the expected issuer.",
        audience_mismatch: "The token authenticated but its aud is not the expected audience.",
        subject_mismatch: "The token authenticated but its sub is not the expected subject.",
        missing_jti: "The replay check needs a jti and the token has none.",
        replayed: "This jti was already seen by the replay check."
    };

    function ch() {
        var s = "";
        for (var i = 0; i < arguments.length; i++) s += String.fromCodePoint(arguments[i]);
        return s;
    }

    var TEXT_PRESETS = [
        {label: "a Japanese identifier", value: ch(0x5c71, 0x7530, 0x592a, 0x90ce)},
        {label: "admin with a zero-width space", value: "admin" + ch(0x200b)},
        {label: "a bidi override", value: "paid " + ch(0x202e) + "DIAPNU"},
        {label: "composed cafe", value: "caf" + ch(0xe9)},
        {label: "decomposed cafe", value: "cafe" + ch(0x301)},
        {label: "Cyrillic a in admin", value: ch(0x430) + "dmin"},
        {label: "a tab", value: "user\t1"}
    ];

    function append(text, cls) {
        var span = document.createElement("span");
        span.className = cls;
        span.textContent = text + "\n";
        out.appendChild(span);
        out.scrollTop = out.scrollHeight;
    }

    function quote(s) {
        var q = "\"";
        for (var i = 0; i < s.length; i++) {
            var cp = s.codePointAt(i);
            if (cp > 0xffff) i += 1;
            var c = String.fromCodePoint(cp);
            if (c === "\\" || c === "\"") q += "\\" + c;
            else if (c === "\n") q += "\\n";
            else if (c === "\t") q += "\\t";
            else if (c === "\r") continue;
            else if (cp < 0x20 || cp > 0x7e) q += "\\u{" + cp.toString(16).toUpperCase() + "}";
            else q += c;
        }
        return q + "\"";
    }

    function arg(s) {
        if (s === "" || s === "$" || /[^\x21-\x7e]|["\\]/.test(s)) return quote(s);
        return s;
    }

    function tokenArg(t) {
        if (t !== "" && t === lastToken) return "$";
        return arg(t);
    }

    function parse(reply) {
        var fields = {};
        var lines = reply.split("\n");
        var kept = [];
        for (var i = 0; i < lines.length; i++) {
            var l = lines[i];
            if (l === "") continue;
            kept.push(l);
            var at = l.indexOf(" = ");
            if (at > 0) {
                var name = l.substring(0, at);
                var value = l.substring(at + 3);
                if (fields[name] === undefined) fields[name] = value;
                fields.all = fields.all || [];
                fields.all.push([name, value]);
            }
        }
        fields.lines = kept;
        return fields;
    }

    function exec(text, silent, keepToken) {
        var trimmed = text.trim();
        if (trimmed === "") return {lines: []};
        if (!silent) append("> " + trimmed, "cmd");
        if (trimmed.charAt(0) === "#") return {lines: []};
        var reply = run(trimmed);
        var f = parse(reply);
        if (!silent) {
            for (var i = 0; i < f.lines.length; i++) {
                var l = f.lines[i];
                var cls = "res";
                if (l.indexOf("error:") === 0) cls = "err";
                if (l === "verdict = ok") cls = "ok";
                if (l.indexOf("verdict = ") === 0 && l !== "verdict = ok") cls = "bad";
                append(l, cls);
            }
        }
        var head = trimmed.split(/\s+/)[0];
        if (f.token !== undefined) {
            lastToken = f.token;
            if (!keepToken && head !== "wrap") setToken(f.token);
        }
        if (head === "keygen" || head === "import" || head === "unwrap" || head === "kid") refreshKeys();
        return f;
    }

    function remember(text) {
        if (history[history.length - 1] !== text) history.push(text);
        cursor = history.length;
    }

    function el(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text !== undefined) e.textContent = text;
        return e;
    }

    function fillSelect(select, names, keep) {
        var current = keep ? select.value : "";
        select.textContent = "";
        for (var i = 0; i < names.length; i++) {
            var o = el("option", "", names[i]);
            o.value = names[i];
            select.appendChild(o);
        }
        if (names.length === 0) {
            var none = el("option", "", "no key yet");
            none.value = "";
            select.appendChild(none);
        } else if (names.indexOf(current) >= 0) {
            select.value = current;
        }
    }

    function refreshKeys() {
        var f = exec("keys", true);
        keys = [];
        var all = f.all || [];
        for (var i = 0; i < all.length; i++) {
            var m = /^(\w+), kid (.*)$/.exec(all[i][1]);
            if (m) keys.push({name: all[i][0], kind: m[1], kid: m[2]});
        }
        var body = $("keys-table").querySelector("tbody");
        body.textContent = "";
        for (var k = 0; k < keys.length; k++) {
            var tr = el("tr");
            tr.appendChild(el("td", "mono", keys[k].name));
            tr.appendChild(el("td", "", keys[k].kind === "local" ? "local (seals and opens)" : keys[k].kind === "secret" ? "signing pair (signs and verifies)" : "public (verifies only)"));
            tr.appendChild(el("td", "mono small", keys[k].kid));
            var td = el("td");
            var b = el("button", "", "show");
            b.type = "button";
            b.dataset.key = keys[k].name;
            td.appendChild(b);
            tr.appendChild(td);
            body.appendChild(tr);
        }
        $("keys-table").hidden = keys.length === 0;
        $("keys-empty").hidden = keys.length !== 0;
        var issuers = [];
        var verifiers = [];
        var names = [];
        for (var j = 0; j < keys.length; j++) {
            names.push(keys[j].name);
            verifiers.push(keys[j].name);
            if (keys[j].kind !== "public") issuers.push(keys[j].name);
        }
        var locals = [];
        for (var l = 0; l < keys.length; l++) {
            if (keys[l].kind === "local") locals.push(keys[l].name);
        }
        fillSelect($("issue-key"), issuers, true);
        fillSelect($("verify-key"), verifiers, true);
        fillSelect($("kid-key"), names, true);
        fillSelect($("forge-key"), names, true);
        fillSelect($("wrap-key"), locals, true);
        fillSelect($("wrap-target"), locals, true);
        fillSelect($("unwrap-key"), locals, true);
        fillSelect($("export-key"), names, true);
        refreshExportAs();
    }

    function refreshExportAs() {
        var kind = keyKind($("export-key").value);
        var select = $("export-as");
        var current = select.value;
        select.textContent = "";
        var options = [];
        if (kind === "local") options.push(["", "kcb2.local: the key itself (keep private)"]);
        if (kind === "secret") {
            options.push(["", "kcb2.secret: the whole pair (keep private)"]);
            options.push(["public", "kcb2.public: the verifying half (share)"]);
        }
        if (kind === "public") options.push(["", "kcb2.public: the verifying half (share)"]);
        if (options.length === 0) options.push(["", "no key yet"]);
        for (var i = 0; i < options.length; i++) {
            var o = el("option", "", options[i][1]);
            o.value = options[i][0];
            select.appendChild(o);
        }
        if (kind === "secret" && current === "public") select.value = "public";
    }

    function keyKind(name) {
        for (var i = 0; i < keys.length; i++) {
            if (keys[i].name === name) return keys[i].kind;
        }
        return "";
    }

    function keyName() {
        var n = $("key-name").value.trim();
        if (n === "") {
            var base = "key";
            var i = 1;
            while (keyKind(base + "-" + i) !== "") i += 1;
            n = base + "-" + i;
        }
        return n;
    }

    function badge(verdict) {
        var b = el("span", "badge " + (verdict === "ok" ? "good" : "bad"), verdict);
        return b;
    }

    function resultBox(box, verdict, rows, note) {
        box.textContent = "";
        box.hidden = false;
        var head = el("div", "verdict");
        head.appendChild(badge(verdict));
        head.appendChild(el("span", "explain", EXPLAIN[verdict] || ""));
        box.appendChild(head);
        if (note) box.appendChild(el("p", "hint", note));
        for (var i = 0; i < rows.length; i++) {
            var dl = el("div", "kv");
            dl.appendChild(el("span", "k", rows[i][0]));
            var v = el("span", "v mono");
            if (rows[i][2]) v.className += " pre";
            v.textContent = rows[i][1];
            dl.appendChild(v);
            box.appendChild(dl);
        }
    }

    function pretty(json) {
        try {
            return JSON.stringify(JSON.parse(json), null, 2);
        } catch (e) {
            return json;
        }
    }

    function claimsTable(json) {
        var obj;
        try {
            obj = JSON.parse(json);
        } catch (e) {
            return null;
        }
        var t = el("table", "claims");
        var names = Object.keys(obj);
        for (var i = 0; i < names.length; i++) {
            var tr = el("tr");
            tr.appendChild(el("th", "", names[i]));
            var v = obj[names[i]];
            tr.appendChild(el("td", "mono", typeof v === "string" ? v : JSON.stringify(v)));
            t.appendChild(tr);
        }
        return t;
    }

    function setToken(t) {
        if (tokenBox.value !== t) tokenBox.value = t;
        inspect();
    }

    function shorten(seg) {
        if (seg.length <= 240) return seg;
        return seg.substring(0, 180) + " [" + (seg.length - 204) + " more] " + seg.substring(seg.length - 24);
    }

    function inspect() {
        var t = tokenBox.value.trim();
        var anatomy = $("anatomy");
        var peek = $("peek");
        anatomy.textContent = "";
        peek.textContent = "";
        if (t === "") return;
        var header = "";
        if (t.indexOf("cb2.local.") === 0) header = "cb2.local.";
        if (t.indexOf("cb2.public.") === 0) header = "cb2.public.";
        if (header === "") {
            anatomy.appendChild(el("span", "seg other", t.length > 80 ? t.substring(0, 80) + "..." : t));
            anatomy.appendChild(el("span", "legend", "not a cb2 token"));
        } else {
            var rest = t.substring(header.length);
            var dot = rest.indexOf(".");
            var body = dot < 0 ? rest : rest.substring(0, dot);
            var footer = dot < 0 ? "" : rest.substring(dot + 1);
            anatomy.appendChild(el("span", "seg hdr", header));
            anatomy.appendChild(el("span", "seg body", shorten(body)));
            if (dot >= 0) {
                anatomy.appendChild(el("span", "seg dot", "."));
                anatomy.appendChild(el("span", "seg ftr", shorten(footer)));
            }
            var legend = el("div", "legend");
            legend.appendChild(el("span", "sw hdr", "header, " + header.length + " chars: the version and purpose"));
            legend.appendChild(el("span", "sw body", "body, " + body.length + " chars: nonce, ciphertext and tag" + (header === "cb2.public." ? " (for public: payload and signatures)" : "")));
            if (dot >= 0) legend.appendChild(el("span", "sw ftr", "footer, " + footer.length + " chars: in the clear, authenticated"));
            anatomy.appendChild(legend);
        }
        var f = exec("peek " + arg(t), true);
        var all = f.all || [];
        for (var i = 0; i < all.length; i++) {
            if (all[i][0] === "claims" || all[i][0] === "exp") continue;
            peek.appendChild(el("dt", "", all[i][0]));
            peek.appendChild(el("dd", "mono", all[i][1]));
        }
        unverified(f);
    }

    function relative(rfc) {
        var at = Date.parse(rfc);
        if (isNaN(at)) return "";
        var d = Math.round((at - Date.now()) / 1000);
        var abs = Math.abs(d);
        var unit = abs < 120 ? abs + " seconds" : abs < 7200 ? Math.round(abs / 60) + " minutes" : abs < 172800 ? Math.round(abs / 3600) + " hours" : Math.round(abs / 86400) + " days";
        return d < 0 ? unit + " ago" : "in " + unit;
    }

    function unverified(f) {
        var box = $("unverified");
        box.textContent = "";
        box.hidden = true;
        if (f.header !== "cb2.public.") {
            if (f.header === "cb2.local.") {
                box.hidden = false;
                box.appendChild(el("p", "ok-line", "A local token's claims are encrypted: nothing can read them without the key. Only the footer travels in clear."));
            }
            return;
        }
        box.hidden = false;
        box.appendChild(el("p", "warn", "Decoded without verifying: anyone can write these bytes. Nothing below may be trusted until step 4 verifies the signatures."));
        if (f.claims === undefined) return;
        var t = claimsTable(f.claims);
        if (t === null) {
            box.appendChild(el("p", "ok-line", f.claims));
            return;
        }
        var rows = t.querySelectorAll("tr");
        for (var i = 0; i < rows.length; i++) {
            var name = rows[i].children[0].textContent;
            if (name === "exp" || name === "nbf" || name === "iat") {
                var when = relative(rows[i].children[1].textContent);
                if (when !== "") rows[i].children[1].appendChild(el("span", "small", "  (" + when + (name === "exp" && when.indexOf("ago") >= 0 ? ", expired" : "") + ")"));
            }
        }
        box.appendChild(t);
    }

    function customRow(name, value, type) {
        var body = $("custom-table").querySelector("tbody");
        var tr = el("tr");
        var n = el("input");
        n.type = "text";
        n.placeholder = "name";
        n.spellcheck = false;
        n.value = name || "";
        var v = el("input");
        v.type = "text";
        v.placeholder = "value";
        v.spellcheck = false;
        v.value = value || "";
        var s = el("select");
        var o1 = el("option", "", "string");
        o1.value = "string";
        var o2 = el("option", "", "JSON");
        o2.value = "json";
        s.appendChild(o1);
        s.appendChild(o2);
        s.value = type || "string";
        var x = el("button", "", "remove");
        x.type = "button";
        x.addEventListener("click", function () { tr.remove(); });
        var tds = [n, v, s, x];
        for (var i = 0; i < tds.length; i++) {
            var td = el("td");
            td.appendChild(tds[i]);
            tr.appendChild(td);
        }
        body.appendChild(tr);
    }

    function customRows() {
        var rows = $("custom-table").querySelectorAll("tbody tr");
        var out = [];
        for (var i = 0; i < rows.length; i++) {
            var cells = rows[i].querySelectorAll("input, select");
            out.push({name: cells[0].value.trim(), value: cells[1].value, type: cells[2].value});
        }
        return out;
    }

    function clearCustom() {
        $("custom-table").querySelector("tbody").textContent = "";
    }

    function issueMode() {
        return document.querySelector("input[name=issue-mode]:checked").value;
    }

    function verifyMode() {
        return document.querySelector("input[name=verify-mode]:checked").value;
    }

    function issueCommand() {
        var key = $("issue-key").value;
        if (key === "") return null;
        if (issueMode() === "raw") {
            var verb = keyKind(key) === "local" ? "seal" : "sign";
            var parts = [verb, arg(key), quote($("r-msg").value)];
            var footer = $("r-footer").value;
            var implicit = $("r-implicit").value;
            if (footer !== "" || implicit !== "") parts.push(quote(footer));
            if (implicit !== "") parts.push(quote(implicit));
            return parts.join(" ");
        }
        var c = ["claims", arg(key)];
        var named = ["iss", "sub", "aud", "jti", "exp", "nbf", "iat"];
        for (var i = 0; i < named.length; i++) {
            var v = $("c-" + named[i]).value;
            if (v.trim() !== "") c.push(arg(named[i] + "=" + v));
        }
        var custom = customRows();
        for (var j = 0; j < custom.length; j++) {
            if (custom[j].name === "") continue;
            c.push(arg(custom[j].name + (custom[j].type === "json" ? ":=" : "=") + custom[j].value));
        }
        var imp = $("c-implicit").value;
        if (imp !== "") c.push(arg("implicit=" + imp));
        return c.join(" ");
    }

    function issue() {
        var command = issueCommand();
        var box = $("issue-result");
        $("verify-result").hidden = true;
        if (command === null) {
            resultBox(box, "argument", [], "Make a key first.");
            return;
        }
        var f = exec(command);
        var verdict = f.verdict || "argument";
        var rows = [];
        if (f.payload) rows.push(["payload", pretty(f.payload), true]);
        var all = f.all || [];
        for (var i = 0; i < all.length; i++) {
            if (all[i][0] === "refused") rows.push(["refused", all[i][1]]);
        }
        if (f.footer !== undefined) rows.push(["footer", f.footer === "" ? "(none)" : f.footer]);
        if (f.length) rows.push(["token length", f.length + " characters"]);
        var note = "";
        if (verdict === "ok") note = "The token is now in step 3. Verify it in step 4, or change a field and issue again.";
        if (f.lines.length && f.lines[0].indexOf("error:") === 0) note = f.lines[0];
        resultBox(box, verdict, rows, note);
    }

    function verifyCommand(keyOverride) {
        var key = keyOverride || $("verify-key").value;
        var t = tokenBox.value.trim();
        if (key === "" || t === "") return null;
        if (verifyMode() === "raw") {
            var verb = keyKind(key) === "local" ? "open" : "verify";
            var parts = [verb, arg(key), tokenArg(t)];
            var footer = $("vr-footer").value;
            var implicit = $("vr-implicit").value;
            if (footer !== "" || implicit !== "") parts.push(quote(footer));
            if (implicit !== "") parts.push(quote(implicit));
            return parts.join(" ");
        }
        var c = ["check", arg(key), tokenArg(t)];
        var named = ["iss", "aud", "sub"];
        for (var i = 0; i < named.length; i++) {
            var v = $("v-" + named[i]).value;
            if (v.trim() !== "") c.push(arg(named[i] + "=" + v));
        }
        if ($("v-any-iss").checked) c.push("any-iss");
        if ($("v-any-aud").checked) c.push("any-aud");
        if ($("v-replay").checked) c.push("replay");
        if ($("v-no-exp").checked) c.push("no-exp");
        if ($("v-skew").value !== "") c.push("skew=" + $("v-skew").value);
        if ($("v-now").value.trim() !== "") c.push(arg("now=" + $("v-now").value.trim()));
        if ($("v-max").value !== "") c.push("max=" + $("v-max").value);
        if ($("v-implicit").value !== "") c.push(arg("implicit=" + $("v-implicit").value));
        return c.join(" ");
    }

    function verify() {
        var command = verifyCommand();
        var box = $("verify-result");
        if (command === null) {
            resultBox(box, "argument", [], tokenBox.value.trim() === "" ? "There is no token in step 3." : "Pick a key.");
            return;
        }
        var f = exec(command);
        var verdict = f.verdict || "argument";
        var rows = [];
        if (f.rules) rows.push(["rules", f.rules]);
        if (f.message !== undefined) rows.push(["message", f.message]);
        if (f.exp) rows.push(["exp", f.exp]);
        var note = "";
        if (f.lines.length && f.lines[0].indexOf("error:") === 0) note = f.lines[0];
        resultBox(box, verdict, rows, note);
        if (f.claims) {
            var t = claimsTable(f.claims);
            if (t) {
                box.appendChild(el("p", "hint", "The claims, now trusted:"));
                box.appendChild(t);
            }
        }
    }

    var foundKey = "";

    function lookup() {
        var t = tokenBox.value.trim();
        var dl = $("lookup-result");
        dl.textContent = "";
        $("lookup-verdict").hidden = true;
        foundKey = "";
        if (t === "") {
            dl.appendChild(el("dt", "", "token"));
            dl.appendChild(el("dd", "", "there is no token in step 3"));
            return;
        }
        var f = exec("lookup " + tokenArg(t));
        var all = f.all || [];
        for (var i = 0; i < all.length; i++) {
            dl.appendChild(el("dt", "", all[i][0]));
            var dd = el("dd", "mono", all[i][1]);
            if (all[i][0] === "key") {
                var m = /^(\S+) \((local|secret|public)\)$/.exec(all[i][1]);
                if (m && foundKey === "") foundKey = m[1];
                dd.className += m ? " good" : " refused";
            }
            dl.appendChild(dd);
        }
    }

    function lookupVerify() {
        var box = $("lookup-verdict");
        if (foundKey === "") {
            resultBox(box, "no_key", [], "No key was found for this token: look it up first, or there is no stored key with its kid. A verifier stops here, before any cryptography.");
            return;
        }
        $("verify-key").value = foundKey;
        var command = verifyCommand(foundKey);
        if (command === null) {
            resultBox(box, "argument", [], "There is no token in step 3.");
            return;
        }
        var f = exec(command);
        var rows = [["key", foundKey]];
        if (f.rules) rows.push(["rules", f.rules]);
        var note = "";
        if (f.lines.length && f.lines[0].indexOf("error:") === 0) note = f.lines[0];
        resultBox(box, f.verdict || "argument", rows, note);
        if (f.claims) {
            var t = claimsTable(f.claims);
            if (t) box.appendChild(t);
        }
    }

    function base64url(text) {
        var bytes = new TextEncoder().encode(text);
        var bin = "";
        for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    function kidOf(name) {
        for (var i = 0; i < keys.length; i++) {
            if (keys[i].name === name) return keys[i].kid;
        }
        return "none";
    }

    function forge() {
        var t = tokenBox.value.trim();
        var name = $("forge-key").value;
        if (t === "" || name === "") return;
        var header = t.indexOf("cb2.local.") === 0 ? "cb2.local." : t.indexOf("cb2.public.") === 0 ? "cb2.public." : "";
        if (header === "") return;
        var kid = kidOf(name);
        var rest = t.substring(header.length);
        var dot = rest.indexOf(".");
        var body = dot < 0 ? rest : rest.substring(0, dot);
        var footer = kid === "none" ? "" : "." + base64url(JSON.stringify({kid: kid}));
        append("# the footer of the token is rewritten by the page to name " + name + (kid === "none" ? " (no kid: the footer is removed)" : ""), "cmd");
        setToken(header + body + footer);
        lookup();
    }

    function wrapKey() {
        var w = $("wrap-key").value;
        var k = $("wrap-target").value;
        var box = $("wrap-result");
        if (w === "" || k === "") {
            resultBox(box, "argument", [], "Make two local keys first: one to wrap and one to wrap it with.");
            return;
        }
        var f = exec("wrap " + arg(w) + " " + arg(k));
        if (f.token !== undefined) $("wrap-text").value = f.token;
        var rows = [];
        if (f.length) rows.push(["length", f.length + " characters"]);
        resultBox(box, f.verdict || "argument", rows, f.verdict === "ok" ? "Unwrap it below, under the same wrapping key, or flip a character first." : "");
    }

    function unwrapKey() {
        var w = $("unwrap-key").value;
        var t = $("wrap-text").value.trim();
        var box = $("wrap-result");
        if (w === "" || t === "") {
            resultBox(box, "argument", [], t === "" ? "There is no kcb2.local-wrap string to unwrap." : "Pick a wrapping key.");
            return;
        }
        var name = $("unwrap-name").value.trim();
        var f = exec("unwrap " + arg(w) + " " + arg(t) + (name === "" ? "" : " " + arg(name)));
        var rows = [];
        if (f.key) rows.push(["stored as", f.key]);
        if (f["kcb2.lid"]) rows.push(["kcb2.lid", f["kcb2.lid"]]);
        if (f.kid) rows.push(["kid", f.kid]);
        var note = "";
        if (f.lines.length && f.lines[0].indexOf("error:") === 0) note = f.lines[0];
        if (f.verdict === "ok") note = "The key is in step 1 now and can issue and verify like the original.";
        resultBox(box, f.verdict || "argument", rows, note);
    }

    function tamperWrap() {
        var t = $("wrap-text").value.trim();
        if (t === "") return;
        var f = exec("tamper " + (t === lastToken ? "$" : arg(t)), false, true);
        if (f.token !== undefined) $("wrap-text").value = f.token;
    }

    function exportedString(f) {
        return f["kcb2.local"] || f["kcb2.secret"] || f["kcb2.public"] || "";
    }

    function exportKey() {
        var k = $("export-key").value;
        var box = $("export-result");
        if (k === "") {
            resultBox(box, "argument", [], "Make a key in step 1 first.");
            return;
        }
        var half = $("export-as").value === "public";
        var f = exec("export " + arg(k) + (half ? " public" : ""));
        var text = exportedString(f);
        if (text !== "") $("export-text").value = text;
        var rows = [];
        if (f["kcb2.local"]) rows.push(["kind", "kcb2.local: a secret, only its holders open its tokens"]);
        if (f["kcb2.secret"]) rows.push(["kind", "kcb2.secret: a secret, it signs"]);
        if (f["kcb2.public"]) rows.push(["kind", "kcb2.public: not secret, it only verifies"]);
        if (text !== "") rows.push(["length", text.length + " characters"]);
        if (f.kid) rows.push(["kid", f.kid + " (not part of the string)"]);
        var note = "";
        if (f.lines.length && f.lines[0].indexOf("error:") === 0) note = f.lines[0];
        if (f.verdict === "ok") note = "Import it below under another name, or copy it into another session.";
        resultBox(box, f.verdict || "argument", rows, note);
    }

    function exportAll() {
        var f = exec("export");
        var script = [];
        for (var i = 0; i < f.lines.length; i++) {
            var l = f.lines[i];
            if (l.indexOf("import ") === 0 || l.indexOf("kid ") === 0) script.push(l);
        }
        $("export-text").value = script.join("\n");
        var rows = [["keys", f.keys || "0"], ["lines", script.length + " (one import per key, plus a kid line for each id that is not the default)"]];
        resultBox($("export-result"), f.verdict || "argument", rows, "Reset the transcript, paste the script into the import box, and every key comes back with its id.");
    }

    function importScript(text) {
        var lines = text.split("\n");
        var imported = 0;
        var verdict = "ok";
        var note = "";
        for (var i = 0; i < lines.length; i++) {
            var l = lines[i].trim();
            if (l === "") continue;
            var f = exec(l);
            if (l.indexOf("import ") === 0 && f.verdict === "ok") imported += 1;
            if (f.verdict && f.verdict !== "ok" && verdict === "ok") verdict = f.verdict;
            if (f.lines.length && f.lines[0].indexOf("error:") === 0 && note === "") note = f.lines[0];
        }
        if (verdict === "ok" && note === "") note = "The keys are in step 1, with the ids the script set.";
        resultBox($("export-result"), verdict, [["imported", imported + " key" + (imported === 1 ? "" : "s")]], note);
    }

    function importKeys() {
        var t = $("import-text").value.trim();
        var box = $("export-result");
        if (t === "") return;
        if (t.indexOf("\n") >= 0 || t.indexOf("import ") === 0 || t.indexOf("kid ") === 0 || t.charAt(0) === "#") {
            importScript(t);
            return;
        }
        if (t.indexOf("kcb2.local-wrap.") === 0) {
            resultBox(box, "argument", [], "That is a wrapped key: unwrap it in step 6 under the key that wrapped it.");
            return;
        }
        var n = $("import-name").value.trim();
        var f = exec("import " + arg(t) + (n === "" ? "" : " " + arg(n)));
        var rows = [];
        if (f.key) rows.push(["stored as", f.key]);
        if (f["kcb2.lid"]) rows.push(["kcb2.lid", f["kcb2.lid"]]);
        if (f["kcb2.pid"]) rows.push(["kcb2.pid", f["kcb2.pid"]]);
        if (f.kid) rows.push(["kid", f.kid]);
        var note = "";
        if (f.lines.length && f.lines[0].indexOf("error:") === 0) note = f.lines[0];
        if (f.verdict === "ok") note = "The key is in step 1 with its default id. If the original had another id, set it there.";
        if (f.verdict && f.verdict !== "ok" && note === "") note = "Not a kcb2 string this build accepts: the prefix names the kind and the rest is its base64url bytes.";
        resultBox(box, f.verdict || "argument", rows, note);
    }

    function inspectText(value) {
        var f = exec("text " + quote(value));
        var dl = $("text-result");
        dl.textContent = "";
        var all = f.all || [];
        for (var i = 0; i < all.length; i++) {
            dl.appendChild(el("dt", "", all[i][0]));
            var dd = el("dd", "mono", all[i][1]);
            if (all[i][0] === "identifier") dd.className += all[i][1] === "ok" ? " good" : " refused";
            dl.appendChild(dd);
        }
    }

    function ensureLocal(name) {
        if (keyKind(name) !== "local") exec("keygen local " + name);
    }

    function ensureSigner(name) {
        if (keyKind(name) !== "secret") exec("keygen public " + name);
    }

    function setMode(name, value) {
        var radios = document.querySelectorAll("input[name=" + name + "]");
        for (var i = 0; i < radios.length; i++) {
            if (radios[i].value === value) radios[i].checked = true;
        }
        applyModes();
    }

    function applyModes() {
        $("issue-claims").hidden = issueMode() !== "claims";
        $("issue-raw").hidden = issueMode() !== "raw";
        $("verify-rules").hidden = verifyMode() !== "rules";
        $("verify-raw").hidden = verifyMode() !== "raw";
    }

    function setClaims(values) {
        var named = ["iss", "sub", "aud", "jti", "exp", "nbf", "iat", "implicit"];
        for (var i = 0; i < named.length; i++) {
            $("c-" + named[i]).value = values[named[i]] === undefined ? "" : values[named[i]];
        }
        clearCustom();
        var custom = values.custom || [];
        for (var j = 0; j < custom.length; j++) customRow(custom[j][0], custom[j][1], custom[j][2]);
    }

    function setRules(values) {
        $("v-iss").value = values.iss || "";
        $("v-aud").value = values.aud || "";
        $("v-sub").value = values.sub || "";
        $("v-skew").value = values.skew || "";
        $("v-now").value = values.now || "";
        $("v-max").value = values.max || "";
        $("v-implicit").value = values.implicit || "";
        $("v-any-iss").checked = !!values.anyIss;
        $("v-any-aud").checked = !!values.anyAud;
        $("v-replay").checked = !!values.replay;
        $("v-no-exp").checked = !!values.noExp;
    }

    var BASE = {iss: "https://issuer.example", sub: "user-1", aud: "api", jti: "t-1", exp: "+3600", custom: [["role", "admin", "string"]]};
    var RULES = {iss: "https://issuer.example", aud: "api"};
    var COMPOSED = "Pe" + ch(0xf1) + "a";
    var DECOMPOSED = "Pen" + ch(0x303) + "a";

    function scenarioStart(key) {
        ensureLocal(key || "alice");
        $("issue-key").value = key || "alice";
        $("verify-key").value = key || "alice";
        setMode("issue-mode", "claims");
        setMode("verify-mode", "rules");
    }

    var SCENARIOS = [
        {label: "issue and verify", hint: "A local key, the usual claims, a verifier that names the issuer and audience it expects. Everything matches.", go: function () {
            scenarioStart();
            setClaims(BASE);
            issue();
            setRules(RULES);
            verify();
        }},
        {label: "wrong audience", hint: "The same token checked by a service expecting another audience. The token authenticates, then the audience rule fails: audience_mismatch is a verdict given only after authentication.", go: function () {
            scenarioStart();
            setClaims(BASE);
            issue();
            setRules({iss: RULES.iss, aud: "other"});
            verify();
        }},
        {label: "rules that name nothing", hint: "No expected issuer, no expected audience, and neither marked as any. The verifier refuses before reading the token. Tick any issuer and any audience to allow it explicitly.", go: function () {
            scenarioStart();
            setClaims(BASE);
            issue();
            setRules({});
            verify();
        }},
        {label: "expired, then clock skew", hint: "A token that expired a minute ago fails with expired. The same token under a clock skew of 120 seconds passes: change the skew field and verify again.", go: function () {
            scenarioStart();
            setClaims({iss: BASE.iss, sub: BASE.sub, aud: BASE.aud, exp: "-60"});
            issue();
            setRules(RULES);
            verify();
            setRules({iss: RULES.iss, aud: RULES.aud, skew: "120"});
            verify();
        }},
        {label: "replay", hint: "With the replay check on, each jti is accepted once. The second verification of the same token is replayed. Press verify once more to see it again.", go: function () {
            scenarioStart();
            setClaims(BASE);
            $("c-jti").value = randomId();
            issue();
            setRules({iss: RULES.iss, aud: RULES.aud, replay: true});
            verify();
            verify();
        }},
        {label: "one flipped character", hint: "The token in step 3 had one character of its body flipped. Any change makes it invalid, with no detail about what changed.", go: function () {
            scenarioStart();
            setClaims(BASE);
            issue();
            tamper();
            setRules(RULES);
            verify();
        }},
        {label: "custom claims of any type", hint: "String claims are typed; a JSON claim carries any JSON value. The verifier returns them as given. A custom claim may not reuse a registered name.", go: function () {
            scenarioStart();
            setClaims({iss: BASE.iss, sub: BASE.sub, aud: BASE.aud, exp: "+3600", custom: [["role", "admin", "string"], ["scopes", "[\"read\",\"write\"]", "json"], ["level", "3", "json"], ["active", "true", "json"]]});
            issue();
            setRules(RULES);
            verify();
        }},
        {label: "implicit assertion", hint: "The implicit assertion is authenticated but not sent in the token. Issued with request-7 and checked with request-8, the token is invalid; the verifier must know the same context.", go: function () {
            scenarioStart();
            setClaims({iss: BASE.iss, sub: BASE.sub, aud: BASE.aud, exp: "+3600", implicit: "request-7"});
            issue();
            setRules({iss: RULES.iss, aud: RULES.aud, implicit: "request-8"});
            verify();
        }},
        {label: "raw message with a footer", hint: "A raw token carries any bytes. The footer is in the clear and authenticated; here the verifier opens the token with the same footer and implicit assertion. Change either and open again.", go: function () {
            scenarioStart();
            setMode("issue-mode", "raw");
            setMode("verify-mode", "raw");
            $("r-msg").value = "hello, world";
            $("r-footer").value = "{\"kid\":\"example\"}";
            $("r-implicit").value = "request-7";
            issue();
            $("vr-footer").value = "{\"kid\":\"example\"}";
            $("vr-implicit").value = "request-7";
            verify();
        }},
        {label: "a look-alike subject", hint: "The subject is admin followed by a zero-width space, invisible on screen. The issuer refuses it with argument and names the code point. Step 5 shows what is inside any text.", go: function () {
            scenarioStart();
            setClaims({iss: BASE.iss, sub: "admin" + ch(0x200b), aud: BASE.aud, exp: "+3600"});
            issue();
            inspectText("admin" + ch(0x200b));
            $("text-in").value = "admin" + ch(0x200b);
        }},
        {label: "international text in claims", hint: "A subject with a composed n-tilde, a claim named in Japanese, a city with an umlaut and an emoji value: every script is accepted and travels as UTF-8 in the payload; the transcript writes the code points as escapes, so the commands stay ASCII. Identifiers are compared byte for byte with no normalisation: checked against the decomposed spelling of the subject, which looks the same, the token is subject_mismatch; checked against the spelling it was issued with, ok.", go: function () {
            scenarioStart();
            setClaims({iss: BASE.iss, sub: COMPOSED, aud: BASE.aud, exp: "+3600", custom: [[ch(0x540d, 0x524d), ch(0x5c71, 0x7530, 0x592a, 0x90ce), "string"], ["city", "Z" + ch(0xfc) + "rich", "string"], ["mood", ch(0x1f600), "string"]]});
            issue();
            setRules({iss: RULES.iss, aud: RULES.aud, sub: DECOMPOSED});
            verify();
            setRules({iss: RULES.iss, aud: RULES.aud, sub: COMPOSED});
            verify();
            $("text-in").value = DECOMPOSED;
            inspectText(DECOMPOSED);
        }},
        {label: "key id in the footer", hint: "The key carries an id, bound into the footer as {\"kid\":...}. A verifier reads it without verifying anything, picks the key, then verifies. Clear the id in step 1 and the token has no footer.", go: function () {
            scenarioStart();
            exec("kid alice " + quote("prod-2026"));
            setClaims(BASE);
            issue();
            exec("peek $");
            setRules(RULES);
            verify();
        }},
        {label: "key rotation by kid", hint: "Two keys with their own ids. A token issued under the newer key names it in the footer; the lookup picks that key and the verification passes. Issue under the older key in step 2 and look up again.", go: function () {
            scenarioStart();
            ensureLocal("alice-2026");
            exec("kid alice " + quote("prod-2025"));
            exec("kid alice-2026 " + quote("prod-2026"));
            $("issue-key").value = "alice-2026";
            setClaims(BASE);
            issue();
            setRules(RULES);
            lookup();
            lookupVerify();
            $("lookup-verdict").scrollIntoView({behavior: "smooth", block: "nearest"});
        }},
        {label: "a forged kid", hint: "The token was issued under alice, then its footer was rewritten to name vault. The lookup follows the kid, as it must, and picks vault; the verification under vault is invalid, since the footer is authenticated and the body was never sealed under vault.", go: function () {
            scenarioStart();
            ensureLocal("vault");
            setClaims(BASE);
            issue();
            setRules(RULES);
            $("forge-key").value = "vault";
            forge();
            lookupVerify();
            $("lookup-verdict").scrollIntoView({behavior: "smooth", block: "nearest"});
        }},
        {label: "wrap a key", hint: "The key alice is wrapped under the key vault and unwrapped again as alice-again. The two have the same kcb2.lid in step 1: it is the same key. Flip one character of the wrapped string and unwrap again to see invalid.", go: function () {
            ensureLocal("alice");
            ensureLocal("vault");
            $("wrap-key").value = "vault";
            $("wrap-target").value = "alice";
            wrapKey();
            $("unwrap-key").value = "vault";
            $("unwrap-name").value = "alice-again";
            unwrapKey();
            $("wrap-result").scrollIntoView({behavior: "smooth", block: "nearest"});
        }},
        {label: "export and import a key", hint: "The key alice leaves as a kcb2.local string and comes back as alice-copy: the same kcb2.lid in step 1. A token issued under alice verifies under alice-copy.", go: function () {
            scenarioStart();
            $("export-key").value = "alice";
            refreshExportAs();
            exportKey();
            $("import-text").value = $("export-text").value;
            $("import-name").value = "alice-copy";
            importKeys();
            setClaims(BASE);
            issue();
            $("verify-key").value = "alice-copy";
            setRules(RULES);
            verify();
        }},
        {label: "save every key as a script", hint: "The key alice gets the id prod-2026, then the whole session is exported: one import line per key, and a kid line for alice, since a kcb2 string does not carry the id. Importing the script puts every key back with its id.", go: function () {
            ensureLocal("alice");
            exec("kid alice prod-2026");
            exportAll();
            $("import-text").value = $("export-text").value;
            importKeys();
            $("export-result").scrollIntoView({behavior: "smooth", block: "nearest"});
        }},
        {label: "share only the public key", pq: true, hint: "The signing pair issuer is exported as its public half and imported as verifier, a key that verifies and cannot sign: step 2 does not list it. A token signed by issuer verifies under verifier.", go: function () {
            ensureSigner("issuer");
            $("export-key").value = "issuer";
            refreshExportAs();
            $("export-as").value = "public";
            exportKey();
            $("import-text").value = $("export-text").value;
            $("import-name").value = "verifier";
            importKeys();
            $("issue-key").value = "issuer";
            setMode("issue-mode", "claims");
            setMode("verify-mode", "rules");
            setClaims(BASE);
            issue();
            $("verify-key").value = "verifier";
            setRules(RULES);
            verify();
        }},
        {label: "signed token (Ed25519 + ML-DSA-65)", pq: true, hint: "A signing pair signs; its public half verifies. Both signatures must verify: a classical one and a post-quantum one. Step 3 can read the claims of a public token before verifying, since they travel in clear; it says so, and nothing there is trusted.", go: function () {
            ensureSigner("issuer");
            $("issue-key").value = "issuer";
            $("verify-key").value = "issuer";
            setMode("issue-mode", "claims");
            setMode("verify-mode", "rules");
            setClaims(BASE);
            issue();
            setRules(RULES);
            verify();
        }}
    ];

    function randomId() {
        var bytes = new Uint8Array(8);
        crypto.getRandomValues(bytes);
        var s = "";
        for (var i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
        return s;
    }

    function tamper() {
        var t = tokenBox.value.trim();
        if (t === "") return;
        exec("tamper " + tokenArg(t));
    }

    function enable() {
        cmd.disabled = false;
        $("run").disabled = false;
        var buttons = document.querySelectorAll("button[data-pq]");
        for (var i = 0; i < buttons.length; i++) {
            buttons[i].disabled = !hasPq;
            if (!hasPq) buttons[i].title = "this build has no liboqs; cb2.public is unavailable";
        }
        status.textContent = hasPq
            ? "ready: cb2.local and cb2.public (Ed25519 + ML-DSA-65)"
            : "ready: cb2.local only; this build has no liboqs";
        status.className = "status ready";
        refreshKeys();
    }

    function wire() {
        var scen = $("scenarios");
        SCENARIOS.forEach(function (s) {
            var b = el("button", "", s.label);
            b.type = "button";
            if (s.pq) b.dataset.pq = "1";
            b.addEventListener("click", function () {
                $("scenario-hint").textContent = s.hint;
                s.go();
                if (!$("verify-result").hidden) $("verify-result").scrollIntoView({behavior: "smooth", block: "nearest"});
            });
            scen.appendChild(b);
        });

        var presets = $("text-presets");
        TEXT_PRESETS.forEach(function (p) {
            var b = el("button", "", p.label);
            b.type = "button";
            b.addEventListener("click", function () {
                $("text-in").value = p.value;
                inspectText(p.value);
            });
            presets.appendChild(b);
        });

        $("key-local").addEventListener("click", function () { exec("keygen local " + arg(keyName())); $("key-name").value = ""; });
        $("key-public").addEventListener("click", function () { exec("keygen public " + arg(keyName())); $("key-name").value = ""; });
        $("import-run").addEventListener("click", importKeys);
        $("export-key").addEventListener("change", refreshExportAs);
        $("export-run").addEventListener("click", exportKey);
        $("export-all").addEventListener("click", exportAll);
        $("export-copy").addEventListener("click", function () {
            try {
                navigator.clipboard.writeText($("export-text").value);
            } catch (e) {
                $("export-text").select();
            }
        });
        $("export-to-import").addEventListener("click", function () {
            $("import-text").value = $("export-text").value;
            $("import-name").value = "";
        });
        $("kid-set").addEventListener("click", function () {
            var k = $("kid-key").value;
            var id = $("kid-text").value;
            if (k === "" || id.trim() === "") return;
            exec("kid " + arg(k) + " " + quote(id));
        });
        $("kid-clear").addEventListener("click", function () {
            var k = $("kid-key").value;
            if (k !== "") exec("kid " + arg(k) + " none");
        });
        $("keys-table").addEventListener("click", function (e) {
            var t = e.target;
            if (t instanceof HTMLButtonElement && t.dataset.key) exec("show " + arg(t.dataset.key));
        });

        var radios = document.querySelectorAll("input[name=issue-mode], input[name=verify-mode]");
        for (var i = 0; i < radios.length; i++) radios[i].addEventListener("change", applyModes);

        $("custom-add").addEventListener("click", function () { customRow("", "", "string"); });
        $("c-jti-random").addEventListener("click", function () { $("c-jti").value = randomId(); });
        $("issue-run").addEventListener("click", issue);
        $("verify-run").addEventListener("click", verify);

        var timer = null;
        tokenBox.addEventListener("input", function () {
            clearTimeout(timer);
            timer = setTimeout(inspect, 150);
        });
        $("token-tamper").addEventListener("click", tamper);
        $("token-peek").addEventListener("click", function () {
            var t = tokenBox.value.trim();
            if (t !== "") exec("peek " + tokenArg(t));
        });
        $("token-copy").addEventListener("click", function () {
            try {
                navigator.clipboard.writeText(tokenBox.value);
            } catch (e) {
                tokenBox.select();
            }
        });
        $("token-clear").addEventListener("click", function () { setToken(""); });

        $("lookup-run").addEventListener("click", lookup);
        $("lookup-verify").addEventListener("click", lookupVerify);
        $("forge-run").addEventListener("click", forge);
        $("wrap-run").addEventListener("click", wrapKey);
        $("unwrap-run").addEventListener("click", unwrapKey);
        $("wrap-tamper").addEventListener("click", tamperWrap);
        $("text-run").addEventListener("click", function () { inspectText($("text-in").value); });
        $("text-in").addEventListener("keydown", function (e) {
            if (e.key === "Enter") {
                e.preventDefault();
                inspectText($("text-in").value);
            }
        });
        $("text-use").addEventListener("click", function () {
            $("c-sub").value = $("text-in").value;
            setMode("issue-mode", "claims");
            $("card-issue").scrollIntoView({behavior: "smooth", block: "start"});
        });

        $("form").addEventListener("submit", function (e) {
            e.preventDefault();
            var text = cmd.value;
            if (text.trim() === "") return;
            remember(text);
            exec(text);
            cmd.value = "";
        });
        cmd.addEventListener("keydown", function (e) {
            if (e.key === "ArrowUp" && cursor > 0) {
                cursor -= 1;
                cmd.value = history[cursor];
                e.preventDefault();
            }
            if (e.key === "ArrowDown") {
                if (cursor < history.length - 1) {
                    cursor += 1;
                    cmd.value = history[cursor];
                } else {
                    cursor = history.length;
                    cmd.value = "";
                }
                e.preventDefault();
            }
        });

        $("demo").addEventListener("click", function () { runScript("demo.cb2"); });
        $("demo-public").addEventListener("click", function () { runScript("demo_public.cb2"); });
        $("demo-text").addEventListener("click", function () { runScript("demo_text.cb2"); });
        $("help").addEventListener("click", function () { exec("help"); });
        $("clear").addEventListener("click", function () { out.textContent = ""; });
        $("reset").addEventListener("click", function () {
            reset();
            out.textContent = "";
            lastToken = "";
            setToken("");
            $("issue-result").hidden = true;
            $("verify-result").hidden = true;
            $("text-result").textContent = "";
            $("lookup-result").textContent = "";
            $("lookup-verdict").hidden = true;
            foundKey = "";
            $("wrap-result").hidden = true;
            $("wrap-text").value = "";
            $("scenario-hint").textContent = "";
            append("session reset: keys and the last token are gone", "res");
            refreshKeys();
        });
        customRow("role", "admin", "string");
        applyModes();
    }

    function runScript(name) {
        fetch("demo/" + name).then(function (r) {
            if (!r.ok) throw new Error(r.status);
            return r.text();
        }).then(function (text) {
            var lines = text.split("\n");
            for (var i = 0; i < lines.length; i++) exec(lines[i]);
            refreshKeys();
        }).catch(function (e) {
            append("error: could not load " + name + " (" + e + ")", "err");
        });
    }

    if (typeof createCb2 !== "function") {
        status.textContent = "dist/cb2.js is missing; run web/build.sh first";
        status.className = "status err";
        return;
    }
    createCb2().then(function (m) {
        run = m.cwrap("cb2_web_run", "string", ["string"]);
        reset = m.cwrap("cb2_web_reset", null, []);
        hasPq = m.ccall("cb2_web_has_pq", "number", [], []) === 1;
        wire();
        enable();
    }).catch(function (e) {
        status.textContent = "the library failed to load: " + e;
        status.className = "status err";
    });
})();
