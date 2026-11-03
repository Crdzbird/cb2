(function () {
    "use strict";

    var out = document.getElementById("out");
    var form = document.getElementById("form");
    var cmd = document.getElementById("cmd");
    var runButton = document.getElementById("run");
    var status = document.getElementById("status");
    var history = [];
    var cursor = 0;
    var run = null;
    var reset = null;
    var hasPq = false;

    function append(text, cls) {
        var span = document.createElement("span");
        span.className = cls;
        span.textContent = text + "\n";
        out.appendChild(span);
        out.scrollTop = out.scrollHeight;
    }

    function exec(text) {
        var trimmed = text.trim();
        if (trimmed === "") return;
        append("> " + trimmed, "cmd");
        if (trimmed.charAt(0) === "#") return;
        var reply = run(trimmed);
        var lines = reply.split("\n");
        for (var i = 0; i < lines.length; i++) {
            var l = lines[i];
            if (l === "") continue;
            var cls = "res";
            if (l.indexOf("error:") === 0) cls = "err";
            if (l === "verdict = ok") cls = "ok";
            if (l.indexOf("verdict = ") === 0 && l !== "verdict = ok") cls = "bad";
            append(l, cls);
        }
    }

    function remember(text) {
        if (history[history.length - 1] !== text) history.push(text);
        cursor = history.length;
    }

    function runScript(name) {
        fetch("demo/" + name).then(function (r) {
            if (!r.ok) throw new Error(r.status);
            return r.text();
        }).then(function (text) {
            var lines = text.split("\n");
            for (var i = 0; i < lines.length; i++) exec(lines[i]);
        }).catch(function (e) {
            append("error: could not load " + name + " (" + e + ")", "err");
        });
    }

    function enable() {
        cmd.disabled = false;
        runButton.disabled = false;
        var buttons = document.querySelectorAll("button[data-pq]");
        for (var i = 0; i < buttons.length; i++) {
            buttons[i].disabled = !hasPq;
            if (!hasPq) buttons[i].title = "this build has no liboqs; cb2.public is unavailable";
        }
        status.textContent = hasPq
            ? "ready: cb2.local and cb2.public (Ed25519 + ML-DSA-65)"
            : "ready: cb2.local only; this build has no liboqs";
        status.className = "status ready";
        cmd.focus();
    }

    form.addEventListener("submit", function (e) {
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

    document.addEventListener("click", function (e) {
        var target = e.target;
        if (!(target instanceof HTMLButtonElement) || !target.dataset.cmd) return;
        remember(target.dataset.cmd);
        exec(target.dataset.cmd);
    });

    document.getElementById("demo").addEventListener("click", function () { runScript("demo.cb2"); });
    document.getElementById("demo-public").addEventListener("click", function () { runScript("demo_public.cb2"); });
    document.getElementById("help").addEventListener("click", function () { exec("help"); });
    document.getElementById("clear").addEventListener("click", function () { out.textContent = ""; });
    document.getElementById("reset").addEventListener("click", function () {
        reset();
        out.textContent = "";
        append("session reset: keys and the last token are gone", "res");
    });

    if (typeof createCb2 !== "function") {
        status.textContent = "dist/cb2.js is missing; run web/build.sh first";
        status.className = "status err";
        return;
    }
    createCb2().then(function (m) {
        run = m.cwrap("cb2_web_run", "string", ["string"]);
        reset = m.cwrap("cb2_web_reset", null, []);
        hasPq = m.ccall("cb2_web_has_pq", "number", [], []) === 1;
        enable();
    }).catch(function (e) {
        status.textContent = "the library failed to load: " + e;
        status.className = "status err";
    });
})();
