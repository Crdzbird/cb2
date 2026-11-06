(function () {
    "use strict";

    function $(id) { return document.getElementById(id); }

    var ATTACK_EVERY = 100;
    var TARGET_MS = 40;
    var WARMUP = 3;
    var WARMUP_MS = 1000;
    var DEFAULT_COUNT = {bearer: 1000000, bound: 10000, signed: 10000};
    var SVG = "http://www.w3.org/2000/svg";
    var W = 600;
    var H = 200;

    var mod = null;
    var setupFn = null;
    var batchFn = null;
    var state = null;

    function el(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text !== undefined) e.textContent = text;
        return e;
    }

    function count(n) { return Math.round(n).toLocaleString("en-US"); }

    function us(v) {
        if (v >= 1000) return (v / 1000).toFixed(2) + " ms";
        if (v >= 100) return v.toFixed(0) + " us";
        if (v >= 10) return v.toFixed(1) + " us";
        return v.toFixed(2) + " us";
    }

    function mb(bytes) { return (bytes / 1048576).toFixed(1) + " MB"; }

    function seconds(ms) {
        if (ms >= 60000) return Math.floor(ms / 60000) + " min " + Math.round((ms % 60000) / 1000) + " s";
        if (ms < 1000) return Math.round(ms) + " ms";
        return (ms / 1000).toFixed(1) + " s";
    }

    function niceCeil(v) {
        if (!(v > 0)) return 1;
        var p = Math.pow(10, Math.floor(Math.log(v) / Math.LN10));
        var steps = [1, 2, 2.5, 5, 10];
        for (var i = 0; i < steps.length; i++) if (steps[i] * p >= v) return steps[i] * p;
        return 10 * p;
    }

    function percentile(sorted, q) {
        if (sorted.length === 0) return 0;
        var at = Math.min(sorted.length - 1, Math.floor(q * (sorted.length - 1) + 0.5));
        return sorted[at];
    }

    function mean(list, key) {
        var s = 0;
        for (var i = 0; i < list.length; i++) s += list[i][key];
        return list.length ? s / list.length : 0;
    }

    function steady() {
        var out = [];
        for (var i = 0; i < state.samples.length; i++) if (!state.samples[i].warm) out.push(state.samples[i]);
        return out;
    }

    function sortedOf(list, key) {
        var v = [];
        for (var i = 0; i < list.length; i++) v.push(list[i][key]);
        return v.sort(function (a, b) { return a - b; });
    }

    function ready() {
        if (mod) return Promise.resolve();
        return createCb2().then(function (m) {
            mod = m;
            setupFn = m.cwrap("cb2_web_load_setup", "string", ["string"]);
            batchFn = m.cwrap("cb2_web_load_batch", "string", ["number", "number"]);
        });
    }

    function svgEl(tag, attrs) {
        var e = document.createElementNS(SVG, tag);
        for (var k in attrs) if (Object.prototype.hasOwnProperty.call(attrs, k)) e.setAttribute(k, attrs[k]);
        return e;
    }

    function points(key, max) {
        var s = steady();
        var p = [];
        for (var i = 0; i < s.length; i++) {
            p.push((s[i].at / state.total * W).toFixed(1) + "," + (H - Math.min(s[i][key], max) / max * H).toFixed(1));
        }
        return p.join(" ");
    }

    function draw() {
        var svg = $("load-chart");
        while (svg.firstChild) svg.removeChild(svg.firstChild);
        var st = steady();
        var top = percentile(sortedOf(st, "server"), 0.99);
        if (state.bound) top = Math.max(top, percentile(sortedOf(st, "client"), 0.99));
        var max = niceCeil(top * 1.4);
        var above = 0;
        var worst = 0;
        for (var i = 0; i < st.length; i++) {
            var v = Math.max(st[i].server, state.bound ? st[i].client : 0);
            if (v > max) above += 1;
            worst = Math.max(worst, v);
        }
        $("load-clipped").textContent = above === 0 ? "" : count(above) + (above === 1 ? " batch" : " batches") +
            " above the top of the chart, drawn at its edge; the worst, client or server, at " + us(worst) +
            " per request. A spike like this is the browser or the device pausing the page, not the library.";
        for (var g = 1; g < 4; g++) {
            svg.appendChild(svgEl("line", {x1: 0, x2: W, y1: H * g / 4, y2: H * g / 4, "class": "grid", "vector-effect": "non-scaling-stroke"}));
        }
        if (st.length > 0) {
            var y = H - percentile(sortedOf(st, "server"), 0.5) / max * H;
            svg.appendChild(svgEl("line", {x1: 0, x2: W, y1: y, y2: y, "class": "median", "vector-effect": "non-scaling-stroke"}));
        }
        if (state.bound) svg.appendChild(svgEl("polyline", {points: points("client", max), "class": "client", "vector-effect": "non-scaling-stroke"}));
        svg.appendChild(svgEl("polyline", {points: points("server", max), "class": "server", "vector-effect": "non-scaling-stroke"}));
        $("load-ymax").textContent = us(max);
        $("load-ymid").textContent = us(max / 2);
        $("load-xmax").textContent = count(state.total) + " requests";
        $("legend-client").hidden = !state.bound;
        state.drawn = performance.now();
    }

    function live(b) {
        var dl = $("load-live");
        dl.textContent = "";
        var wall = performance.now() - state.started;
        var rows = [
            ["requests", count(b.done) + " of " + count(state.total)],
            ["elapsed", seconds(wall) + (state.running && b.done < state.total ? ", about " + seconds(wall / b.done * (state.total - b.done)) + " left" : "")],
            ["throughput", count(b.done / (wall / 1000)) + " requests per second, one thread"],
            ["server, this batch", us(b.server_ms * 1000 / b.n) + " per request"]
        ];
        if (state.bound) rows.push(["client, this batch", us(b.client_ms * 1000 / b.n) + " per request, making the proof"]);
        rows.push(["answers", count(b.ok) + " accepted, " + count(b.refused) + " of " + count(b.attacks) + " attacks refused, " + count(b.wrong) + " wrong"]);
        if (state.bound) rows.push(["proof replay store", count(b.replay) + " ids, each kept for its 60 seconds"]);
        rows.push(["wasm memory", mb(b.memory)]);
        for (var i = 0; i < rows.length; i++) {
            dl.appendChild(el("dt", "", rows[i][0]));
            var dd = el("dd", "", rows[i][1]);
            if (rows[i][0] === "answers") dd.className = b.wrong === 0 ? "good" : "refused";
            dl.appendChild(dd);
        }
        $("load-bar").style.width = (b.done / state.total * 100).toFixed(1) + "%";
    }

    function kv(box, k, v) {
        var row = el("div", "kv");
        row.appendChild(el("span", "k", k));
        row.appendChild(el("span", "v", v));
        box.appendChild(row);
    }

    function timing(box, st, server, first, lastFifth) {
        kv(box, "server per request", "median " + us(percentile(server, 0.5)) + ", p95 " + us(percentile(server, 0.95)) +
            ", p99 " + us(percentile(server, 0.99)) + ", worst batch " + us(server.length ? server[server.length - 1] : 0));
        if (state.bound) kv(box, "client per request", "median " + us(percentile(sortedOf(st, "client"), 0.5)) + " to make the proof");
        kv(box, "first and last fifth", us(first) + " and " + us(lastFifth) + " per request on the server");
        kv(box, "checks per second", count(1e6 / Math.max(percentile(server, 0.5), 0.001)) + " on this thread at the median");
    }

    function summary(stopped) {
        var box = $("load-result");
        box.textContent = "";
        box.hidden = false;
        var b = state.last;
        var st = steady();
        var server = sortedOf(st, "server");
        var fifth = Math.max(1, Math.floor(st.length / 5));
        var first = mean(st.slice(0, fifth), "server");
        var lastFifth = mean(st.slice(st.length - fifth), "server");
        var drift = first > 0 ? (lastFifth / first - 1) * 100 : 0;
        var head = el("div", "verdict");
        var right = b.wrong === 0;
        head.appendChild(el("span", "badge " + (right ? "good" : "bad"), right ? "every answer right" : count(b.wrong) + " wrong"));
        var line = count(b.done) + " requests in " + seconds(performance.now() - state.started) + (stopped ? ", stopped early" : "") + ". ";
        line += st.length >= 5
            ? "The server time per request moved " + (drift >= 0 ? "+" : "") + drift.toFixed(1) + " percent from the first fifth of the run to the last."
            : "Too few batches for a drift figure; run more requests.";
        if (!right) line += " The first wrong verdict was " + b.first_wrong + ".";
        head.appendChild(el("span", "explain", line));
        box.appendChild(head);
        if (st.length > 0) timing(box, st, server, first, lastFifth);
        kv(box, "answers", count(b.ok) + " accepted, " + count(b.refused) + " of " + count(b.attacks) + " attacks refused");
        kv(box, "on the wire", count(state.info.token_bytes + state.info.proof_bytes) + " bytes per request" +
            (state.bound ? " (token " + count(state.info.token_bytes) + ", proof " + count(state.info.proof_bytes) + ")" : ""));
        kv(box, "wasm memory", mb(state.info.memory) + " after setup, " + mb(b.memory) + " at the end" + (state.bound ? "; " + count(b.replay) + " proof ids still held" : ""));
        kv(box, "setup", count(state.info.users) + " users and their tokens" + (state.bound ? " and client key pairs" : "") + " in " + seconds(state.info.setup_ms));
        box.appendChild(el("p", "hint small", "Batches: " + count(st.length) + " timed, after " + count(state.samples.length - st.length) +
            " warm-up batches in the first second, which size the batch and let the wasm engine compile its fast tier; those are left out of the chart and the figures."));
    }

    function finish(stopped) {
        state.running = false;
        live(state.last);
        draw();
        summary(stopped);
        $("load-run").disabled = false;
        $("load-stop").disabled = true;
        $("load-kind").disabled = false;
        $("load-count").disabled = false;
    }

    function fail(text) {
        var box = $("load-result");
        box.textContent = "";
        box.hidden = false;
        var head = el("div", "verdict");
        head.appendChild(el("span", "badge bad", "error"));
        head.appendChild(el("span", "explain", text));
        box.appendChild(head);
        if (state) state.running = false;
        $("load-run").disabled = false;
        $("load-stop").disabled = true;
        $("load-kind").disabled = false;
        $("load-count").disabled = false;
    }

    function step() {
        if (state.stop) return finish(true);
        var n = Math.min(state.size, state.total - state.done);
        var b = JSON.parse(batchFn(n, ATTACK_EVERY));
        if (b.error) return fail(b.error);
        var sizing = state.samples.length < WARMUP;
        var warm = sizing || performance.now() - state.started < WARMUP_MS;
        state.samples.push({at: b.done, server: b.server_ms * 1000 / n, client: b.client_ms * 1000 / n, warm: warm});
        if (sizing) state.size = Math.max(1, Math.min(100000, Math.round(n * TARGET_MS / Math.max(b.server_ms + b.client_ms, 0.5))));
        state.done = b.done;
        state.last = b;
        live(b);
        if (performance.now() - state.drawn > 250) draw();
        if (state.done >= state.total) return finish(false);
        setTimeout(step, 0);
    }

    function start() {
        var kind = $("load-kind").value;
        var total = parseInt($("load-count").value, 10);
        $("load-run").disabled = true;
        $("load-kind").disabled = true;
        $("load-count").disabled = true;
        $("load-result").hidden = true;
        $("load-live").textContent = "";
        $("load-bar").style.width = "0";
        $("load-clipped").textContent = "";
        $("load-state").textContent = "setting up 256 users";
        ready().then(function () {
            setTimeout(function () {
                var info = JSON.parse(setupFn(kind));
                $("load-state").textContent = "";
                if (info.error) return fail(info.error);
                state = {kind: kind, bound: kind === "bound", total: total, done: 0, size: 4, samples: [], info: info,
                         started: performance.now(), drawn: 0, running: true, stop: false, last: null};
                $("load-stop").disabled = false;
                step();
            }, 30);
        }).catch(function (e) {
            $("load-state").textContent = "";
            fail("the library failed to load: " + e);
        });
    }

    function wire() {
        if (!$("card-load")) return;
        if (typeof createCb2 !== "function") {
            $("load-run").disabled = true;
            return;
        }
        $("load-kind").addEventListener("change", function () {
            $("load-count").value = String(DEFAULT_COUNT[$("load-kind").value]);
        });
        $("load-run").addEventListener("click", start);
        $("load-stop").addEventListener("click", function () {
            if (state && state.running) state.stop = true;
        });
        $("load-count").value = String(DEFAULT_COUNT[$("load-kind").value]);
    }

    wire();
})();
