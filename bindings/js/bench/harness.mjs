/**
 * The timing harness shared by the Node and browser runners. Each
 * operation runs for a warmup period, then in batches large enough that
 * one batch takes at least the target time, so a coarse timer still
 * measures it; the result is the median time of one operation over the
 * batches. The cases are run in several interleaved rounds and each
 * operation reports the median of its round medians, so a change in the
 * machine's load during the run does not land on one case alone. An
 * operation that returns a promise is awaited each time, one that does not
 * is called in a plain loop.
 */

/** Full runs and the quick smoke run used in CI. */
export const PROFILES = {
    full: { warmupMs: 300, batchMs: 10, samples: 21, rounds: 5 },
    quick: { warmupMs: 20, batchMs: 2, samples: 5, rounds: 1 },
};

async function runBatch(fn, isAsync, n) {
    const start = performance.now();
    if (isAsync) {
        for (let i = 0; i < n; i++) await fn();
    }
    if (!isAsync) {
        for (let i = 0; i < n; i++) fn();
    }
    return performance.now() - start;
}

/**
 * Times fn and resolves to the median microseconds per call.
 * @param {() => unknown} fn
 * @param {{ warmupMs: number, batchMs: number, samples: number }} profile
 * @returns {Promise<number>}
 */
export async function measure(fn, profile) {
    const first = fn();
    const isAsync = first instanceof Promise;
    await first;
    const warmupEnd = performance.now() + profile.warmupMs;
    while (performance.now() < warmupEnd) await runBatch(fn, isAsync, 16);
    let n = 1;
    while ((await runBatch(fn, isAsync, n)) < profile.batchMs) n *= 2;
    const perCall = [];
    for (let s = 0; s < profile.samples; s++) perCall.push(((await runBatch(fn, isAsync, n)) * 1000) / n);
    return median(perCall);
}

function median(values) {
    const sorted = [...values].sort((a, b) => a - b);
    return sorted[Math.floor(sorted.length / 2)];
}

/**
 * Times the issue and verify operation of every case, in profile.rounds
 * interleaved rounds.
 * @param {Array<{ group: string, name: string, issue: () => unknown, verify: () => unknown, size: number }>} cases
 * @param {{ warmupMs: number, batchMs: number, samples: number, rounds: number }} profile
 * @param {(line: string) => void} [progress]
 */
export async function runAll(cases, profile, progress = () => {}) {
    const issue = cases.map(() => []);
    const verify = cases.map(() => []);
    for (let round = 1; round <= profile.rounds; round++) {
        for (const [i, c] of cases.entries()) {
            issue[i].push(await measure(c.issue, profile));
            verify[i].push(await measure(c.verify, profile));
            progress(`round ${round}, ${c.name}: issue ${issue[i].at(-1).toFixed(1)} us, verify ${verify[i].at(-1).toFixed(1)} us`);
        }
    }
    return cases.map((c, i) => ({ group: c.group, name: c.name, issue: median(issue[i]), verify: median(verify[i]), size: c.size }));
}

function us(value) {
    return value < 100 ? value.toFixed(1) : value.toFixed(0);
}

/** The results as a Markdown table, one row per case, grouped by key kind. */
export function table(rows) {
    const lines = [
        "| key | token | issue (us) | verify (us) | token bytes |",
        "|---|---|--:|--:|--:|",
    ];
    for (const r of rows) lines.push(`| ${r.group} | ${r.name} | ${us(r.issue)} | ${us(r.verify)} | ${r.size} |`);
    return lines.join("\n");
}
