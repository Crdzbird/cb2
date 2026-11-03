/**
 * paseto5_bench: cb2.local seal and open against cryptolib's v4.local and
 * cb1.local at 64 B, 1 KiB and 64 KiB payloads, with a 44-byte footer and
 * an empty implicit assertion. Each cell is the median of seven repeats
 * of at least 200 ms of back-to-back calls, in ns per operation; the
 * paseto5 rows measure the caller-buffer functions (no allocation) and
 * the allocating convenience functions separately.
 */

#include "bench_ref.hpp"

#include <paseto5/paseto5.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

double measure(const std::function<void()>& op) {
    std::vector<double> samples;
    for (int rep = 0; rep < 7; ++rep) {
        std::size_t iters = 1;
        double ns = 0;
        for (;;) {
            const auto t0 = Clock::now();
            for (std::size_t i = 0; i < iters; ++i) op();
            const auto t1 = Clock::now();
            ns = static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());
            if (ns >= 200e6) break;
            iters *= 2;
        }
        samples.push_back(ns / static_cast<double>(iters));
    }
    std::sort(samples.begin(), samples.end());
    return samples[3];
}

struct Row {
    std::string name;
    double seal_ns[3];
    double open_ns[3];
};

const std::size_t SIZES[3] = {64, 1024, 65536};

void bench_reference(const bench_ref::Impl& impl, const uint8_t* key, const std::vector<uint8_t>& footer, Row& row) {
    for (int s = 0; s < 3; ++s) {
        std::vector<uint8_t> msg(SIZES[s]);
        for (std::size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<uint8_t>(i * 7 + 1);
        std::vector<uint8_t> tok(impl.token_len(msg.size(), footer.size()));
        std::size_t n = 0;
        if (!impl.seal(tok.data(), tok.size(), n, key, msg.data(), msg.size(), footer.data(), footer.size(), nullptr, 0)) {
            std::fprintf(stderr, "%s seal failed\n", impl.name);
            std::exit(1);
        }
        std::vector<uint8_t> out(impl.open_capacity(tok.size()));
        std::size_t m = 0;
        if (!impl.open(out.data(), out.size(), m, tok.data(), tok.size(), key, footer.data(), footer.size(), nullptr, 0) || m != msg.size()) {
            std::fprintf(stderr, "%s open failed\n", impl.name);
            std::exit(1);
        }
        row.seal_ns[s] = measure([&] {
            std::size_t k = 0;
            (void)impl.seal(tok.data(), tok.size(), k, key, msg.data(), msg.size(), footer.data(), footer.size(), nullptr, 0);
        });
        row.open_ns[s] = measure([&] {
            std::size_t k = 0;
            (void)impl.open(out.data(), out.size(), k, tok.data(), tok.size(), key, footer.data(), footer.size(), nullptr, 0);
        });
    }
}

void bench_paseto5(const paseto5::LocalKey& key, const std::vector<uint8_t>& footer, Row& buffers, Row& alloc) {
    for (int s = 0; s < 3; ++s) {
        std::vector<uint8_t> msg(SIZES[s]);
        for (std::size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<uint8_t>(i * 7 + 1);
        std::vector<uint8_t> tok(paseto5::Local::token_len(msg.size(), footer.size()));
        std::size_t n = 0;
        if (paseto5::Local::seal_into(tok, n, key, msg, footer) != paseto5::Status::ok) {
            std::fprintf(stderr, "paseto5 seal failed\n");
            std::exit(1);
        }
        const std::string_view token(reinterpret_cast<const char*>(tok.data()), tok.size());
        std::vector<uint8_t> out(paseto5::Local::open_capacity(tok.size()));
        std::size_t m = 0;
        if (paseto5::Local::open_into(out, m, token, key, footer) != paseto5::Status::ok || m != msg.size()) {
            std::fprintf(stderr, "paseto5 open failed\n");
            std::exit(1);
        }
        buffers.seal_ns[s] = measure([&] {
            std::size_t k = 0;
            (void)paseto5::Local::seal_into(tok, k, key, msg, footer);
        });
        buffers.open_ns[s] = measure([&] {
            std::size_t k = 0;
            (void)paseto5::Local::open_into(out, k, token, key, footer);
        });
        const std::string fixed(token);
        alloc.seal_ns[s] = measure([&] {
            auto r = paseto5::Local::seal(key, msg, footer);
            if (r.is_err()) std::abort();
        });
        alloc.open_ns[s] = measure([&] {
            auto r = paseto5::Local::open(fixed, key, footer);
            if (r.is_err()) std::abort();
        });
    }
}

void print(const std::vector<Row>& rows) {
    std::printf("\n| implementation | seal 64 B | seal 1 KiB | seal 64 KiB | open 64 B | open 1 KiB | open 64 KiB |\n");
    std::printf("|---|---:|---:|---:|---:|---:|---:|\n");
    for (const Row& r : rows) {
        std::printf("| %s | %.0f ns | %.0f ns | %.1f us | %.0f ns | %.0f ns | %.1f us |\n", r.name.c_str(),
                    r.seal_ns[0], r.seal_ns[1], r.seal_ns[2] / 1000.0, r.open_ns[0], r.open_ns[1], r.open_ns[2] / 1000.0);
    }
    std::printf("\n64 KiB throughput (seal / open):\n");
    for (const Row& r : rows) {
        const double mb = 65536.0 / 1048576.0;
        std::printf("  %-32s %.0f MB/s / %.0f MB/s\n", r.name.c_str(), mb / (r.seal_ns[2] / 1e9), mb / (r.open_ns[2] / 1e9));
    }
}

}

int main() {
    if (sodium_init() < 0) return 2;
    uint8_t raw[32];
    for (int i = 0; i < 32; ++i) raw[i] = static_cast<uint8_t>(0x70 + i);
    const paseto5::LocalKey key = paseto5::LocalKey::from_bytes(raw).value();
    const std::string footer_text = "{\"kid\":\"kcb2.lid.0123456789abcdefghijklmnopqrs\"}";
    const std::vector<uint8_t> footer(footer_text.begin(), footer_text.end());
    std::vector<Row> rows;
    Row buffers{"paseto5 cb2.local (caller buffers)", {}, {}};
    Row alloc{"paseto5 cb2.local (allocating)", {}, {}};
    bench_paseto5(key, footer, buffers, alloc);
    rows.push_back(buffers);
    rows.push_back(alloc);
    for (const bench_ref::Impl& impl : {bench_ref::v4_local(), bench_ref::cb1_local()}) {
        Row r{impl.name, {}, {}};
        bench_reference(impl, raw, footer, r);
        rows.push_back(r);
    }
    print(rows);
    return 0;
}
