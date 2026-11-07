/**
 * cb2_size: the size and speed harness of the compact-tokens work
 * (docs/research/token-size/PLAN.md, Phase 0).
 *
 * The corpus is 1,000 claim sets drawn from a fixed seed: issuer
 * https://auth.example.com, one of four audiences, sub user-NNNNNN, iat
 * up to ten minutes before a fixed instant and exp fifteen minutes after
 * iat, a UUID jti, and the custom claims role and tenant. Every token
 * length depends only on the claims, so the size table is the same on
 * every run and every machine; keys and nonces are fresh each run.
 *
 * Rows: the claims JSON, cb2.local, a cb2.local bound to a local proof
 * key with its cb2.holder-local proof, and with cb2.public, cb2.public
 * itself, tokens of both purposes bound to a client key pair and the
 * cb2.holder-public proof, and the same tokens under the cb3 headers
 * (compact.hpp). Each row gives the minimum, mean and maximum
 * length in characters (bytes for the claims) and whether the longest
 * fits a 4,096-byte cookie and one 8 KB header field.
 *
 *   cb2_size                print the size table and the timings
 *   cb2_size --sizes        print the size table in the expected-file format
 *   cb2_size --check FILE   compare the size table with FILE exactly; exit 1
 *                           on any difference, a missing row or an extra row
 *
 * Timings are the median of five passes over the corpus, each pass giving
 * the mean time per operation; they are informational and never checked.
 */

#include <cb2/cb2.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr int64_t CORPUS_NOW = 1'800'000'000;
constexpr int CORPUS_SIZE = 1000;
constexpr uint64_t CORPUS_SEED = 7;
constexpr std::size_t COOKIE_LIMIT = 4096;
constexpr std::size_t HEADER_LIMIT = 8192;
const char* const ISSUER = "https://auth.example.com";
const char* const TARGET = "https://api.example.com/v1/me";

std::string hex(std::mt19937_64& r, int n) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < n; ++i) s += digits[r() % 16];
    return s;
}

std::string uuid(std::mt19937_64& r) {
    return hex(r, 8) + "-" + hex(r, 4) + "-" + hex(r, 4) + "-" + hex(r, 4) + "-" + hex(r, 12);
}

struct Item {
    cb2::Claims claims;
    std::string proof_id;
};

std::vector<Item> corpus() {
    static const char* audiences[] = {"api", "billing", "admin-console", "mobile"};
    static const char* roles[] = {"user", "admin", "viewer", "editor"};
    std::mt19937_64 r(CORPUS_SEED);
    std::vector<Item> items;
    for (int i = 0; i < CORPUS_SIZE; ++i) {
        Item it;
        cb2::Claims& c = it.claims;
        c.iss = ISSUER;
        c.aud = audiences[r() % 4];
        c.sub = "user-" + std::to_string(100000 + r() % 900000);
        c.iat = CORPUS_NOW - static_cast<int64_t>(r() % 600);
        c.exp = *c.iat + 900;
        c.jti = uuid(r);
        (void)c.set("role", roles[r() % 4]);
        (void)c.set("tenant", "acme-" + std::to_string(r() % 50));
        it.proof_id = uuid(r);
        items.push_back(std::move(it));
    }
    return items;
}

struct Row {
    std::size_t min = SIZE_MAX;
    std::size_t max = 0;
    std::size_t sum = 0;
    std::size_t count = 0;
    void add(std::size_t n) {
        min = std::min(min, n);
        max = std::max(max, n);
        sum += n;
        ++count;
    }
    [[nodiscard]] std::string mean() const {
        char buf[32];
        std::snprintf(buf, sizeof buf, "%.3f", static_cast<double>(sum) / static_cast<double>(count));
        return buf;
    }
};

cb2::ValidationRules rules_for(const cb2::Claims& c) {
    return cb2::ValidationRules().at(CORPUS_NOW).expect_issuer(ISSUER).expect_audience(*c.aud);
}

cb2::ValidationRules rules_with_proof(const cb2::Claims& c, const std::string& proof) {
    return rules_for(c)
        .with_holder_proof(proof, cb2::HolderRequest{"GET", TARGET, std::nullopt})
        .with_proof_replay_check([](std::string_view) { return true; });
}

template <class T>
T must(cb2::Result<T> r, const char* what) {
    if (r.is_err()) {
        std::fprintf(stderr, "cb2_size: %s failed: %s\n", what, cb2::error_name(r.error()));
        std::exit(2);
    }
    return std::move(r.value());
}

struct Run {
    std::vector<std::string> order;
    std::map<std::string, Row> rows;
    std::vector<std::pair<std::string, std::function<void()>>> timed;
    void add(const std::string& name, std::size_t n) {
        if (!rows.count(name)) order.push_back(name);
        rows[name].add(n);
    }
};

void check(bool ok, const char* what) {
    if (ok) return;
    std::fprintf(stderr, "cb2_size: %s was refused\n", what);
    std::exit(2);
}

Run measure() {
    Run run;
    static const std::vector<Item> items = corpus();
    static const cb2::LocalKey key = must(cb2::LocalKey::generate(), "local key");
    static const cb2::HolderRequest get{"GET", TARGET, std::nullopt};
    static std::vector<std::string> local_tokens;
    static std::vector<cb2::ValidationRules> rules;
    static std::vector<std::string> cb3_local_tokens;
    for (const Item& it : items) {
        run.add("claims.json", it.claims.to_json().size());
        local_tokens.push_back(must(cb2::Token::seal(key, it.claims), "seal"));
        run.add("cb2.local", local_tokens.back().size());
        rules.push_back(rules_for(it.claims));
        check(cb2::Token::open(local_tokens.back(), key, rules.back()).is_ok(), "cb2.local");
        cb2::Claims bound = it.claims;
        const cb2::LocalKey proof_key = must(cb2::HolderProof::bind_local(bound), "bind_local");
        const std::string token = must(cb2::Token::seal(key, bound), "seal bound");
        const std::string proof = must(cb2::HolderProof::make_local(proof_key, get, token, it.proof_id, CORPUS_NOW, 60), "make_local");
        check(cb2::Token::open(token, key, rules_with_proof(bound, proof)).is_ok(), "bound cb2.local");
        run.add("cb2.local.bound-local", token.size());
        run.add("cb2.holder-local", proof.size());
        cb3_local_tokens.push_back(must(cb2::CompactToken::seal(key, it.claims), "cb3 seal"));
        run.add("cb3.local", cb3_local_tokens.back().size());
        check(cb2::CompactToken::open(cb3_local_tokens.back(), key, rules.back()).is_ok(), "cb3.local");
        const std::string cb3_token = must(cb2::CompactToken::seal(key, bound), "cb3 seal bound");
        const std::string cb3_proof = must(cb2::HolderProof::make_local(proof_key, get, cb3_token, it.proof_id, CORPUS_NOW, 60), "make_local");
        check(cb2::CompactToken::open(cb3_token, key, rules_with_proof(bound, cb3_proof)).is_ok(), "bound cb3.local");
        run.add("cb3.local.bound-local", cb3_token.size());
    }
    run.timed.push_back({"cb2.local seal", [] {
        for (const Item& it : items) (void)cb2::Token::seal(key, it.claims);
    }});
    run.timed.push_back({"cb2.local open", [] {
        for (std::size_t i = 0; i < local_tokens.size(); ++i) (void)cb2::Token::open(local_tokens[i], key, rules[i]);
    }});
    run.timed.push_back({"cb3.local seal", [] {
        for (const Item& it : items) (void)cb2::CompactToken::seal(key, it.claims);
    }});
    run.timed.push_back({"cb3.local open", [] {
        for (std::size_t i = 0; i < cb3_local_tokens.size(); ++i) (void)cb2::CompactToken::open(cb3_local_tokens[i], key, rules[i]);
    }});
#ifdef CB2_HAS_PQ
    static const cb2::SecretKey issuer = must(cb2::SecretKey::generate(), "issuer key");
    static const cb2::PublicKey issuer_public = issuer.public_key();
    static const cb2::SecretKey client = must(cb2::SecretKey::generate(), "client key");
    static std::vector<std::string> public_tokens;
    static std::vector<std::string> bound_tokens;
    static std::vector<cb2::ValidationRules> bound_rules;
    static std::vector<std::string> cb3_public_tokens;
    static std::vector<std::string> cb3_bound_tokens;
    static std::vector<cb2::ValidationRules> cb3_bound_rules;
    for (std::size_t i = 0; i < items.size(); ++i) {
        const Item& it = items[i];
        public_tokens.push_back(must(cb2::Token::sign(issuer, it.claims), "sign"));
        run.add("cb2.public", public_tokens.back().size());
        check(cb2::Token::verify(public_tokens.back(), issuer_public, rules[i]).is_ok(), "cb2.public");
        cb2::Claims bound = it.claims;
        bound.cnf = client.public_key().to_paserk();
        const std::string local = must(cb2::Token::seal(key, bound), "seal bound");
        const std::string pub = must(cb2::Token::sign(issuer, bound), "sign bound");
        const std::string local_proof = must(cb2::HolderProof::make(client, get, local, it.proof_id, CORPUS_NOW, 60), "make");
        const std::string pub_proof = must(cb2::HolderProof::make(client, get, pub, it.proof_id, CORPUS_NOW, 60), "make");
        check(cb2::Token::open(local, key, rules_with_proof(bound, local_proof)).is_ok(), "bound cb2.local");
        check(cb2::Token::verify(pub, issuer_public, rules_with_proof(bound, pub_proof)).is_ok(), "bound cb2.public");
        run.add("cb2.local.bound-public", local.size());
        run.add("cb2.public.bound-public", pub.size());
        run.add("cb2.holder-public", pub_proof.size());
        bound_tokens.push_back(pub);
        bound_rules.push_back(rules_with_proof(bound, pub_proof));
        cb3_public_tokens.push_back(must(cb2::CompactToken::sign(issuer, it.claims), "cb3 sign"));
        run.add("cb3.public", cb3_public_tokens.back().size());
        check(cb2::CompactToken::verify(cb3_public_tokens.back(), issuer_public, rules[i]).is_ok(), "cb3.public");
        const std::string cb3_local = must(cb2::CompactToken::seal(key, bound), "cb3 seal bound");
        const std::string cb3_pub = must(cb2::CompactToken::sign(issuer, bound), "cb3 sign bound");
        const std::string cb3_local_proof = must(cb2::HolderProof::make(client, get, cb3_local, it.proof_id, CORPUS_NOW, 60), "make");
        const std::string cb3_pub_proof = must(cb2::HolderProof::make(client, get, cb3_pub, it.proof_id, CORPUS_NOW, 60), "make");
        check(cb2::CompactToken::open(cb3_local, key, rules_with_proof(bound, cb3_local_proof)).is_ok(), "bound cb3.local");
        check(cb2::CompactToken::verify(cb3_pub, issuer_public, rules_with_proof(bound, cb3_pub_proof)).is_ok(), "bound cb3.public");
        run.add("cb3.local.bound-public", cb3_local.size());
        run.add("cb3.public.bound-public", cb3_pub.size());
        cb3_bound_tokens.push_back(cb3_pub);
        cb3_bound_rules.push_back(rules_with_proof(bound, cb3_pub_proof));
    }
    run.timed.push_back({"cb2.public sign", [] {
        for (const Item& it : items) (void)cb2::Token::sign(issuer, it.claims);
    }});
    run.timed.push_back({"cb2.public verify", [] {
        for (std::size_t i = 0; i < public_tokens.size(); ++i) (void)cb2::Token::verify(public_tokens[i], issuer_public, rules[i]);
    }});
    run.timed.push_back({"bound cb2.public request check", [] {
        for (std::size_t i = 0; i < bound_tokens.size(); ++i) (void)cb2::Token::verify(bound_tokens[i], issuer_public, bound_rules[i]);
    }});
    run.timed.push_back({"cb3.public sign", [] {
        for (const Item& it : items) (void)cb2::CompactToken::sign(issuer, it.claims);
    }});
    run.timed.push_back({"cb3.public verify", [] {
        for (std::size_t i = 0; i < cb3_public_tokens.size(); ++i) (void)cb2::CompactToken::verify(cb3_public_tokens[i], issuer_public, rules[i]);
    }});
    run.timed.push_back({"bound cb3.public request check", [] {
        for (std::size_t i = 0; i < cb3_bound_tokens.size(); ++i) (void)cb2::CompactToken::verify(cb3_bound_tokens[i], issuer_public, cb3_bound_rules[i]);
    }});
#endif
    return run;
}

std::string size_line(const std::string& name, const Row& row) {
    return name + " " + std::to_string(row.min) + " " + row.mean() + " " + std::to_string(row.max);
}

int check_against(const Run& run, const char* path) {
    std::ifstream in(path);
    if (!in) {
        std::fprintf(stderr, "cb2_size: cannot read %s\n", path);
        return 2;
    }
    std::map<std::string, std::string> expected;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        expected[line.substr(0, line.find(' '))] = line;
    }
    int failures = 0;
    for (const std::string& name : run.order) {
        const std::string got = size_line(name, run.rows.at(name));
        const auto it = expected.find(name);
        if (it == expected.end()) {
            std::printf("extra row:  %s\n", got.c_str());
            ++failures;
            continue;
        }
        if (it->second != got) {
            std::printf("expected:   %s\ngot:        %s\n", it->second.c_str(), got.c_str());
            ++failures;
        }
        expected.erase(it);
    }
    for (const auto& [name, want] : expected) {
#ifndef CB2_HAS_PQ
        if (name.find("public") != std::string::npos) continue;
#endif
        std::printf("missing row: %s\n", want.c_str());
        ++failures;
    }
    std::printf("cb2_size: %zu rows checked, %d differences\n", run.order.size(), failures);
    return failures == 0 ? 0 : 1;
}

double median_us(const std::function<void()>& pass) {
    std::vector<double> per_op;
    for (int p = 0; p < 5; ++p) {
        const auto t0 = std::chrono::steady_clock::now();
        pass();
        const auto t1 = std::chrono::steady_clock::now();
        per_op.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count() / CORPUS_SIZE);
    }
    std::sort(per_op.begin(), per_op.end());
    return per_op[per_op.size() / 2];
}

void print_table(const Run& run) {
    std::printf("%-24s %6s %10s %6s  %-6s %-6s\n", "row", "min", "mean", "max", "cookie", "8 KB");
    for (const std::string& name : run.order) {
        const Row& row = run.rows.at(name);
        const bool cookie = row.max <= COOKIE_LIMIT;
        const bool header = row.max <= HEADER_LIMIT;
        std::printf("%-24s %6zu %10s %6zu  %-6s %-6s\n", name.c_str(), row.min, row.mean().c_str(), row.max,
                    cookie ? "fits" : "no", header ? "fits" : "no");
    }
}

}

int main(int argc, char** argv) {
    const std::string mode = argc > 1 ? argv[1] : "";
    if (mode == "--check" && argc < 3) {
        std::fprintf(stderr, "usage: cb2_size [--sizes | --check FILE]\n");
        return 2;
    }
    const Run run = measure();
    if (mode == "--check") return check_against(run, argv[2]);
    if (mode == "--sizes") {
        for (const std::string& name : run.order) std::printf("%s\n", size_line(name, run.rows.at(name)).c_str());
        return 0;
    }
    std::printf("corpus: %d claim sets, seed %llu\n\n", CORPUS_SIZE, static_cast<unsigned long long>(CORPUS_SEED));
    print_table(run);
    std::printf("\n%-32s %10s\n", "operation", "us/op");
    for (const auto& [name, pass] : run.timed) std::printf("%-32s %10.2f\n", name.c_str(), median_us(pass));
    return 0;
}
