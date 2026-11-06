/**
 * The heavy load run of the web playground: many requests against one
 * resource, run in batches so that the page stays responsive and can
 * time each batch. A run has its own keys, its own users and its own
 * replay store, apart from the playground session. Every request is a
 * real check under the rules a resource sets; every attack_every-th one
 * is an attack (a changed character, an expired token, a token under
 * another key, a replayed proof or a proof for another target) whose
 * verdict is checked too, so a run shows the answers stay right as well
 * as fast. Without liboqs only the bearer kind exists.
 */

#pragma once

#include <cb2/cb2.hpp>

#include <cstdio>
#include <ctime>
#include <deque>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace cb2_load {

enum class Kind { bearer, bound, signed_token };

using Clock = double (*)();

constexpr std::size_t USERS = 256;
constexpr cb2::Seconds PROOF_LIFETIME = 60;
constexpr cb2::Seconds TOKEN_LIFETIME = 6 * 3600;
constexpr const char* ISSUER = "https://issuer.example";
constexpr const char* AUDIENCE = "api";
constexpr const char* TARGET = "https://api.example/v1/me";
constexpr const char* OTHER_TARGET = "https://api.example/v1/admin";

struct Run {
    Kind kind = Kind::bearer;
    std::optional<cb2::LocalKey> local;
#ifdef CB2_HAS_PQ
    std::optional<cb2::SecretKey> issuer;
    std::optional<cb2::PublicKey> issuer_public;
    std::vector<cb2::SecretKey> clients;
#endif
    std::vector<std::string> tokens;
    std::string expired;
    std::string foreign;
    std::unordered_set<std::string> seen;
    std::deque<std::pair<cb2::Seconds, std::string>> expiry;
    std::string last_proof;
    unsigned long long done = 0;
    unsigned long long ok = 0;
    unsigned long long attacks = 0;
    unsigned long long refused = 0;
    unsigned long long wrong = 0;
    std::string first_wrong;
};

inline Run& run() {
    static Run r;
    return r;
}

inline cb2::Seconds now() { return static_cast<cb2::Seconds>(std::time(nullptr)); }

inline std::size_t memory_bytes() { return __builtin_wasm_memory_size(0) * 65536u; }

inline std::string tampered(std::string t) {
    const std::size_t at = t.size() / 2;
    t[at] = t[at] == 'A' ? 'B' : 'A';
    return t;
}

inline cb2::Claims claims_for(std::size_t user, cb2::Seconds exp) {
    cb2::Claims c;
    c.iss = ISSUER;
    c.aud = AUDIENCE;
    c.sub = "user-" + std::to_string(user);
    c.jti = "t-" + std::to_string(user);
    c.exp = exp;
    return c;
}

inline cb2::ValidationRules rules(cb2::Seconds at) {
    return cb2::ValidationRules().at(at).expect_issuer(ISSUER).expect_audience(AUDIENCE);
}

template <class R>
std::string text_of(R&& result) {
    return result.is_ok() ? std::move(result).value() : std::string();
}

template <class R>
std::optional<cb2::Error> verdict(const R& result) {
    if (result.is_ok()) return std::nullopt;
    return result.error();
}

inline std::string issue(Run& r, const cb2::Claims& c) {
#ifdef CB2_HAS_PQ
    if (r.kind == Kind::signed_token) return text_of(cb2::Token::sign(*r.issuer, c));
#endif
    return text_of(cb2::Token::seal(*r.local, c));
}

inline std::optional<cb2::Error> check(Run& r, const std::string& token, const cb2::ValidationRules& v) {
#ifdef CB2_HAS_PQ
    if (r.kind == Kind::signed_token) return verdict(cb2::Token::verify(token, *r.issuer_public, v));
#endif
    return verdict(cb2::Token::open(token, *r.local, v));
}

inline void record(Run& r, bool attack, cb2::Error expected, std::optional<cb2::Error> got) {
    const bool right = attack ? (got.has_value() && *got == expected) : !got.has_value();
    if (attack) r.attacks += 1;
    if (attack && right) r.refused += 1;
    if (!attack && right) r.ok += 1;
    if (right) return;
    r.wrong += 1;
    if (r.first_wrong.empty()) r.first_wrong = got.has_value() ? cb2::error_name(*got) : "ok";
}

inline bool make_keys(Run& r, cb2::Seconds t) {
    r.local.emplace(cb2::LocalKey::generate().value());
    if (r.kind == Kind::bearer) return true;
#ifdef CB2_HAS_PQ
    if (r.kind == Kind::signed_token) {
        r.issuer.emplace(cb2::SecretKey::generate().value());
        r.issuer_public.emplace(r.issuer->public_key());
        r.foreign = text_of(cb2::Token::sign(cb2::SecretKey::generate().value(), claims_for(0, t + TOKEN_LIFETIME)));
    }
    for (std::size_t u = 0; r.kind == Kind::bound && u < USERS; ++u) r.clients.push_back(cb2::SecretKey::generate().value());
    return true;
#else
    (void)t;
    return false;
#endif
}

inline cb2::Claims user_claims(Run& r, std::size_t user, cb2::Seconds exp) {
    cb2::Claims c = claims_for(user, exp);
#ifdef CB2_HAS_PQ
    if (r.kind == Kind::bound) c.cnf = r.clients[user].public_key().to_paserk();
#else
    (void)r;
#endif
    return c;
}

inline std::string proof_for(Run& r, std::size_t user, const char* target, const std::string& jti, cb2::Seconds at) {
#ifdef CB2_HAS_PQ
    return text_of(cb2::HolderProof::make(r.clients[user], cb2::HolderRequest{"GET", target, std::nullopt},
                                          r.tokens[user], jti, at, PROOF_LIFETIME));
#else
    (void)r, (void)user, (void)target, (void)jti, (void)at;
    return {};
#endif
}

/// Starts a run of one kind: "bearer" (cb2.local tokens), "bound"
/// (cb2.local tokens bound to a client key, a holder proof per request)
/// or "signed" (cb2.public tokens). Returns a JSON object with what the
/// setup made and what it cost, or with an error.
inline std::string setup(const std::string& kind, Clock clock_ms) {
    const double started = clock_ms();
    Run& r = run();
    r = Run{};
    if (kind != "bearer" && kind != "bound" && kind != "signed") return "{\"error\":\"unknown kind\"}";
    if (kind == "bound") r.kind = Kind::bound;
    if (kind == "signed") r.kind = Kind::signed_token;
    const cb2::Seconds t = now();
    if (!make_keys(r, t)) return "{\"error\":\"this build has no liboqs\"}";
    for (std::size_t u = 0; u < USERS; ++u) {
        r.tokens.push_back(issue(r, user_claims(r, u, t + TOKEN_LIFETIME)));
        if (r.tokens.back().empty()) return "{\"error\":\"a token could not be issued\"}";
    }
    r.expired = issue(r, user_claims(r, 0, t - 60));
    if (r.kind != Kind::signed_token) r.foreign = text_of(cb2::Token::seal(cb2::LocalKey::generate().value(), claims_for(0, t + TOKEN_LIFETIME)));
    const std::string sample = r.kind == Kind::bound ? proof_for(r, 0, TARGET, "sample", t) : std::string();
    char buf[256];
    std::snprintf(buf, sizeof buf, "{\"users\":%zu,\"token_bytes\":%zu,\"proof_bytes\":%zu,\"setup_ms\":%.3f,\"memory\":%zu}",
                  USERS, r.tokens[0].size(), sample.size(), clock_ms() - started, memory_bytes());
    return buf;
}

inline void forget_expired(Run& r, cb2::Seconds t) {
    while (!r.expiry.empty() && r.expiry.front().first < t) {
        r.seen.erase(r.expiry.front().second);
        r.expiry.pop_front();
    }
}

/// The attack of request k, 0 to 2, or -1 for an honest request.
inline int attack_of(unsigned long long k, int attack_every) {
    if (attack_every < 2) return -1;
    const auto every = static_cast<unsigned long long>(attack_every);
    if (k % every != every - 1) return -1;
    return static_cast<int>((k / every) % 3);
}

/// The client side of a bound batch: one proof per request, made by the
/// user's client key. Attack 0 takes the proof of the request before,
/// already seen; attack 2 makes one for another target.
inline std::vector<std::string> make_proofs(Run& r, std::size_t count, const std::vector<int>& attack, cb2::Seconds t) {
    std::vector<std::string> proofs(count);
    for (std::size_t i = 0; i < count; ++i) {
        const std::size_t u = (r.done + i) % USERS;
        const std::string jti = "p-" + std::to_string(r.done + i);
        if (attack[i] == 0) proofs[i] = i > 0 ? proofs[i - 1] : r.last_proof;
        if (attack[i] != 0) proofs[i] = proof_for(r, u, attack[i] == 2 ? OTHER_TARGET : TARGET, jti, t);
    }
    return proofs;
}

/// Attack 0 replays the request before, token and proof; attack 1
/// changes one character of the token; attack 2 presents a proof made
/// for another target.
inline void check_bound(Run& r, std::size_t i, int a, const std::string& proof, cb2::Seconds t) {
    const std::size_t u = (r.done + i + (a == 0 ? USERS - 1 : 0)) % USERS;
    const std::string token = a == 1 ? tampered(r.tokens[u]) : r.tokens[u];
    cb2::Error expected = cb2::Error::invalid;
    if (a == 0) expected = cb2::Error::proof_replayed;
    if (a == 2) expected = cb2::Error::proof_mismatch;
    cb2::ValidationRules v = rules(t).with_holder_proof(proof, cb2::HolderRequest{"GET", TARGET, std::nullopt});
    v.with_proof_replay_check([&r, t](std::string_view jti) {
        std::string id(jti);
        if (!r.seen.insert(id).second) return false;
        r.expiry.emplace_back(t + PROOF_LIFETIME, std::move(id));
        return true;
    });
    record(r, a >= 0, expected, check(r, token, v));
    if (a < 0) r.last_proof = proof;
}

/// Attack 0 changes one character, attack 1 presents an expired token,
/// attack 2 a token under another key.
inline void check_plain(Run& r, std::size_t i, int a, cb2::Seconds t) {
    const std::size_t u = (r.done + i) % USERS;
    const std::string* token = &r.tokens[u];
    std::string changed;
    if (a == 0) changed = tampered(*token);
    if (a == 0) token = &changed;
    if (a == 1) token = &r.expired;
    if (a == 2) token = &r.foreign;
    record(r, a >= 0, a == 1 ? cb2::Error::expired : cb2::Error::invalid, check(r, *token, rules(t)));
}

/// Runs the next n requests and returns a JSON object with the client
/// and server time of the batch in milliseconds, the running counts,
/// the replay store size and the wasm memory.
inline std::string batch(int n, int attack_every, Clock clock_ms) {
    Run& r = run();
    if (r.tokens.empty()) return "{\"error\":\"no run\"}";
    const cb2::Seconds t = now();
    forget_expired(r, t);
    const std::size_t count = n > 0 ? static_cast<std::size_t>(n) : 0;
    std::vector<int> attack(count);
    for (std::size_t i = 0; i < count; ++i) attack[i] = attack_of(r.done + i, attack_every);
    const double c0 = clock_ms();
    const std::vector<std::string> proofs = r.kind == Kind::bound ? make_proofs(r, count, attack, t) : std::vector<std::string>();
    const double c1 = clock_ms();
    for (std::size_t i = 0; i < count; ++i) {
        if (r.kind == Kind::bound) check_bound(r, i, attack[i], proofs[i], t);
        if (r.kind != Kind::bound) check_plain(r, i, attack[i], t);
    }
    const double c2 = clock_ms();
    r.done += count;
    char buf[512];
    std::snprintf(buf, sizeof buf,
                  "{\"n\":%zu,\"client_ms\":%.3f,\"server_ms\":%.3f,\"done\":%llu,\"ok\":%llu,\"attacks\":%llu,"
                  "\"refused\":%llu,\"wrong\":%llu,\"first_wrong\":\"%s\",\"replay\":%zu,\"memory\":%zu}",
                  count, c1 - c0, c2 - c1, r.done, r.ok, r.attacks, r.refused, r.wrong, r.first_wrong.c_str(),
                  r.seen.size(), memory_bytes());
    return buf;
}

}
