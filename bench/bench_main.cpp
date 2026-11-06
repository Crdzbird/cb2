/**
 * cb2_bench: cb2.local and cb2.public against PASETO v1 to v4, JWS
 * (HS256, RS256, ES256, EdDSA) and JWE (dir, A256GCM), at 64 B, 1 KiB
 * and 64 KiB payloads with a 44-byte footer where the format has one and
 * an empty implicit assertion. Each cell is the median of seven repeats
 * of at least 200 ms of back-to-back calls, in time per operation, of
 * the allocating functions of every implementation. The references are
 * bench/reference.hpp, checked against the official PASETO vectors and
 * the RFC 7515 example by tests/test_reference.cpp. CipherBird's own
 * v4.local and cb1.local rows appear when cryptolib is found.
 *
 * A second table measures one sender-constrained request: the client
 * makes a holder proof for GET https://api.example/v1/me and the server
 * checks the access token and that proof under the rules a resource would
 * set, for cb2 bound tokens and for JWT access tokens with RFC 9449 DPoP
 * proofs. The DPoP rows do the two signature checks, the ath hash and the
 * jkt thumbprint and no JSON claim checks, and take the client key as
 * known instead of reading it from the proof header: a lower bound for
 * JWT, as the JWS rows of the first table are.
 *
 * --fast-random selects libsodium's own userspace random generator for
 * every nonce in the run, the application opt-in README.md describes;
 * --only <text> measures only the rows whose name contains the text.
 */

#include "reference.hpp"

#ifdef CB2_BENCH_CRYPTOLIB
#include "bench_ref.hpp"
#endif

#include <cb2/cb2.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
using ref::Bytes;
using ref::Span;

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

/// One implementation: seal makes a token of a message and a footer,
/// open checks it and returns the message.
struct Scheme {
    std::string name;
    bool encrypts;
    bool has_footer;
    std::function<std::string(Span msg, Span footer)> seal;
    std::function<bool(std::string_view token, Span footer, Bytes& out)> open;
};

struct Row {
    std::string name;
    bool encrypts;
    std::size_t bytes_at_64;
    double seal_ns[3];
    double open_ns[3];
};

const std::size_t SIZES[3] = {64, 1024, 65536};

Row bench(const Scheme& s, Span footer_in) {
    Row row{s.name, s.encrypts, 0, {}, {}};
    const Span footer = s.has_footer ? footer_in : Span{};
    for (int k = 0; k < 3; ++k) {
        Bytes msg(SIZES[k]);
        for (std::size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<uint8_t>(i * 7 + 1);
        const std::string token = s.seal(msg, footer);
        Bytes out;
        if (token.empty() || !s.open(token, footer, out) || out != msg) {
            std::fprintf(stderr, "%s: round trip failed at %zu bytes\n", s.name.c_str(), SIZES[k]);
            std::exit(1);
        }
        if (k == 0) row.bytes_at_64 = token.size();
        row.seal_ns[k] = measure([&] {
            const std::string t = s.seal(msg, footer);
            if (t.empty()) std::abort();
        });
        row.open_ns[k] = measure([&] {
            Bytes m;
            if (!s.open(token, footer, m)) std::abort();
        });
    }
    return row;
}

std::string cell(double ns) {
    char buf[32];
    if (ns >= 1e6) std::snprintf(buf, sizeof buf, "%.2f ms", ns / 1e6);
    else if (ns >= 1e4) std::snprintf(buf, sizeof buf, "%.1f us", ns / 1e3);
    else std::snprintf(buf, sizeof buf, "%.0f ns", ns);
    return std::string(buf);
}

void print(const std::vector<Row>& rows) {
    std::printf("\n| implementation | token at 64 B | seal 64 B | seal 1 KiB | seal 64 KiB | open 64 B | open 1 KiB | open 64 KiB |\n");
    std::printf("|---|---:|---:|---:|---:|---:|---:|---:|\n");
    for (const Row& r : rows) {
        std::printf("| %s | %zu | %s | %s | %s | %s | %s | %s |\n", r.name.c_str(), r.bytes_at_64,
                    cell(r.seal_ns[0]).c_str(), cell(r.seal_ns[1]).c_str(), cell(r.seal_ns[2]).c_str(),
                    cell(r.open_ns[0]).c_str(), cell(r.open_ns[1]).c_str(), cell(r.open_ns[2]).c_str());
    }
    std::printf("\n64 KiB throughput (seal / open):\n");
    for (const Row& r : rows) {
        const double mb = 65536.0 / 1048576.0;
        std::printf("  %-30s %.0f MB/s / %.0f MB/s\n", r.name.c_str(), mb / (r.seal_ns[2] / 1e9), mb / (r.open_ns[2] / 1e9));
    }
}

struct Keys {
    uint8_t k32[32];
    uint8_t ed_pk[32];
    uint8_t ed_sk[64];
    ref::Evp rsa;
    ref::Evp p384;
    ref::Evp p256;
};

std::vector<Scheme> schemes(const Keys& keys, const cb2::LocalKey& local) {
    std::vector<Scheme> v;
    const Span k32(keys.k32, 32);
    const uint8_t* ed_pk = keys.ed_pk;
    const uint8_t* ed_sk = keys.ed_sk;
    EVP_PKEY* rsa = keys.rsa.key;
    EVP_PKEY* p384 = keys.p384.key;
    EVP_PKEY* p256 = keys.p256.key;
    v.push_back({"cb2.local", true, true,
                 [&local](Span m, Span f) { auto r = cb2::Local::seal(local, m, f); return r.is_ok() ? r.value() : std::string(); },
                 [&local](std::string_view t, Span f, Bytes& out) {
                     auto r = cb2::Local::open(t, local, f);
                     if (r.is_err()) return false;
                     out.assign(r.value().begin(), r.value().end());
                     return true;
                 }});
    v.push_back({"PASETO v4.local", true, true,
                 [k32](Span m, Span f) { uint8_t n[32]; ref::random(n, 32); return ref::v4_local_encrypt(k32, m, f, {}, n); },
                 [k32](std::string_view t, Span f, Bytes& out) { return ref::v4_local_decrypt(k32, t, f, {}, out); }});
    v.push_back({"PASETO v3.local", true, true,
                 [k32](Span m, Span f) { uint8_t n[32]; ref::random(n, 32); return ref::v3_local_encrypt(k32, m, f, {}, n); },
                 [k32](std::string_view t, Span f, Bytes& out) { return ref::v3_local_decrypt(k32, t, f, {}, out); }});
    v.push_back({"PASETO v2.local", true, true,
                 [k32](Span m, Span f) { uint8_t n[24]; ref::random(n, 24); return ref::v2_local_encrypt(k32, m, f, n); },
                 [k32](std::string_view t, Span f, Bytes& out) { return ref::v2_local_decrypt(k32, t, f, out); }});
    v.push_back({"PASETO v1.local", true, true,
                 [k32](Span m, Span f) { uint8_t n[32]; ref::random(n, 32); return ref::v1_local_encrypt(k32, m, f, n); },
                 [k32](std::string_view t, Span f, Bytes& out) { return ref::v1_local_decrypt(k32, t, f, out); }});
    v.push_back({"JWE dir A256GCM", true, false,
                 [k32](Span m, Span) { uint8_t iv[12]; ref::random(iv, 12); return ref::jwe_a256gcm_seal(k32, m, iv); },
                 [k32](std::string_view t, Span, Bytes& out) { return ref::jwe_a256gcm_open(k32, t, out); }});
#ifdef CB2_HAS_PQ
    static const cb2::SecretKey signer = cb2::SecretKey::generate().value();
    static const cb2::PublicKey verifier = signer.public_key();
    v.push_back({"cb2.public (Ed25519 + ML-DSA-65)", false, true,
                 [](Span m, Span f) { auto r = cb2::Public::sign(signer, m, f); return r.is_ok() ? r.value() : std::string(); },
                 [](std::string_view t, Span f, Bytes& out) {
                     auto r = cb2::Public::verify(t, verifier, f);
                     if (r.is_err()) return false;
                     out = std::move(r.value());
                     return true;
                 }});
#endif
    v.push_back({"PASETO v4.public (Ed25519)", false, true,
                 [ed_sk](Span m, Span f) { return ref::v4_public_sign(ed_sk, m, f, {}); },
                 [ed_pk](std::string_view t, Span f, Bytes& out) { return ref::v4_public_verify(ed_pk, t, f, {}, out); }});
    v.push_back({"PASETO v3.public (ECDSA P-384)", false, true,
                 [p384](Span m, Span f) { return ref::v3_public_sign(p384, m, f, {}); },
                 [p384](std::string_view t, Span f, Bytes& out) { return ref::v3_public_verify(p384, t, f, {}, out); }});
    v.push_back({"PASETO v2.public (Ed25519)", false, true,
                 [ed_sk](Span m, Span f) { return ref::v2_public_sign(ed_sk, m, f); },
                 [ed_pk](std::string_view t, Span f, Bytes& out) { return ref::v2_public_verify(ed_pk, t, f, out); }});
    v.push_back({"PASETO v1.public (RSA-2048 PSS)", false, true,
                 [rsa](Span m, Span f) { return ref::v1_public_sign(rsa, m, f); },
                 [rsa](std::string_view t, Span f, Bytes& out) { return ref::v1_public_verify(rsa, t, f, out); }});
    v.push_back({"JWS EdDSA (Ed25519)", false, false,
                 [ed_sk](Span m, Span) { return ref::jws("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}", m, [ed_sk](Span in, Bytes& sig) { return ref::eddsa_sign(ed_sk, in, sig); }); },
                 [ed_pk](std::string_view t, Span, Bytes& out) { return ref::jws_verify(t, [ed_pk](Span in, Span sig) { return ref::eddsa_verify(ed_pk, in, sig); }, out); }});
    v.push_back({"JWS ES256 (ECDSA P-256)", false, false,
                 [p256](Span m, Span) { return ref::jws("{\"alg\":\"ES256\",\"typ\":\"JWT\"}", m, [p256](Span in, Bytes& sig) { return ref::es256_sign(p256, in, sig); }); },
                 [p256](std::string_view t, Span, Bytes& out) { return ref::jws_verify(t, [p256](Span in, Span sig) { return ref::es256_verify(p256, in, sig); }, out); }});
    v.push_back({"JWS RS256 (RSA-2048)", false, false,
                 [rsa](Span m, Span) { return ref::jws("{\"alg\":\"RS256\",\"typ\":\"JWT\"}", m, [rsa](Span in, Bytes& sig) { return ref::rs256_sign(rsa, in, sig); }); },
                 [rsa](std::string_view t, Span, Bytes& out) { return ref::jws_verify(t, [rsa](Span in, Span sig) { return ref::rs256_verify(rsa, in, sig); }, out); }});
    v.push_back({"JWS HS256 (HMAC-SHA256)", false, false,
                 [k32](Span m, Span) { return ref::jws("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", m, [k32](Span in, Bytes& sig) { return ref::hs256_sign(k32, in, sig); }); },
                 [k32](std::string_view t, Span, Bytes& out) { return ref::jws_verify(t, [k32](Span in, Span sig) { return ref::hs256_verify(k32, in, sig); }, out); }});
#ifdef CB2_BENCH_CRYPTOLIB
    for (const bench_ref::Impl& impl : {bench_ref::v4_local(), bench_ref::cb1_local()}) {
        v.push_back({impl.name, true, true,
                     [impl, k32](Span m, Span f) {
                         std::string t(impl.token_len(m.size(), f.size()), '\0');
                         std::size_t n = 0;
                         if (!impl.seal(reinterpret_cast<uint8_t*>(t.data()), t.size(), n, k32.data(), m.data(), m.size(), f.data(), f.size(), nullptr, 0)) return std::string();
                         t.resize(n);
                         return t;
                     },
                     [impl, k32](std::string_view t, Span f, Bytes& out) {
                         out.resize(impl.open_capacity(t.size()));
                         std::size_t n = 0;
                         if (!impl.open(out.data(), out.size(), n, reinterpret_cast<const uint8_t*>(t.data()), t.size(), k32.data(), f.data(), f.size(), nullptr, 0)) return false;
                         out.resize(n);
                         return true;
                     }});
    }
#endif
    return v;
}

/// One sender-constrained request: prove makes the client's proof for
/// the request, check verifies the access token with that proof on the
/// server. A bearer row has no proof and an empty prove.
struct Request {
    std::string name;
    std::string token;
    std::string proof;
    std::function<std::string()> prove;
    std::function<bool(const std::string& proof)> check;
};

const cb2::Seconds REQ_NOW = 1700000000;
const char* const REQ_TARGET = "https://api.example/v1/me";

std::string sha256_b64(std::string_view in) {
    uint8_t h[32];
    crypto_hash_sha256(h, reinterpret_cast<const uint8_t*>(in.data()), in.size());
    return ref::b64({h, 32});
}

/// The RFC 7638 canonical JWK of a P-256 public key, members in
/// lexicographic order, so its SHA-256 is the jkt thumbprint.
std::string p256_jwk(EVP_PKEY* key) {
    uint8_t buf[200];
    std::size_t n = 0;
    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, buf, sizeof buf, &n) != 1 || n != 65 || buf[0] != 0x04) return {};
    return "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + ref::b64({buf + 1, 32}) + "\",\"y\":\"" + ref::b64({buf + 33, 32}) + "\"}";
}

bool has_member(const Bytes& json, std::string_view name, std::string_view value) {
    const std::string needle = "\"" + std::string(name) + "\":\"" + std::string(value) + "\"";
    return std::search(json.begin(), json.end(), needle.begin(), needle.end()) != json.end();
}

/// A JWT access token signed by the issuer with cnf.jkt naming the
/// client's P-256 key, and DPoP proofs signed by the client with ES256.
template <class Sign, class Verify>
Request dpop_request(const std::string& name, const char* alg, Sign issuer_sign, Verify issuer_verify, EVP_PKEY* client) {
    const std::string jwk = p256_jwk(client);
    const std::string jkt = sha256_b64(jwk);
    const std::string claims = "{\"iss\":\"https://issuer.example\",\"aud\":\"api\",\"sub\":\"user-1\",\"exp\":" +
                               std::to_string(REQ_NOW + 3600) + ",\"jti\":\"t-1\",\"cnf\":{\"jkt\":\"" + jkt + "\"}}";
    const std::string token = ref::jws("{\"alg\":\"" + std::string(alg) + "\",\"typ\":\"at+jwt\"}", ref::sp(claims), issuer_sign);
    const std::string header = "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":" + jwk + "}";
    auto prove = [token, header, client] {
        const std::string payload = "{\"jti\":\"p-1\",\"htm\":\"GET\",\"htu\":\"" + std::string(REQ_TARGET) + "\",\"iat\":" +
                                    std::to_string(REQ_NOW) + ",\"ath\":\"" + sha256_b64(token) + "\"}";
        return ref::jws(header, ref::sp(payload), [client](Span in, Bytes& sig) { return ref::es256_sign(client, in, sig); });
    };
    auto check = [token, jwk, issuer_verify, client](const std::string& proof) {
        Bytes claims_out;
        Bytes proof_out;
        if (!ref::jws_verify(token, issuer_verify, claims_out)) return false;
        if (!ref::jws_verify(proof, [client](Span in, Span sig) { return ref::es256_verify(client, in, sig); }, proof_out)) return false;
        return has_member(proof_out, "ath", sha256_b64(token)) && has_member(claims_out, "jkt", sha256_b64(jwk));
    };
    return {name, token, prove(), prove, check};
}

std::vector<Request> requests(const Keys& keys, const cb2::LocalKey& local) {
    std::vector<Request> v;
    static const ref::Evp client_p256 = ref::keygen("EC", "P-256");
    EVP_PKEY* rsa = keys.rsa.key;
    EVP_PKEY* p256 = keys.p256.key;
    auto rules = [] {
        return cb2::ValidationRules().at(REQ_NOW).expect_issuer("https://issuer.example").expect_audience("api");
    };
    cb2::Claims c;
    c.iss = "https://issuer.example";
    c.aud = "api";
    c.sub = "user-1";
    c.exp = REQ_NOW + 3600;
    c.jti = "t-1";
    const std::string bearer = cb2::Token::seal(local, c).value();
    v.push_back({"cb2.local bearer, no proof", bearer, "", [] { return std::string(); },
                 [bearer, &local, rules](const std::string&) { return cb2::Token::open(bearer, local, rules()).is_ok(); }});
#ifdef CB2_HAS_PQ
    static const cb2::SecretKey client = cb2::SecretKey::generate().value();
    static const cb2::SecretKey issuer = cb2::SecretKey::generate().value();
    static const cb2::PublicKey issuer_public = issuer.public_key();
    c.cnf = client.public_key().to_paserk();
    const cb2::HolderRequest get{"GET", REQ_TARGET, std::nullopt};
    auto with_proof = [rules, get](const std::string& proof) {
        return rules().with_holder_proof(proof, get).with_proof_replay_check([](std::string_view) { return true; });
    };
    for (bool pub : {false, true}) {
        const std::string token = pub ? cb2::Token::sign(issuer, c).value() : cb2::Token::seal(local, c).value();
        auto prove = [token, get] { return cb2::HolderProof::make(client, get, token, "p-1", REQ_NOW, 60).value(); };
        std::function<bool(const std::string&)> check;
        if (pub) check = [token, with_proof](const std::string& p) { return cb2::Token::verify(token, issuer_public, with_proof(p)).is_ok(); };
        if (!pub) check = [token, &local, with_proof](const std::string& p) { return cb2::Token::open(token, local, with_proof(p)).is_ok(); };
        v.push_back({pub ? "cb2.public bound + holder proof" : "cb2.local bound + holder proof", token, prove(), prove, check});
    }
#endif
    v.push_back(dpop_request("JWT RS256 + DPoP ES256", "RS256",
                             [rsa](Span in, Bytes& sig) { return ref::rs256_sign(rsa, in, sig); },
                             [rsa](Span in, Span sig) { return ref::rs256_verify(rsa, in, sig); }, client_p256.key));
    v.push_back(dpop_request("JWT ES256 + DPoP ES256", "ES256",
                             [p256](Span in, Bytes& sig) { return ref::es256_sign(p256, in, sig); },
                             [p256](Span in, Span sig) { return ref::es256_verify(p256, in, sig); }, client_p256.key));
    return v;
}

void print_requests(const std::vector<Request>& reqs, const std::string& only) {
    std::printf("\n| request | token | proof | on the wire | client: make proof | server: check token and proof |\n");
    std::printf("|---|---:|---:|---:|---:|---:|\n");
    for (const Request& r : reqs) {
        if (!only.empty() && r.name.find(only) == std::string::npos) continue;
        std::fprintf(stderr, "measuring %s\n", r.name.c_str());
        if (r.token.empty() || !r.check(r.proof)) {
            std::fprintf(stderr, "%s: the request does not check\n", r.name.c_str());
            std::exit(1);
        }
        const std::string client = r.proof.empty() ? std::string("-") : cell(measure([&] {
            if (r.prove().empty()) std::abort();
        }));
        const double server = measure([&] {
            if (!r.check(r.proof)) std::abort();
        });
        std::printf("| %s | %zu | %zu | %zu | %s | %s |\n", r.name.c_str(), r.token.size(), r.proof.size(),
                    r.token.size() + r.proof.size(), client.c_str(), cell(server).c_str());
    }
}

}

int main(int argc, char** argv) {
    std::string only;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--fast-random") {
            if (randombytes_set_implementation(&randombytes_internal_implementation) != 0) return 2;
        } else if (a == "--only" && i + 1 < argc) {
            only = argv[++i];
        } else {
            std::fprintf(stderr, "usage: cb2_bench [--fast-random] [--only <text>]\n");
            return 2;
        }
    }
    if (sodium_init() < 0) return 2;
    std::printf("random source: %s\n", randombytes_implementation_name());
    Keys keys;
    for (int i = 0; i < 32; ++i) keys.k32[i] = static_cast<uint8_t>(0x70 + i);
    crypto_sign_keypair(keys.ed_pk, keys.ed_sk);
    keys.rsa = ref::keygen("RSA", nullptr);
    keys.p384 = ref::keygen("EC", "P-384");
    keys.p256 = ref::keygen("EC", "P-256");
    if (keys.rsa.key == nullptr || keys.p384.key == nullptr || keys.p256.key == nullptr) return 2;
    const cb2::LocalKey local = cb2::LocalKey::from_bytes(keys.k32).value();
    const std::string footer_text = "{\"kid\":\"kcb2.lid.0123456789abcdefghijklmnopqrs\"}";
    const Bytes footer(footer_text.begin(), footer_text.end());
    std::vector<Row> rows;
    for (const Scheme& s : schemes(keys, local)) {
        if (!only.empty() && s.name.find(only) == std::string::npos) continue;
        std::fprintf(stderr, "measuring %s\n", s.name.c_str());
        rows.push_back(bench(s, footer));
    }
    print(rows);
    print_requests(requests(keys, local), only);
    return 0;
}
