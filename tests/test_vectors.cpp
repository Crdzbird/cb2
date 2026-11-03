/**
 * Known-answer vectors produced by paseto5_gen_vectors and committed under
 * tests/vectors. Every local vector is re-sealed with the recorded nonce
 * and must reproduce the token byte for byte; every public vector must
 * verify (ML-DSA signing is randomised, so public tokens are checked, not
 * reproduced); every failure vector must fail; every claims vector must
 * yield the recorded verdict.
 */

#include "test_runner.hpp"
#include "test_util.hpp"

#include <string>
#include <vector>

using paseto5::Claims;
using paseto5::Error;
using paseto5::Local;
using paseto5::LocalKey;
using paseto5::Status;
using paseto5::Token;
using paseto5::ValidationRules;
using paseto5::json::Value;
using tu::Bytes;

namespace {

bool load(const char* file, Value& root) {
    const std::string path = std::string(PASETO5_VECTOR_DIR) + "/" + file;
    auto text = tu::read_file(path.c_str());
    if (!text) {
        std::printf("      missing vector file %s\n", path.c_str());
        return false;
    }
    return paseto5::json::Reader::parse(*text, root, 32) && root.is_object();
}

const Value* tests_of(const Value& root) {
    const Value* t = root.get("tests");
    return t != nullptr && t->kind == Value::Kind::array ? t : nullptr;
}

ValidationRules rules_of(const Value& v) {
    ValidationRules r;
    const Value* o = v.get("rules");
    if (o == nullptr) return r;
    r.at(tu::num(*o, "now"));
    if (!tu::flag(*o, "require-exp")) r.allow_missing_exp();
    if (!tu::flag(*o, "require-audience")) r.allow_any_audience();
    if (!tu::flag(*o, "require-issuer")) r.allow_any_issuer();
    if (const Value* seen = o->get("seen-jti"); seen != nullptr) {
        std::vector<std::string> list;
        for (const Value& j : seen->items) list.push_back(j.text);
        r.with_replay_check([list](std::string_view jti) {
            for (const auto& s : list) if (s == jti) return false;
            return true;
        });
    }
    r.with_clock_skew(tu::num(*o, "clock-skew"));
    if (o->get("max-token-bytes") != nullptr) r.with_max_token_bytes(static_cast<size_t>(tu::num(*o, "max-token-bytes")));
    if (o->get("issuer") != nullptr) r.expect_issuer(tu::str(*o, "issuer"));
    if (o->get("audience") != nullptr) r.expect_audience(tu::str(*o, "audience"));
    if (o->get("subject") != nullptr) r.expect_subject(tu::str(*o, "subject"));
    return r;
}

std::string verdict_name(bool ok, Error e) { return ok ? "ok" : paseto5::error_name(e); }

}

TEST_CASE("vectors/cb2.local vectors reproduce and open") {
    Value root;
    REQUIRE(load("cb2_local.json", root));
    const Value* tests = tests_of(root);
    REQUIRE(tests != nullptr);
    int seen = 0;
    for (const Value& v : tests->items) {
        ++seen;
        const std::string name = tu::str(v, "name");
        const Bytes key = tu::unhex(tu::str(v, "key"));
        const Bytes footer = tu::bytes_of(tu::str(v, "footer"));
        const Bytes implicit = tu::bytes_of(tu::str(v, "implicit-assertion"));
        const std::string token = tu::str(v, "token");
        auto k = LocalKey::from_bytes(key);
        REQUIRE(k.is_ok());
        if (tu::flag(v, "expect-fail")) {
            auto r = Local::open(token, k.value(), footer, implicit);
            if (!(r.is_err() && r.error() == Error::invalid)) std::printf("      %s should fail\n", name.c_str());
            CHECK(r.is_err() && r.error() == Error::invalid);
            continue;
        }
        const Bytes nonce = tu::unhex(tu::str(v, "nonce"));
        const Bytes payload = tu::bytes_of(tu::str(v, "payload"));
        std::string out(Local::token_len(payload.size(), footer.size()), '\0');
        size_t n = 0;
        CHECK(Local::seal_with_nonce_for_testing({reinterpret_cast<uint8_t*>(out.data()), out.size()}, n, k.value(), payload, footer, implicit, nonce) == Status::ok);
        if (out != token) std::printf("      %s token differs\n", name.c_str());
        CHECK(out == token);
        auto back = Local::open(token, k.value(), footer, implicit);
        REQUIRE(back.is_ok());
        CHECK(Bytes(back.value().begin(), back.value().end()) == payload);
    }
    CHECK(seen >= 10);
}

TEST_CASE("vectors/cb2.local weak keys are refused on import") {
    Value root;
    REQUIRE(load("cb2_local.json", root));
    const Value* weak = root.get("weak-keys");
    REQUIRE(weak != nullptr && weak->kind == Value::Kind::array);
    int seen = 0;
    for (const Value& w : weak->items) {
        ++seen;
        auto r = LocalKey::from_bytes(tu::unhex(tu::str(w, "key")));
        CHECK(r.is_err() && paseto5::error_name(r.error()) == tu::str(w, "expect"));
    }
    CHECK(seen == 3);
}

TEST_CASE("vectors/cb2.local tamper vectors all fail") {
    Value root;
    REQUIRE(load("cb2_local.json", root));
    const Value* tamper = root.get("tamper");
    REQUIRE(tamper != nullptr && tamper->is_object());
    const Bytes key = tu::unhex(tu::str(*tamper, "key"));
    const Bytes footer = tu::bytes_of(tu::str(*tamper, "footer"));
    const Bytes implicit = tu::bytes_of(tu::str(*tamper, "implicit-assertion"));
    auto k = LocalKey::from_bytes(key);
    REQUIRE(k.is_ok());
    CHECK(Local::open(tu::str(*tamper, "token"), k.value(), footer, implicit).is_ok());
    const Value* cases = tamper->get("cases");
    REQUIRE(cases != nullptr && cases->kind == Value::Kind::array);
    CHECK(cases->items.size() == tu::str(*tamper, "token").size());
    for (const Value& c : cases->items) {
        auto r = Local::open(tu::str(c, "token"), k.value(), footer, implicit);
        CHECK(r.is_err() && r.error() == Error::invalid);
    }
}

#ifdef PASETO5_HAS_PQ
TEST_CASE("vectors/cb2.public vectors verify and failure vectors fail") {
    Value root;
    REQUIRE(load("cb2_public.json", root));
    const Value* tests = tests_of(root);
    REQUIRE(tests != nullptr);
    int seen = 0;
    for (const Value& v : tests->items) {
        ++seen;
        const std::string name = tu::str(v, "name");
        auto pk = paseto5::PublicKey::from_bytes(tu::unhex(tu::str(v, "public-key")));
        REQUIRE(pk.is_ok());
        const Bytes footer = tu::bytes_of(tu::str(v, "footer"));
        const Bytes implicit = tu::bytes_of(tu::str(v, "implicit-assertion"));
        const std::string token = tu::str(v, "token");
        auto r = paseto5::Public::verify(token, pk.value(), footer, implicit);
        if (tu::flag(v, "expect-fail")) {
            if (!r.is_err()) std::printf("      %s should fail\n", name.c_str());
            CHECK(r.is_err() && r.error() == Error::invalid);
            continue;
        }
        if (!r.is_ok()) std::printf("      %s should verify\n", name.c_str());
        REQUIRE(r.is_ok());
        CHECK(r.value() == tu::bytes_of(tu::str(v, "payload")));
        auto sk = paseto5::SecretKey::from_bytes(tu::unhex(tu::str(v, "secret-key")));
        REQUIRE(sk.is_ok());
        CHECK(std::equal(pk.value().bytes().begin(), pk.value().bytes().end(), sk.value().public_key().bytes().begin()));
        auto again = paseto5::Public::sign(sk.value(), r.value(), footer, implicit);
        REQUIRE(again.is_ok());
        CHECK(again.value().size() == token.size());
        CHECK(paseto5::Public::verify(again.value(), pk.value(), footer, implicit).is_ok());
    }
    CHECK(seen >= 6);
    const Value* tamper = root.get("tamper");
    REQUIRE(tamper != nullptr && tamper->is_object());
    auto pk = paseto5::PublicKey::from_bytes(tu::unhex(tu::str(*tamper, "public-key")));
    REQUIRE(pk.is_ok());
    const Value* cases = tamper->get("cases");
    REQUIRE(cases != nullptr);
    for (const Value& c : cases->items) {
        auto r = paseto5::Public::verify(tu::str(c, "token"), pk.value(), tu::bytes_of(tu::str(*tamper, "footer")), tu::bytes_of(tu::str(*tamper, "implicit-assertion")));
        CHECK(r.is_err() && r.error() == Error::invalid);
    }
}
#endif

#ifdef PASETO5_HAS_PQ
TEST_CASE("vectors/cb2.public rejected secret keys are refused on import") {
    Value root;
    REQUIRE(load("cb2_public.json", root));
    const Value* rejected = root.get("rejected-secret-keys");
    REQUIRE(rejected != nullptr && rejected->kind == Value::Kind::array);
    int seen = 0;
    for (const Value& v : rejected->items) {
        ++seen;
        auto r = paseto5::SecretKey::from_bytes(tu::unhex(tu::str(v, "secret-key")));
        if (!r.is_err()) std::printf("      %s should be refused\n", tu::str(v, "name").c_str());
        CHECK(r.is_err() && paseto5::error_name(r.error()) == tu::str(v, "expect"));
    }
    CHECK(seen == 5);
}
#endif

TEST_CASE("vectors/claims vectors yield the recorded verdicts") {
    Value root;
    REQUIRE(load("claims.json", root));
    const Value* tests = tests_of(root);
    REQUIRE(tests != nullptr);
    int seen = 0;
    for (const Value& v : tests->items) {
        ++seen;
        const std::string name = tu::str(v, "name");
        const std::string purpose = tu::str(v, "purpose");
        const std::string token = tu::str(v, "token");
        const std::string implicit = tu::str(v, "implicit-assertion");
        const ValidationRules rules = rules_of(v);
        std::string verdict;
        if (purpose == "local") {
            auto k = LocalKey::from_bytes(tu::unhex(tu::str(v, "key")));
            REQUIRE(k.is_ok());
            if (v.get("key-id") != nullptr) k.value().set_key_id(tu::str(v, "key-id"));
            const Bytes nonce = tu::unhex(tu::str(v, "nonce"));
            if (!nonce.empty()) {
                const std::string payload = tu::str(v, "payload");
                const std::string footer = Token::footer_for(k.value().key_id());
                std::string out(Local::token_len(payload.size(), footer.size()), '\0');
                size_t n = 0;
                CHECK(Local::seal_with_nonce_for_testing({reinterpret_cast<uint8_t*>(out.data()), out.size()}, n, k.value(), paseto5::bytes(payload), paseto5::bytes(footer), paseto5::bytes(implicit), nonce) == Status::ok);
                if (tu::str(v, "verifier-key").empty()) CHECK(out == token);
            }
            auto vk = tu::str(v, "verifier-key").empty() ? k.value().clone() : LocalKey::from_bytes(tu::unhex(tu::str(v, "verifier-key"))).value();
            if (v.get("verifier-key-id") != nullptr) vk.set_key_id(tu::str(v, "verifier-key-id"));
            auto r = Token::open(token, vk, rules, implicit);
            verdict = verdict_name(r.is_ok(), r.is_ok() ? Error::internal : r.error());
            const std::string canonical = v.get("payload-canonical") != nullptr ? tu::str(v, "payload-canonical") : tu::str(v, "payload");
            if (r.is_ok()) CHECK(r.value().to_json() == canonical);
        }
#ifdef PASETO5_HAS_PQ
        if (purpose == "public") {
            auto pk = paseto5::PublicKey::from_bytes(tu::unhex(tu::str(v, "public-key")));
            REQUIRE(pk.is_ok());
            if (v.get("verifier-key-id") != nullptr) pk.value().set_key_id(tu::str(v, "verifier-key-id"));
            auto r = Token::verify(token, pk.value(), rules, implicit);
            verdict = verdict_name(r.is_ok(), r.is_ok() ? Error::internal : r.error());
            if (r.is_ok()) CHECK(r.value().to_json() == tu::str(v, "payload"));
        }
#endif
        if (verdict.empty()) continue;
        if (verdict != tu::str(v, "expect")) std::printf("      %s: got %s, expected %s\n", name.c_str(), verdict.c_str(), tu::str(v, "expect").c_str());
        CHECK(verdict == tu::str(v, "expect"));
    }
    CHECK(seen >= 12);
}

TEST_CASE("vectors/paserk vectors reproduce") {
    Value root;
    REQUIRE(load("paserk.json", root));
    const Value* local = root.get("local");
    REQUIRE(local != nullptr);
    auto k = LocalKey::from_bytes(tu::unhex(tu::str(*local, "key")));
    REQUIRE(k.is_ok());
    const paseto5::SecureString p = k.value().to_paserk();
    CHECK(std::string(p.data(), p.size()) == tu::str(*local, "kcb2.local"));
    CHECK(k.value().paserk_id() == tu::str(*local, "kcb2.lid"));
    const Value* wrap = root.get("local-wrap");
    REQUIRE(wrap != nullptr);
    auto wk = LocalKey::from_bytes(tu::unhex(tu::str(*wrap, "wrapping-key")));
    REQUIRE(wk.is_ok());
    auto w = paseto5::KeyWrap::wrap_with_nonce_for_testing(wk.value(), k.value(), tu::unhex(tu::str(*wrap, "nonce")));
    REQUIRE(w.is_ok());
    CHECK(w.value() == tu::str(*wrap, "kcb2.local-wrap"));
    auto u = paseto5::KeyWrap::unwrap(tu::str(*wrap, "kcb2.local-wrap"), wk.value());
    REQUIRE(u.is_ok());
    CHECK(u.value().paserk_id() == k.value().paserk_id());
#ifdef PASETO5_HAS_PQ
    const Value* pub = root.get("public");
    REQUIRE(pub != nullptr);
    auto sk = paseto5::SecretKey::from_bytes(tu::unhex(tu::str(*pub, "secret-key")));
    REQUIRE(sk.is_ok());
    const paseto5::PublicKey pk = sk.value().public_key();
    CHECK(pk.to_paserk() == tu::str(*pub, "kcb2.public"));
    CHECK(pk.paserk_id() == tu::str(*pub, "kcb2.pid"));
    const paseto5::SecureString sp = sk.value().to_paserk();
    CHECK(std::string(sp.data(), sp.size()) == tu::str(*pub, "kcb2.secret"));
    CHECK(tu::hex(pk.bytes()) == tu::str(*pub, "public-key"));
#endif
}
