#include "test_runner.hpp"
#include "test_util.hpp"

#include <optional>
#include <set>
#include <string>

using cb2::Claims;
using cb2::Error;
using cb2::Holder;
using cb2::HolderRequest;
using cb2::LocalKey;
using cb2::Seconds;
using cb2::Token;
using cb2::ValidationRules;

namespace {

constexpr Seconds NOW = 1700000000;

LocalKey key_a() { return LocalKey::from_bytes(tu::pattern(32, 0x70)).value(); }

std::string norm(const char* s) { return Holder::normalize_target(s).value_or("<none>"); }

}

TEST_CASE("holder/target normalisation follows RFC 9449") {
    CHECK(norm("https://API.Example/v1/me?x=1#frag") == "https://api.example/v1/me");
    CHECK(norm("HTTPS://api.example:443/v1/me") == "https://api.example/v1/me");
    CHECK(norm("http://api.example:80/") == "http://api.example/");
    CHECK(norm("http://api.example:8080/a") == "http://api.example:8080/a");
    CHECK(norm("https://api.example") == "https://api.example/");
    CHECK(norm("https://api.example?x=1") == "https://api.example/");
    CHECK(norm("https://api.example/A%2Fb/./c") == "https://api.example/A%2Fb/./c");
    CHECK(norm("https://[::1]:443/x") == "https://[::1]/x");
    CHECK(norm("https://[::1]:8443/x") == "https://[::1]:8443/x");
    CHECK(norm("ftp://Host:21/x") == "ftp://host:21/x");
    CHECK(norm("https://api.example:/x") == "https://api.example/x");
    CHECK(!Holder::normalize_target("api.example/v1").has_value());
    CHECK(!Holder::normalize_target("https://user@api.example/").has_value());
    CHECK(!Holder::normalize_target("https://api.example:4a3/").has_value());
    CHECK(!Holder::normalize_target("://x").has_value());
    CHECK(!Holder::normalize_target("1http://x/").has_value());
    CHECK(!Holder::normalize_target("https:///x").has_value());
    CHECK(!Holder::normalize_target("").has_value());
}

TEST_CASE("holder/a host with a colon or a stray bracket has no normal form") {
    CHECK(norm("https://h:1/x") == "https://h:1/x");
    CHECK(!Holder::normalize_target("https://h:1:443/x").has_value());
    CHECK(!Holder::normalize_target("https://h:1:/x").has_value());
    CHECK(!Holder::normalize_target("https://::1/x").has_value());
    CHECK(!Holder::normalize_target("https://[::1/x").has_value());
    CHECK(!Holder::normalize_target("https://::1]/x").has_value());
    CHECK(!Holder::normalize_target("https://[::1]x/").has_value());
    CHECK(!Holder::normalize_target("https://[[::1]]/").has_value());
    CHECK(!Holder::normalize_target("https://a[b]/").has_value());
    CHECK(!Holder::normalize_target("https://[]/").has_value());
    CHECK(norm("https://[::1]:/x") == "https://[::1]/x");
    CHECK(norm("https://[FE80::1]:8443/x") == "https://[fe80::1]:8443/x");
}

TEST_CASE("holder/cnf is a registered claim written after jti and read back") {
    Claims c;
    c.jti = "id-1";
    c.exp = NOW;
    c.cnf = "kcb2.public.AAAA";
    CHECK(!c.set("cnf", "x"));
    CHECK(c.to_json() == "{\"exp\":\"2023-11-14T22:13:20+00:00\",\"jti\":\"id-1\",\"cnf\":\"kcb2.public.AAAA\"}");
    auto back = Claims::from_json(c.to_json());
    REQUIRE(back.is_ok());
    CHECK(back.value().cnf == std::optional<std::string>("kcb2.public.AAAA"));
    CHECK(Claims::from_json("{\"exp\":\"2023-11-14T22:13:20+00:00\",\"cnf\":1}").is_err());
    Claims bad;
    bad.cnf = "kcb2.public.\xe2\x80\x8b";
    CHECK(!bad.text_ok());
}

TEST_CASE("holder/a verifier that ignores or does not require the constraint, and an unbound token") {
    const LocalKey k = key_a();
    Claims c;
    c.iss = "https://issuer.example";
    c.aud = "api";
    c.exp = NOW + 3600;
    auto bearer = Token::seal(k, c);
    REQUIRE(bearer.is_ok());
    const ValidationRules base = ValidationRules().at(NOW).expect_issuer("https://issuer.example").expect_audience("api");
    CHECK(Token::open(bearer.value(), k, base).is_ok());
    auto need = Token::open(bearer.value(), k, ValidationRules(base).require_sender_constraint());
    CHECK(need.is_err() && need.error() == Error::missing_cnf);
    CHECK(Token::open(bearer.value(), k, ValidationRules(base).ignore_sender_constraint()).is_ok());
    auto both = Token::open(bearer.value(), k, ValidationRules(base).require_sender_constraint().ignore_sender_constraint());
    CHECK(both.is_err() && both.error() == Error::rules_incomplete);
    c.cnf = "kcb2.public.not-a-key";
    auto odd = Token::seal(k, c);
    REQUIRE(odd.is_ok());
    auto no_proof = Token::open(odd.value(), k, base);
    CHECK(no_proof.is_err() && no_proof.error() == Error::missing_proof);
    CHECK(Token::open(odd.value(), k, ValidationRules(base).ignore_sender_constraint()).is_ok());
    auto half = ValidationRules(base).with_holder_proof("cb2.holder-public.x", HolderRequest{"GET", "https://a/", std::nullopt});
    auto incomplete = Token::open(std::string(100000, 'A'), k, half);
    CHECK(incomplete.is_err() && incomplete.error() == Error::rules_incomplete);
    c.cnf = "kcb2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    auto local_mode = Token::seal(k, c);
    REQUIRE(local_mode.is_ok());
    half.with_proof_replay_check([](std::string_view) { return true; });
    auto weak = Token::open(local_mode.value(), k, half);
    CHECK(weak.is_err() && weak.error() == Error::claims_malformed);
}

#ifdef CB2_HAS_PQ

namespace {

const cb2::SecretKey& client() {
    static const cb2::SecretKey k = cb2::SecretKey::generate().value();
    return k;
}

const cb2::SecretKey& stranger() {
    static const cb2::SecretKey k = cb2::SecretKey::generate().value();
    return k;
}

HolderRequest get_me() { return HolderRequest{"GET", "https://api.example/v1/me", std::nullopt}; }

Claims bound_claims() {
    Claims c;
    c.iss = "https://issuer.example";
    c.aud = "api";
    c.sub = "user-1";
    c.exp = NOW + 3600;
    c.cnf = client().public_key().to_paserk();
    return c;
}

std::string bound_token() {
    static const std::string t = Token::seal(key_a(), bound_claims()).value();
    return t;
}

/// Rules at now that carry the proof for the request and accept every
/// proof jti.
ValidationRules checking(Seconds now, const std::string& proof, const HolderRequest& r) {
    return ValidationRules().at(now).expect_issuer("https://issuer.example").expect_audience("api")
        .with_holder_proof(proof, r).with_proof_replay_check([](std::string_view) { return true; });
}

std::string prove(const cb2::SecretKey& who, const HolderRequest& r, const std::string& token, Seconds now,
                  Seconds lifetime = Holder::DEFAULT_LIFETIME, const char* jti = "p-1") {
    return cb2::HolderProof::make(who, r, token, jti, now, lifetime).value();
}

}

TEST_CASE("holder/a bound token opens only with a proof for this request and this token") {
    const LocalKey k = key_a();
    const std::string token = bound_token();
    auto bare = Token::open(token, k, ValidationRules().at(NOW).expect_issuer("https://issuer.example").expect_audience("api"));
    CHECK(bare.is_err() && bare.error() == Error::missing_proof);
    const std::string proof = prove(client(), get_me(), token, NOW);
    CHECK(proof.rfind("cb2.holder-public.", 0) == 0);
    auto ok = Token::open(token, k, checking(NOW, proof, get_me()));
    REQUIRE(ok.is_ok());
    CHECK(ok.value().cnf == std::optional<std::string>(client().public_key().to_paserk()));
    auto pc = cb2::HolderProof::check(client().public_key(), token, checking(NOW, proof, get_me()));
    REQUIRE(pc.is_ok());
    CHECK(pc.value().get("htu") == std::optional<std::string_view>("https://api.example/v1/me"));
    CHECK(pc.value().get("htm") == std::optional<std::string_view>("GET"));
    CHECK(pc.value().exp == std::optional<Seconds>(NOW + 60));
    CHECK(Token::open(token, k, checking(NOW, proof, HolderRequest{"GET", "HTTPS://API.EXAMPLE:443/v1/me?page=2#top", std::nullopt})).is_ok());
    CHECK(Token::open(token, k, checking(NOW + 59, proof, get_me())).is_ok());
    CHECK(Token::open(token, k, checking(NOW, proof, get_me()).ignore_sender_constraint()).is_ok());
    CHECK(Token::open(token, k, checking(NOW, proof, get_me()).require_sender_constraint()).is_ok());
}

TEST_CASE("holder/anything before the proof authenticates is proof_invalid") {
    const LocalKey k = key_a();
    const std::string token = bound_token();
    auto verdict = [&](const std::string& proof, const HolderRequest& r = get_me()) {
        auto v = Token::open(token, k, checking(NOW, proof, r));
        return v.is_ok() ? std::string("ok") : std::string(cb2::error_name(v.error()));
    };
    CHECK(verdict(prove(stranger(), get_me(), token, NOW)) == "proof_invalid");
    Claims other = bound_claims();
    other.sub = "user-2";
    const std::string other_token = Token::seal(k, other).value();
    CHECK(verdict(prove(client(), get_me(), other_token, NOW)) == "proof_invalid");
    std::string proof = prove(client(), get_me(), token, NOW);
    std::string flipped = proof;
    flipped[40] = flipped[40] == 'A' ? 'B' : 'A';
    CHECK(verdict(flipped) == "proof_invalid");
    std::string as_public = proof;
    as_public.replace(0, std::string("cb2.holder-public.").size(), "cb2.public.");
    CHECK(verdict(as_public) == "proof_invalid");
    const std::string footer = "{\"kid\":\"" + client().public_key().paserk_id() + "\"}";
    CHECK(cb2::Public::verify(proof, client().public_key(), cb2::bytes(footer), cb2::bytes(token)).is_err());
    const std::string payload = cb2::HolderProof::claims_for(get_me(), "p-1", NOW).value().to_json();
    const std::string signed_as_token = cb2::Public::sign(client(), cb2::bytes(payload), cb2::bytes(footer), cb2::bytes(token)).value();
    CHECK(verdict(signed_as_token) == "proof_invalid");
    CHECK(verdict("") == "proof_invalid");
    CHECK(verdict(std::string(20000, 'A')) == "proof_invalid");
}

TEST_CASE("holder/an authenticated proof is checked for its claims, times, request, nonce and replay") {
    const LocalKey k = key_a();
    const std::string token = bound_token();
    auto verdict = [&](const ValidationRules& r) {
        auto v = Token::open(token, k, r);
        return v.is_ok() ? std::string("ok") : std::string(cb2::error_name(v.error()));
    };
    const std::string proof = prove(client(), get_me(), token, NOW);
    CHECK(verdict(checking(NOW, proof, HolderRequest{"POST", "https://api.example/v1/me", std::nullopt})) == "proof_mismatch");
    CHECK(verdict(checking(NOW, proof, HolderRequest{"GET", "https://api.example/v1/you", std::nullopt})) == "proof_mismatch");
    CHECK(verdict(checking(NOW, proof, HolderRequest{"GET", "https://api.example:8443/v1/me", std::nullopt})) == "proof_mismatch");
    CHECK(verdict(checking(NOW, proof, HolderRequest{"GET", "https://api.example/v1/me", "n-1"})) == "proof_mismatch");
    CHECK(verdict(checking(NOW + 60, proof, get_me())) == "proof_expired");
    CHECK(verdict(checking(NOW + 61, proof, get_me())) == "proof_expired");
    CHECK(verdict(checking(NOW + 61, proof, get_me()).with_clock_skew(5)) == "ok");
    CHECK(verdict(checking(NOW - 1, proof, get_me())) == "proof_expired");
    CHECK(verdict(checking(NOW - 1, proof, get_me()).with_clock_skew(1)) == "ok");
    const std::string long_lived = prove(client(), get_me(), token, NOW, 600);
    CHECK(verdict(checking(NOW, long_lived, get_me())) == "proof_expired");
    CHECK(verdict(checking(NOW, long_lived, get_me()).with_proof_lifetime(600)) == "ok");
    const std::string with_nonce = prove(client(), HolderRequest{"GET", "https://api.example/v1/me", "n-1"}, token, NOW);
    CHECK(verdict(checking(NOW, with_nonce, HolderRequest{"GET", "https://api.example/v1/me", "n-1"})) == "ok");
    CHECK(verdict(checking(NOW, with_nonce, HolderRequest{"GET", "https://api.example/v1/me", "n-2"})) == "proof_mismatch");
    CHECK(verdict(checking(NOW, with_nonce, get_me())) == "ok");
    std::set<std::string> seen;
    ValidationRules once = checking(NOW, proof, get_me()).with_proof_replay_check([&seen](std::string_view j) {
        return seen.insert(std::string(j)).second;
    });
    CHECK(verdict(once) == "ok");
    CHECK(verdict(once) == "proof_replayed");
    CHECK(seen == std::set<std::string>{"p-1"});
    CHECK(cb2::HolderProof::make(client(), HolderRequest{"GET", "not a uri", std::nullopt}, token, "p-2", NOW).is_err());
    auto thrown = checking(NOW, proof, get_me()).with_proof_replay_check([](std::string_view) -> bool { throw 1; });
    CHECK(verdict(thrown) == "internal");
    auto no_request_scheme = checking(NOW, proof, HolderRequest{"GET", "api.example/v1/me", std::nullopt});
    CHECK(verdict(no_request_scheme) == "argument");
    Claims expired = bound_claims();
    expired.exp = NOW - 1;
    const std::string stale = Token::seal(k, expired).value();
    auto order = Token::open(stale, k, ValidationRules().at(NOW).expect_issuer("https://issuer.example").expect_audience("api"));
    CHECK(order.is_err() && order.error() == Error::expired);
}

TEST_CASE("holder/a proof that authenticates but is not a proof claims object is proof_malformed") {
    const LocalKey k = key_a();
    const std::string token = bound_token();
    const std::string footer = "{\"kid\":\"" + client().public_key().paserk_id() + "\"}";
    auto raw = [&](std::string_view payload) {
        return cb2::detail::PublicCore::sign(Holder::PUBLIC_HEADER, client(), cb2::bytes(payload), cb2::bytes(footer), cb2::bytes(token)).value();
    };
    auto verdict = [&](const std::string& proof) {
        auto v = Token::open(token, k, checking(NOW, proof, get_me()));
        return v.is_ok() ? std::string("ok") : std::string(cb2::error_name(v.error()));
    };
    CHECK(verdict(raw("not json")) == "proof_malformed");
    CHECK(verdict(raw("{\"jti\":\"p\",\"iat\":\"2023-11-14T22:13:20+00:00\",\"exp\":\"2023-11-14T22:14:20+00:00\",\"htu\":\"https://api.example/v1/me\"}")) == "proof_malformed");
    CHECK(verdict(raw("{\"jti\":\"p\",\"iat\":\"2023-11-14T22:13:20+00:00\",\"exp\":\"2023-11-14T22:14:20+00:00\",\"htm\":\"GET\",\"htu\":\"https://api.example/v1/me\"}")) == "ok");
    CHECK(verdict(raw("{\"jti\":\"p\",\"exp\":\"2023-11-14T22:14:20+00:00\",\"htm\":\"GET\",\"htu\":\"https://api.example/v1/me\"}")) == "proof_malformed");
    CHECK(verdict(raw("{\"jti\":\"p\",\"iat\":\"2023-11-14T22:13:20+00:00\",\"exp\":\"2023-11-14T22:14:20+00:00\",\"htm\":1,\"htu\":\"https://api.example/v1/me\"}")) == "proof_malformed");
}

TEST_CASE("holder/cnf forms the verifier refuses after authentication") {
    const LocalKey k = key_a();
    auto verdict = [&](Claims c, bool public_purpose) {
        const std::string token = public_purpose
            ? cb2::Public::sign(client(), cb2::bytes(c.to_json()), cb2::bytes(client().footer())).value()
            : Token::seal(k, c).value();
        ValidationRules r = ValidationRules().at(NOW).expect_issuer("https://issuer.example").expect_audience("api")
            .with_holder_proof("cb2.holder-public.x", get_me()).with_proof_replay_check([](std::string_view) { return true; });
        auto v = public_purpose ? Token::verify(token, client().public_key(), r) : Token::open(token, k, r);
        return v.is_ok() ? std::string("ok") : std::string(cb2::error_name(v.error()));
    };
    Claims c = bound_claims();
    c.cnf = "kcb2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    CHECK(verdict(c, true) == "claims_malformed");
    CHECK(Token::sign(client(), c).is_err());
    CHECK(verdict(c, false) == "claims_malformed");
    c.cnf = key_a().to_paserk().data();
    CHECK(verdict(c, false) == "proof_invalid");
    c.cnf = "kcb2.public.short";
    CHECK(verdict(c, false) == "claims_malformed");
    c.cnf = "kcb2.pid.AAAA";
    CHECK(verdict(c, false) == "claims_malformed");
    c.cnf = client().public_key().to_paserk();
    CHECK(verdict(c, false) == "proof_invalid");
    CHECK(verdict(c, true) == "proof_invalid");
}

TEST_CASE("holder/make and claims_for refuse bad input") {
    const std::string token = bound_token();
    CHECK(cb2::HolderProof::make(client(), get_me(), token, "", NOW).is_err());
    CHECK(cb2::HolderProof::make(client(), HolderRequest{"GET", "api.example", std::nullopt}, token, "p", NOW).is_err());
    CHECK(cb2::HolderProof::make(client(), HolderRequest{"GET\xff", "https://api.example/", std::nullopt}, token, "p", NOW).is_err());
    CHECK(cb2::HolderProof::make(client(), HolderRequest{"GET\xe2\x80\x8b", "https://api.example/", std::nullopt}, token, "p", NOW).is_ok());
    CHECK(cb2::HolderProof::claims_for(get_me(), "p", NOW, -5).value().exp == std::optional<Seconds>(NOW));
    auto c = cb2::HolderProof::claims_for(HolderRequest{"GET", "https://API.example:443/x?y", "n"}, "p", NOW).value();
    CHECK(c.to_json() == "{\"exp\":\"2023-11-14T22:14:20+00:00\",\"iat\":\"2023-11-14T22:13:20+00:00\",\"jti\":\"p\",\"htm\":\"GET\",\"htu\":\"https://api.example/x\",\"nonce\":\"n\"}");
}

#endif
