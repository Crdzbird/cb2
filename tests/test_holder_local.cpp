#include "test_runner.hpp"
#include "test_util.hpp"

#include <optional>
#include <set>
#include <string>

using cb2::Claims;
using cb2::Error;
using cb2::Holder;
using cb2::HolderProof;
using cb2::HolderRequest;
using cb2::LocalKey;
using cb2::Seconds;
using cb2::Token;
using cb2::ValidationRules;

namespace {

constexpr Seconds NOW = 1700000000;

LocalKey token_key() { return LocalKey::from_bytes(tu::pattern(32, 0x70)).value(); }
LocalKey proof_key() { return LocalKey::from_bytes(tu::pattern(32, 0x20)).value(); }
LocalKey stranger_key() { return LocalKey::from_bytes(tu::pattern(32, 0x40)).value(); }

std::string text_of(const LocalKey& k) {
    const cb2::SecureString s = k.to_paserk();
    return std::string(s.data(), s.size());
}

HolderRequest get_me() { return HolderRequest{"GET", "https://api.example/v1/me", std::nullopt}; }

Claims bound_claims(const LocalKey& pk, const char* sub = "service-a") {
    Claims c;
    c.iss = "https://issuer.example";
    c.aud = "api";
    c.sub = sub;
    c.exp = NOW + 3600;
    c.cnf = text_of(pk);
    return c;
}

std::string bound_token() {
    static const std::string t = Token::seal(token_key(), bound_claims(proof_key())).value();
    return t;
}

ValidationRules base(Seconds now) {
    return ValidationRules().at(now).expect_issuer("https://issuer.example").expect_audience("api");
}

ValidationRules checking(Seconds now, const std::string& proof, const HolderRequest& r) {
    return base(now).with_holder_proof(proof, r).with_proof_replay_check([](std::string_view) { return true; });
}

std::string prove(const LocalKey& who, const HolderRequest& r, const std::string& token, Seconds now,
                  Seconds lifetime = Holder::DEFAULT_LIFETIME, const char* jti = "p-1") {
    return HolderProof::make_local(who, r, token, jti, now, lifetime).value();
}

std::string verdict_of(const std::string& token, const ValidationRules& r) {
    auto v = Token::open(token, token_key(), r);
    return v.is_ok() ? std::string("ok") : std::string(cb2::error_name(v.error()));
}

/// Seals payload under h with key, the proof key's footer and the access
/// token as implicit assertion, as make_local does with any payload.
std::string raw_local(std::string_view h, const LocalKey& key, std::string_view payload, std::string_view footer,
                      std::string_view implicit) {
    std::string out(cb2::detail::LocalCore::token_len(h, payload.size(), footer.size()), '\0');
    std::size_t n = 0;
    const tu::Bytes nonce = tu::pattern(32, 0x90);
    const cb2::Status s = cb2::detail::LocalCore::seal(h, {reinterpret_cast<uint8_t*>(out.data()), out.size()}, n,
                                                       cb2::detail::KeyAccess::local(key), cb2::bytes(payload),
                                                       cb2::bytes(footer), cb2::bytes(implicit), nonce.data());
    return s == cb2::Status::ok ? out : std::string();
}

std::string proof_footer() { return Token::footer_for(proof_key().paserk_id()); }

}

TEST_CASE("holder-local/the issuer binds a fresh proof key and the client proves with it") {
    Claims c = bound_claims(proof_key());
    c.cnf.reset();
    auto issued = HolderProof::bind_local(c);
    REQUIRE(issued.is_ok());
    REQUIRE(c.cnf.has_value());
    CHECK(*c.cnf == text_of(issued.value()));
    CHECK(c.cnf->rfind("kcb2.local.", 0) == 0);
    CHECK(c.cnf->size() == 54);
    CHECK(HolderProof::bind_local(c).is_err());
    Claims other = bound_claims(proof_key());
    other.cnf.reset();
    REQUIRE(HolderProof::bind_local(other).is_ok());
    CHECK(other.cnf != c.cnf);
    const std::string token = Token::seal(token_key(), c).value();
    const LocalKey client = LocalKey::from_paserk(text_of(issued.value())).value();
    const std::string proof = prove(client, get_me(), token, NOW);
    CHECK(proof.rfind("cb2.holder-local.", 0) == 0);
    CHECK(proof.size() < 450);
    CHECK(verdict_of(token, checking(NOW, proof, get_me())) == "ok");
    CHECK(verdict_of(token, base(NOW)) == "missing_proof");
}

TEST_CASE("holder-local/a bound token opens only with a proof for this request and this token") {
    const std::string token = bound_token();
    const std::string proof = prove(proof_key(), get_me(), token, NOW);
    auto ok = Token::open(token, token_key(), checking(NOW, proof, get_me()));
    REQUIRE(ok.is_ok());
    CHECK(ok.value().cnf == std::optional<std::string>(text_of(proof_key())));
    auto pc = HolderProof::check_local(proof_key(), token, checking(NOW, proof, get_me()));
    REQUIRE(pc.is_ok());
    CHECK(pc.value().get("htu") == std::optional<std::string_view>("https://api.example/v1/me"));
    CHECK(pc.value().get("htm") == std::optional<std::string_view>("GET"));
    CHECK(pc.value().exp == std::optional<Seconds>(NOW + 60));
    auto kid = Token::peek_key_id(proof);
    REQUIRE(kid.has_value());
    CHECK(kid->value == proof_key().paserk_id());
    CHECK(verdict_of(token, checking(NOW, proof, HolderRequest{"GET", "HTTPS://API.EXAMPLE:443/v1/me?page=2#top", std::nullopt})) == "ok");
    CHECK(verdict_of(token, checking(NOW + 59, proof, get_me())) == "ok");
    CHECK(verdict_of(token, checking(NOW, proof, get_me()).require_sender_constraint()) == "ok");
    CHECK(verdict_of(token, base(NOW).ignore_sender_constraint()) == "ok");
    CHECK(verdict_of(token, base(NOW)) == "missing_proof");
    LocalKey renamed = proof_key();
    renamed.set_key_id("client-7");
    CHECK(verdict_of(token, checking(NOW, prove(renamed, get_me(), token, NOW), get_me())) == "ok");
}

TEST_CASE("holder-local/anything before the proof authenticates is proof_invalid") {
    const std::string token = bound_token();
    auto verdict = [&](const std::string& proof) { return verdict_of(token, checking(NOW, proof, get_me())); };
    CHECK(verdict(prove(stranger_key(), get_me(), token, NOW)) == "proof_invalid");
    CHECK(verdict(prove(token_key(), get_me(), token, NOW)) == "proof_invalid");
    const std::string other_token = Token::seal(token_key(), bound_claims(proof_key(), "service-b")).value();
    CHECK(verdict(prove(proof_key(), get_me(), other_token, NOW)) == "proof_invalid");
    const std::string proof = prove(proof_key(), get_me(), token, NOW);
    for (std::size_t i = 0; i < proof.size(); ++i) {
        std::string t = proof;
        t[i] = t[i] == 'A' ? 'B' : 'A';
        if (verdict(t) != "proof_invalid") {
            std::printf("      position %zu accepted\n", i);
            CHECK(false);
        }
    }
    std::string as_local = proof;
    as_local.replace(0, Holder::LOCAL_HEADER.size(), "cb2.local.");
    CHECK(verdict(as_local) == "proof_invalid");
    const std::string payload = HolderProof::claims_for(get_me(), "p-1", NOW).value().to_json();
    CHECK(verdict(raw_local("cb2.local.", proof_key(), payload, proof_footer(), token)) == "proof_invalid");
    CHECK(verdict(raw_local("kcb2.local-wrap.", proof_key(), payload, proof_footer(), token)) == "proof_invalid");
    CHECK(verdict(raw_local(Holder::LOCAL_HEADER, proof_key(), payload, "", token)) == "proof_invalid");
    CHECK(verdict(raw_local(Holder::LOCAL_HEADER, proof_key(), payload, "{\"kid\":\"client-7\"}", token)) == "proof_invalid");
    CHECK(verdict(raw_local(Holder::LOCAL_HEADER, proof_key(), payload, proof_footer(), "")) == "proof_invalid");
    CHECK(verdict(raw_local(Holder::LOCAL_HEADER, proof_key(), payload, proof_footer(), token)) == "ok");
    CHECK(verdict(proof.substr(0, proof.find('.', Holder::LOCAL_HEADER.size()))) == "proof_invalid");
    CHECK(verdict("") == "proof_invalid");
    CHECK(verdict("cb2.holder-local.") == "proof_invalid");
    CHECK(verdict(std::string(20000, 'A')) == "proof_invalid");
    const HolderRequest long_nonce{"GET", "https://api.example/v1/me", std::string(400, 'n')};
    const std::string long_proof = prove(proof_key(), long_nonce, token, NOW);
    REQUIRE(long_proof.size() > token.size());
    CHECK(verdict_of(token, checking(NOW, long_proof, long_nonce).with_max_token_bytes(long_proof.size() - 1)) == "proof_invalid");
    CHECK(verdict_of(token, checking(NOW, long_proof, long_nonce).with_max_token_bytes(long_proof.size())) == "ok");
}

TEST_CASE("holder-local/a proof is never an access token and an access token is never a proof") {
    const std::string token = bound_token();
    const std::string proof = prove(proof_key(), get_me(), token, NOW);
    auto as_token = Token::open(proof, proof_key(), base(NOW).allow_missing_exp(), token);
    CHECK(as_token.is_err() && as_token.error() == Error::invalid);
    CHECK(verdict_of(token, checking(NOW, token, get_me())) == "proof_invalid");
    const std::string sealed_by_client = Token::seal(proof_key(), HolderProof::claims_for(get_me(), "p-1", NOW).value(), token).value();
    CHECK(verdict_of(token, checking(NOW, sealed_by_client, get_me())) == "proof_invalid");
}

TEST_CASE("holder-local/an authenticated proof is checked for its times, request, nonce and replay") {
    const std::string token = bound_token();
    auto verdict = [&](const ValidationRules& r) { return verdict_of(token, r); };
    const std::string proof = prove(proof_key(), get_me(), token, NOW);
    CHECK(verdict(checking(NOW, proof, HolderRequest{"POST", "https://api.example/v1/me", std::nullopt})) == "proof_mismatch");
    CHECK(verdict(checking(NOW, proof, HolderRequest{"get", "https://api.example/v1/me", std::nullopt})) == "proof_mismatch");
    CHECK(verdict(checking(NOW, proof, HolderRequest{"GET", "https://api.example/v1/you", std::nullopt})) == "proof_mismatch");
    CHECK(verdict(checking(NOW, proof, HolderRequest{"GET", "https://other.example/v1/me", std::nullopt})) == "proof_mismatch");
    CHECK(verdict(checking(NOW, proof, HolderRequest{"GET", "http://api.example/v1/me", std::nullopt})) == "proof_mismatch");
    CHECK(verdict(checking(NOW, proof, HolderRequest{"GET", "https://api.example:8443/v1/me", std::nullopt})) == "proof_mismatch");
    CHECK(verdict(checking(NOW, proof, HolderRequest{"GET", "https://api.example/v1/me", "n-1"})) == "proof_mismatch");
    CHECK(verdict(checking(NOW + 60, proof, get_me())) == "proof_expired");
    CHECK(verdict(checking(NOW + 61, proof, get_me()).with_clock_skew(5)) == "ok");
    CHECK(verdict(checking(NOW - 1, proof, get_me())) == "proof_expired");
    CHECK(verdict(checking(NOW - 1, proof, get_me()).with_clock_skew(1)) == "ok");
    const std::string long_lived = prove(proof_key(), get_me(), token, NOW, 600);
    CHECK(verdict(checking(NOW, long_lived, get_me())) == "proof_expired");
    CHECK(verdict(checking(NOW, long_lived, get_me()).with_proof_lifetime(600)) == "ok");
    const std::string with_nonce = prove(proof_key(), HolderRequest{"GET", "https://api.example/v1/me", "n-1"}, token, NOW);
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
    auto thrown = checking(NOW, proof, get_me()).with_proof_replay_check([](std::string_view) -> bool { throw 1; });
    CHECK(verdict(thrown) == "internal");
    CHECK(verdict(checking(NOW, proof, HolderRequest{"GET", "api.example/v1/me", std::nullopt})) == "argument");
    CHECK(verdict(base(NOW).with_holder_proof(proof, get_me())) == "rules_incomplete");
    CHECK(verdict(checking(NOW + 7200, proof, get_me())) == "expired");
}

TEST_CASE("holder-local/a proof that authenticates but is not a proof claims object is proof_malformed") {
    const std::string token = bound_token();
    auto verdict = [&](std::string_view payload) {
        return verdict_of(token, checking(NOW, raw_local(Holder::LOCAL_HEADER, proof_key(), payload, proof_footer(), token), get_me()));
    };
    CHECK(verdict("not json") == "proof_malformed");
    CHECK(verdict("{\"jti\":\"p\",\"iat\":\"2023-11-14T22:13:20+00:00\",\"exp\":\"2023-11-14T22:14:20+00:00\",\"htu\":\"https://api.example/v1/me\"}") == "proof_malformed");
    CHECK(verdict("{\"iat\":\"2023-11-14T22:13:20+00:00\",\"exp\":\"2023-11-14T22:14:20+00:00\",\"htm\":\"GET\",\"htu\":\"https://api.example/v1/me\"}") == "proof_malformed");
    CHECK(verdict("{\"jti\":\"p\",\"iat\":\"2023-11-14T22:13:20+00:00\",\"exp\":\"2023-11-14T22:14:20+00:00\",\"htm\":1,\"htu\":\"https://api.example/v1/me\"}") == "proof_malformed");
    CHECK(verdict("{\"jti\":\"p\",\"jti\":\"q\",\"iat\":\"2023-11-14T22:13:20+00:00\",\"exp\":\"2023-11-14T22:14:20+00:00\",\"htm\":\"GET\",\"htu\":\"https://api.example/v1/me\"}") == "proof_malformed");
    CHECK(verdict("{\"jti\":\"p\",\"iat\":\"2023-11-14T22:13:20+00:00\",\"exp\":\"2023-11-14T22:14:20+00:00\",\"htm\":\"GET\",\"htu\":\"https://api.example/v1/me\"}") == "ok");
}

TEST_CASE("holder-local/cnf forms the verifier refuses after authentication") {
    auto verdict = [&](const std::string& cnf) {
        Claims c = bound_claims(proof_key());
        c.cnf = cnf;
        const std::string token = Token::seal(token_key(), c).value();
        return verdict_of(token, checking(NOW, prove(proof_key(), get_me(), token, NOW), get_me()));
    };
    CHECK(verdict(text_of(proof_key())) == "ok");
    CHECK(verdict("kcb2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == "claims_malformed");
    CHECK(verdict("kcb2.local.AAAA") == "claims_malformed");
    CHECK(verdict(text_of(proof_key()) + "A") == "claims_malformed");
    CHECK(verdict("kcb2.lid." + text_of(proof_key()).substr(11)) == "claims_malformed");
    CHECK(verdict(text_of(stranger_key())) == "proof_invalid");
}

TEST_CASE("holder-local/make_local refuses bad input") {
    const std::string token = bound_token();
    CHECK(HolderProof::make_local(proof_key(), get_me(), token, "", NOW).is_err());
    CHECK(HolderProof::make_local(proof_key(), HolderRequest{"GET", "api.example", std::nullopt}, token, "p", NOW).is_err());
    CHECK(HolderProof::make_local(proof_key(), HolderRequest{"GET\xff", "https://api.example/", std::nullopt}, token, "p", NOW).is_err());
    const std::string a = prove(proof_key(), get_me(), token, NOW);
    const std::string b = prove(proof_key(), get_me(), token, NOW);
    CHECK(a != b);
    CHECK(a.size() == b.size());
}

#ifdef CB2_HAS_PQ

TEST_CASE("holder-local/the modes do not cross: public proofs, public tokens and local proofs") {
    const cb2::SecretKey client = cb2::SecretKey::generate().value();
    const std::string token = bound_token();
    CHECK(verdict_of(token, checking(NOW, HolderProof::make(client, get_me(), token, "p-1", NOW).value(), get_me())) == "proof_invalid");
    Claims pub = bound_claims(proof_key());
    pub.cnf = client.public_key().to_paserk();
    const std::string public_bound = Token::seal(token_key(), pub).value();
    CHECK(verdict_of(public_bound, checking(NOW, prove(proof_key(), get_me(), public_bound, NOW), get_me())) == "proof_invalid");
    CHECK(verdict_of(public_bound, checking(NOW, HolderProof::make(client, get_me(), public_bound, "p-1", NOW).value(), get_me())) == "ok");
    Claims local_in_public = bound_claims(proof_key());
    CHECK(Token::sign(client, local_in_public).is_err());
    const std::string forged = cb2::Public::sign(client, cb2::bytes(local_in_public.to_json()), cb2::bytes(client.footer())).value();
    auto v = Token::verify(forged, client.public_key(), checking(NOW, prove(proof_key(), get_me(), forged, NOW), get_me()));
    CHECK(v.is_err() && v.error() == Error::claims_malformed);
}

#endif
