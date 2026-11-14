#include "test_runner.hpp"
#include "test_util.hpp"

#include <cstdint>
#include <initializer_list>
#include <set>
#include <string>
#include <vector>

using cb2::Claims;
using cb2::CompactClaims;
using cb2::CompactToken;
using cb2::Error;
using cb2::LocalKey;
using cb2::Rfc3339;
using cb2::Seconds;
using cb2::Token;
using cb2::ValidationRules;

namespace {

constexpr Seconds NOW = 1700000000;
const char* const UUID = "6dc1614e-1fe8-9d1b-69c4-f1cf07ab4d5c";

LocalKey key_a() { return LocalKey::from_bytes(tu::pattern(32, 0x70)).value(); }

Claims good_claims() {
    Claims c;
    c.iss = "https://issuer.example";
    c.sub = "user-1";
    c.aud = "api";
    c.exp = NOW + 900;
    c.nbf = NOW - 10;
    c.iat = NOW - 10;
    c.jti = UUID;
    CHECK(c.set("role", "admin"));
    CHECK(c.set_json("limits", R"({"n":-42,"tags":["a",true,null],"deep":{"x":9223372036854775807}})"));
    return c;
}

ValidationRules rules() { return ValidationRules().at(NOW).expect_issuer("https://issuer.example").expect_audience("api"); }

std::vector<uint8_t> raw(std::initializer_list<int> b) {
    std::vector<uint8_t> v;
    for (const int x : b) v.push_back(static_cast<uint8_t>(x));
    return v;
}

Error decode_error(const std::vector<uint8_t>& payload) {
    const auto r = CompactClaims::decode(payload);
    return r.is_ok() ? Error::internal : r.error();
}

std::vector<uint8_t> encoded(const Claims& c) {
    const std::string s = CompactClaims::encode(c).value();
    return {s.begin(), s.end()};
}

}

TEST_CASE("compact/the time bounds are the RFC 3339 range of cb2") {
    Seconds t = 0;
    CHECK(Rfc3339::parse("0000-01-01T00:00:00Z", t) && t == CompactClaims::MIN_TIME);
    CHECK(Rfc3339::parse("9999-12-31T23:59:59Z", t) && t == CompactClaims::MAX_TIME);
}

TEST_CASE("compact/claims round trip through the CBOR profile") {
    const Claims c = good_claims();
    const auto back = CompactClaims::decode(encoded(c));
    REQUIRE(back.is_ok());
    CHECK(back.value().to_json() == c.to_json());
    CHECK(encoded(c).size() < c.to_json().size());
}

TEST_CASE("compact/a canonical UUID jti travels as 16 bytes, any other jti as text") {
    Claims c;
    c.jti = UUID;
    const auto a = encoded(c);
    CHECK(a == raw({0xa1, 0x07, 0x50, 0x6d, 0xc1, 0x61, 0x4e, 0x1f, 0xe8, 0x9d, 0x1b, 0x69, 0xc4, 0xf1, 0xcf, 0x07,
                    0xab, 0x4d, 0x5c}));
    c.jti = "6DC1614E-1FE8-9D1B-69C4-F1CF07AB4D5C";
    const auto upper = encoded(c);
    CHECK(upper[2] == 0x78 && upper.size() == 4 + 36);
    CHECK(CompactClaims::decode(upper).value().jti == c.jti);
    c.jti = "id-1";
    CHECK(encoded(c) == raw({0xa1, 0x07, 0x64, 'i', 'd', '-', '1'}));
}

TEST_CASE("compact/the issuer refuses what the profile cannot carry") {
    Claims c = good_claims();
    CHECK(c.set_json("ratio", "1.5"));
    CHECK(CompactClaims::encode(c).error() == Error::argument);
    Claims big;
    CHECK(big.set_json("n", "9223372036854775808"));
    CHECK(CompactClaims::encode(big).error() == Error::argument);
    Claims late;
    late.exp = CompactClaims::MAX_TIME + 1;
    CHECK(CompactClaims::encode(late).error() == Error::argument);
    Claims bound;
    bound.cnf = "kcb2.local.short";
    CHECK(CompactClaims::encode(bound).error() == Error::argument);
    bound.cnf = "not-a-key";
    CHECK(CompactClaims::encode(bound).error() == Error::argument);
    Claims bad;
    bad.sub = std::string("a\x7f", 2);
    CHECK(CompactClaims::encode(bad).error() == Error::argument);
}

TEST_CASE("compact/every byte outside the profile is claims_malformed") {
    const Error M = Error::claims_malformed;
    CHECK(CompactClaims::decode(raw({0xa0})).is_ok());
    CHECK(decode_error(raw({})) == M);
    CHECK(decode_error(raw({0x80})) == M);
    CHECK(decode_error(raw({0xa0, 0x00})) == M);
    CHECK(decode_error(raw({0xbf, 0xff})) == M);
    CHECK(decode_error(raw({0xb8, 0x00})) == M);
    CHECK(decode_error(raw({0xa1, 0x18, 0x01, 0x61, 'a'})) == M);
    CHECK(decode_error(raw({0xa1, 0x00, 0x61, 'a'})) == M);
    CHECK(decode_error(raw({0xa1, 0x09, 0x61, 'a'})) == M);
    CHECK(decode_error(raw({0xa2, 0x02, 0x61, 'a', 0x01, 0x61, 'b'})) == M);
    CHECK(decode_error(raw({0xa2, 0x01, 0x61, 'a', 0x01, 0x61, 'b'})) == M);
    CHECK(decode_error(raw({0xa2, 0x61, 'r', 0x01, 0x01, 0x61, 'a'})) == M);
    CHECK(decode_error(raw({0xa2, 0x61, 'r', 0x01, 0x61, 'r', 0x02})) == M);
    CHECK(decode_error(raw({0xa1, 0x60, 0x01})) == M);
    CHECK(decode_error(raw({0xa1, 0x63, 'i', 's', 's', 0x61, 'a'})) == M);
    CHECK(decode_error(raw({0xa1, 0x01, 0x62, 0xc3, 0x28})) == M);
    CHECK(decode_error(raw({0xa1, 0x01, 0x41, 'a'})) == M);
    CHECK(decode_error(raw({0xa1, 0x01, 0x7f, 0x61, 'a', 0xff})) == M);
    CHECK(decode_error(raw({0xa1, 0x04, 0x61, '1'})) == M);
    CHECK(decode_error(raw({0xa1, 0x04, 0xfb, 0, 0, 0, 0, 0, 0, 0, 0})) == M);
    CHECK(decode_error(raw({0xa1, 0x04, 0xc1, 0x00})) == M);
    CHECK(decode_error(raw({0xa1, 0x04, 0x1b, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x00, 0x00, 0x00})) == M);
    CHECK(decode_error(raw({0xa1, 0x04, 0x1a, 0x00, 0x00, 0x00, 0x05})) == M);
    CHECK(decode_error(raw({0xa1, 0x07, 0x4f, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})) == M);
    CHECK(decode_error(raw({0xa1, 0x08, 0x41, 0x01})) == M);
    CHECK(decode_error(raw({0xa1, 0x61, 'x', 0xf7})) == M);
    CHECK(decode_error(raw({0xa1, 0x61, 'x', 0xf8, 0x20})) == M);
    CHECK(decode_error(raw({0xa1, 0x61, 'x', 0xf9, 0x00, 0x00})) == M);
    CHECK(decode_error(raw({0xa1, 0x61, 'x', 0x41, 0x00})) == M);
    CHECK(decode_error(raw({0xa1, 0x61, 'x', 0x9f, 0xff})) == M);
    CHECK(decode_error(raw({0xa1, 0x61, 'x', 0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0})) == M);
    CHECK(decode_error(raw({0xa1, 0x61, 'x', 0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0})) == M);
    CHECK(CompactClaims::decode(raw({0xa1, 0x61, 'x', 0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})).is_ok());
    CHECK(decode_error(raw({0xa1, 0x61, 'x', 0xa2, 0x61, 'k', 0x01, 0x61, 'k', 0x02})) == M);
    CHECK(decode_error(raw({0xa1, 0x61, 'x', 0xa1, 0x01, 0x01})) == M);
    CHECK(decode_error(raw({0xa1, 0x61, 'x', 0x9a, 0xff, 0xff, 0xff, 0xff})) == M);
}

TEST_CASE("compact/a text jti in canonical UUID form is not canonical") {
    std::vector<uint8_t> p = raw({0xa1, 0x07, 0x78, 0x24});
    for (const char ch : std::string(UUID)) p.push_back(static_cast<uint8_t>(ch));
    CHECK(decode_error(p) == Error::claims_malformed);
}

TEST_CASE("compact/custom values nest exactly as deep as in cb2") {
    auto nested = [](std::size_t arrays) {
        std::vector<uint8_t> p = raw({0xa1, 0x61, 'x'});
        for (std::size_t i = 0; i < arrays; ++i) p.push_back(0x81);
        p.push_back(0x00);
        return p;
    };
    CHECK(CompactClaims::decode(nested(15)).is_ok());
    CHECK(decode_error(nested(16)) == Error::claims_malformed);
    std::string json = "{\"x\":";
    for (int i = 0; i < 15; ++i) json += "[";
    json += "0";
    for (int i = 0; i < 15; ++i) json += "]";
    json += "}";
    CHECK(Claims::from_json(json).is_ok());
    CHECK(Claims::from_json("{\"x\":[" + json.substr(5, json.size() - 6) + "]}").error() == Error::claims_malformed);
}

TEST_CASE("compact/cb3.local seals and opens with every verdict of cb2") {
    const LocalKey key = key_a();
    const Claims c = good_claims();
    const std::string tok = CompactToken::seal(key, c).value();
    CHECK(tok.starts_with("cb3.local."));
    const auto opened = CompactToken::open(tok, key, rules());
    REQUIRE(opened.is_ok());
    CHECK(opened.value().to_json() == c.to_json());
    CHECK(CompactToken::open(tok, key, ValidationRules().at(NOW + 900).expect_issuer("https://issuer.example").expect_audience("api")).error() == Error::expired);
    CHECK(CompactToken::open(tok, key, ValidationRules().at(NOW).expect_issuer("https://other.example").expect_audience("api")).error() == Error::issuer_mismatch);
    CHECK(CompactToken::open(tok, key, ValidationRules().at(NOW).expect_issuer("https://issuer.example").expect_audience("web")).error() == Error::audience_mismatch);
    CHECK(CompactToken::open(tok, key, ValidationRules().at(NOW).expect_issuer("https://issuer.example")).error() == Error::rules_incomplete);
    CHECK(CompactToken::open(tok, key, rules().with_max_token_bytes(tok.size() - 1)).error() == Error::too_large);
    std::set<std::string> seen;
    auto once = rules().with_replay_check([&seen](std::string_view j) { return seen.insert(std::string(j)).second; });
    CHECK(CompactToken::open(tok, key, once).is_ok());
    CHECK(CompactToken::open(tok, key, once).error() == Error::replayed);
}

TEST_CASE("compact/cb3.local keeps the cb2 nonce, tag and an exact length") {
    const LocalKey key = key_a();
    const Claims c = good_claims();
    const std::string payload = CompactClaims::encode(c).value();
    const std::string tok = CompactToken::seal(key, c).value();
    const std::size_t body = 32 + payload.size() + 32;
    CHECK(tok.size() == 10 + (body * 4 + 2) / 3 + 1 + 22);
    CHECK(CompactToken::NONCE_BYTES == 32);
    CHECK(tok != CompactToken::seal(key, c).value());
}

TEST_CASE("compact/cb2 and cb3 never open each other's tokens") {
    const LocalKey key = key_a();
    const Claims c = good_claims();
    const std::string cb3 = CompactToken::seal(key, c).value();
    const std::string cb2 = Token::seal(key, c).value();
    CHECK(Token::open(cb3, key, rules()).error() == Error::invalid);
    CHECK(CompactToken::open(cb2, key, rules()).error() == Error::invalid);
    const std::string relabelled = "cb2.local." + cb3.substr(10);
    CHECK(Token::open(relabelled, key, rules()).error() == Error::invalid);
    const std::string relabelled3 = "cb3.local." + cb2.substr(10);
    CHECK(CompactToken::open(relabelled3, key, rules()).error() == Error::invalid);
}

TEST_CASE("compact/the key digest binds the key id") {
    LocalKey key = key_a();
    const Claims c = good_claims();
    const std::string tok = CompactToken::seal(key, c).value();
    const auto d = CompactToken::peek_key_digest(tok);
    REQUIRE(d.has_value());
    const std::string f = CompactToken::footer_for(key.key_id());
    CHECK(f.size() == 16 && std::string(d->value.begin(), d->value.end()) == f);
    LocalKey renamed = key_a();
    renamed.set_key_id("other");
    CHECK(CompactToken::open(tok, renamed, rules()).error() == Error::invalid);
    LocalKey anonymous = key_a();
    anonymous.clear_key_id();
    CHECK(CompactToken::open(tok, anonymous, rules()).error() == Error::invalid);
    const std::string bare = CompactToken::seal(anonymous, c).value();
    CHECK(bare.find('.', 10) == std::string::npos);
    CHECK(CompactToken::open(bare, anonymous, rules()).is_ok());
    CHECK(CompactToken::open(bare, key, rules()).error() == Error::invalid);
    CHECK(!CompactToken::peek_key_digest(bare).has_value());
}

TEST_CASE("compact/every changed character of a cb3.local token is refused") {
    const LocalKey key = key_a();
    const std::string tok = CompactToken::seal(key, good_claims()).value();
    for (std::size_t i = 0; i < tok.size(); ++i) {
        std::string t = tok;
        t[i] = t[i] == 'A' ? 'B' : 'A';
        const auto r = CompactToken::open(t, key, rules());
        CHECK(r.is_err() && r.error() == Error::invalid);
    }
}

TEST_CASE("compact/a cb3.local token bound to a local proof key needs its proof") {
    const LocalKey key = key_a();
    Claims c = good_claims();
    const LocalKey proof_key = cb2::HolderProof::bind_local(c).value();
    const std::string tok = CompactToken::seal(key, c).value();
    CHECK(CompactToken::open(tok, key, rules()).error() == Error::missing_proof);
    const cb2::HolderRequest get{"GET", "https://api.example/v1/me", std::nullopt};
    const std::string proof = cb2::HolderProof::make_local(proof_key, get, tok, "p-1", NOW, 60).value();
    auto with = rules().with_holder_proof(proof, get).with_proof_replay_check([](std::string_view) { return true; });
    const auto opened = CompactToken::open(tok, key, with);
    REQUIRE(opened.is_ok());
    CHECK(opened.value().cnf == c.cnf);
    const std::string other = cb2::HolderProof::make_local(proof_key, get, Token::seal(key, c).value(), "p-2", NOW, 60).value();
    auto wrong = rules().with_holder_proof(other, get).with_proof_replay_check([](std::string_view) { return true; });
    CHECK(CompactToken::open(tok, key, wrong).error() == Error::proof_invalid);
}

#ifdef CB2_HAS_PQ
TEST_CASE("compact/cb3.public signs and verifies, bound tokens included") {
    const auto issuer = cb2::SecretKey::generate().value();
    const auto client = cb2::SecretKey::generate().value();
    Claims c = good_claims();
    const std::string tok = CompactToken::sign(issuer, c).value();
    CHECK(tok.starts_with("cb3.public."));
    const auto ok = CompactToken::verify(tok, issuer.public_key(), rules());
    REQUIRE(ok.is_ok());
    CHECK(ok.value().to_json() == c.to_json());
    CHECK(Token::verify(tok, issuer.public_key(), rules()).error() == Error::invalid);
    CHECK(CompactToken::verify(Token::sign(issuer, c).value(), issuer.public_key(), rules()).error() == Error::invalid);
    std::string t = tok;
    t[20] = t[20] == 'A' ? 'B' : 'A';
    CHECK(CompactToken::verify(t, issuer.public_key(), rules()).error() == Error::invalid);
    c.cnf = client.public_key().to_paserk();
    const std::string bound = CompactToken::sign(issuer, c).value();
    const std::string json_bound = Token::sign(issuer, c).value();
    CHECK(bound.size() + 800 < json_bound.size());
    const cb2::HolderRequest get{"GET", "https://api.example/v1/me", std::nullopt};
    const std::string proof = cb2::HolderProof::make(client, get, bound, "p-1", NOW, 60).value();
    auto with = rules().with_holder_proof(proof, get).with_proof_replay_check([](std::string_view) { return true; });
    const auto checked = CompactToken::verify(bound, issuer.public_key(), with);
    REQUIRE(checked.is_ok());
    CHECK(checked.value().cnf == c.cnf);
    Claims local_cnf = good_claims();
    (void)cb2::HolderProof::bind_local(local_cnf);
    CHECK(CompactToken::sign(issuer, local_cnf).error() == Error::argument);
}
#endif
