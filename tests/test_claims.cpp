#include "test_runner.hpp"
#include "test_util.hpp"

#include <string>
#include <vector>

using paseto5::Claims;
using paseto5::Error;
using paseto5::LocalKey;
using paseto5::Rfc3339;
using paseto5::Seconds;
using paseto5::Token;
using paseto5::ValidationRules;
using tu::Bytes;

namespace {

constexpr Seconds NOW = 1700000000;

LocalKey key_a() { return LocalKey::from_bytes(tu::pattern(32, 0x70)).value(); }

bool json_ok(std::string_view s) {
    paseto5::json::Value v;
    return paseto5::json::Reader::parse(s, v);
}

Claims good_claims() {
    Claims c;
    c.iss = "https://issuer.example";
    c.sub = "user-1";
    c.aud = "api";
    c.exp = NOW + 3600;
    c.nbf = NOW - 10;
    c.iat = NOW - 10;
    c.jti = "id-1";
    CHECK(c.set("role", "admin"));
    return c;
}

}

TEST_CASE("claims/rfc3339 parses and formats") {
    Seconds t = 0;
    CHECK(Rfc3339::parse("1970-01-01T00:00:00Z", t) && t == 0);
    CHECK(Rfc3339::parse("2022-01-01T00:00:00+00:00", t) && t == 1640995200);
    CHECK(Rfc3339::parse("2000-02-29T12:00:00Z", t) && t == 951825600);
    CHECK(Rfc3339::parse("2023-11-14T22:13:20Z", t) && t == NOW);
    CHECK(Rfc3339::parse("2023-11-14T23:13:20+01:00", t) && t == NOW);
    CHECK(Rfc3339::parse("2023-11-14T20:43:20-01:30", t) && t == NOW);
    CHECK(Rfc3339::parse("2023-11-14t22:13:20.123z", t) && t == NOW);
    CHECK(Rfc3339::parse("2038-01-19T03:14:08Z", t) && t == 2147483648LL);
    CHECK(Rfc3339::parse("1969-12-31T23:59:59Z", t) && t == -1);
    CHECK(!Rfc3339::parse("2023-11-14T22:13:20", t));
    CHECK(!Rfc3339::parse("2023-13-14T22:13:20Z", t));
    CHECK(!Rfc3339::parse("2023-02-29T22:13:20Z", t));
    CHECK(!Rfc3339::parse("2023-11-14T24:13:20Z", t));
    CHECK(!Rfc3339::parse("2023-11-14T22:13:20.Z", t));
    CHECK(!Rfc3339::parse("2023-11-14T22:13:20+0100", t));
    CHECK(!Rfc3339::parse("2023-11-14T22:13:20+25:00", t));
    CHECK(!Rfc3339::parse("2023-11-14 22:13:20Z", t));
    CHECK(!Rfc3339::parse("", t));
    CHECK(!Rfc3339::parse("1700000000", t));
    CHECK(Rfc3339::format(0) == "1970-01-01T00:00:00+00:00");
    CHECK(Rfc3339::format(1640995200) == "2022-01-01T00:00:00+00:00");
    CHECK(Rfc3339::format(-1) == "1969-12-31T23:59:59+00:00");
    for (Seconds s : {Seconds{0}, Seconds{951825600}, Seconds{NOW}, Seconds{4102444800LL}, Seconds{-86400 * 365}}) {
        Seconds back = 0;
        CHECK(Rfc3339::parse(Rfc3339::format(s), back) && back == s);
    }
}

TEST_CASE("claims/json reader is strict") {
    CHECK(json_ok("{}"));
    CHECK(json_ok(" {\"a\":1,\"b\":[1,2,{\"c\":null}],\"d\":\"\\u00e9\\ud83d\\ude00\",\"e\":true} "));
    CHECK(json_ok("\"\xc3\xa9\""));
    CHECK(json_ok("-0.5e+10"));
    CHECK(!json_ok(""));
    CHECK(!json_ok("{\"a\":1,}"));
    CHECK(!json_ok("{\"a\":1,\"a\":2}"));
    CHECK(!json_ok("{a:1}"));
    CHECK(!json_ok("01"));
    CHECK(!json_ok("1."));
    CHECK(!json_ok(".5"));
    CHECK(!json_ok("+1"));
    CHECK(!json_ok("NaN"));
    CHECK(!json_ok("\"tab\there\""));
    CHECK(!json_ok("\"\\x41\""));
    CHECK(!json_ok("\"\\ud83d\""));
    CHECK(!json_ok("\"\\ude00\""));
    CHECK(!json_ok("\"\xc3\""));
    CHECK(!json_ok("\"\xc0\x80\""));
    CHECK(!json_ok("\"\xed\xa0\x80\""));
    CHECK(!json_ok("{} {}"));
    CHECK(!json_ok(std::string_view("{}\0", 3)));
    CHECK(!json_ok("\xef\xbb\xbf{}"));
    CHECK(!json_ok("[1 2]"));
    std::string deep;
    for (int i = 0; i < 20; ++i) deep += '[';
    for (int i = 0; i < 20; ++i) deep += ']';
    CHECK(!json_ok(deep));
    std::string shallow;
    for (int i = 0; i < 10; ++i) shallow += '[';
    for (int i = 0; i < 10; ++i) shallow += ']';
    CHECK(json_ok(shallow));
}

TEST_CASE("claims/json writer escapes and the reader reads it back") {
    std::string out;
    paseto5::json::Writer::string(out, "a\"b\\c\n\x01\x1f\x7f\xc3\xa9/");
    CHECK(out == "\"a\\\"b\\\\c\\n\\u0001\\u001f\x7f\xc3\xa9/\"");
    paseto5::json::Value v;
    CHECK(paseto5::json::Reader::parse(out, v));
    CHECK(v.text == "a\"b\\c\n\x01\x1f\x7f\xc3\xa9/");
}

TEST_CASE("claims/to_json and from_json round trip without number coercion") {
    Claims c = good_claims();
    CHECK(c.set_json("n", "1.50e3"));
    CHECK(c.set_json("obj", "{\"x\":[1,2]}"));
    CHECK(!c.set("exp", "x"));
    CHECK(!c.set("", "x"));
    CHECK(!c.set_json("bad", "{"));
    const std::string j = c.to_json();
    CHECK(j.rfind("{\"iss\":\"https://issuer.example\",\"sub\":\"user-1\",\"aud\":\"api\",\"exp\":\"2023-11-14T23:13:20+00:00\"", 0) == 0);
    auto back = Claims::from_json(j);
    REQUIRE(back.is_ok());
    const Claims& b = back.value();
    CHECK(b.iss == c.iss && b.sub == c.sub && b.aud == c.aud && b.jti == c.jti);
    CHECK(b.exp == c.exp && b.nbf == c.nbf && b.iat == c.iat);
    CHECK(b.get("role") == std::optional<std::string_view>("admin"));
    CHECK(!b.get("n").has_value());
    CHECK(b.get_json("n") == std::optional<std::string>("1.50e3"));
    CHECK(b.get_json("obj") == std::optional<std::string>("{\"x\":[1,2]}"));
    CHECK(!b.get("missing").has_value());
    CHECK(b.to_json() == j);
}

TEST_CASE("claims/registered claims must be strings with valid timestamps") {
    CHECK(Claims::from_json("{\"exp\":1700000000}").is_err());
    CHECK(Claims::from_json("{\"exp\":\"soon\"}").is_err());
    CHECK(Claims::from_json("{\"aud\":[\"a\"]}").is_err());
    CHECK(Claims::from_json("[]").is_err());
    CHECK(Claims::from_json("{\"exp\":\"2023-11-14T22:13:20Z\",\"exp\":\"2023-11-14T22:13:20Z\"}").is_err());
    auto ok = Claims::from_json("{}");
    CHECK(ok.is_ok() && !ok.value().exp.has_value());
}

TEST_CASE("claims/validator enforces exp, nbf, iat, skew and bindings") {
    const Claims c = good_claims();
    CHECK(tu::lenient(NOW).check(c).is_ok());
    auto e = tu::lenient(NOW + 3600).check(c);
    CHECK(e.is_err() && e.error() == Error::expired);
    CHECK(tu::lenient(NOW + 3600 - 1).check(c).is_ok());
    CHECK(tu::lenient(NOW + 3600 + 30).with_clock_skew(60).check(c).is_ok());
    Claims no_exp = good_claims();
    no_exp.exp.reset();
    auto m = tu::lenient(NOW).check(no_exp);
    CHECK(m.is_err() && m.error() == Error::missing_exp);
    CHECK(tu::lenient(NOW).allow_missing_exp().check(no_exp).is_ok());
    Claims future = good_claims();
    future.nbf = NOW + 100;
    auto n = tu::lenient(NOW).check(future);
    CHECK(n.is_err() && n.error() == Error::not_yet_valid);
    CHECK(tu::lenient(NOW).with_clock_skew(100).check(future).is_ok());
    Claims iat = good_claims();
    iat.iat = NOW + 100;
    auto i = tu::lenient(NOW).check(iat);
    CHECK(i.is_err() && i.error() == Error::issued_in_future);
    auto iss = tu::lenient(NOW).expect_issuer("other").check(c);
    CHECK(iss.is_err() && iss.error() == Error::issuer_mismatch);
    auto aud = tu::lenient(NOW).expect_audience("other").check(c);
    CHECK(aud.is_err() && aud.error() == Error::audience_mismatch);
    auto sub = tu::lenient(NOW).expect_subject("other").check(c);
    CHECK(sub.is_err() && sub.error() == Error::subject_mismatch);
    CHECK(tu::lenient(NOW).expect_issuer("https://issuer.example").expect_audience("api").expect_subject("user-1").check(c).is_ok());
    Claims no_aud = good_claims();
    no_aud.aud.reset();
    CHECK(tu::lenient(NOW).expect_audience("api").check(no_aud).is_err());
}

TEST_CASE("claims/token layer binds the key id into the footer and validates after authenticating") {
    const LocalKey k = key_a();
    const Claims c = good_claims();
    auto tok = Token::seal(k, c, "ctx");
    REQUIRE(tok.is_ok());
    CHECK(tok.value().find('.', 9) != std::string::npos);
    auto peek = Token::peek_key_id(tok.value());
    REQUIRE(peek.has_value());
    CHECK(peek->value == k.paserk_id());
    auto open = Token::open(tok.value(), k, tu::lenient(NOW).expect_audience("api"), "ctx");
    REQUIRE(open.is_ok());
    CHECK(open.value().sub == c.sub);
    CHECK(open.value().get("role") == std::optional<std::string_view>("admin"));

    LocalKey renamed = k.clone();
    renamed.set_key_id("other");
    auto r = Token::open(tok.value(), renamed, tu::lenient(NOW), "ctx");
    CHECK(r.is_err() && r.error() == Error::invalid);
    LocalKey anonymous = k.clone();
    anonymous.clear_key_id();
    auto a = Token::open(tok.value(), anonymous, tu::lenient(NOW), "ctx");
    CHECK(a.is_err() && a.error() == Error::invalid);
    auto wrong_ctx = Token::open(tok.value(), k, tu::lenient(NOW), "ctz");
    CHECK(wrong_ctx.is_err() && wrong_ctx.error() == Error::invalid);

    auto expired = Token::open(tok.value(), k, tu::lenient(NOW + 7200), "ctx");
    CHECK(expired.is_err() && expired.error() == Error::expired);
    auto aud = Token::open(tok.value(), k, tu::lenient(NOW).expect_audience("other"), "ctx");
    CHECK(aud.is_err() && aud.error() == Error::audience_mismatch);

    auto big = Token::open(tok.value(), k, tu::lenient(NOW).with_max_token_bytes(tok.value().size() - 1), "ctx");
    CHECK(big.is_err() && big.error() == Error::too_large);
    const std::string garbage(ValidationRules::DEFAULT_MAX_TOKEN_BYTES + 1, 'A');
    auto g = Token::open(garbage, k, tu::lenient(NOW), "ctx");
    CHECK(g.is_err() && g.error() == Error::too_large);
    CHECK(!Token::peek_key_id(garbage).has_value());

    auto no_kid = Token::seal(anonymous, c);
    REQUIRE(no_kid.is_ok());
    CHECK(no_kid.value().find('.', 9) == std::string::npos);
    CHECK(!Token::peek_key_id(no_kid.value()).has_value());
    CHECK(Token::open(no_kid.value(), anonymous, tu::lenient(NOW)).is_ok());
    CHECK(Token::open(no_kid.value(), k, tu::lenient(NOW)).is_err());
    CHECK(Token::footer_for(std::optional<std::string>("a\"b")) == "{\"kid\":\"a\\\"b\"}");
    CHECK(Token::footer_for(std::nullopt).empty());
}

TEST_CASE("claims/a token whose payload is not a claims object is claims_malformed after authentication") {
    const LocalKey k = key_a();
    auto tok = paseto5::Local::seal(k, tu::bytes_of("[1,2]"), paseto5::bytes(Token::footer_for(k.key_id())));
    REQUIRE(tok.is_ok());
    auto r = Token::open(tok.value(), k, tu::lenient(NOW));
    CHECK(r.is_err() && r.error() == Error::claims_malformed);
    auto tok2 = paseto5::Local::seal(k, tu::bytes_of("{\"exp\":123}"), paseto5::bytes(Token::footer_for(k.key_id())));
    REQUIRE(tok2.is_ok());
    auto r2 = Token::open(tok2.value(), k, tu::lenient(NOW));
    CHECK(r2.is_err() && r2.error() == Error::claims_malformed);
}

#ifdef PASETO5_HAS_PQ
TEST_CASE("claims/public token layer binds the key id and validates") {
    static const paseto5::SecretKey sk = paseto5::SecretKey::generate().value();
    const paseto5::PublicKey pk = sk.public_key();
    const Claims c = good_claims();
    auto tok = Token::sign(sk, c, "ctx");
    REQUIRE(tok.is_ok());
    auto peek = Token::peek_key_id(tok.value());
    REQUIRE(peek.has_value());
    CHECK(peek->value == pk.paserk_id());
    auto v = Token::verify(tok.value(), pk, tu::lenient(NOW).expect_issuer("https://issuer.example"), "ctx");
    REQUIRE(v.is_ok());
    CHECK(v.value().jti == c.jti);
    auto expired = Token::verify(tok.value(), pk, tu::lenient(NOW + 7200), "ctx");
    CHECK(expired.is_err() && expired.error() == Error::expired);
    paseto5::PublicKey renamed = pk;
    renamed.set_key_id("other");
    auto r = Token::verify(tok.value(), renamed, tu::lenient(NOW), "ctx");
    CHECK(r.is_err() && r.error() == Error::invalid);
    auto small = Token::verify(tok.value(), pk, tu::lenient(NOW).with_max_token_bytes(4096), "ctx");
    CHECK(small.is_err() && small.error() == Error::too_large);
}
#endif

TEST_CASE("claims/rules must name an audience and an issuer or allow any, before the token is read") {
    const LocalKey k = key_a();
    const Claims c = good_claims();
    auto tok = Token::seal(k, c);
    REQUIRE(tok.is_ok());
    CHECK(!ValidationRules().complete());
    CHECK(!ValidationRules().expect_audience("api").complete());
    CHECK(!ValidationRules().expect_issuer("https://issuer.example").complete());
    CHECK(ValidationRules().expect_audience("api").expect_issuer("https://issuer.example").complete());
    CHECK(ValidationRules().expect_audience("api").allow_any_issuer().complete());
    CHECK(ValidationRules().allow_any_audience().expect_issuer("x").complete());
    CHECK(ValidationRules().allow_any_audience().allow_any_issuer().complete());
    auto silent = ValidationRules().at(NOW).check(c);
    CHECK(silent.is_err() && silent.error() == Error::rules_incomplete);
    auto half = Token::open(tok.value(), k, ValidationRules().at(NOW).expect_audience("api"));
    CHECK(half.is_err() && half.error() == Error::rules_incomplete);
    auto garbage = Token::open(std::string(100000, 'A'), k, ValidationRules().at(NOW));
    CHECK(garbage.is_err() && garbage.error() == Error::rules_incomplete);
    LocalKey bad_kid = k.clone();
    bad_kid.set_key_id("a\xe2\x80\x8b");
    auto before_kid = Token::open(tok.value(), bad_kid, ValidationRules().at(NOW));
    CHECK(before_kid.is_err() && before_kid.error() == Error::rules_incomplete);
    CHECK(Token::open(tok.value(), k, ValidationRules().at(NOW).expect_audience("api").expect_issuer("https://issuer.example")).is_ok());
    CHECK(Token::open(tok.value(), k, ValidationRules().at(NOW).expect_audience("api").allow_any_issuer()).is_ok());
    CHECK(Token::open(tok.value(), k, tu::lenient(NOW)).is_ok());
    auto other = Token::open(tok.value(), k, ValidationRules().at(NOW).expect_audience("other-service").allow_any_issuer());
    CHECK(other.is_err() && other.error() == Error::audience_mismatch);
}

TEST_CASE("claims/the replay check runs last and sees the jti of tokens that passed everything else") {
    const LocalKey k = key_a();
    const Claims c = good_claims();
    auto tok = Token::seal(k, c);
    REQUIRE(tok.is_ok());
    std::vector<std::string> seen;
    auto remember = [&seen](std::string_view jti) {
        for (const auto& s : seen) if (s == jti) return false;
        seen.emplace_back(jti);
        return true;
    };
    const auto rules = tu::lenient(NOW).with_replay_check(remember);
    CHECK(rules.has_replay_check());
    CHECK(Token::open(tok.value(), k, rules).is_ok());
    auto again = Token::open(tok.value(), k, rules);
    CHECK(again.is_err() && again.error() == Error::replayed);
    CHECK(seen.size() == 1 && seen[0] == "id-1");
    auto expired = Token::open(tok.value(), k, tu::lenient(NOW + 7200).with_replay_check([&seen](std::string_view) {
        seen.emplace_back("should not be called");
        return true;
    }));
    CHECK(expired.is_err() && expired.error() == Error::expired);
    CHECK(seen.size() == 1);
    Claims no_jti = good_claims();
    no_jti.jti.reset();
    auto anon = Token::seal(k, no_jti);
    REQUIRE(anon.is_ok());
    auto missing = Token::open(anon.value(), k, tu::lenient(NOW).with_replay_check([](std::string_view) { return true; }));
    CHECK(missing.is_err() && missing.error() == Error::missing_jti);
    CHECK(Token::open(anon.value(), k, tu::lenient(NOW)).is_ok());
    auto thrown = Token::open(tok.value(), k, tu::lenient(NOW).with_replay_check([](std::string_view) -> bool { throw 1; }));
    CHECK(thrown.is_err() && thrown.error() == Error::internal);
}
