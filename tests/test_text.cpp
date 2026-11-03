#include "test_runner.hpp"
#include "test_util.hpp"

#include <string>
#include <string_view>

using cb2::Claims;
using cb2::Error;
using cb2::LocalKey;
using cb2::Token;
using cb2::ValidationRules;
namespace text = cb2::text;

namespace {

constexpr cb2::Seconds NOW = 1700000000;

constexpr std::string_view N_TILDE = "\xc3\xb1";
constexpr std::string_view N_COMBINING = "n\xcc\x83";
constexpr std::string_view ZWSP = "\xe2\x80\x8b";
constexpr std::string_view RLO = "\xe2\x80\xae";
constexpr std::string_view BOM = "\xef\xbb\xbf";
constexpr std::string_view SOFT_HYPHEN = "\xc2\xad";
constexpr std::string_view VS16 = "\xef\xb8\x8f";
constexpr std::string_view TAG_A = "\xf3\xa0\x81\x81";
constexpr std::string_view NONCHAR = "\xef\xbf\xbe";
constexpr std::string_view PRIVATE_USE = "\xee\x80\x80";
constexpr std::string_view PLANE15 = "\xf3\xb0\x80\x80";
constexpr std::string_view C1_NEL = "\xc2\x85";
constexpr std::string_view JAPANESE = "\xe6\x97\xa5\xe6\x9c\xac";
constexpr std::string_view ARABIC = "\xd8\xb9\xd8\xb1\xd8\xa8\xd9\x8a";
constexpr std::string_view GREEK = "\xce\xb1\xce\xb2\xce\xb3";
constexpr std::string_view DEVANAGARI = "\xe0\xa4\xa8\xe0\xa4\xbf";
constexpr std::string_view EMOJI = "\xf0\x9f\x98\x80";
constexpr std::string_view ISSUER = "Compa\xc3\xb1\xc3\xad" "a";

LocalKey key_a() { return LocalKey::from_bytes(tu::pattern(32, 0x70)).value(); }

template <class... Parts>
std::string cat(Parts... parts) {
    std::string s;
    (s.append(std::string_view(parts)), ...);
    return s;
}

Claims international() {
    Claims c;
    c.iss = ISSUER;
    c.sub = std::string(JAPANESE);
    c.aud = std::string(ARABIC);
    c.jti = cat(GREEK, "-", EMOJI);
    c.exp = NOW + 3600;
    CHECK(c.set(cat("a", N_TILDE, "o"), "2026"));
    CHECK(c.set("ciudad", "Bogot\xc3\xa1"));
    return c;
}

std::string raw_token(const LocalKey& k, std::string_view payload) {
    auto t = cb2::Local::seal(k, tu::bytes_of(payload), cb2::bytes(Token::footer_for(k.key_id())));
    CHECK(t.is_ok());
    return t.is_ok() ? t.value() : std::string();
}

}

TEST_CASE("text/the UTF-8 decoder is strict") {
    for (const auto s : {N_TILDE, N_COMBINING, ZWSP, JAPANESE, ARABIC, GREEK, DEVANAGARI, EMOJI, TAG_A, PLANE15})
        CHECK(text::valid_utf8(s));
    CHECK(text::valid_utf8(""));
    CHECK(text::valid_utf8("plain ascii"));
    for (const auto s : {"\xc0\x80", "\xc1\xbf", "\xe0\x80\x80", "\xed\xa0\x80", "\xf0\x80\x80\x80",
                         "\xf4\x90\x80\x80", "\xf5\x80\x80\x80", "\xc3", "\x80", "\xe6\x97", "\xf8\x88\x80\x80\x80"})
        CHECK(!text::valid_utf8(s));
    std::size_t i = 0;
    unsigned cp = 0;
    CHECK(text::decode(EMOJI, i, cp) && cp == 0x1F600 && i == 4);
    i = 0;
    CHECK(text::decode(N_TILDE, i, cp) && cp == 0xF1 && i == 2);
}

TEST_CASE("text/the identifier policy accepts every script and refuses the invisible") {
    for (const auto s : {N_TILDE, N_COMBINING, JAPANESE, ARABIC, GREEK, DEVANAGARI, EMOJI, ISSUER})
        CHECK(text::identifier_ok(s));
    CHECK(text::identifier_ok(""));
    CHECK(text::identifier_ok("https://issuer.example/path?q=1 with spaces"));
    for (const auto s : {ZWSP, RLO, BOM, SOFT_HYPHEN, VS16, TAG_A, NONCHAR, PRIVATE_USE, PLANE15, C1_NEL})
        CHECK(!text::identifier_ok(cat("a", s, "b")));
    CHECK(!text::identifier_ok(std::string_view("a\0b", 3)));
    CHECK(!text::identifier_ok("a\tb"));
    CHECK(!text::identifier_ok("a\x7f" "b"));
    CHECK(!text::identifier_ok("\xc3"));
    CHECK(text::is_noncharacter(0xFFFE) && text::is_noncharacter(0x10FFFF) && text::is_noncharacter(0xFDD0));
    CHECK(!text::is_noncharacter(0xFDF0) && !text::is_noncharacter(0xFFFD));
    CHECK(text::is_default_ignorable(0x2066) && text::is_default_ignorable(0xE0001));
    CHECK(!text::is_default_ignorable(0x20) && !text::is_default_ignorable(0x303));
}

TEST_CASE("text/international claims round trip and bind byte for byte") {
    LocalKey k = key_a();
    k.set_key_id(cat("llave-", N_TILDE));
    const Claims c = international();
    auto tok = Token::seal(k, c, cat("contexto-", EMOJI));
    REQUIRE(tok.is_ok());
    for (const char ch : tok.value()) CHECK(static_cast<unsigned char>(ch) < 0x80);
    auto peek = Token::peek_key_id(tok.value());
    REQUIRE(peek.has_value());
    CHECK(peek->value == cat("llave-", N_TILDE));
    const auto rules = tu::lenient(NOW).expect_issuer(std::string(ISSUER))
                           .expect_audience(std::string(ARABIC)).expect_subject(std::string(JAPANESE));
    auto open = Token::open(tok.value(), k, rules, cat("contexto-", EMOJI));
    REQUIRE(open.is_ok());
    CHECK(open.value().jti == c.jti);
    CHECK(open.value().get(cat("a", N_TILDE, "o")) == std::optional<std::string_view>("2026"));
    CHECK(open.value().get("ciudad") == std::optional<std::string_view>("Bogot\xc3\xa1"));
    CHECK(open.value().to_json() == c.to_json());
    CHECK(c.to_json().find(ISSUER) != std::string::npos);
    CHECK(c.to_json().find("\\u") == std::string::npos);

    const std::string escaped = "{\"iss\":\"Compa\\u00f1\\u00eda\",\"sub\":\"\\u65e5\\u672c\",\"aud\":\"" +
                                std::string(ARABIC) + "\",\"exp\":\"2023-11-14T23:13:20+00:00\",\"jti\":\"" +
                                cat(GREEK, "-", "\\ud83d\\ude00") + "\"}";
    auto esc = Token::open(raw_token(k, escaped), k, rules);
    REQUIRE(esc.is_ok());
    CHECK(esc.value().iss == c.iss && esc.value().sub == c.sub && esc.value().jti == c.jti);
}

TEST_CASE("text/no normalisation: composed and decomposed forms are different identifiers") {
    const LocalKey k = key_a();
    Claims c = international();
    c.iss = cat("Espa", N_TILDE, "a");
    auto tok = Token::seal(k, c);
    REQUIRE(tok.is_ok());
    CHECK(Token::open(tok.value(), k, tu::lenient(NOW).expect_issuer(cat("Espa", N_TILDE, "a"))).is_ok());
    auto r = Token::open(tok.value(), k, tu::lenient(NOW).expect_issuer(cat("Espa", N_COMBINING, "a")));
    CHECK(r.is_err() && r.error() == Error::issuer_mismatch);
}

TEST_CASE("text/the issuer side refuses identifiers that break the policy") {
    const LocalKey k = key_a();
    for (const auto bad : {ZWSP, RLO, BOM, SOFT_HYPHEN, NONCHAR, PRIVATE_USE, C1_NEL, std::string_view("\xc3")}) {
        Claims c = international();
        c.iss = cat("issuer", bad);
        auto r = Token::seal(k, c);
        CHECK(r.is_err() && r.error() == Error::argument);
        Claims s = international();
        s.sub = cat("user", bad);
        CHECK(Token::seal(k, s).is_err());
        Claims j = international();
        j.jti = std::string(bad);
        CHECK(Token::seal(k, j).is_err());
        Claims n = international();
        CHECK(!n.set(cat("name", bad), "v"));
        CHECK(!n.set_json(cat("name", bad), "1"));
    }
    Claims value_ok = international();
    CHECK(value_ok.set("note", cat("a", ZWSP, RLO, "b")));
    CHECK(!value_ok.set("note", "\xc3"));
    auto tok = Token::seal(k, value_ok);
    REQUIRE(tok.is_ok());
    auto back = Token::open(tok.value(), k, tu::lenient(NOW));
    REQUIRE(back.is_ok());
    CHECK(back.value().get("note") == std::optional<std::string_view>(cat("a", ZWSP, RLO, "b")));

    LocalKey bad_kid = key_a();
    bad_kid.set_key_id(cat("kid", ZWSP));
    auto s = Token::seal(bad_kid, international());
    CHECK(s.is_err() && s.error() == Error::argument);
    auto o = Token::open(tok.value(), bad_kid, tu::lenient(NOW));
    CHECK(o.is_err() && o.error() == Error::argument);
    auto raw = cb2::Local::seal(bad_kid, tu::bytes_of("{}"), cb2::bytes(Token::footer_for(bad_kid.key_id())));
    REQUIRE(raw.is_ok());
    CHECK(!Token::peek_key_id(raw.value()).has_value());
}

TEST_CASE("text/the verifier side refuses identifiers that break the policy after authenticating") {
    const LocalKey k = key_a();
    const std::string exp = "\"exp\":\"2023-11-14T23:13:20+00:00\"";
    auto r1 = Token::open(raw_token(k, "{\"iss\":\"a\\u200bb\"," + exp + "}"), k, tu::lenient(NOW));
    CHECK(r1.is_err() && r1.error() == Error::claims_malformed);
    auto r2 = Token::open(raw_token(k, "{\"sub\":\"a" + std::string(RLO) + "b\"," + exp + "}"), k, tu::lenient(NOW));
    CHECK(r2.is_err() && r2.error() == Error::claims_malformed);
    auto r3 = Token::open(raw_token(k, "{\"a\\ufeffb\":1," + exp + "}"), k, tu::lenient(NOW));
    CHECK(r3.is_err() && r3.error() == Error::claims_malformed);
    auto r4 = Token::open(raw_token(k, "{\"jti\":\"\\ue000\"," + exp + "}"), k, tu::lenient(NOW));
    CHECK(r4.is_err() && r4.error() == Error::claims_malformed);
    auto ok = Token::open(raw_token(k, "{\"x\":\"a\\u200bb\",\"iss\":\"" + std::string(ISSUER) + "\"," + exp + "}"),
                          k, tu::lenient(NOW).expect_issuer(std::string(ISSUER)));
    REQUIRE(ok.is_ok());
    CHECK(ok.value().get("x") == std::optional<std::string_view>(cat("a", ZWSP, "b")));
    auto wrong_iss = Token::open(raw_token(k, "{\"iss\":\"a\\u200bb\"," + exp + "}"), k,
                                 tu::lenient(NOW).expect_issuer("ab"));
    CHECK(wrong_iss.is_err() && wrong_iss.error() == Error::claims_malformed);
}

TEST_CASE("text/the raw token layer carries any bytes in message, footer and implicit assertion") {
    const LocalKey k = key_a();
    const std::string msg = cat(JAPANESE, ZWSP, "\xff\x00\xfe");
    const std::string footer = cat(ARABIC, RLO);
    const std::string implicit = cat(EMOJI, BOM);
    auto tok = cb2::Local::seal(k, tu::bytes_of(msg), tu::bytes_of(footer), tu::bytes_of(implicit));
    REQUIRE(tok.is_ok());
    for (const char ch : tok.value()) CHECK(static_cast<unsigned char>(ch) < 0x80);
    auto back = cb2::Local::open(tok.value(), k, tu::bytes_of(footer), tu::bytes_of(implicit));
    REQUIRE(back.is_ok());
    CHECK(tu::str_of(back.value()) == msg);
    CHECK(cb2::Local::open(tok.value(), k, tu::bytes_of(cat(ARABIC)), tu::bytes_of(implicit)).is_err());
}
