#include "test_runner.hpp"
#include "test_util.hpp"

#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

using cb2::ClaimTable;
using cb2::Claims;
using cb2::CompactClaims;
using cb2::CompactToken;
using cb2::Error;
using cb2::LocalKey;
using cb2::Seconds;
using cb2::ValidationRules;

namespace {

constexpr Seconds NOW = 1700000000;
const char* const ISSUER = "https://issuer.example";

LocalKey key_a() { return LocalKey::from_bytes(tu::pattern(32, 0x70)).value(); }

ClaimTable table() { return ClaimTable::make({ISSUER, "api", "billing"}).value(); }

Claims claims() {
    Claims c;
    c.iss = ISSUER;
    c.sub = "user-1";
    c.aud = "billing";
    c.exp = NOW + 900;
    c.iat = NOW;
    return c;
}

ValidationRules rules() { return ValidationRules().at(NOW).expect_issuer(ISSUER).expect_audience("billing"); }

std::vector<uint8_t> raw(std::initializer_list<int> b) {
    std::vector<uint8_t> v;
    for (const int x : b) v.push_back(static_cast<uint8_t>(x));
    return v;
}

Error decode_error(const std::vector<uint8_t>& payload, const ClaimTable* t) {
    const auto r = CompactClaims::decode(payload, t);
    return r.is_ok() ? Error::internal : r.error();
}

std::size_t local_len(std::size_t payload) { return 10 + ((32 + payload + 32) * 4 + 2) / 3 + 1 + 22; }

}

TEST_CASE("claim table/make accepts 1 to 256 distinct identifiers and nothing else") {
    std::vector<std::string> full;
    for (int i = 0; i < 256; ++i) full.push_back("aud-" + std::to_string(i));
    CHECK(ClaimTable::make(full).is_ok());
    full.push_back("one-more");
    CHECK(ClaimTable::make(full).error() == Error::argument);
    CHECK(ClaimTable::make({}).error() == Error::argument);
    CHECK(ClaimTable::make({"api", "api"}).error() == Error::argument);
    CHECK(ClaimTable::make({"api", ""}).error() == Error::argument);
    CHECK(ClaimTable::make({"a\nb"}).error() == Error::argument);
}

TEST_CASE("claim table/the digest covers every entry and their order") {
    const auto a = ClaimTable::make({"x", "y"}).value();
    CHECK(a.digest() == ClaimTable::make({"x", "y"}).value().digest());
    CHECK(a.digest() != ClaimTable::make({"y", "x"}).value().digest());
    CHECK(a.digest() != ClaimTable::make({"x", "y", "z"}).value().digest());
    CHECK(a.digest() != ClaimTable::make({"xy"}).value().digest());
    const std::string bound = a.bind("ctx");
    CHECK(bound.size() == 11 + 32 + 3 && bound.starts_with("kcb3.table.") && bound.ends_with("ctx"));
}

TEST_CASE("claim table/iss and aud in the table travel as indexes") {
    const ClaimTable t = table();
    const std::string plain = CompactClaims::encode(claims()).value();
    const std::string packed = CompactClaims::encode(claims(), &t).value();
    CHECK(plain.size() - packed.size() == (1 + 22 - 1) + (1 + 7 - 1));
    CHECK(static_cast<uint8_t>(packed[1]) == 0x01 && static_cast<uint8_t>(packed[2]) == 0x00);
    const auto back = CompactClaims::decode({reinterpret_cast<const uint8_t*>(packed.data()), packed.size()}, &t);
    REQUIRE(back.is_ok());
    CHECK(back.value().to_json() == claims().to_json());
    Claims other = claims();
    other.aud = "mobile";
    const std::string mixed = CompactClaims::encode(other, &t).value();
    CHECK(mixed.find("mobile") != std::string::npos);
    CHECK(CompactClaims::decode({reinterpret_cast<const uint8_t*>(mixed.data()), mixed.size()}, &t).value().aud == "mobile");
}

TEST_CASE("claim table/an index or a text that the table forbids is claims_malformed") {
    const ClaimTable t = table();
    CHECK(decode_error(raw({0xa1, 0x01, 0x03}), &t) == Error::claims_malformed);
    CHECK(decode_error(raw({0xa1, 0x03, 0x18, 0x18}), &t) == Error::claims_malformed);
    CHECK(decode_error(raw({0xa1, 0x01, 0x00}), nullptr) == Error::claims_malformed);
    CHECK(decode_error(raw({0xa1, 0x02, 0x00}), &t) == Error::claims_malformed);
    CHECK(decode_error(raw({0xa1, 0x03, 0x63, 'a', 'p', 'i'}), &t) == Error::claims_malformed);
    CHECK(decode_error(raw({0xa1, 0x03, 0x18, 0x01}), &t) == Error::claims_malformed);
    CHECK(CompactClaims::decode(raw({0xa1, 0x03, 0x02}), &t).value().aud == "billing");
    CHECK(CompactClaims::decode(raw({0xa1, 0x03, 0x63, 'a', 'p', 'i'}), nullptr).value().aud == "api");
}

TEST_CASE("claim table/a tabled token opens only under the same table") {
    const LocalKey key = key_a();
    const ClaimTable t = table();
    const std::string tok = CompactToken::seal(key, claims(), t).value();
    const std::string plain = CompactToken::seal(key, claims()).value();
    CHECK(tok.size() == local_len(CompactClaims::encode(claims(), &t).value().size()));
    CHECK(plain.size() == local_len(CompactClaims::encode(claims()).value().size()));
    CHECK(plain.size() - tok.size() >= 38);
    const auto opened = CompactToken::open(tok, key, rules(), t);
    REQUIRE(opened.is_ok());
    CHECK(opened.value().to_json() == claims().to_json());
    CHECK(CompactToken::open(tok, key, rules()).error() == Error::invalid);
    CHECK(CompactToken::open(tok, key, rules(), ClaimTable::make({"api", ISSUER, "billing"}).value()).error() == Error::invalid);
    CHECK(CompactToken::open(tok, key, rules(), ClaimTable::make({ISSUER, "api", "billing", "x"}).value()).error() == Error::invalid);
    CHECK(CompactToken::open(plain, key, rules(), t).error() == Error::invalid);
    CHECK(CompactToken::open(tok, key, rules(), t, "ctx").error() == Error::invalid);
    const std::string with_ctx = CompactToken::seal(key, claims(), t, "ctx").value();
    CHECK(CompactToken::open(with_ctx, key, rules(), t, "ctx").is_ok());
}

TEST_CASE("claim table/issuer and audience verdicts survive the table") {
    const LocalKey key = key_a();
    const ClaimTable t = table();
    const std::string tok = CompactToken::seal(key, claims(), t).value();
    CHECK(CompactToken::open(tok, key, ValidationRules().at(NOW).expect_issuer("https://other.example").expect_audience("billing"), t).error() == Error::issuer_mismatch);
    CHECK(CompactToken::open(tok, key, ValidationRules().at(NOW).expect_issuer(ISSUER).expect_audience("api"), t).error() == Error::audience_mismatch);
    CHECK(CompactToken::open(tok, key, ValidationRules().at(NOW).allow_any_issuer().allow_any_audience(), t).is_ok());
    CHECK(CompactToken::open(tok, key, ValidationRules().at(NOW + 900).expect_issuer(ISSUER).expect_audience("billing"), t).error() == Error::expired);
}

TEST_CASE("claim table/an implicit assertion that could pass for a bound one is refused") {
    const LocalKey key = key_a();
    const ClaimTable t = table();
    const std::string bound = t.bind("");
    CHECK(CompactToken::seal(key, claims(), bound).error() == Error::argument);
    CHECK(CompactToken::seal(key, claims(), "kcb3.table.").error() == Error::argument);
    const std::string tok = CompactToken::seal(key, claims(), t).value();
    CHECK(CompactToken::open(tok, key, rules(), bound).error() == Error::argument);
    CHECK(CompactToken::seal(key, claims(), t, "kcb3.table.x").is_ok());
    CHECK(CompactToken::seal(key, claims(), "kcb3.tablex").is_ok());
}

#ifdef CB2_HAS_PQ
TEST_CASE("claim table/cb3.public signs and verifies under a table") {
    const auto issuer = cb2::SecretKey::generate().value();
    const ClaimTable t = table();
    const std::string tok = CompactToken::sign(issuer, claims(), t).value();
    CHECK(tok.size() + 38 <= CompactToken::sign(issuer, claims()).value().size());
    CHECK(CompactToken::verify(tok, issuer.public_key(), rules(), t).is_ok());
    CHECK(CompactToken::verify(tok, issuer.public_key(), rules()).error() == Error::invalid);
    CHECK(CompactToken::verify(tok, issuer.public_key(), rules(), ClaimTable::make({ISSUER}).value()).error() == Error::invalid);
    CHECK(CompactToken::sign(issuer, claims(), t.bind("")).error() == Error::argument);
}
#endif
