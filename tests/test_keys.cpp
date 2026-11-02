#include "test_runner.hpp"
#include "test_util.hpp"

#include <algorithm>
#include <string>

using paseto5::KeyWrap;
using paseto5::LocalKey;
using tu::Bytes;

TEST_CASE("keys/local key generate, import, PASERK and id") {
    auto g = LocalKey::generate();
    REQUIRE(g.is_ok());
    auto g2 = LocalKey::generate();
    REQUIRE(g2.is_ok());
    CHECK(g.value().paserk_id() != g2.value().paserk_id());
    const LocalKey& k = g.value();
    const paseto5::SecureString p = k.to_paserk();
    const std::string_view pv(p.data(), p.size());
    CHECK(pv.rfind("k5.local.", 0) == 0 && pv.size() == 9 + 43);
    auto back = LocalKey::from_paserk(pv);
    REQUIRE(back.is_ok());
    CHECK(back.value().paserk_id() == k.paserk_id());
    CHECK(k.paserk_id().rfind("k5.lid.", 0) == 0 && k.paserk_id().size() == 7 + 44);
    CHECK(k.key_id() == std::optional<std::string>(k.paserk_id()));
    CHECK(LocalKey::from_bytes(tu::pattern(31, 0)).is_err());
    CHECK(LocalKey::from_bytes(tu::pattern(33, 0)).is_err());
    CHECK(LocalKey::from_paserk("k5.lid.AAAA").is_err());
    CHECK(LocalKey::from_paserk(std::string(pv) + "A").is_err());
    CHECK(LocalKey::from_paserk(pv.substr(0, pv.size() - 1)).is_err());
    auto fixed = LocalKey::from_bytes(tu::pattern(32, 0x70));
    REQUIRE(fixed.is_ok());
    auto fixed2 = LocalKey::from_bytes(tu::pattern(32, 0x70));
    CHECK(fixed.value().paserk_id() == fixed2.value().paserk_id());
    LocalKey cl = fixed.value().clone();
    CHECK(cl.paserk_id() == fixed.value().paserk_id());
    cl.set_key_id("custom");
    CHECK(cl.key_id() == std::optional<std::string>("custom"));
    cl.clear_key_id();
    CHECK(!cl.key_id().has_value());
    CHECK(cl.paserk_id() == fixed.value().paserk_id());
}

TEST_CASE("keys/local-wrap round trip and failures") {
    const LocalKey wrapping = LocalKey::from_bytes(tu::pattern(32, 0x01)).value();
    const LocalKey other = LocalKey::from_bytes(tu::pattern(32, 0x02)).value();
    const LocalKey inner = LocalKey::from_bytes(tu::pattern(32, 0x03)).value();
    auto w = KeyWrap::wrap(wrapping, inner);
    REQUIRE(w.is_ok());
    CHECK(w.value().size() == KeyWrap::WRAPPED_LEN);
    CHECK(KeyWrap::WRAPPED_LEN == 142);
    CHECK(w.value().rfind("k5.local-wrap.", 0) == 0);
    auto u = KeyWrap::unwrap(w.value(), wrapping);
    REQUIRE(u.is_ok());
    CHECK(u.value().paserk_id() == inner.paserk_id());
    auto w2 = KeyWrap::wrap(wrapping, inner);
    REQUIRE(w2.is_ok());
    CHECK(w2.value() != w.value());
    auto bad_key = KeyWrap::unwrap(w.value(), other);
    CHECK(bad_key.is_err() && bad_key.error() == paseto5::Error::invalid);
    for (size_t pos = 0; pos < w.value().size(); ++pos) {
        std::string t = w.value();
        t[pos] = t[pos] == 'A' ? 'B' : 'A';
        CHECK(KeyWrap::unwrap(t, wrapping).is_err());
    }
    CHECK(KeyWrap::unwrap(w.value().substr(1), wrapping).is_err());
    CHECK(KeyWrap::unwrap(w.value() + "A", wrapping).is_err());
    std::string as_token = w.value();
    as_token.replace(0, 14, "v5.local.");
    CHECK(paseto5::Local::open(as_token, wrapping).is_err());
}

TEST_CASE("keys/wrapped keys are not v5.local tokens of the key and vice versa") {
    const LocalKey wrapping = LocalKey::from_bytes(tu::pattern(32, 0x01)).value();
    const LocalKey inner = LocalKey::from_bytes(tu::pattern(32, 0x03)).value();
    auto tok = paseto5::Local::seal(wrapping, tu::pattern(32, 0x03));
    REQUIRE(tok.is_ok());
    std::string as_wrap = tok.value();
    as_wrap.replace(0, 9, "k5.local-wrap.");
    CHECK(KeyWrap::unwrap(as_wrap, wrapping).is_err());
}
