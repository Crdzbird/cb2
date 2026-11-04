#include "test_runner.hpp"
#include "test_util.hpp"

#include <algorithm>
#include <string>

using cb2::KeyWrap;
using cb2::LocalKey;
using tu::Bytes;

TEST_CASE("keys/local key generate, import, PASERK and id") {
    auto g = LocalKey::generate();
    REQUIRE(g.is_ok());
    auto g2 = LocalKey::generate();
    REQUIRE(g2.is_ok());
    CHECK(g.value().paserk_id() != g2.value().paserk_id());
    const LocalKey& k = g.value();
    const cb2::SecureString p = k.to_paserk();
    const std::string_view pv(p.data(), p.size());
    CHECK(pv.rfind("kcb2.local.", 0) == 0 && pv.size() == 11 + 43);
    auto back = LocalKey::from_paserk(pv);
    REQUIRE(back.is_ok());
    CHECK(back.value().paserk_id() == k.paserk_id());
    CHECK(k.paserk_id().rfind("kcb2.lid.", 0) == 0 && k.paserk_id().size() == 9 + 44);
    CHECK(k.key_id() == std::optional<std::string>(k.paserk_id()));
    CHECK(LocalKey::from_bytes(tu::pattern(31, 0)).is_err());
    CHECK(LocalKey::from_bytes(tu::pattern(33, 0)).is_err());
    CHECK(LocalKey::from_paserk("kcb2.lid.AAAA").is_err());
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
    CHECK(KeyWrap::WRAPPED_LEN == 144);
    CHECK(w.value().rfind("kcb2.local-wrap.", 0) == 0);
    auto u = KeyWrap::unwrap(w.value(), wrapping);
    REQUIRE(u.is_ok());
    CHECK(u.value().paserk_id() == inner.paserk_id());
    auto w2 = KeyWrap::wrap(wrapping, inner);
    REQUIRE(w2.is_ok());
    CHECK(w2.value() != w.value());
    auto bad_key = KeyWrap::unwrap(w.value(), other);
    CHECK(bad_key.is_err() && bad_key.error() == cb2::Error::invalid);
    for (size_t pos = 0; pos < w.value().size(); ++pos) {
        std::string t = w.value();
        t[pos] = t[pos] == 'A' ? 'B' : 'A';
        CHECK(KeyWrap::unwrap(t, wrapping).is_err());
    }
    CHECK(KeyWrap::unwrap(w.value().substr(1), wrapping).is_err());
    CHECK(KeyWrap::unwrap(w.value() + "A", wrapping).is_err());
    std::string as_token = w.value();
    as_token.replace(0, 16, "cb2.local.");
    CHECK(cb2::Local::open(as_token, wrapping).is_err());
}

TEST_CASE("keys/wrapped keys are not cb2.local tokens of the key and vice versa") {
    const LocalKey wrapping = LocalKey::from_bytes(tu::pattern(32, 0x01)).value();
    const LocalKey inner = LocalKey::from_bytes(tu::pattern(32, 0x03)).value();
    auto tok = cb2::Local::seal(wrapping, tu::pattern(32, 0x03));
    REQUIRE(tok.is_ok());
    std::string as_wrap = tok.value();
    as_wrap.replace(0, 10, "kcb2.local-wrap.");
    CHECK(KeyWrap::unwrap(as_wrap, wrapping).is_err());
}

TEST_CASE("keys/a key whose bytes are all equal is refused on import") {
    for (uint8_t b : {uint8_t{0x00}, uint8_t{0x42}, uint8_t{0xff}}) {
        const Bytes k(32, b);
        auto r = LocalKey::from_bytes(k);
        CHECK(r.is_err() && r.error() == cb2::Error::argument);
        std::string text = "kcb2.local.";
        std::string body(cb2::detail::b64::encoded_len(k.size()), '\0');
        cb2::detail::b64::encode(body.data(), k.data(), k.size());
        auto p = LocalKey::from_paserk(text + body);
        CHECK(p.is_err() && p.error() == cb2::Error::argument);
    }
    Bytes almost(32, 0x42);
    almost[31] = 0x43;
    CHECK(LocalKey::from_bytes(almost).is_ok());
    CHECK(LocalKey::from_bytes(tu::pattern(32, 0x00)).is_ok());
    CHECK(cb2::detail::constant_bytes(almost.data(), 31) && !cb2::detail::constant_bytes(almost.data(), 32));
}

#ifdef CB2_HAS_PQ
TEST_CASE("keys/a secret key survives moves and clones with its memory lock") {
    auto gen = cb2::SecretKey::generate();
    REQUIRE(gen.is_ok());
    const cb2::PublicKey pk = gen.value().public_key();
    cb2::SecretKey moved(std::move(gen.value()));
    cb2::SecretKey assigned = cb2::SecretKey::generate().value();
    assigned = std::move(moved);
    const cb2::SecretKey cloned = assigned.clone();
    assigned = cb2::SecretKey::generate().value();
    auto tok = cb2::Public::sign(cloned, cb2::bytes("m"));
    REQUIRE(tok.is_ok());
    CHECK(cb2::Public::verify(tok.value(), pk).is_ok());
    CHECK(cloned.public_key().paserk_id() == pk.paserk_id());
    CHECK(assigned.public_key().paserk_id() != pk.paserk_id());
}
#endif
