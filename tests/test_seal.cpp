#include "test_runner.hpp"
#include "test_util.hpp"

#include <string>
#include <vector>

#ifdef CB2_HAS_SEAL

using cb2::Error;
using cb2::LocalKey;
using cb2::RecipientKey;
using cb2::RecipientPublicKey;
using cb2::Seal;
using cb2::json::Value;
using tu::Bytes;

namespace {

bool load_xwing(Value& root) {
    const std::string path = std::string(CB2_VECTOR_DIR) + "/xwing/xwing.json";
    auto text = tu::read_file(path.c_str());
    if (!text) {
        std::printf("      missing %s\n", path.c_str());
        return false;
    }
    return cb2::json::Reader::parse(*text, root, 32) && root.get("tests") != nullptr;
}

const RecipientKey& recipient() {
    static const RecipientKey r = RecipientKey::generate().value();
    return r;
}

}

TEST_CASE("seal/X-Wing reproduces the draft's test vectors") {
    Value root;
    REQUIRE(load_xwing(root));
    int seen = 0;
    for (const Value& v : root.get("tests")->items) {
        ++seen;
        const Bytes seed = tu::unhex(tu::str(v, "seed"));
        const Bytes eseed = tu::unhex(tu::str(v, "eseed"));
        REQUIRE(seed.size() == 32 && eseed.size() == 64);
        Bytes expanded(cb2::detail::XWing::EXPANDED_BYTES);
        REQUIRE(cb2::detail::XWing::expand(seed.data(), expanded.data()));
        const std::span<const uint8_t> pk(expanded.data() + cb2::detail::XWing::ML_SK_BYTES + 32, cb2::detail::XWing::PK_BYTES);
        CHECK(tu::hex(pk) == tu::str(v, "pk"));
        Bytes ct(cb2::detail::XWing::CT_BYTES), ss(32), ss2(32);
        REQUIRE(cb2::detail::XWing::encaps(pk.data(), eseed.data(), ct.data(), ss.data()));
        CHECK(tu::hex(ct) == tu::str(v, "ct"));
        CHECK(tu::hex(ss) == tu::str(v, "ss"));
        REQUIRE(cb2::detail::XWing::decaps(expanded.data(), ct.data(), ss2.data()));
        CHECK(ss2 == ss);
        auto r = RecipientKey::from_bytes(seed);
        REQUIRE(r.is_ok());
        CHECK(tu::hex(r.value().public_key().bytes()) == tu::str(v, "pk"));
        CHECK(tu::hex(tu::unhex(tu::str(v, "sk"))) == tu::str(v, "seed"));
    }
    CHECK(seen >= 3);
}

TEST_CASE("seal/a key sealed to a recipient comes back only for that recipient") {
    const RecipientKey& r = recipient();
    const LocalKey k = LocalKey::from_bytes(tu::pattern(32, 0x70)).value();
    auto sealed = Seal::seal(r.public_key(), k);
    REQUIRE(sealed.is_ok());
    const std::string& s = sealed.value();
    CHECK(s.size() == Seal::TEXT_BYTES);
    CHECK(s.rfind("kcb2.seal.", 0) == 0);
    CHECK(s.size() == 1632);
    auto back = Seal::unseal(s, r);
    REQUIRE(back.is_ok());
    CHECK(back.value().paserk_id() == k.paserk_id());
    CHECK(back.value().key_id() == std::optional<std::string>(k.paserk_id()));
    auto again = Seal::seal(r.public_key(), k);
    REQUIRE(again.is_ok());
    CHECK(again.value() != s);
    const RecipientKey other = RecipientKey::generate().value();
    auto wrong = Seal::unseal(s, other);
    CHECK(wrong.is_err() && wrong.error() == Error::invalid);
    for (std::size_t pos : {std::size_t{0}, std::size_t{12}, std::size_t{1460}, std::size_t{1500}, std::size_t{1600}, s.size() - 1}) {
        std::string t = s;
        t[pos] = t[pos] == 'A' ? 'B' : 'A';
        auto v = Seal::unseal(t, r);
        CHECK(v.is_err() && v.error() == Error::invalid);
    }
    auto shorter = Seal::unseal(s.substr(0, s.size() - 1), r);
    CHECK(shorter.is_err() && shorter.error() == Error::invalid);
    auto longer = Seal::unseal(s + "A", r);
    CHECK(longer.is_err() && longer.error() == Error::invalid);
    std::string padded = s;
    padded.back() = '=';
    CHECK(Seal::unseal(padded, r).is_err());
    std::string wrapped = s;
    wrapped.replace(0, 10, "kcb2.local-wrap.");
    CHECK(Seal::unseal(wrapped, r).is_err());
    CHECK(cb2::KeyWrap::unwrap(wrapped, k).is_err());
}

TEST_CASE("seal/recipient keys round trip through their strings and ids") {
    const RecipientKey& r = recipient();
    const cb2::SecureString secret = r.to_paserk();
    const std::string text(secret.data(), secret.size());
    CHECK(text.size() == 22 + 43);
    CHECK(text.rfind("kcb2.recipient-secret.", 0) == 0);
    auto back = RecipientKey::from_paserk(text);
    REQUIRE(back.is_ok());
    CHECK(back.value().paserk_id() == r.paserk_id());
    const std::string pub = r.public_key().to_paserk();
    CHECK(pub.size() == 15 + 1622);
    CHECK(pub.rfind("kcb2.recipient.", 0) == 0);
    auto pk = RecipientPublicKey::from_paserk(pub);
    REQUIRE(pk.is_ok());
    CHECK(pk.value().paserk_id() == r.paserk_id());
    CHECK(pk.value().paserk_id().rfind("kcb2.rid.", 0) == 0 && pk.value().paserk_id().size() == 53);
    CHECK(RecipientPublicKey::from_paserk(pub.substr(0, pub.size() - 1)).is_err());
    CHECK(RecipientKey::from_paserk("kcb2.recipient.AAAA").is_err());
    CHECK(RecipientKey::from_bytes(Bytes(31, 1)).is_err());
    const LocalKey k = LocalKey::generate().value();
    auto sealed = Seal::seal(pk.value(), k);
    REQUIRE(sealed.is_ok());
    CHECK(Seal::unseal(sealed.value(), back.value()).is_ok());
    RecipientKey cloned = r.clone();
    RecipientKey moved(std::move(cloned));
    RecipientKey assigned = RecipientKey::generate().value();
    assigned = std::move(moved);
    CHECK(Seal::unseal(sealed.value(), assigned).is_ok());
    CHECK(assigned.paserk_id() == r.paserk_id());
}

#endif
