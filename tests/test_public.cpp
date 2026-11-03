#include "test_runner.hpp"
#include "test_util.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef PASETO5_HAS_PQ

#include <oqs/oqs.h>

using paseto5::Error;

using paseto5::Public;
using paseto5::PublicKey;
using paseto5::SecretKey;
using paseto5::Status;
using tu::Bytes;

namespace {

const SecretKey& signer() {
    static const SecretKey sk = SecretKey::generate().value();
    return sk;
}

const SecretKey& other_signer() {
    static const SecretKey sk = SecretKey::generate().value();
    return sk;
}

std::string reencode(const std::string& token, const Bytes& raw) {
    std::string out = "v5.public.";
    std::string body(paseto5::detail::b64::encoded_len(raw.size()), '\0');
    paseto5::detail::b64::encode(body.data(), raw.data(), raw.size());
    out += body;
    const size_t dot = token.find('.', 10);
    if (dot != std::string::npos) out += token.substr(dot);
    return out;
}

Bytes decode_body(const std::string& token) {
    const size_t dot = token.find('.', 10);
    const std::string body = token.substr(10, dot == std::string::npos ? std::string::npos : dot - 10);
    Bytes raw(body.size());
    size_t n = 0;
    if (!paseto5::detail::b64::decode(raw.data(), raw.size(), body.data(), body.size(), n)) return {};
    raw.resize(n);
    return raw;
}

}

TEST_CASE("public/sizes match the pinned wire format and liboqs") {
    CHECK(PublicKey::BYTES == 1984);
    CHECK(SecretKey::BYTES == 6048);
    CHECK(Public::SIG_BYTES == 3373);
    CHECK(paseto5::detail::MlDsa65::available());
    CHECK(paseto5::has_public());
}

TEST_CASE("public/sign and verify round trip with exact lengths") {
    const SecretKey& sk = signer();
    const PublicKey pk = sk.public_key();
    const Bytes footer = tu::bytes_of("{\"kid\":\"k5.pid.x\"}");
    const Bytes implicit = tu::bytes_of("ctx");
    for (size_t n : {0u, 1u, 2u, 3u, 100u, 4097u}) {
        const Bytes msg = tu::pattern(n, 0x33);
        for (int variant = 0; variant < 4; ++variant) {
            const std::span<const uint8_t> f = variant & 1 ? tu::sp(footer) : std::span<const uint8_t>{};
            const std::span<const uint8_t> i = variant & 2 ? tu::sp(implicit) : std::span<const uint8_t>{};
            auto tok = Public::sign(sk, msg, f, i);
            REQUIRE(tok.is_ok());
            CHECK(tok.value().size() == Public::token_len(n, f.size()));
            CHECK(tok.value().rfind("v5.public.", 0) == 0);
            auto back = Public::verify(tok.value(), pk, f, i);
            REQUIRE(back.is_ok());
            CHECK(back.value() == msg);
        }
    }
}

TEST_CASE("public/both signature halves are required") {
    const SecretKey& sk = signer();
    const PublicKey pk = sk.public_key();
    const Bytes msg = tu::bytes_of("signed");
    auto tok = Public::sign(sk, msg);
    REQUIRE(tok.is_ok());
    Bytes raw = decode_body(tok.value());
    REQUIRE(raw.size() == msg.size() + Public::SIG_BYTES);
    for (size_t pos : {msg.size(), msg.size() + 63, msg.size() + 64, raw.size() - 1}) {
        Bytes bad = raw;
        bad[pos] ^= 0x01;
        auto r = Public::verify(reencode(tok.value(), bad), pk);
        CHECK(r.is_err() && r.error() == paseto5::Error::invalid);
    }
    const PublicKey other = other_signer().public_key();
    Bytes mixed_ed(pk.bytes().begin(), pk.bytes().end());
    std::copy_n(other.bytes().begin(), PublicKey::ED_BYTES, mixed_ed.begin());
    CHECK(Public::verify(tok.value(), PublicKey::from_bytes(mixed_ed).value()).is_err());
    Bytes mixed_ml(pk.bytes().begin(), pk.bytes().end());
    std::copy(other.bytes().begin() + PublicKey::ED_BYTES, other.bytes().end(), mixed_ml.begin() + PublicKey::ED_BYTES);
    CHECK(Public::verify(tok.value(), PublicKey::from_bytes(mixed_ml).value()).is_err());
    CHECK(Public::verify(tok.value(), other).is_err());
    CHECK(Public::verify(tok.value(), pk).is_ok());
}

TEST_CASE("public/every byte of a token tampered is rejected and the output wiped") {
    const SecretKey& sk = signer();
    const PublicKey pk = sk.public_key();
    const Bytes msg = tu::bytes_of("m");
    const Bytes footer = tu::bytes_of("f");
    const Bytes implicit = tu::bytes_of("i");
    auto tok = Public::sign(sk, msg, footer, implicit);
    REQUIRE(tok.is_ok());
    const std::string& t = tok.value();
    for (size_t pos = 0; pos < t.size(); ++pos) {
        std::string bad = t;
        bad[pos] = bad[pos] == 'A' ? 'B' : 'A';
        std::vector<uint8_t> out(Public::verify_capacity(bad.size(), footer.size(), implicit.size()), 0xAA);
        size_t n = 99;
        const Status s = Public::verify_into(out, n, bad, pk, footer, implicit);
        CHECK(s == Status::invalid);
        CHECK(n == 0);
        CHECK(std::all_of(out.begin(), out.end(), [](uint8_t b) { return b == 0; }));
    }
    CHECK(Public::verify(t.substr(0, t.size() - 1), pk, footer, implicit).is_err());
    CHECK(Public::verify(t + "A", pk, footer, implicit).is_err());
}

TEST_CASE("public/wrong footer, implicit and headers fail") {
    const SecretKey& sk = signer();
    const PublicKey pk = sk.public_key();
    const Bytes msg = tu::bytes_of("m");
    const Bytes footer = tu::bytes_of("footer");
    const Bytes implicit = tu::bytes_of("implicit");
    auto tok = Public::sign(sk, msg, footer, implicit);
    REQUIRE(tok.is_ok());
    CHECK(Public::verify(tok.value(), pk, tu::bytes_of("footex"), implicit).is_err());
    CHECK(Public::verify(tok.value(), pk, {}, implicit).is_err());
    CHECK(Public::verify(tok.value(), pk, footer, {}).is_err());
    CHECK(Public::verify(tok.value(), pk, footer, tu::bytes_of("implicix")).is_err());
    std::string local = tok.value();
    local.replace(0, 10, "v5.local.");
    CHECK(Public::verify(local, pk, footer, implicit).is_err());
    std::string v4 = tok.value();
    v4.replace(0, 10, "v4.public.");
    CHECK(Public::verify(v4, pk, footer, implicit).is_err());
    CHECK(Public::verify("v5.public.", pk).is_err());
}

TEST_CASE("public/an implicit assertion larger than the output takes the heap path") {
    const SecretKey& sk = signer();
    const PublicKey pk = sk.public_key();
    const Bytes msg = tu::bytes_of("tiny");
    const Bytes implicit = tu::pattern(20000, 0x55);
    auto tok = Public::sign(sk, msg, {}, implicit);
    REQUIRE(tok.is_ok());
    CHECK(paseto5::detail::pae_len({10, msg.size(), 0, implicit.size()}) > tok.value().size());
    auto back = Public::verify(tok.value(), pk, {}, implicit);
    REQUIRE(back.is_ok());
    CHECK(back.value() == msg);
}

TEST_CASE("public/argument errors never depend on the token") {
    const SecretKey& sk = signer();
    const PublicKey pk = sk.public_key();
    const Bytes msg = tu::bytes_of("abc");
    std::vector<uint8_t> out(Public::token_len(3, 0) - 1);
    size_t n = 5;
    CHECK(Public::sign_into(out, n, sk, msg) == Status::argument);
    CHECK(n == 0);
    auto tok = Public::sign(sk, msg);
    REQUIRE(tok.is_ok());
    std::vector<uint8_t> small(Public::verify_capacity(tok.value().size(), 0, 0) - 1);
    CHECK(Public::verify_into(small, n, tok.value(), pk) == Status::argument);
}

TEST_CASE("public/keys survive the PASERK round trip and derive the same public key") {
    const SecretKey& sk = signer();
    const PublicKey pk = sk.public_key();
    auto sk2 = SecretKey::from_paserk(std::string_view(sk.to_paserk().data(), sk.to_paserk().size()));
    REQUIRE(sk2.is_ok());
    auto pk2 = PublicKey::from_paserk(pk.to_paserk());
    REQUIRE(pk2.is_ok());
    CHECK(pk2.value().bytes().size() == PublicKey::BYTES);
    CHECK(std::equal(pk.bytes().begin(), pk.bytes().end(), pk2.value().bytes().begin()));
    CHECK(sk2.value().public_key().paserk_id() == pk.paserk_id());
    CHECK(pk.paserk_id().rfind("k5.pid.", 0) == 0 && pk.paserk_id().size() == 7 + 44);
    auto tok = Public::sign(sk2.value(), tu::bytes_of("m"));
    REQUIRE(tok.is_ok());
    CHECK(Public::verify(tok.value(), pk2.value()).is_ok());
    CHECK(PublicKey::from_bytes(tu::pattern(1983, 0)).is_err());
    CHECK(SecretKey::from_bytes(tu::pattern(6047, 0)).is_err());
    CHECK(PublicKey::from_paserk("k5.local.AAAA").is_err());
}

TEST_CASE("public/the ML-DSA half is bound to the header by its FIPS 204 context string") {
    const SecretKey& sk = signer();
    const PublicKey pk = sk.public_key();
    auto tok = Public::sign(sk, tu::bytes_of("m"));
    REQUIRE(tok.is_ok());
    Bytes raw = decode_body(tok.value());
    REQUIRE(raw.size() == 1 + Public::SIG_BYTES);
    const Bytes m = tu::bytes_of("m");
    std::vector<uint8_t> pae(paseto5::detail::pae_len({Public::HEADER.size(), m.size(), 0, 0}));
    paseto5::detail::SpanSink sink{pae.data()};
    paseto5::detail::pae_stream(sink, {paseto5::bytes(Public::HEADER), m, {}, {}});
    OQS_SIG* s = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    REQUIRE(s != nullptr);
    uint8_t* ml = raw.data() + 1 + Public::ED_SIG_BYTES;
    size_t len = 0;
    REQUIRE(OQS_SIG_sign(s, ml, &len, pae.data(), pae.size(), paseto5::detail::KeyAccess::ml_secret(sk)) == OQS_SUCCESS);
    CHECK(len == Public::ML_SIG_BYTES);
    auto no_ctx = Public::verify(reencode(tok.value(), raw), pk);
    CHECK(no_ctx.is_err() && no_ctx.error() == Error::invalid);
    const std::string other = "v4.public.";
    REQUIRE(OQS_SIG_sign_with_ctx_str(s, ml, &len, pae.data(), pae.size(), reinterpret_cast<const uint8_t*>(other.data()), other.size(), paseto5::detail::KeyAccess::ml_secret(sk)) == OQS_SUCCESS);
    auto other_ctx = Public::verify(reencode(tok.value(), raw), pk);
    CHECK(other_ctx.is_err() && other_ctx.error() == Error::invalid);
    REQUIRE(OQS_SIG_sign_with_ctx_str(s, ml, &len, pae.data(), pae.size(), reinterpret_cast<const uint8_t*>(Public::HEADER.data()), Public::HEADER.size(), paseto5::detail::KeyAccess::ml_secret(sk)) == OQS_SUCCESS);
    OQS_SIG_free(s);
    CHECK(Public::verify(reencode(tok.value(), raw), pk).is_ok());
}

TEST_CASE("public/importing a secret key checks that its public halves belong to its secret halves") {
    const SecretKey& sk = signer();
    CHECK(sk.consistent());
    Bytes raw(SecretKey::BYTES);
    const paseto5::SecureString text = sk.to_paserk();
    REQUIRE(paseto5::detail::paserk_decode(SecretKey::PASERK_HEADER, std::string_view(text.data(), text.size()), raw.data(), raw.size()));
    CHECK(SecretKey::from_bytes(raw).is_ok());
    struct Case { size_t at; const char* what; };
    const Case cases[] = {
        {3, "Ed25519 seed"},
        {40, "Ed25519 public key carried in the secret key"},
        {SecretKey::ED_BYTES + 100, "ML-DSA tr, the hash of the public key"},
        {SecretKey::ED_BYTES + 200, "ML-DSA s1"},
        {SecretKey::ED_BYTES + SecretKey::ML_BYTES + 10, "ML-DSA public key carried in the secret key"},
    };
    for (const Case& c : cases) {
        Bytes bad = raw;
        bad[c.at] ^= 1;
        auto r = SecretKey::from_bytes(bad);
        if (!r.is_err()) std::printf("      corrupting %s was not noticed\n", c.what);
        CHECK(r.is_err() && r.error() == Error::argument);
        std::string pas = "k5.secret.";
        std::string body(paseto5::detail::b64::encoded_len(bad.size()), '\0');
        paseto5::detail::b64::encode(body.data(), bad.data(), bad.size());
        auto p = SecretKey::from_paserk(pas + body);
        CHECK(p.is_err() && p.error() == Error::argument);
    }
}

#else

TEST_CASE("public/this build has no v5.public") {
    CHECK(!paseto5::has_public());
}

#endif
