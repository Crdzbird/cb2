/**
 * The benchmark's reference constructions against the official PASETO
 * vectors of every version (tests/vectors/paseto-v1 to v4, ISC) and the
 * RFC 7515 HS256 example. A benchmark against a wrong implementation
 * measures nothing, so every reference must reproduce or verify the
 * official tokens before its numbers mean anything. Local tokens are
 * reproduced byte for byte from the recorded nonce input; deterministic
 * signatures (Ed25519) are reproduced; randomised ones (RSA-PSS, ECDSA)
 * are verified and a fresh signature must verify; every F vector fails.
 */

#include "test_runner.hpp"
#include "test_util.hpp"

#include "reference.hpp"

#include <cstring>
#include <string>

using cb2::json::Value;
using ref::Bytes;
using ref::Span;

namespace {

bool load_official(const char* version, Value& root) {
    const std::string path = std::string(CB2_VECTOR_DIR) + "/paseto-" + version + "/" + version + ".json";
    auto text = tu::read_file(path.c_str());
    if (!text) {
        std::printf("      missing %s\n", path.c_str());
        return false;
    }
    return cb2::json::Reader::parse(*text, root, 32) && root.get("tests") != nullptr;
}

bool expect_fail(const Value& v) {
    const Value* f = v.get("expect-fail");
    return f != nullptr && ((f->kind == Value::Kind::boolean && f->b) || (f->is_string() && f->text == "True"));
}

struct Case {
    std::string name;
    bool fail;
    std::string token;
    Bytes key, nonce, payload, footer, implicit;
    std::string public_pem, secret_pem, public_hex, secret_hex;
};

Case read_case(const Value& v) {
    Case c;
    c.name = tu::str(v, "name");
    c.fail = expect_fail(v);
    c.token = tu::str(v, "token");
    c.key = tu::unhex(tu::str(v, "key"));
    c.nonce = tu::unhex(tu::str(v, "nonce"));
    c.payload = tu::bytes_of(tu::str(v, "payload"));
    c.footer = tu::bytes_of(tu::str(v, "footer"));
    c.implicit = tu::bytes_of(tu::str(v, "implicit-assertion"));
    c.public_pem = v.get("public-key-pem") != nullptr ? tu::str(v, "public-key-pem") : tu::str(v, "public-key");
    c.secret_pem = v.get("secret-key-pem") != nullptr ? tu::str(v, "secret-key-pem") : tu::str(v, "secret-key");
    c.public_hex = tu::str(v, "public-key");
    c.secret_hex = tu::str(v, "secret-key");
    return c;
}

bool is_local(const Case& c) { return !c.key.empty(); }

void report(const Case& c, bool ok, const char* what) {
    if (!ok) std::printf("      %s: %s\n", c.name.c_str(), what);
}

}

TEST_CASE("reference/official v1 vectors: local reproduce, public verify") {
    Value root;
    REQUIRE(load_official("v1", root));
    int seen = 0;
    for (const Value& v : root.get("tests")->items) {
        const Case c = read_case(v);
        ++seen;
        Bytes out;
        if (is_local(c)) {
            const bool opened = ref::v1_local_decrypt(c.key, c.token, c.footer, out);
            if (c.fail) {
                report(c, !opened, "should fail");
                CHECK(!opened);
                continue;
            }
            REQUIRE(c.nonce.size() == 32);
            const std::string made = ref::v1_local_encrypt(c.key, c.payload, c.footer, c.nonce.data());
            report(c, made == c.token, "token differs");
            CHECK(made == c.token);
            CHECK(opened && out == c.payload);
            continue;
        }
        ref::Evp pk = ref::public_from_pem(c.public_pem);
        REQUIRE(pk.key != nullptr);
        const bool verified = ref::v1_public_verify(pk.key, c.token, c.footer, out);
        if (c.fail) {
            report(c, !verified, "should fail");
            CHECK(!verified);
            continue;
        }
        report(c, verified, "should verify");
        CHECK(verified && out == c.payload);
        ref::Evp sk = ref::private_from_pem(c.secret_pem);
        REQUIRE(sk.key != nullptr);
        const std::string fresh = ref::v1_public_sign(sk.key, c.payload, c.footer);
        CHECK(fresh.size() == c.token.size());
        CHECK(ref::v1_public_verify(pk.key, fresh, c.footer, out));
    }
    CHECK(seen >= 14);
}

TEST_CASE("reference/official v2 vectors: local and public reproduce") {
    Value root;
    REQUIRE(load_official("v2", root));
    int seen = 0;
    for (const Value& v : root.get("tests")->items) {
        const Case c = read_case(v);
        ++seen;
        Bytes out;
        if (is_local(c)) {
            const bool opened = ref::v2_local_decrypt(c.key, c.token, c.footer, out);
            if (c.fail) {
                CHECK(!opened);
                continue;
            }
            REQUIRE(c.nonce.size() == 24);
            const std::string made = ref::v2_local_encrypt(c.key, c.payload, c.footer, c.nonce.data());
            report(c, made == c.token, "token differs");
            CHECK(made == c.token);
            CHECK(opened && out == c.payload);
            continue;
        }
        const Bytes pk = tu::unhex(c.public_hex);
        const Bytes sk = tu::unhex(c.secret_hex);
        REQUIRE(pk.size() == 32 && sk.size() == 64);
        const bool verified = ref::v2_public_verify(pk.data(), c.token, c.footer, out);
        if (c.fail) {
            CHECK(!verified);
            continue;
        }
        CHECK(verified && out == c.payload);
        const std::string made = ref::v2_public_sign(sk.data(), c.payload, c.footer);
        report(c, made == c.token, "token differs");
        CHECK(made == c.token);
    }
    CHECK(seen >= 15);
}

TEST_CASE("reference/official v3 vectors: local reproduce, public verify") {
    Value root;
    REQUIRE(load_official("v3", root));
    int seen = 0;
    for (const Value& v : root.get("tests")->items) {
        const Case c = read_case(v);
        ++seen;
        Bytes out;
        if (is_local(c)) {
            const bool opened = ref::v3_local_decrypt(c.key, c.token, c.footer, c.implicit, out);
            if (c.fail) {
                report(c, !opened, "should fail");
                CHECK(!opened);
                continue;
            }
            REQUIRE(c.nonce.size() == 32);
            const std::string made = ref::v3_local_encrypt(c.key, c.payload, c.footer, c.implicit, c.nonce.data());
            report(c, made == c.token, "token differs");
            CHECK(made == c.token);
            CHECK(opened && out == c.payload);
            continue;
        }
        ref::Evp pk = ref::public_from_pem(c.public_pem);
        REQUIRE(pk.key != nullptr);
        Bytes point;
        CHECK(ref::ec_compressed_point(pk.key, point) && tu::hex(point) == c.public_hex);
        const bool verified = ref::v3_public_verify(pk.key, c.token, c.footer, c.implicit, out);
        if (c.fail) {
            report(c, !verified, "should fail");
            CHECK(!verified);
            continue;
        }
        report(c, verified, "should verify");
        CHECK(verified && out == c.payload);
        ref::Evp sk = ref::private_from_pem(c.secret_pem);
        REQUIRE(sk.key != nullptr);
        const std::string fresh = ref::v3_public_sign(sk.key, c.payload, c.footer, c.implicit);
        CHECK(fresh.size() == c.token.size());
        CHECK(ref::v3_public_verify(pk.key, fresh, c.footer, c.implicit, out));
    }
    CHECK(seen >= 17);
}

TEST_CASE("reference/official v4 vectors: local and public reproduce") {
    Value root;
    REQUIRE(load_official("v4", root));
    int seen = 0;
    for (const Value& v : root.get("tests")->items) {
        const Case c = read_case(v);
        ++seen;
        Bytes out;
        if (is_local(c)) {
            const bool opened = ref::v4_local_decrypt(c.key, c.token, c.footer, c.implicit, out);
            if (c.fail) {
                CHECK(!opened);
                continue;
            }
            REQUIRE(c.nonce.size() == 32);
            const std::string made = ref::v4_local_encrypt(c.key, c.payload, c.footer, c.implicit, c.nonce.data());
            report(c, made == c.token, "token differs");
            CHECK(made == c.token);
            CHECK(opened && out == c.payload);
            continue;
        }
        const Bytes pk = tu::unhex(c.public_hex);
        const Bytes sk = tu::unhex(c.secret_hex);
        REQUIRE(pk.size() == 32 && sk.size() == 64);
        const bool verified = ref::v4_public_verify(pk.data(), c.token, c.footer, c.implicit, out);
        if (c.fail) {
            CHECK(!verified);
            continue;
        }
        CHECK(verified && out == c.payload);
        const std::string made = ref::v4_public_sign(sk.data(), c.payload, c.footer, c.implicit);
        report(c, made == c.token, "token differs");
        CHECK(made == c.token);
    }
    CHECK(seen >= 17);
}

TEST_CASE("reference/RFC 7515 HS256 example reproduces, and the JOSE references round trip") {
    const std::string key_b64 = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
    Bytes key;
    REQUIRE(ref::unb64(key_b64, key) && key.size() == 64);
    const std::string header = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
    const std::string payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
    const std::string token = ref::jws(header, ref::sp(payload), [&](Span in, Bytes& sig) { return ref::hs256_sign(key, in, sig); });
    const std::string expected = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    CHECK(token == expected);
    Bytes back;
    CHECK(ref::jws_verify(token, [&](Span in, Span sig) { return ref::hs256_verify(key, in, sig); }, back));
    CHECK(back == tu::bytes_of(payload));
    std::string flipped = token;
    flipped.back() = flipped.back() == 'k' ? 'j' : 'k';
    CHECK(!ref::jws_verify(flipped, [&](Span in, Span sig) { return ref::hs256_verify(key, in, sig); }, back));

    ref::Evp rsa = ref::keygen("RSA", nullptr);
    ref::Evp ec = ref::keygen("EC", "P-256");
    REQUIRE(rsa.key != nullptr && ec.key != nullptr);
    uint8_t ed_pk[32], ed_sk[64];
    crypto_sign_keypair(ed_pk, ed_sk);
    const std::string rs = ref::jws("{\"alg\":\"RS256\",\"typ\":\"JWT\"}", ref::sp(payload), [&](Span in, Bytes& sig) { return ref::rs256_sign(rsa.key, in, sig); });
    CHECK(!rs.empty() && ref::jws_verify(rs, [&](Span in, Span sig) { return ref::rs256_verify(rsa.key, in, sig); }, back) && back == tu::bytes_of(payload));
    const std::string es = ref::jws("{\"alg\":\"ES256\",\"typ\":\"JWT\"}", ref::sp(payload), [&](Span in, Bytes& sig) { return ref::es256_sign(ec.key, in, sig); });
    CHECK(!es.empty() && ref::jws_verify(es, [&](Span in, Span sig) { return ref::es256_verify(ec.key, in, sig); }, back) && back == tu::bytes_of(payload));
    CHECK(es.size() > 86 && es.substr(es.rfind('.') + 1).size() == 86);
    const std::string ed = ref::jws("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}", ref::sp(payload), [&](Span in, Bytes& sig) { return ref::eddsa_sign(ed_sk, in, sig); });
    CHECK(!ed.empty() && ref::jws_verify(ed, [&](Span in, Span sig) { return ref::eddsa_verify(ed_pk, in, sig); }, back) && back == tu::bytes_of(payload));
    uint8_t k32[32], iv[12];
    ref::random(k32, 32);
    ref::random(iv, 12);
    const std::string jwe = ref::jwe_a256gcm_seal({k32, 32}, ref::sp(payload), iv);
    CHECK(!jwe.empty() && ref::jwe_a256gcm_open({k32, 32}, jwe, back) && back == tu::bytes_of(payload));
    std::string bad = jwe;
    bad[bad.size() - 3] = bad[bad.size() - 3] == 'A' ? 'B' : 'A';
    CHECK(!ref::jwe_a256gcm_open({k32, 32}, bad, back));
}
