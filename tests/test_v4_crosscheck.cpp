/**
 * Cross-check of the two building blocks cb2 shares with PASETO v4,
 * the pre-authentication encoding and the base64url codec, against the
 * official v4 vectors vendored by the repository. A v4.local encrypt and
 * decrypt and a v4.public sign and verify are rebuilt here from
 * cb2::detail::pae_stream, cb2::detail::b64, split_token and
 * footer_matches plus libsodium's BLAKE2b, XChaCha20 and Ed25519. If the
 * PAE or the codec deviated in any byte, no 4-E token would reproduce and
 * no 4-S token would verify.
 */

#include "test_runner.hpp"
#include "test_util.hpp"

#include <cb2/detail/local_core.hpp>

#include <cstring>
#include <string>

namespace b64 = cb2::detail::b64;
using cb2::json::Value;
using tu::Bytes;

namespace {

struct GenerichashSink {
    crypto_generichash_state st;
    void update(const uint8_t* p, size_t n) { crypto_generichash_update(&st, p, n); }
};

std::string encode_token(std::string_view header, const Bytes& raw, const Bytes& footer) {
    std::string out(cb2::detail::token_len_for(header.size(), raw.size(), footer.size()), '\0');
    const size_t n = cb2::detail::finish_token({reinterpret_cast<uint8_t*>(out.data()), out.size()}, header,
                                                   raw.data(), raw.size(), footer);
    out.resize(n);
    return out;
}

void v4_keys(const Bytes& key, const Bytes& nonce, uint8_t ek[32], uint8_t n2[24], uint8_t ak[32]) {
    uint8_t tmp[56];
    Bytes m = tu::bytes_of("paseto-encryption-key");
    m.insert(m.end(), nonce.begin(), nonce.end());
    crypto_generichash(tmp, 56, m.data(), m.size(), key.data(), key.size());
    std::memcpy(ek, tmp, 32);
    std::memcpy(n2, tmp + 32, 24);
    Bytes a = tu::bytes_of("paseto-auth-key-for-aead");
    a.insert(a.end(), nonce.begin(), nonce.end());
    crypto_generichash(ak, 32, a.data(), a.size(), key.data(), key.size());
}

Bytes v4_tag(const uint8_t ak[32], const Bytes& nonce, const Bytes& c, const Bytes& f, const Bytes& i) {
    GenerichashSink s;
    crypto_generichash_init(&s.st, ak, 32, 32);
    cb2::detail::pae_stream(s, {cb2::bytes("v4.local."), tu::sp(nonce), tu::sp(c), tu::sp(f), tu::sp(i)});
    Bytes t(32);
    crypto_generichash_final(&s.st, t.data(), 32);
    return t;
}

std::string v4_local_encrypt(const Bytes& key, const Bytes& nonce, const Bytes& m, const Bytes& f, const Bytes& i) {
    uint8_t ek[32], n2[24], ak[32];
    v4_keys(key, nonce, ek, n2, ak);
    Bytes c(m.size());
    if (!m.empty()) crypto_stream_xchacha20_xor(c.data(), m.data(), m.size(), n2, ek);
    const Bytes t = v4_tag(ak, nonce, c, f, i);
    Bytes raw = nonce;
    raw.insert(raw.end(), c.begin(), c.end());
    raw.insert(raw.end(), t.begin(), t.end());
    return encode_token("v4.local.", raw, f);
}

bool v4_local_decrypt(std::string_view token, const Bytes& key, const Bytes& f, const Bytes& i, Bytes& out) {
    cb2::detail::Split s{};
    if (!cb2::detail::split_token(token, "v4.local.", !f.empty(), s)) return false;
    Bytes work(token.size());
    size_t raw_len = 0;
    if (!b64::decode(work.data(), work.size(), s.body, s.body_len, raw_len) || raw_len < 64) return false;
    if (!cb2::detail::footer_matches(work.data() + raw_len, work.size() - raw_len, s, f)) return false;
    const Bytes nonce(work.begin(), work.begin() + 32);
    const Bytes c(work.begin() + 32, work.begin() + static_cast<long>(raw_len) - 32);
    const Bytes t(work.begin() + static_cast<long>(raw_len) - 32, work.begin() + static_cast<long>(raw_len));
    uint8_t ek[32], n2[24], ak[32];
    v4_keys(key, nonce, ek, n2, ak);
    if (v4_tag(ak, nonce, c, f, i) != t) return false;
    out.assign(c.size(), 0);
    if (!c.empty()) crypto_stream_xchacha20_xor(out.data(), c.data(), c.size(), n2, ek);
    return true;
}

Bytes v4_public_pae(const Bytes& m, const Bytes& f, const Bytes& i) {
    Bytes pae(cb2::detail::pae_len({10, m.size(), f.size(), i.size()}));
    cb2::detail::SpanSink sink{pae.data()};
    cb2::detail::pae_stream(sink, {cb2::bytes("v4.public."), tu::sp(m), tu::sp(f), tu::sp(i)});
    return pae;
}

std::string v4_public_sign(const Bytes& sk, const Bytes& m, const Bytes& f, const Bytes& i) {
    const Bytes pae = v4_public_pae(m, f, i);
    Bytes raw = m;
    raw.resize(m.size() + 64);
    crypto_sign_detached(raw.data() + m.size(), nullptr, pae.data(), pae.size(), sk.data());
    return encode_token("v4.public.", raw, f);
}

bool v4_public_verify(std::string_view token, const Bytes& pk, const Bytes& f, const Bytes& i, Bytes& out) {
    cb2::detail::Split s{};
    if (!cb2::detail::split_token(token, "v4.public.", !f.empty(), s)) return false;
    Bytes work(token.size());
    size_t raw_len = 0;
    if (!b64::decode(work.data(), work.size(), s.body, s.body_len, raw_len) || raw_len < 64) return false;
    if (!cb2::detail::footer_matches(work.data() + raw_len, work.size() - raw_len, s, f)) return false;
    const Bytes m(work.begin(), work.begin() + static_cast<long>(raw_len) - 64);
    const Bytes pae = v4_public_pae(m, f, i);
    if (crypto_sign_verify_detached(work.data() + raw_len - 64, pae.data(), pae.size(), pk.data()) != 0) return false;
    out = m;
    return true;
}

bool load_v4(Value& root) {
    auto text = tu::read_file(CB2_V4_VECTORS);
    if (!text) {
        std::printf("      official v4 vectors not found at %s\n", CB2_V4_VECTORS);
        return false;
    }
    return cb2::json::Reader::parse(*text, root, 32) && root.is_object();
}

}

TEST_CASE("v4/official v4.local vectors reproduce through cb2's PAE and base64url") {
    Value root;
    REQUIRE(load_v4(root));
    const Value* tests = root.get("tests");
    REQUIRE(tests != nullptr);
    int local = 0, fails = 0;
    for (const Value& v : tests->items) {
        const std::string name = tu::str(v, "name");
        const std::string token = tu::str(v, "token");
        const Bytes f = tu::bytes_of(tu::str(v, "footer"));
        const Bytes i = tu::bytes_of(tu::str(v, "implicit-assertion"));
        if (name.rfind("4-E-", 0) == 0) {
            ++local;
            const Bytes key = tu::unhex(tu::str(v, "key"));
            const Bytes nonce = tu::unhex(tu::str(v, "nonce"));
            const Bytes payload = tu::bytes_of(tu::str(v, "payload"));
            const std::string mine = v4_local_encrypt(key, nonce, payload, f, i);
            if (mine != token) std::printf("      %s differs\n", name.c_str());
            CHECK(mine == token);
            Bytes out;
            CHECK(v4_local_decrypt(token, key, f, i, out) && out == payload);
        }
        if (name.rfind("4-F-", 0) == 0 && v.get("key") != nullptr) {
            ++fails;
            Bytes out;
            CHECK(!v4_local_decrypt(token, tu::unhex(tu::str(v, "key")), f, i, out));
        }
    }
    CHECK(local == 9);
    CHECK(fails == 4);
}

TEST_CASE("v4/official v4.public vectors reproduce through cb2's PAE and base64url") {
    Value root;
    REQUIRE(load_v4(root));
    const Value* tests = root.get("tests");
    REQUIRE(tests != nullptr);
    int pub = 0, fails = 0;
    for (const Value& v : tests->items) {
        const std::string name = tu::str(v, "name");
        const std::string token = tu::str(v, "token");
        const Bytes f = tu::bytes_of(tu::str(v, "footer"));
        const Bytes i = tu::bytes_of(tu::str(v, "implicit-assertion"));
        if (name.rfind("4-S-", 0) == 0) {
            ++pub;
            const Bytes sk = tu::unhex(tu::str(v, "secret-key"));
            const Bytes pk = tu::unhex(tu::str(v, "public-key"));
            const Bytes payload = tu::bytes_of(tu::str(v, "payload"));
            const std::string mine = v4_public_sign(sk, payload, f, i);
            if (mine != token) std::printf("      %s differs\n", name.c_str());
            CHECK(mine == token);
            Bytes out;
            CHECK(v4_public_verify(token, pk, f, i, out) && out == payload);
        }
        if (name.rfind("4-F-", 0) == 0 && v.get("public-key") != nullptr) {
            ++fails;
            Bytes out;
            CHECK(!v4_public_verify(token, tu::unhex(tu::str(v, "public-key")), f, i, out));
        }
    }
    CHECK(pub == 3);
    CHECK(fails == 1);
}
