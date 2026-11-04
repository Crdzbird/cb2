#pragma once

/**
 * Reference constructions the benchmark compares cb2 with, written from
 * their specifications on top of libsodium and OpenSSL 3, and checked
 * against the official PASETO vectors (tests/test_reference.cpp) and the
 * RFC 7515 HS256 example before any number is reported:
 *
 *   PASETO v1.local   AES-256-CTR + HMAC-SHA384, HKDF-SHA384 key split
 *   PASETO v1.public  RSA-2048 PSS, SHA-384, salt 48
 *   PASETO v2.local   XChaCha20-Poly1305, BLAKE2b-derived nonce
 *   PASETO v2.public  Ed25519
 *   PASETO v3.local   AES-256-CTR + HMAC-SHA384, HKDF-SHA384 key split, implicit assertion
 *   PASETO v3.public  ECDSA P-384, SHA-384, public key in the PAE
 *   PASETO v4.local   XChaCha20 + BLAKE2b-256, BLAKE2b key split
 *   PASETO v4.public  Ed25519
 *   JWS               HS256, RS256 (RSA-2048 PKCS1 v1.5), ES256 (ECDSA P-256), EdDSA (Ed25519)
 *   JWE               dir + A256GCM, the JOSE equivalent of a local token
 *
 * The pre-authentication encoding, the base64url codec and the token
 * assembly are cb2's own building blocks, which the v4 cross-check in the
 * test suite already proves identical to PASETO's; every PASETO version
 * shares them, so the benchmark compares the cryptography, not two codecs.
 * Each function takes its randomness as a parameter so that the vector
 * tests can fix it; the benchmark passes fresh bytes from libsodium.
 * Nothing here is hardened: no wiping, no constant-time footer compare
 * beyond what the shared helpers do. These are measuring sticks.
 */

#include <cb2/cb2.hpp>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ref {

using Bytes = std::vector<uint8_t>;
using Span = std::span<const uint8_t>;

inline Span sp(std::string_view s) { return cb2::bytes(s); }
inline Span sp(const Bytes& b) { return b; }

/// h || base64url(raw) [|| "." || base64url(footer)]
inline std::string assemble(std::string_view h, Span raw, Span footer) {
    std::string out(cb2::detail::token_len_for(h.size(), raw.size(), footer.size()), '\0');
    const std::size_t n = cb2::detail::finish_token({reinterpret_cast<uint8_t*>(out.data()), out.size()}, h,
                                                    raw.data(), raw.size(), footer);
    out.resize(n);
    return out;
}

/// Splits a token at its header, decodes the body strictly and compares
/// the footer with the expected one.
inline bool disassemble(std::string_view token, std::string_view h, Span footer, Bytes& raw) {
    cb2::detail::Split s{};
    if (!cb2::detail::split_token(token, h, !footer.empty(), s)) return false;
    Bytes work(token.size());
    std::size_t n = 0;
    if (!cb2::detail::b64::decode(work.data(), work.size(), s.body, s.body_len, n)) return false;
    Bytes fwork(token.size());
    if (!cb2::detail::footer_matches(fwork.data(), fwork.size(), s, footer)) return false;
    work.resize(n);
    raw = std::move(work);
    return true;
}

inline Bytes pae(std::initializer_list<Span> pieces) {
    std::size_t total = 8;
    for (const Span& p : pieces) total += 8 + p.size();
    Bytes out(total);
    cb2::detail::SpanSink sink{out.data()};
    cb2::detail::pae_stream(sink, pieces);
    return out;
}

inline std::string b64(Span in) {
    std::string out(cb2::detail::b64::encoded_len(in.size()), '\0');
    cb2::detail::b64::encode(out.data(), in.data(), in.size());
    return out;
}

inline bool unb64(std::string_view in, Bytes& out) {
    Bytes work(in.size() + 3);
    std::size_t n = 0;
    if (!cb2::detail::b64::decode(work.data(), work.size(), in.data(), in.size(), n)) return false;
    work.resize(n);
    out = std::move(work);
    return true;
}

inline void random(uint8_t* p, std::size_t n) { randombytes_buf(p, n); }

/// OpenSSL handles the benchmark keeps alive.
struct Evp {
    EVP_PKEY* key = nullptr;
    Evp() = default;
    explicit Evp(EVP_PKEY* k) : key(k) {}
    Evp(const Evp&) = delete;
    Evp& operator=(const Evp&) = delete;
    Evp(Evp&& o) noexcept : key(o.key) { o.key = nullptr; }
    Evp& operator=(Evp&& o) noexcept {
        if (this != &o) {
            EVP_PKEY_free(key);
            key = o.key;
            o.key = nullptr;
        }
        return *this;
    }
    ~Evp() { EVP_PKEY_free(key); }
};

inline Evp keygen(const char* type, const char* curve) {
    return Evp(curve != nullptr ? EVP_PKEY_Q_keygen(nullptr, nullptr, type, curve)
                                : EVP_PKEY_Q_keygen(nullptr, nullptr, type, static_cast<std::size_t>(2048)));
}

inline Evp private_from_pem(std::string_view pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    EVP_PKEY* k = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return Evp(k);
}

inline Evp public_from_pem(std::string_view pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    EVP_PKEY* k = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return Evp(k);
}

inline bool hmac(const char* digest, Span key, Span data, uint8_t* out, std::size_t outlen) {
    static EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char*>(digest), 0),
                           OSSL_PARAM_construct_end()};
    std::size_t n = 0;
    const bool ok = ctx != nullptr && EVP_MAC_init(ctx, key.data(), key.size(), params) == 1 &&
                    EVP_MAC_update(ctx, data.data(), data.size()) == 1 &&
                    EVP_MAC_final(ctx, out, &n, outlen) == 1 && n == outlen;
    EVP_MAC_CTX_free(ctx);
    return ok;
}

inline bool hkdf_sha384(Span ikm, Span salt, Span info, uint8_t* out, std::size_t outlen) {
    static EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    char sha384[] = "SHA384";
    OSSL_PARAM params[5];
    int i = 0;
    params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, sha384, 0);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(ikm.data()), ikm.size());
    if (!salt.empty())
        params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt.data()), salt.size());
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(info.data()), info.size());
    params[i] = OSSL_PARAM_construct_end();
    const bool ok = ctx != nullptr && EVP_KDF_derive(ctx, out, outlen, params) == 1;
    EVP_KDF_CTX_free(ctx);
    return ok;
}

inline bool aes256_ctr(Span key, Span iv16, Span in, uint8_t* out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0, fin = 0;
    const bool ok = ctx != nullptr && EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), iv16.data()) == 1 &&
                    EVP_EncryptUpdate(ctx, out, &len, in.data(), static_cast<int>(in.size())) == 1 &&
                    EVP_EncryptFinal_ex(ctx, out + len, &fin) == 1 &&
                    static_cast<std::size_t>(len + fin) == in.size();
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

inline bool aes256_gcm_seal(Span key, Span iv12, Span aad, Span in, uint8_t* out, uint8_t tag[16]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0, fin = 0;
    const bool ok = ctx != nullptr && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
                    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv12.data()) == 1 &&
                    (aad.empty() || EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1) &&
                    EVP_EncryptUpdate(ctx, out, &len, in.data(), static_cast<int>(in.size())) == 1 &&
                    EVP_EncryptFinal_ex(ctx, out + len, &fin) == 1 &&
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

inline bool aes256_gcm_open(Span key, Span iv12, Span aad, Span in, Span tag, uint8_t* out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0, fin = 0;
    uint8_t t[16];
    std::memcpy(t, tag.data(), 16);
    const bool ok = ctx != nullptr && tag.size() == 16 &&
                    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
                    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv12.data()) == 1 &&
                    (aad.empty() || EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1) &&
                    EVP_DecryptUpdate(ctx, out, &len, in.data(), static_cast<int>(in.size())) == 1 &&
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, t) == 1 &&
                    EVP_DecryptFinal_ex(ctx, out + len, &fin) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/// One-shot EVP signature. pss selects RSA-PSS with the digest's length as
/// salt and the same digest for MGF1; otherwise PKCS1 v1.5 for RSA, plain
/// ECDSA (DER) for EC.
inline bool evp_sign(EVP_PKEY* key, const EVP_MD* md, bool pss, Span data, Bytes& sig) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;
    bool ok = ctx != nullptr && EVP_DigestSignInit(ctx, &pctx, md, nullptr, key) == 1;
    if (ok && pss)
        ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1 &&
             EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, EVP_MD_get_size(md)) == 1 &&
             EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) == 1;
    std::size_t n = 0;
    ok = ok && EVP_DigestSign(ctx, nullptr, &n, data.data(), data.size()) == 1;
    sig.resize(n);
    ok = ok && EVP_DigestSign(ctx, sig.data(), &n, data.data(), data.size()) == 1;
    sig.resize(n);
    EVP_MD_CTX_free(ctx);
    return ok;
}

inline bool evp_verify(EVP_PKEY* key, const EVP_MD* md, bool pss, Span data, Span sig) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;
    bool ok = ctx != nullptr && EVP_DigestVerifyInit(ctx, &pctx, md, nullptr, key) == 1;
    if (ok && pss)
        ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1 &&
             EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, EVP_MD_get_size(md)) == 1 &&
             EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) == 1;
    ok = ok && EVP_DigestVerify(ctx, sig.data(), sig.size(), data.data(), data.size()) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

/// DER ECDSA signature to r || s of n bytes each.
inline bool ecdsa_der_to_raw(Span der, std::size_t n, Bytes& raw) {
    const uint8_t* p = der.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size()));
    if (sig == nullptr) return false;
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig, &r, &s);
    raw.assign(2 * n, 0);
    const bool ok = BN_bn2binpad(r, raw.data(), static_cast<int>(n)) == static_cast<int>(n) &&
                    BN_bn2binpad(s, raw.data() + n, static_cast<int>(n)) == static_cast<int>(n);
    ECDSA_SIG_free(sig);
    return ok;
}

inline bool ecdsa_raw_to_der(Span raw, Bytes& der) {
    if (raw.empty() || raw.size() % 2 != 0) return false;
    const std::size_t n = raw.size() / 2;
    ECDSA_SIG* sig = ECDSA_SIG_new();
    BIGNUM* r = BN_bin2bn(raw.data(), static_cast<int>(n), nullptr);
    BIGNUM* s = BN_bin2bn(raw.data() + n, static_cast<int>(n), nullptr);
    if (sig == nullptr || r == nullptr || s == nullptr || ECDSA_SIG_set0(sig, r, s) != 1) {
        ECDSA_SIG_free(sig);
        BN_free(r);
        BN_free(s);
        return false;
    }
    const int len = i2d_ECDSA_SIG(sig, nullptr);
    if (len <= 0) {
        ECDSA_SIG_free(sig);
        return false;
    }
    der.resize(static_cast<std::size_t>(len));
    uint8_t* p = der.data();
    const bool ok = i2d_ECDSA_SIG(sig, &p) == len;
    ECDSA_SIG_free(sig);
    return ok;
}

/// The compressed SEC1 point of an EC public key (49 bytes for P-384).
inline bool ec_compressed_point(EVP_PKEY* key, Bytes& out) {
    uint8_t buf[200];
    std::size_t n = 0;
    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, buf, sizeof buf, &n) != 1 || n == 0) return false;
    if (buf[0] == 0x02 || buf[0] == 0x03) {
        out.assign(buf, buf + n);
        return true;
    }
    if (buf[0] != 0x04 || n % 2 != 1) return false;
    const std::size_t half = (n - 1) / 2;
    out.assign(1 + half, 0);
    out[0] = static_cast<uint8_t>(0x02 | (buf[n - 1] & 1));
    std::memcpy(out.data() + 1, buf + 1, half);
    return true;
}

// PASETO v1

inline std::string v1_local_encrypt(Span key, Span m, Span f, const uint8_t random32[32]) {
    uint8_t pre[48];
    if (!hmac("SHA384", {random32, 32}, m, pre, 48)) return {};
    const Span n(pre, 32);
    uint8_t ek[32], ak[32];
    if (!hkdf_sha384(key, n.first(16), sp("paseto-encryption-key"), ek, 32) ||
        !hkdf_sha384(key, n.first(16), sp("paseto-auth-key-for-aead"), ak, 32))
        return {};
    Bytes raw(32 + m.size() + 48);
    std::memcpy(raw.data(), n.data(), 32);
    if (!aes256_ctr({ek, 32}, n.subspan(16, 16), m, raw.data() + 32)) return {};
    const Bytes pre_auth = pae({sp("v1.local."), n, Span(raw.data() + 32, m.size()), f});
    if (!hmac("SHA384", {ak, 32}, pre_auth, raw.data() + 32 + m.size(), 48)) return {};
    return assemble("v1.local.", raw, f);
}

inline bool v1_local_decrypt(Span key, std::string_view token, Span f, Bytes& out) {
    Bytes raw;
    if (!disassemble(token, "v1.local.", f, raw) || raw.size() < 80) return false;
    const Span n(raw.data(), 32);
    const Span c(raw.data() + 32, raw.size() - 80);
    uint8_t ek[32], ak[32], t[48];
    if (!hkdf_sha384(key, n.first(16), sp("paseto-encryption-key"), ek, 32) ||
        !hkdf_sha384(key, n.first(16), sp("paseto-auth-key-for-aead"), ak, 32))
        return false;
    if (!hmac("SHA384", {ak, 32}, pae({sp("v1.local."), n, c, f}), t, 48) ||
        sodium_memcmp(t, raw.data() + raw.size() - 48, 48) != 0)
        return false;
    out.resize(c.size());
    return aes256_ctr({ek, 32}, n.subspan(16, 16), c, out.data());
}

inline std::string v1_public_sign(EVP_PKEY* sk, Span m, Span f) {
    Bytes sig;
    if (!evp_sign(sk, EVP_sha384(), true, pae({sp("v1.public."), m, f}), sig) || sig.size() != 256) return {};
    Bytes raw(m.begin(), m.end());
    raw.insert(raw.end(), sig.begin(), sig.end());
    return assemble("v1.public.", raw, f);
}

inline bool v1_public_verify(EVP_PKEY* pk, std::string_view token, Span f, Bytes& out) {
    Bytes raw;
    if (!disassemble(token, "v1.public.", f, raw) || raw.size() < 256) return false;
    const Span m(raw.data(), raw.size() - 256);
    if (!evp_verify(pk, EVP_sha384(), true, pae({sp("v1.public."), m, f}), Span(raw.data() + m.size(), 256))) return false;
    out.assign(m.begin(), m.end());
    return true;
}

// PASETO v2

inline std::string v2_local_encrypt(Span key, Span m, Span f, const uint8_t random24[24]) {
    uint8_t n[24];
    crypto_generichash(n, 24, m.data(), m.size(), random24, 24);
    const Bytes ad = pae({sp("v2.local."), Span(n, 24), f});
    Bytes raw(24 + m.size() + 16);
    std::memcpy(raw.data(), n, 24);
    unsigned long long clen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(raw.data() + 24, &clen, m.data(), m.size(), ad.data(), ad.size(),
                                                   nullptr, n, key.data()) != 0)
        return {};
    return assemble("v2.local.", raw, f);
}

inline bool v2_local_decrypt(Span key, std::string_view token, Span f, Bytes& out) {
    Bytes raw;
    if (!disassemble(token, "v2.local.", f, raw) || raw.size() < 40) return false;
    const Span n(raw.data(), 24);
    const Bytes ad = pae({sp("v2.local."), n, f});
    out.resize(raw.size() - 40);
    unsigned long long mlen = 0;
    return crypto_aead_xchacha20poly1305_ietf_decrypt(out.data(), &mlen, nullptr, raw.data() + 24, raw.size() - 24,
                                                      ad.data(), ad.size(), n.data(), key.data()) == 0;
}

inline std::string ed25519_token(std::string_view h, const uint8_t sk[64], Span m, Span f, const Bytes& m2) {
    Bytes raw(m.begin(), m.end());
    raw.resize(m.size() + 64);
    if (crypto_sign_detached(raw.data() + m.size(), nullptr, m2.data(), m2.size(), sk) != 0) return {};
    return assemble(h, raw, f);
}

inline std::string v2_public_sign(const uint8_t sk[64], Span m, Span f) {
    return ed25519_token("v2.public.", sk, m, f, pae({sp("v2.public."), m, f}));
}

inline bool v2_public_verify(const uint8_t pk[32], std::string_view token, Span f, Bytes& out) {
    Bytes raw;
    if (!disassemble(token, "v2.public.", f, raw) || raw.size() < 64) return false;
    const Span m(raw.data(), raw.size() - 64);
    const Bytes m2 = pae({sp("v2.public."), m, f});
    if (crypto_sign_verify_detached(raw.data() + m.size(), m2.data(), m2.size(), pk) != 0) return false;
    out.assign(m.begin(), m.end());
    return true;
}

// PASETO v3

inline bool v3_split(Span key, Span n, uint8_t ek[32], uint8_t n2[16], uint8_t ak[48]) {
    Bytes info = Bytes(sp("paseto-encryption-key").begin(), sp("paseto-encryption-key").end());
    info.insert(info.end(), n.begin(), n.end());
    uint8_t tmp[48];
    if (!hkdf_sha384(key, {}, info, tmp, 48)) return false;
    std::memcpy(ek, tmp, 32);
    std::memcpy(n2, tmp + 32, 16);
    Bytes ainfo = Bytes(sp("paseto-auth-key-for-aead").begin(), sp("paseto-auth-key-for-aead").end());
    ainfo.insert(ainfo.end(), n.begin(), n.end());
    return hkdf_sha384(key, {}, ainfo, ak, 48);
}

inline std::string v3_local_encrypt(Span key, Span m, Span f, Span i, const uint8_t random32[32]) {
    const Span n(random32, 32);
    uint8_t ek[32], n2[16], ak[48];
    if (!v3_split(key, n, ek, n2, ak)) return {};
    Bytes raw(32 + m.size() + 48);
    std::memcpy(raw.data(), n.data(), 32);
    if (!aes256_ctr({ek, 32}, {n2, 16}, m, raw.data() + 32)) return {};
    const Bytes pre_auth = pae({sp("v3.local."), n, Span(raw.data() + 32, m.size()), f, i});
    if (!hmac("SHA384", {ak, 48}, pre_auth, raw.data() + 32 + m.size(), 48)) return {};
    return assemble("v3.local.", raw, f);
}

inline bool v3_local_decrypt(Span key, std::string_view token, Span f, Span i, Bytes& out) {
    Bytes raw;
    if (!disassemble(token, "v3.local.", f, raw) || raw.size() < 80) return false;
    const Span n(raw.data(), 32);
    const Span c(raw.data() + 32, raw.size() - 80);
    uint8_t ek[32], n2[16], ak[48], t[48];
    if (!v3_split(key, n, ek, n2, ak)) return false;
    if (!hmac("SHA384", {ak, 48}, pae({sp("v3.local."), n, c, f, i}), t, 48) ||
        sodium_memcmp(t, raw.data() + raw.size() - 48, 48) != 0)
        return false;
    out.resize(c.size());
    return aes256_ctr({ek, 32}, {n2, 16}, c, out.data());
}

inline std::string v3_public_sign(EVP_PKEY* sk, Span m, Span f, Span i) {
    Bytes pk, der, sig;
    if (!ec_compressed_point(sk, pk) || pk.size() != 49) return {};
    if (!evp_sign(sk, EVP_sha384(), false, pae({pk, sp("v3.public."), m, f, i}), der) || !ecdsa_der_to_raw(der, 48, sig))
        return {};
    Bytes raw(m.begin(), m.end());
    raw.insert(raw.end(), sig.begin(), sig.end());
    return assemble("v3.public.", raw, f);
}

inline bool v3_public_verify(EVP_PKEY* pk, std::string_view token, Span f, Span i, Bytes& out) {
    Bytes raw, point, der;
    if (!disassemble(token, "v3.public.", f, raw) || raw.size() < 96) return false;
    if (!ec_compressed_point(pk, point) || point.size() != 49) return false;
    const Span m(raw.data(), raw.size() - 96);
    if (!ecdsa_raw_to_der(Span(raw.data() + m.size(), 96), der)) return false;
    if (!evp_verify(pk, EVP_sha384(), false, pae({point, sp("v3.public."), m, f, i}), der)) return false;
    out.assign(m.begin(), m.end());
    return true;
}

// PASETO v4

inline void v4_split(Span key, Span n, uint8_t ek[32], uint8_t n2[24], uint8_t ak[32]) {
    uint8_t tmp[56];
    Bytes info = Bytes(sp("paseto-encryption-key").begin(), sp("paseto-encryption-key").end());
    info.insert(info.end(), n.begin(), n.end());
    crypto_generichash(tmp, 56, info.data(), info.size(), key.data(), key.size());
    std::memcpy(ek, tmp, 32);
    std::memcpy(n2, tmp + 32, 24);
    Bytes ainfo = Bytes(sp("paseto-auth-key-for-aead").begin(), sp("paseto-auth-key-for-aead").end());
    ainfo.insert(ainfo.end(), n.begin(), n.end());
    crypto_generichash(ak, 32, ainfo.data(), ainfo.size(), key.data(), key.size());
}

inline std::string v4_local_encrypt(Span key, Span m, Span f, Span i, const uint8_t random32[32]) {
    const Span n(random32, 32);
    uint8_t ek[32], n2[24], ak[32];
    v4_split(key, n, ek, n2, ak);
    Bytes raw(32 + m.size() + 32);
    std::memcpy(raw.data(), n.data(), 32);
    if (!m.empty() && crypto_stream_xchacha20_xor(raw.data() + 32, m.data(), m.size(), n2, ek) != 0) return {};
    const Bytes pre_auth = pae({sp("v4.local."), n, Span(raw.data() + 32, m.size()), f, i});
    crypto_generichash(raw.data() + 32 + m.size(), 32, pre_auth.data(), pre_auth.size(), ak, 32);
    return assemble("v4.local.", raw, f);
}

inline bool v4_local_decrypt(Span key, std::string_view token, Span f, Span i, Bytes& out) {
    Bytes raw;
    if (!disassemble(token, "v4.local.", f, raw) || raw.size() < 64) return false;
    const Span n(raw.data(), 32);
    const Span c(raw.data() + 32, raw.size() - 64);
    uint8_t ek[32], n2[24], ak[32], t[32];
    v4_split(key, n, ek, n2, ak);
    const Bytes pre_auth = pae({sp("v4.local."), n, c, f, i});
    crypto_generichash(t, 32, pre_auth.data(), pre_auth.size(), ak, 32);
    if (crypto_verify_32(t, raw.data() + raw.size() - 32) != 0) return false;
    out.resize(c.size());
    return c.empty() || crypto_stream_xchacha20_xor(out.data(), c.data(), c.size(), n2, ek) == 0;
}

inline std::string v4_public_sign(const uint8_t sk[64], Span m, Span f, Span i) {
    return ed25519_token("v4.public.", sk, m, f, pae({sp("v4.public."), m, f, i}));
}

inline bool v4_public_verify(const uint8_t pk[32], std::string_view token, Span f, Span i, Bytes& out) {
    Bytes raw;
    if (!disassemble(token, "v4.public.", f, raw) || raw.size() < 64) return false;
    const Span m(raw.data(), raw.size() - 64);
    const Bytes m2 = pae({sp("v4.public."), m, f, i});
    if (crypto_sign_verify_detached(raw.data() + m.size(), m2.data(), m2.size(), pk) != 0) return false;
    out.assign(m.begin(), m.end());
    return true;
}

// JOSE

/// base64url(header) || "." || base64url(payload) || "." || base64url(sig(input))
template <class Sign>
std::string jws(std::string_view header, Span payload, Sign sign) {
    std::string input = b64(sp(header));
    input += '.';
    input += b64(payload);
    Bytes sig;
    if (!sign(sp(input), sig)) return {};
    input += '.';
    input += b64(sig);
    return input;
}

/// Splits a compact JWS, checks the signature over the first two
/// segments and returns the payload. The header is not parsed: the
/// verifier knows which algorithm it accepts, as every safe JWT verifier
/// must; this favours JWT in the comparison, not cb2.
template <class Verify>
bool jws_verify(std::string_view token, Verify verify, Bytes& payload) {
    const std::size_t d1 = token.find('.');
    if (d1 == std::string_view::npos) return false;
    const std::size_t d2 = token.find('.', d1 + 1);
    if (d2 == std::string_view::npos || token.find('.', d2 + 1) != std::string_view::npos) return false;
    Bytes sig;
    if (!unb64(token.substr(d2 + 1), sig)) return false;
    if (!verify(sp(token.substr(0, d2)), sig)) return false;
    return unb64(token.substr(d1 + 1, d2 - d1 - 1), payload);
}

inline bool hs256_sign(Span key, Span input, Bytes& sig) {
    sig.resize(32);
    return hmac("SHA256", key, input, sig.data(), 32);
}

inline bool hs256_verify(Span key, Span input, Span sig) {
    uint8_t t[32];
    return sig.size() == 32 && hmac("SHA256", key, input, t, 32) && sodium_memcmp(t, sig.data(), 32) == 0;
}

inline bool rs256_sign(EVP_PKEY* sk, Span input, Bytes& sig) { return evp_sign(sk, EVP_sha256(), false, input, sig); }
inline bool rs256_verify(EVP_PKEY* pk, Span input, Span sig) { return evp_verify(pk, EVP_sha256(), false, input, sig); }

inline bool es256_sign(EVP_PKEY* sk, Span input, Bytes& sig) {
    Bytes der;
    return evp_sign(sk, EVP_sha256(), false, input, der) && ecdsa_der_to_raw(der, 32, sig);
}

inline bool es256_verify(EVP_PKEY* pk, Span input, Span sig) {
    Bytes der;
    return sig.size() == 64 && ecdsa_raw_to_der(sig, der) && evp_verify(pk, EVP_sha256(), false, input, der);
}

inline bool eddsa_sign(const uint8_t sk[64], Span input, Bytes& sig) {
    sig.resize(64);
    return crypto_sign_detached(sig.data(), nullptr, input.data(), input.size(), sk) == 0;
}

inline bool eddsa_verify(const uint8_t pk[32], Span input, Span sig) {
    return sig.size() == 64 && crypto_sign_verify_detached(sig.data(), input.data(), input.size(), pk) == 0;
}

/// JWE compact serialisation with alg dir and enc A256GCM: the protected
/// header, an empty encrypted key, the IV, the ciphertext and the tag; the
/// AAD is the ASCII of the encoded header.
inline std::string jwe_a256gcm_seal(Span key, Span payload, const uint8_t iv[12]) {
    static constexpr std::string_view HEADER = "{\"alg\":\"dir\",\"enc\":\"A256GCM\"}";
    const std::string h = b64(sp(HEADER));
    Bytes c(payload.size());
    uint8_t tag[16];
    if (!aes256_gcm_seal(key, {iv, 12}, sp(h), payload, c.data(), tag)) return {};
    std::string out = h;
    out += "..";
    out += b64({iv, 12});
    out += '.';
    out += b64(c);
    out += '.';
    out += b64({tag, 16});
    return out;
}

inline bool jwe_a256gcm_open(Span key, std::string_view token, Bytes& out) {
    std::size_t pos[4];
    std::size_t from = 0;
    for (std::size_t k = 0; k < 4; ++k) {
        pos[k] = token.find('.', from);
        if (pos[k] == std::string_view::npos) return false;
        from = pos[k] + 1;
    }
    if (token.find('.', from) != std::string_view::npos || pos[1] != pos[0] + 1) return false;
    const std::string_view h = token.substr(0, pos[0]);
    Bytes iv, c, tag;
    if (!unb64(token.substr(pos[1] + 1, pos[2] - pos[1] - 1), iv) || iv.size() != 12 ||
        !unb64(token.substr(pos[2] + 1, pos[3] - pos[2] - 1), c) || !unb64(token.substr(pos[3] + 1), tag) ||
        tag.size() != 16)
        return false;
    out.resize(c.size());
    return aes256_gcm_open(key, iv, sp(h), c, tag, out.data());
}

}
