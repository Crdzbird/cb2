#pragma once

/**
 * The cb2.local construction, parameterised by its header so that the
 * kcb2.local-wrap key wrapping reuses it byte for byte.
 *
 * Inputs: a 32-byte key K, a 32-byte nonce n, a message m, a footer f and
 * an implicit assertion i.
 *
 *   Ek || n2 || Ak = BLAKE3-keyed(K, h || n), 88 bytes of extendable output
 *                    (Ek 32 bytes, n2 24 bytes, Ak 32 bytes)
 *   c              = XChaCha20(Ek, n2) XOR m
 *   t              = BLAKE3-keyed(Ak, PAE(h, n, c, f, i)), 32 bytes
 *   token          = h || base64url(n || c || t) [ || "." || base64url(f) ]
 *
 * Opening checks the header, decodes the body and the footer, compares the
 * footer in constant time, recomputes t and compares it with
 * crypto_verify_32, and only then decrypts. Every token-dependent failure
 * is the single verdict Status::invalid. The derived keys live in a stack
 * struct that is wiped on every path.
 *
 * XChaCha20 is libsodium's. With CB2_OPENSSL_CHACHA (the CMake default on
 * native builds) a message of OPENSSL_CHACHA_MIN_BYTES or more goes
 * through OpenSSL's ChaCha20 instead, after libsodium's HChaCha20: the
 * same keystream byte for byte, which the test suite checks across the
 * threshold, from an implementation that uses the CPU's vector unit where
 * libsodium's does not. Short messages stay on libsodium, whose call has
 * no setup cost.
 */

#include "base64url.hpp"
#include "blake3.hpp"
#include "pae.hpp"
#include "secure.hpp"

#include <sodium.h>

#ifdef CB2_OPENSSL_CHACHA
#include <openssl/evp.h>
#endif

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

namespace cb2 {

/// Verdict of the buffer-level functions. ok; invalid (any failure that
/// depends on the token: one verdict, no detail); argument (a caller error
/// independent of token content); internal (a backend failed).
enum class Status : uint8_t { ok, invalid, argument, internal };

/// Largest message, footer or implicit assertion any function accepts.
inline constexpr std::size_t MAX_INPUT_BYTES = std::size_t{1} << 26;

/// Longest token the allocating open and verify functions accept unless
/// the caller raises the limit: 1 MiB. Decided on the length alone, so a
/// flood of oversize garbage costs nothing but the comparison. The
/// caller-buffer functions have no such limit; there the caller sized the
/// buffer and has already paid.
inline constexpr std::size_t DEFAULT_RAW_MAX_TOKEN_BYTES = std::size_t{1} << 20;

namespace detail {

inline constexpr std::size_t LOCAL_KEY_BYTES = 32;
inline constexpr std::size_t LOCAL_NONCE_BYTES = 32;
inline constexpr std::size_t LOCAL_TAG_BYTES = 32;
inline constexpr std::size_t LOCAL_EK_BYTES = 32;
inline constexpr std::size_t LOCAL_N2_BYTES = 24;
inline constexpr std::size_t LOCAL_AK_BYTES = 32;
inline constexpr std::size_t LOCAL_SPLIT_BYTES = LOCAL_EK_BYTES + LOCAL_N2_BYTES + LOCAL_AK_BYTES;
inline constexpr std::size_t LOCAL_OVERHEAD = LOCAL_NONCE_BYTES + LOCAL_TAG_BYTES;
inline constexpr std::size_t MAX_HEADER_BYTES = 32;

/// Messages of this many bytes or more use OpenSSL's ChaCha20 when the
/// build enables it; below it libsodium's call is the cheaper one.
inline constexpr std::size_t OPENSSL_CHACHA_MIN_BYTES = 512;

/// out = in XOR XChaCha20(ek, n2), libsodium.
[[nodiscard]] inline bool xchacha20_xor_sodium(uint8_t* out, const uint8_t* in, std::size_t n,
                                               const uint8_t* n2, const uint8_t* ek) noexcept {
    return n == 0 || crypto_stream_xchacha20_xor(out, in, n, n2, ek) == 0;
}

#ifdef CB2_OPENSSL_CHACHA
/// The same keystream through OpenSSL: HChaCha20 of the key and the
/// first 16 nonce bytes (libsodium's crypto_core_hchacha20), then ChaCha20
/// under that subkey with the IETF nonce layout, four zero bytes and the
/// last 8 nonce bytes, counter 0. Identical to the 64-bit counter form for
/// every length this library accepts. in and out are equal or disjoint.
[[nodiscard]] inline bool xchacha20_xor_openssl(uint8_t* out, const uint8_t* in, std::size_t n,
                                                const uint8_t* n2, const uint8_t* ek) noexcept {
    static EVP_CIPHER* const cipher = EVP_CIPHER_fetch(nullptr, "ChaCha20", nullptr);
    if (n == 0) return true;
    if (cipher == nullptr || n > static_cast<std::size_t>(INT32_MAX)) return false;
    SecureArray<32> sub;
    if (crypto_core_hchacha20(sub.v, n2, ek, nullptr) != 0) return false;
    uint8_t iv[16] = {};
    std::memcpy(iv + 8, n2 + 16, 8);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    const bool ok = ctx != nullptr && EVP_EncryptInit_ex(ctx, cipher, nullptr, sub.v, iv) == 1 &&
                    EVP_EncryptUpdate(ctx, out, &len, in, static_cast<int>(n)) == 1 &&
                    static_cast<std::size_t>(len) == n;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
#endif

/// The XChaCha20 the local construction uses: libsodium below the
/// threshold, OpenSSL at or above it when the build enables it.
[[nodiscard]] inline bool xchacha20_xor(uint8_t* out, const uint8_t* in, std::size_t n,
                                        const uint8_t* n2, const uint8_t* ek) noexcept {
#ifdef CB2_OPENSSL_CHACHA
    if (n >= OPENSSL_CHACHA_MIN_BYTES) return xchacha20_xor_openssl(out, in, n, n2, ek);
#endif
    return xchacha20_xor_sodium(out, in, n, n2, ek);
}

/// Token text length for a header, a raw body and a footer.
[[nodiscard]] constexpr std::size_t
token_len_for(std::size_t header, std::size_t raw, std::size_t footer) noexcept {
    const std::size_t f = footer == 0 ? 0 : 1 + b64::encoded_len(footer);
    return header + b64::encoded_len(raw) + f;
}

/// The body and footer text of a token after its header. Fails when the
/// header differs, when a dot is followed by nothing, or when the presence
/// of a footer disagrees with expect_footer.
struct Split {
    const char* body = nullptr;
    std::size_t body_len = 0;
    const char* footer = nullptr;
    std::size_t footer_len = 0;
};

[[nodiscard]] inline bool split_token(std::string_view token, std::string_view header,
                                      bool expect_footer, Split& out) noexcept {
    if (token.size() <= header.size() ||
        std::memcmp(token.data(), header.data(), header.size()) != 0)
        return false;
    const char* rest = token.data() + header.size();
    const std::size_t rest_len = token.size() - header.size();
    const char* dot = static_cast<const char*>(std::memchr(rest, '.', rest_len));
    out.body = rest;
    out.body_len = dot ? static_cast<std::size_t>(dot - rest) : rest_len;
    out.footer = dot ? dot + 1 : nullptr;
    out.footer_len = dot ? rest_len - out.body_len - 1 : 0;
    if (dot != nullptr && out.footer_len == 0) return false;
    return (dot != nullptr) == expect_footer;
}

/// Decodes the footer text into work and compares it with expected in
/// constant time.
[[nodiscard]] inline bool footer_matches(uint8_t* work, std::size_t cap, const Split& s,
                                         std::span<const uint8_t> expected) noexcept {
    std::size_t flen = 0;
    if (s.footer != nullptr && !b64::decode(work, cap, s.footer, s.footer_len, flen)) return false;
    return ct_equal({work, flen}, expected);
}

/// Writes the token text: header, the base64url of raw (already placed at
/// the end of the body region) and the footer.
inline std::size_t finish_token(std::span<uint8_t> out, std::string_view header,
                                const uint8_t* raw, std::size_t raw_len,
                                std::span<const uint8_t> footer) noexcept {
    auto* text = reinterpret_cast<char*>(out.data());
    std::memcpy(text, header.data(), header.size());
    std::size_t pos = header.size() + b64::encode(text + header.size(), raw, raw_len);
    if (!footer.empty()) {
        text[pos++] = '.';
        pos += b64::encode(text + pos, footer.data(), footer.size());
    }
    return pos;
}

/// Groups the many small PAE updates into one hasher update, so the MAC
/// of a short token costs one hasher update, not eleven: 256 bytes hold
/// the whole encoding of a 64-byte message with a key id footer.
template <class Inner>
class BufferedSink {
public:
    explicit BufferedSink(Inner& inner) noexcept : inner_(inner) {}
    void update(const uint8_t* p, std::size_t n) noexcept {
        if (n > sizeof buf_ - pos_) {
            flush();
            if (n > sizeof buf_) {
                inner_.update(p, n);
                return;
            }
        }
        std::memcpy(buf_ + pos_, p, n);
        pos_ += n;
    }
    void flush() noexcept {
        inner_.update(buf_, pos_);
        pos_ = 0;
    }

private:
    Inner& inner_;
    uint8_t buf_[256];
    std::size_t pos_ = 0;
};

struct LocalKeys {
    uint8_t split[LOCAL_SPLIT_BYTES];
    uint8_t tag[LOCAL_TAG_BYTES];
    [[nodiscard]] const uint8_t* ek() const noexcept { return split; }
    [[nodiscard]] const uint8_t* n2() const noexcept { return split + LOCAL_EK_BYTES; }
    [[nodiscard]] const uint8_t* ak() const noexcept { return split + LOCAL_EK_BYTES + LOCAL_N2_BYTES; }
    LocalKeys() noexcept : split{}, tag{} {}
    LocalKeys(const LocalKeys&) = delete;
    LocalKeys& operator=(const LocalKeys&) = delete;
    ~LocalKeys() { wipe(this, sizeof *this); }
};

class LocalCore {
public:
    [[nodiscard]] static constexpr std::size_t
    token_len(std::string_view h, std::size_t msg, std::size_t footer) noexcept {
        if (msg > MAX_INPUT_BYTES || footer > MAX_INPUT_BYTES) return 0;
        return token_len_for(h.size(), LOCAL_OVERHEAD + msg, footer);
    }

    [[nodiscard]] static constexpr std::size_t max_token_len(std::string_view h) noexcept {
        return token_len(h, MAX_INPUT_BYTES, MAX_INPUT_BYTES);
    }

    [[nodiscard]] static constexpr std::size_t
    open_capacity(std::string_view h, std::size_t token_len) noexcept {
        if (token_len <= h.size() || token_len > max_token_len(h)) return 0;
        return (token_len - h.size()) * 3 / 4;
    }

    /// Seals msg under key with the given 32-byte nonce. out must hold
    /// token_len(h, msg.size(), footer.size()) bytes and overlap no input.
    [[nodiscard]] static Status
    seal(std::string_view h, std::span<uint8_t> out, std::size_t& out_len, const uint8_t* key,
         std::span<const uint8_t> msg, std::span<const uint8_t> footer,
         std::span<const uint8_t> implicit, const uint8_t* nonce) noexcept {
        out_len = 0;
        const std::size_t need = token_len(h, msg.size(), footer.size());
        if (h.size() > MAX_HEADER_BYTES || need == 0 || implicit.size() > MAX_INPUT_BYTES ||
            out.size() < need)
            return Status::argument;
        if (overlaps(out, msg) || overlaps(out, footer) || overlaps(out, implicit) ||
            overlaps(out, {key, LOCAL_KEY_BYTES}) || overlaps(out, {nonce, LOCAL_NONCE_BYTES}))
            return Status::argument;
        if (!ensure_sodium()) return Status::internal;
        const std::size_t raw_len = LOCAL_OVERHEAD + msg.size();
        uint8_t* raw = out.data() + h.size() + b64::encoded_len(raw_len) - raw_len;
        uint8_t* c = raw + LOCAL_NONCE_BYTES;
        LocalKeys k;
        derive(k, key, h, nonce);
        std::memcpy(raw, nonce, LOCAL_NONCE_BYTES);
        if (!xchacha20_xor(c, msg.data(), msg.size(), k.n2(), k.ek())) {
            wipe(out.data(), need);
            return Status::internal;
        }
        mac(k, c + msg.size(), h, nonce, {c, msg.size()}, footer, implicit);
        out_len = finish_token(out, h, raw, raw_len, footer);
        return Status::ok;
    }

    /// Authenticates and decrypts token. out must hold
    /// open_capacity(h, token.size()) bytes and overlap no input. On success
    /// the message is out[0, out_len) and the rest of that region is zero;
    /// on failure the region is zero and out_len is 0.
    [[nodiscard]] static Status
    open(std::string_view h, std::span<uint8_t> out, std::size_t& out_len, std::string_view token,
         const uint8_t* key, std::span<const uint8_t> expected_footer,
         std::span<const uint8_t> implicit) noexcept {
        out_len = 0;
        const std::size_t cap = open_capacity(h, token.size());
        if (h.size() > MAX_HEADER_BYTES || expected_footer.size() > MAX_INPUT_BYTES ||
            implicit.size() > MAX_INPUT_BYTES || out.size() < cap)
            return Status::argument;
        if (overlaps(out, as_bytes(token)) || overlaps(out, expected_footer) ||
            overlaps(out, implicit) || overlaps(out, {key, LOCAL_KEY_BYTES}))
            return Status::argument;
        if (!ensure_sodium()) return Status::internal;
        const Status s = open_impl(h, out.first(cap), out_len, token, key, expected_footer, implicit);
        if (s == Status::ok) return s;
        if (cap != 0) wipe(out.data(), cap);
        out_len = 0;
        return s;
    }

private:
    static void derive(LocalKeys& k, const uint8_t* key, std::string_view h,
                       const uint8_t* n) noexcept {
        Blake3Keyed hk(key);
        hk.update(reinterpret_cast<const uint8_t*>(h.data()), h.size());
        hk.update(n, LOCAL_NONCE_BYTES);
        hk.finalize(k.split, LOCAL_SPLIT_BYTES);
    }

    static void mac(LocalKeys& k, uint8_t* tag, std::string_view h, const uint8_t* n,
                    std::span<const uint8_t> c, std::span<const uint8_t> f,
                    std::span<const uint8_t> i) noexcept {
        Blake3Keyed hm(k.ak());
        BufferedSink<Blake3Keyed> sink(hm);
        pae_stream(sink, {as_bytes(h), {n, LOCAL_NONCE_BYTES}, c, f, i});
        sink.flush();
        hm.finalize(tag, LOCAL_TAG_BYTES);
    }

    static Status open_impl(std::string_view h, std::span<uint8_t> work, std::size_t& out_len,
                            std::string_view token, const uint8_t* key,
                            std::span<const uint8_t> expected_footer,
                            std::span<const uint8_t> implicit) noexcept {
        Split s{};
        if (work.empty() || !split_token(token, h, !expected_footer.empty(), s))
            return Status::invalid;
        std::size_t raw_len = 0;
        if (!b64::decode(work.data(), work.size(), s.body, s.body_len, raw_len) ||
            raw_len < LOCAL_OVERHEAD)
            return Status::invalid;
        if (!footer_matches(work.data() + raw_len, work.size() - raw_len, s, expected_footer))
            return Status::invalid;
        uint8_t n[LOCAL_NONCE_BYTES];
        uint8_t t[LOCAL_TAG_BYTES];
        std::memcpy(n, work.data(), LOCAL_NONCE_BYTES);
        std::memcpy(t, work.data() + raw_len - LOCAL_TAG_BYTES, LOCAL_TAG_BYTES);
        const std::size_t clen = raw_len - LOCAL_OVERHEAD;
        uint8_t* c = work.data() + LOCAL_NONCE_BYTES;
        LocalKeys k;
        derive(k, key, h, n);
        mac(k, k.tag, h, n, {c, clen}, expected_footer, implicit);
        if (crypto_verify_32(t, k.tag) != 0) return Status::invalid;
        std::memmove(work.data(), c, clen);
        if (!xchacha20_xor(work.data(), work.data(), clen, k.n2(), k.ek())) return Status::internal;
        wipe(work.data() + clen, work.size() - clen);
        out_len = clen;
        return Status::ok;
    }
};

}

}
