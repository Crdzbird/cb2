#pragma once

/**
 * cb2::Public: cb2.public tokens, present only under CB2_HAS_PQ.
 *
 *   h    = "cb2.public."
 *   m2   = PAE(h, m, f, i)
 *   sig  = Ed25519-sign(sk_ed, m2) || ML-DSA-65-sign(sk_ml, m2, ctx = h), 3373 bytes
 *   body = m || sig
 *   token = h || base64url(body) [ || "." || base64url(f) ]
 *
 * A token verifies only when both halves verify under the matching halves
 * of the public key. The ML-DSA half carries the header as its FIPS 204
 * context string, so the same key signing anything else, even these PAE
 * bytes under another context, yields nothing a cb2.public verifier
 * accepts. The pre-authentication encoding is public, so it is built in
 * plain memory: inside the output buffer when it fits there (the usual
 * case), otherwise in one heap allocation.
 *
 * The construction is detail::PublicCore, parameterised by its header so
 * that the holder proof purpose (holder.hpp) reuses it byte for byte with
 * its own header as the domain string; Public is the cb2.public instance.
 */

#ifdef CB2_HAS_PQ

#include "detail/local_core.hpp"
#include "detail/pae.hpp"
#include "detail/pq.hpp"
#include "keys.hpp"
#include "local.hpp"
#include "result.hpp"

#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cb2 {

namespace detail {

/// The hybrid signature construction for a given header.
class PublicCore {
public:
    static constexpr std::size_t ED_SIG_BYTES = crypto_sign_BYTES;
    static constexpr std::size_t ML_SIG_BYTES = MlDsa65::SIG_BYTES;
    static constexpr std::size_t SIG_BYTES = ED_SIG_BYTES + ML_SIG_BYTES;

    [[nodiscard]] static constexpr std::size_t
    token_len(std::string_view h, std::size_t msg_len, std::size_t footer_len) noexcept {
        if (msg_len > MAX_INPUT_BYTES || footer_len > MAX_INPUT_BYTES) return 0;
        return token_len_for(h.size(), msg_len + SIG_BYTES, footer_len);
    }

    [[nodiscard]] static constexpr std::size_t max_token_len(std::string_view h) noexcept {
        return token_len(h, MAX_INPUT_BYTES, MAX_INPUT_BYTES);
    }

    [[nodiscard]] static constexpr std::size_t
    open_capacity(std::string_view h, std::size_t token_len) noexcept {
        if (token_len <= h.size() || token_len > max_token_len(h)) return 0;
        return (token_len - h.size()) * 3 / 4;
    }

    [[nodiscard]] static constexpr std::size_t
    verify_capacity(std::string_view h, std::size_t token_len, std::size_t footer_len,
                    std::size_t implicit_len) noexcept {
        const std::size_t cap = open_capacity(h, token_len);
        if (cap == 0) return 0;
        return cap + pae_len({h.size(), cap, footer_len, implicit_len});
    }

    [[nodiscard]] static Status
    sign_into(std::string_view h, std::span<uint8_t> out, std::size_t& out_len, const SecretKey& key,
              std::span<const uint8_t> msg, std::span<const uint8_t> footer,
              std::span<const uint8_t> implicit) noexcept {
        out_len = 0;
        const std::size_t need = token_len(h, msg.size(), footer.size());
        if (h.size() > MAX_HEADER_BYTES || h.size() > MlDsa65::MAX_CTX_BYTES || need == 0 ||
            implicit.size() > MAX_INPUT_BYTES || out.size() < need)
            return Status::argument;
        if (overlaps(out, msg) || overlaps(out, footer) || overlaps(out, implicit))
            return Status::argument;
        if (!ensure_sodium() || !MlDsa65::available()) return Status::internal;
        const std::size_t plen = pae_len({h.size(), msg.size(), footer.size(), implicit.size()});
        std::vector<uint8_t> heap;
        uint8_t* pae = out.data();
        if (plen > out.size()) {
            try {
                heap.resize(plen);
            } catch (...) {
                return Status::internal;
            }
            pae = heap.data();
        }
        SpanSink sink{pae};
        pae_stream(sink, {as_bytes(h), msg, footer, implicit});
        uint8_t sig[SIG_BYTES];
        if (!sign_pae(h, sig, pae, plen, key)) {
            wipe(out.data(), plen > out.size() ? need : (plen > need ? plen : need));
            return Status::internal;
        }
        declassify(sig, SIG_BYTES);
        const std::size_t raw_len = msg.size() + SIG_BYTES;
        uint8_t* raw = out.data() + h.size() + b64::encoded_len(raw_len) - raw_len;
        if (!msg.empty()) std::memmove(raw, msg.data(), msg.size());
        std::memcpy(raw + msg.size(), sig, SIG_BYTES);
        out_len = finish_token(out, h, raw, raw_len, footer);
        return Status::ok;
    }

    [[nodiscard]] static Status
    verify_into(std::string_view h, std::span<uint8_t> out, std::size_t& out_len,
                std::string_view token, const PublicKey& key, std::span<const uint8_t> expected_footer,
                std::span<const uint8_t> implicit) noexcept {
        out_len = 0;
        const std::size_t cap = verify_capacity(h, token.size(), expected_footer.size(), implicit.size());
        if (h.size() > MAX_HEADER_BYTES || h.size() > MlDsa65::MAX_CTX_BYTES ||
            expected_footer.size() > MAX_INPUT_BYTES || implicit.size() > MAX_INPUT_BYTES ||
            out.size() < cap)
            return Status::argument;
        if (overlaps(out, as_bytes(token)) || overlaps(out, expected_footer) ||
            overlaps(out, implicit) || overlaps(out, key.bytes()))
            return Status::argument;
        if (!ensure_sodium() || !MlDsa65::available()) return Status::internal;
        const Status s = verify_impl(h, out.first(cap), out_len, token, key, expected_footer, implicit);
        if (s == Status::ok) return s;
        if (cap != 0) wipe(out.data(), cap);
        out_len = 0;
        return s;
    }

    [[nodiscard]] static Result<std::string>
    sign(std::string_view h, const SecretKey& key, std::span<const uint8_t> msg,
         std::span<const uint8_t> footer, std::span<const uint8_t> implicit) {
        const std::size_t need = token_len(h, msg.size(), footer.size());
        if (need == 0) return Result<std::string>::err(Error::argument);
        std::string tok(need, '\0');
        std::size_t n = 0;
        const Status s = sign_into(h, {reinterpret_cast<uint8_t*>(tok.data()), tok.size()}, n, key,
                                   msg, footer, implicit);
        if (s != Status::ok) return Result<std::string>::err(to_error(s));
        return Result<std::string>::ok(std::move(tok));
    }

    [[nodiscard]] static Result<std::vector<uint8_t>>
    verify(std::string_view h, std::string_view token, const PublicKey& key,
           std::span<const uint8_t> expected_footer, std::span<const uint8_t> implicit,
           std::size_t max_token_bytes) {
        if (token.size() > max_token_bytes) return Result<std::vector<uint8_t>>::err(Error::too_large);
        const std::size_t cap = verify_capacity(h, token.size(), expected_footer.size(), implicit.size());
        if (cap == 0) return Result<std::vector<uint8_t>>::err(Error::invalid);
        std::vector<uint8_t> buf(cap);
        std::size_t n = 0;
        const Status s = verify_into(h, buf, n, token, key, expected_footer, implicit);
        if (s != Status::ok) return Result<std::vector<uint8_t>>::err(to_error(s));
        buf.resize(n);
        return Result<std::vector<uint8_t>>::ok(std::move(buf));
    }

private:
    [[nodiscard]] static bool sign_pae(std::string_view h, uint8_t* sig, const uint8_t* pae,
                                       std::size_t plen, const SecretKey& key) noexcept {
        unsigned long long ed_len = 0;
        if (crypto_sign_detached(sig, &ed_len, pae, plen, KeyAccess::ed_secret(key)) != 0 ||
            ed_len != ED_SIG_BYTES)
            return false;
        return MlDsa65::sign(sig + ED_SIG_BYTES, pae, plen, as_bytes(h), KeyAccess::ml_secret(key));
    }

    static Status verify_impl(std::string_view h, std::span<uint8_t> work, std::size_t& out_len,
                              std::string_view token, const PublicKey& key,
                              std::span<const uint8_t> expected_footer,
                              std::span<const uint8_t> implicit) noexcept {
        Split s{};
        const std::size_t decoded_cap = open_capacity(h, token.size());
        if (decoded_cap == 0 || !split_token(token, h, !expected_footer.empty(), s))
            return Status::invalid;
        std::size_t raw_len = 0;
        if (!b64::decode(work.data(), decoded_cap, s.body, s.body_len, raw_len) ||
            raw_len < SIG_BYTES)
            return Status::invalid;
        if (!footer_matches(work.data() + raw_len, decoded_cap - raw_len, s, expected_footer))
            return Status::invalid;
        const std::size_t mlen = raw_len - SIG_BYTES;
        const uint8_t* m = work.data();
        const uint8_t* sig = work.data() + mlen;
        uint8_t* pae = work.data() + decoded_cap;
        const std::size_t plen = pae_len({h.size(), mlen, expected_footer.size(), implicit.size()});
        SpanSink sink{pae};
        pae_stream(sink, {as_bytes(h), {m, mlen}, expected_footer, implicit});
        const bool ed_ok = crypto_sign_verify_detached(sig, pae, plen, KeyAccess::ed_public(key)) == 0;
        const bool ml_ok = MlDsa65::verify(pae, plen, sig + ED_SIG_BYTES, ML_SIG_BYTES, as_bytes(h),
                                           KeyAccess::ml_public(key));
        if (!ed_ok || !ml_ok) return Status::invalid;
        wipe(work.data() + mlen, work.size() - mlen);
        out_len = mlen;
        return Status::ok;
    }
};

}

class Public {
public:
    static constexpr std::string_view HEADER = "cb2.public.";
    static constexpr std::size_t ED_SIG_BYTES = detail::PublicCore::ED_SIG_BYTES;
    static constexpr std::size_t ML_SIG_BYTES = detail::PublicCore::ML_SIG_BYTES;
    static constexpr std::size_t SIG_BYTES = detail::PublicCore::SIG_BYTES;

    [[nodiscard]] static constexpr std::size_t
    token_len(std::size_t msg_len, std::size_t footer_len) noexcept {
        return detail::PublicCore::token_len(HEADER, msg_len, footer_len);
    }

    [[nodiscard]] static constexpr std::size_t max_token_len() noexcept {
        return detail::PublicCore::max_token_len(HEADER);
    }

    /// Bytes the decoded body and footer of a token of this length need.
    [[nodiscard]] static constexpr std::size_t open_capacity(std::size_t token_len) noexcept {
        return detail::PublicCore::open_capacity(HEADER, token_len);
    }

    /// Output capacity verify_into requires: the decoded region plus the
    /// scratch for the pre-authentication encoding. 0 for a length no
    /// valid token has.
    [[nodiscard]] static constexpr std::size_t
    verify_capacity(std::size_t token_len, std::size_t footer_len, std::size_t implicit_len) noexcept {
        return detail::PublicCore::verify_capacity(HEADER, token_len, footer_len, implicit_len);
    }

    /// Signs msg into out, which must hold token_len(msg.size(),
    /// footer.size()) bytes and overlap no input. On success out_len is that
    /// length, otherwise 0.
    [[nodiscard]] static Status
    sign_into(std::span<uint8_t> out, std::size_t& out_len, const SecretKey& key,
              std::span<const uint8_t> msg, std::span<const uint8_t> footer = {},
              std::span<const uint8_t> implicit = {}) noexcept {
        return detail::PublicCore::sign_into(HEADER, out, out_len, key, msg, footer, implicit);
    }

    /// Verifies token under key into out, which must hold
    /// verify_capacity(token.size(), expected_footer.size(), implicit.size())
    /// bytes and overlap no input. On success the message is out[0, out_len)
    /// and the rest of the region is zero; on failure the region is zero and
    /// out_len is 0.
    [[nodiscard]] static Status
    verify_into(std::span<uint8_t> out, std::size_t& out_len, std::string_view token,
                const PublicKey& key, std::span<const uint8_t> expected_footer = {},
                std::span<const uint8_t> implicit = {}) noexcept {
        return detail::PublicCore::verify_into(HEADER, out, out_len, token, key, expected_footer, implicit);
    }

    /// Signs msg and returns the token text. One allocation.
    [[nodiscard]] static Result<std::string>
    sign(const SecretKey& key, std::span<const uint8_t> msg, std::span<const uint8_t> footer = {},
         std::span<const uint8_t> implicit = {}) {
        return detail::PublicCore::sign(HEADER, key, msg, footer, implicit);
    }

    /// Verifies token and returns the message. One allocation. A token
    /// longer than max_token_bytes is too_large before any of it is read;
    /// the default keeps a garbage token from costing a 48 MiB buffer.
    [[nodiscard]] static Result<std::vector<uint8_t>>
    verify(std::string_view token, const PublicKey& key, std::span<const uint8_t> expected_footer = {},
           std::span<const uint8_t> implicit = {},
           std::size_t max_token_bytes = DEFAULT_RAW_MAX_TOKEN_BYTES) {
        return detail::PublicCore::verify(HEADER, token, key, expected_footer, implicit, max_token_bytes);
    }
};

}

#endif
