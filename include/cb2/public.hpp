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

class Public {
public:
    static constexpr std::string_view HEADER = "cb2.public.";
    static constexpr std::size_t ED_SIG_BYTES = crypto_sign_BYTES;
    static constexpr std::size_t ML_SIG_BYTES = detail::MlDsa65::SIG_BYTES;
    static constexpr std::size_t SIG_BYTES = ED_SIG_BYTES + ML_SIG_BYTES;

    [[nodiscard]] static constexpr std::size_t
    token_len(std::size_t msg_len, std::size_t footer_len) noexcept {
        if (msg_len > MAX_INPUT_BYTES || footer_len > MAX_INPUT_BYTES) return 0;
        return detail::token_len_for(HEADER.size(), msg_len + SIG_BYTES, footer_len);
    }

    [[nodiscard]] static constexpr std::size_t max_token_len() noexcept {
        return token_len(MAX_INPUT_BYTES, MAX_INPUT_BYTES);
    }

    /// Bytes the decoded body and footer of a token of this length need.
    [[nodiscard]] static constexpr std::size_t open_capacity(std::size_t token_len) noexcept {
        if (token_len <= HEADER.size() || token_len > max_token_len()) return 0;
        return (token_len - HEADER.size()) * 3 / 4;
    }

    /// Output capacity verify_into requires: the decoded region plus the
    /// scratch for the pre-authentication encoding. 0 for a length no
    /// valid token has.
    [[nodiscard]] static constexpr std::size_t
    verify_capacity(std::size_t token_len, std::size_t footer_len, std::size_t implicit_len) noexcept {
        const std::size_t cap = open_capacity(token_len);
        if (cap == 0) return 0;
        return cap + detail::pae_len({HEADER.size(), cap, footer_len, implicit_len});
    }

    /// Signs msg into out, which must hold token_len(msg.size(),
    /// footer.size()) bytes and overlap no input. On success out_len is that
    /// length, otherwise 0.
    [[nodiscard]] static Status
    sign_into(std::span<uint8_t> out, std::size_t& out_len, const SecretKey& key,
              std::span<const uint8_t> msg, std::span<const uint8_t> footer = {},
              std::span<const uint8_t> implicit = {}) noexcept {
        out_len = 0;
        const std::size_t need = token_len(msg.size(), footer.size());
        if (need == 0 || implicit.size() > MAX_INPUT_BYTES || out.size() < need)
            return Status::argument;
        if (detail::overlaps(out, msg) || detail::overlaps(out, footer) ||
            detail::overlaps(out, implicit))
            return Status::argument;
        if (!detail::ensure_sodium() || !detail::MlDsa65::available()) return Status::internal;
        const std::size_t plen = detail::pae_len({HEADER.size(), msg.size(), footer.size(), implicit.size()});
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
        detail::SpanSink sink{pae};
        detail::pae_stream(sink, {bytes(HEADER), msg, footer, implicit});
        uint8_t sig[SIG_BYTES];
        if (!sign_pae(sig, pae, plen, key)) {
            detail::wipe(out.data(), plen > out.size() ? need : (plen > need ? plen : need));
            return Status::internal;
        }
        const std::size_t raw_len = msg.size() + SIG_BYTES;
        uint8_t* raw = out.data() + HEADER.size() + detail::b64::encoded_len(raw_len) - raw_len;
        if (!msg.empty()) std::memmove(raw, msg.data(), msg.size());
        std::memcpy(raw + msg.size(), sig, SIG_BYTES);
        out_len = detail::finish_token(out, HEADER, raw, raw_len, footer);
        return Status::ok;
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
        out_len = 0;
        const std::size_t cap = verify_capacity(token.size(), expected_footer.size(), implicit.size());
        if (expected_footer.size() > MAX_INPUT_BYTES || implicit.size() > MAX_INPUT_BYTES ||
            out.size() < cap)
            return Status::argument;
        if (detail::overlaps(out, bytes(token)) || detail::overlaps(out, expected_footer) ||
            detail::overlaps(out, implicit) || detail::overlaps(out, key.bytes()))
            return Status::argument;
        if (!detail::ensure_sodium() || !detail::MlDsa65::available()) return Status::internal;
        const Status s = verify_impl(out.first(cap), out_len, token, key, expected_footer, implicit);
        if (s == Status::ok) return s;
        if (cap != 0) detail::wipe(out.data(), cap);
        out_len = 0;
        return s;
    }

    /// Signs msg and returns the token text. One allocation.
    [[nodiscard]] static Result<std::string>
    sign(const SecretKey& key, std::span<const uint8_t> msg, std::span<const uint8_t> footer = {},
         std::span<const uint8_t> implicit = {}) {
        const std::size_t need = token_len(msg.size(), footer.size());
        if (need == 0) return Result<std::string>::err(Error::argument);
        std::string tok(need, '\0');
        std::size_t n = 0;
        const Status s = sign_into({reinterpret_cast<uint8_t*>(tok.data()), tok.size()}, n, key,
                                   msg, footer, implicit);
        if (s != Status::ok) return Result<std::string>::err(to_error(s));
        return Result<std::string>::ok(std::move(tok));
    }

    /// Verifies token and returns the message. One allocation. A token
    /// longer than max_token_bytes is too_large before any of it is read;
    /// the default keeps a garbage token from costing a 48 MiB buffer.
    [[nodiscard]] static Result<std::vector<uint8_t>>
    verify(std::string_view token, const PublicKey& key, std::span<const uint8_t> expected_footer = {},
           std::span<const uint8_t> implicit = {},
           std::size_t max_token_bytes = DEFAULT_RAW_MAX_TOKEN_BYTES) {
        if (token.size() > max_token_bytes) return Result<std::vector<uint8_t>>::err(Error::too_large);
        const std::size_t cap = verify_capacity(token.size(), expected_footer.size(), implicit.size());
        if (cap == 0) return Result<std::vector<uint8_t>>::err(Error::invalid);
        std::vector<uint8_t> buf(cap);
        std::size_t n = 0;
        const Status s = verify_into(buf, n, token, key, expected_footer, implicit);
        if (s != Status::ok) return Result<std::vector<uint8_t>>::err(to_error(s));
        buf.resize(n);
        return Result<std::vector<uint8_t>>::ok(std::move(buf));
    }

private:
    [[nodiscard]] static bool sign_pae(uint8_t* sig, const uint8_t* pae, std::size_t plen,
                                       const SecretKey& key) noexcept {
        unsigned long long ed_len = 0;
        if (crypto_sign_detached(sig, &ed_len, pae, plen, detail::KeyAccess::ed_secret(key)) != 0 ||
            ed_len != ED_SIG_BYTES)
            return false;
        return detail::MlDsa65::sign(sig + ED_SIG_BYTES, pae, plen, bytes(HEADER),
                                     detail::KeyAccess::ml_secret(key));
    }

    static Status verify_impl(std::span<uint8_t> work, std::size_t& out_len, std::string_view token,
                              const PublicKey& key, std::span<const uint8_t> expected_footer,
                              std::span<const uint8_t> implicit) noexcept {
        detail::Split s{};
        const std::size_t decoded_cap = open_capacity(token.size());
        if (decoded_cap == 0 || !detail::split_token(token, HEADER, !expected_footer.empty(), s))
            return Status::invalid;
        std::size_t raw_len = 0;
        if (!detail::b64::decode(work.data(), decoded_cap, s.body, s.body_len, raw_len) ||
            raw_len < SIG_BYTES)
            return Status::invalid;
        if (!detail::footer_matches(work.data() + raw_len, decoded_cap - raw_len, s, expected_footer))
            return Status::invalid;
        const std::size_t mlen = raw_len - SIG_BYTES;
        const uint8_t* m = work.data();
        const uint8_t* sig = work.data() + mlen;
        uint8_t* pae = work.data() + decoded_cap;
        const std::size_t plen = detail::pae_len({HEADER.size(), mlen, expected_footer.size(), implicit.size()});
        detail::SpanSink sink{pae};
        detail::pae_stream(sink, {bytes(HEADER), {m, mlen}, expected_footer, implicit});
        const bool ed_ok = crypto_sign_verify_detached(sig, pae, plen, detail::KeyAccess::ed_public(key)) == 0;
        const bool ml_ok = detail::MlDsa65::verify(pae, plen, sig + ED_SIG_BYTES, ML_SIG_BYTES,
                                                   bytes(HEADER), detail::KeyAccess::ml_public(key));
        if (!ed_ok || !ml_ok) return Status::invalid;
        detail::wipe(work.data() + mlen, work.size() - mlen);
        out_len = mlen;
        return Status::ok;
    }
};

}

#endif
