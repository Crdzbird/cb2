#pragma once

/**
 * paseto5::Local: cb2.local tokens. The construction is in
 * detail/local_core.hpp; this class fixes the header, takes a LocalKey and
 * offers both the caller-buffer functions (no allocation) and the
 * convenience functions (exactly one allocation each).
 */

#include "detail/local_core.hpp"
#include "detail/nonce.hpp"
#include "keys.hpp"
#include "result.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

namespace paseto5 {

/// Bytes of a string, for footers and implicit assertions given as text.
[[nodiscard]] inline std::span<const uint8_t> bytes(std::string_view s) noexcept {
    return detail::as_bytes(s);
}

/// Maps a buffer-level Status to an Error.
[[nodiscard]] inline Error to_error(Status s) noexcept {
    switch (s) {
        case Status::ok: return Error::internal;
        case Status::invalid: return Error::invalid;
        case Status::argument: return Error::argument;
        case Status::internal: return Error::internal;
    }
    return Error::internal;
}

class Local {
public:
    static constexpr std::string_view HEADER = "cb2.local.";
    static constexpr std::size_t NONCE_BYTES = detail::LOCAL_NONCE_BYTES;
    static constexpr std::size_t TAG_BYTES = detail::LOCAL_TAG_BYTES;

    /// Exact token length for a message and footer, or 0 when either
    /// exceeds MAX_INPUT_BYTES.
    [[nodiscard]] static constexpr std::size_t
    token_len(std::size_t msg_len, std::size_t footer_len) noexcept {
        return detail::LocalCore::token_len(HEADER, msg_len, footer_len);
    }

    /// Length of the longest token open accepts.
    [[nodiscard]] static constexpr std::size_t max_token_len() noexcept {
        return detail::LocalCore::max_token_len(HEADER);
    }

    /// Output capacity open_into requires for a token of this length; 0
    /// for a length no valid token has.
    [[nodiscard]] static constexpr std::size_t open_capacity(std::size_t token_len) noexcept {
        return detail::LocalCore::open_capacity(HEADER, token_len);
    }

    /// Seals msg with a fresh nonce into out, which must hold
    /// token_len(msg.size(), footer.size()) bytes and overlap no input. On
    /// success out_len is that length, otherwise 0.
    [[nodiscard]] static Status
    seal_into(std::span<uint8_t> out, std::size_t& out_len, const LocalKey& key,
              std::span<const uint8_t> msg, std::span<const uint8_t> footer = {},
              std::span<const uint8_t> implicit = {}) noexcept {
        out_len = 0;
        if (!detail::ensure_sodium()) return Status::internal;
        uint8_t n[NONCE_BYTES];
        detail::fresh_nonce(n, NONCE_BYTES);
        return detail::LocalCore::seal(HEADER, out, out_len, detail::KeyAccess::local(key), msg,
                                       footer, implicit, n);
    }

    /// Authenticates and decrypts token into out, which must hold
    /// open_capacity(token.size()) bytes and overlap no input. The tag is
    /// verified in constant time before anything is decrypted. On success
    /// the message is out[0, out_len) and the rest of the region is zero;
    /// on failure the region is zero and out_len is 0.
    [[nodiscard]] static Status
    open_into(std::span<uint8_t> out, std::size_t& out_len, std::string_view token,
              const LocalKey& key, std::span<const uint8_t> expected_footer = {},
              std::span<const uint8_t> implicit = {}) noexcept {
        return detail::LocalCore::open(HEADER, out, out_len, token, detail::KeyAccess::local(key),
                                       expected_footer, implicit);
    }

    /// Seals msg and returns the token text. One allocation.
    [[nodiscard]] static Result<std::string>
    seal(const LocalKey& key, std::span<const uint8_t> msg, std::span<const uint8_t> footer = {},
         std::span<const uint8_t> implicit = {}) {
        const std::size_t need = token_len(msg.size(), footer.size());
        if (need == 0) return Result<std::string>::err(Error::argument);
        std::string tok(need, '\0');
        std::size_t n = 0;
        const Status s = seal_into({reinterpret_cast<uint8_t*>(tok.data()), tok.size()}, n, key,
                                   msg, footer, implicit);
        if (s != Status::ok) return Result<std::string>::err(to_error(s));
        return Result<std::string>::ok(std::move(tok));
    }

    /// Opens token and returns the message in wiped memory. One allocation.
    /// A token longer than max_token_bytes is too_large before any of it
    /// is read; the default keeps a garbage token from costing a 48 MiB
    /// buffer and the hashing of it.
    [[nodiscard]] static Result<SecureBytes>
    open(std::string_view token, const LocalKey& key, std::span<const uint8_t> expected_footer = {},
         std::span<const uint8_t> implicit = {},
         std::size_t max_token_bytes = DEFAULT_RAW_MAX_TOKEN_BYTES) {
        if (token.size() > max_token_bytes) return Result<SecureBytes>::err(Error::too_large);
        const std::size_t cap = open_capacity(token.size());
        if (cap == 0) return Result<SecureBytes>::err(Error::invalid);
        SecureBytes buf(cap);
        std::size_t n = 0;
        const Status s = open_into(buf, n, token, key, expected_footer, implicit);
        if (s != Status::ok) return Result<SecureBytes>::err(to_error(s));
        buf.resize(n);
        return Result<SecureBytes>::ok(std::move(buf));
    }

#ifdef PASETO5_TEST_NONCE
    /// Test builds only: seals with a caller-chosen 32-byte nonce, to
    /// produce known-answer vectors. A repeated nonce under one key reuses
    /// the keystream and must never happen outside a test.
    [[nodiscard]] static Status
    seal_with_nonce_for_testing(std::span<uint8_t> out, std::size_t& out_len, const LocalKey& key,
                                std::span<const uint8_t> msg, std::span<const uint8_t> footer,
                                std::span<const uint8_t> implicit,
                                std::span<const uint8_t> nonce) noexcept {
        out_len = 0;
        if (nonce.size() != NONCE_BYTES) return Status::argument;
        return detail::LocalCore::seal(HEADER, out, out_len, detail::KeyAccess::local(key), msg,
                                       footer, implicit, nonce.data());
    }
#endif
};

}
