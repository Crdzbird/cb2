#pragma once

/**
 * kcb2.local-wrap: a LocalKey wrapped under another LocalKey with the
 * cb2.local construction, header "kcb2.local-wrap.", no footer and no
 * implicit assertion. The wrapped form is header || base64url(n || c || t)
 * with c the 32 encrypted key bytes, 142 characters in all.
 */

#include "detail/local_core.hpp"
#include "detail/nonce.hpp"
#include "keys.hpp"
#include "local.hpp"
#include "result.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace cb2 {

class KeyWrap {
public:
    static constexpr std::string_view HEADER = "kcb2.local-wrap.";
    static constexpr std::size_t WRAPPED_LEN =
        detail::LocalCore::token_len(HEADER, LocalKey::BYTES, 0);

    /// Wraps key under wrapping_key.
    [[nodiscard]] static Result<std::string> wrap(const LocalKey& wrapping_key, const LocalKey& key) {
        if (!detail::ensure_sodium()) return Result<std::string>::err(Error::internal);
        uint8_t n[detail::LOCAL_NONCE_BYTES];
        detail::fresh_nonce(n, sizeof n);
        return wrap_with(wrapping_key, key, n);
    }

    /// Unwraps a kcb2.local-wrap string under wrapping_key. The returned
    /// key carries its derived kcb2.lid as key id.
    [[nodiscard]] static Result<LocalKey> unwrap(std::string_view wrapped, const LocalKey& wrapping_key) {
        if (wrapped.size() != WRAPPED_LEN) return Result<LocalKey>::err(Error::invalid);
        detail::SecureArray<detail::LocalCore::open_capacity(HEADER, WRAPPED_LEN)> work;
        std::size_t n = 0;
        const Status s = detail::LocalCore::open(HEADER, {work.v, sizeof work.v}, n, wrapped,
                                                 detail::KeyAccess::local(wrapping_key), {}, {});
        if (s != Status::ok) return Result<LocalKey>::err(to_error(s));
        if (n != LocalKey::BYTES) return Result<LocalKey>::err(Error::invalid);
        return LocalKey::from_bytes({work.v, LocalKey::BYTES});
    }

#ifdef CB2_TEST_NONCE
    /// Test builds only: wraps with a caller-chosen 32-byte nonce.
    [[nodiscard]] static Result<std::string>
    wrap_with_nonce_for_testing(const LocalKey& wrapping_key, const LocalKey& key,
                                std::span<const uint8_t> nonce) {
        if (nonce.size() != detail::LOCAL_NONCE_BYTES) return Result<std::string>::err(Error::argument);
        return wrap_with(wrapping_key, key, nonce.data());
    }
#endif

private:
    [[nodiscard]] static Result<std::string>
    wrap_with(const LocalKey& wrapping_key, const LocalKey& key, const uint8_t* nonce) {
        std::string out(WRAPPED_LEN, '\0');
        std::size_t n = 0;
        const Status s = detail::LocalCore::seal(
            HEADER, {reinterpret_cast<uint8_t*>(out.data()), out.size()}, n,
            detail::KeyAccess::local(wrapping_key), {detail::KeyAccess::local(key), LocalKey::BYTES},
            {}, {}, nonce);
        if (s != Status::ok) return Result<std::string>::err(to_error(s));
        return Result<std::string>::ok(std::move(out));
    }
};

}
