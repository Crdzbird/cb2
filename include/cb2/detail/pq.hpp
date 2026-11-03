#pragma once

/**
 * ML-DSA-65 (FIPS 204) through liboqs, present only when CB2_HAS_PQ is
 * defined. One OQS_SIG object is created on first use and shared: it is an
 * immutable table of function pointers and sizes, safe to use from several
 * threads. The sizes liboqs reports are checked against the constants this
 * library pins in its wire format, and the backend must support the FIPS
 * 204 context string; a mismatch makes the backend unavailable instead of
 * producing tokens of another shape. Every signature is made and checked
 * with a context string, so a signature made for one purpose never
 * verifies for another, whatever else the same key signs.
 */

#ifdef CB2_HAS_PQ

#include <oqs/oqs.h>

#include <cstddef>
#include <cstdint>
#include <span>

namespace cb2::detail {

class MlDsa65 {
public:
    static constexpr std::size_t PUBLIC_BYTES = 1952;
    static constexpr std::size_t SECRET_BYTES = 4032;
    static constexpr std::size_t SIG_BYTES = 3309;
    /// FIPS 204 bounds the context string at 255 bytes.
    static constexpr std::size_t MAX_CTX_BYTES = 255;

    [[nodiscard]] static bool available() noexcept { return instance() != nullptr; }

    [[nodiscard]] static bool keypair(uint8_t* pk, uint8_t* sk) noexcept {
        const OQS_SIG* s = instance();
        return s != nullptr && OQS_SIG_keypair(s, pk, sk) == OQS_SUCCESS;
    }

    /// Writes exactly SIG_BYTES to sig: the FIPS 204 signature of m under
    /// the context string ctx.
    [[nodiscard]] static bool sign(uint8_t* sig, const uint8_t* m, std::size_t mlen,
                                   std::span<const uint8_t> ctx, const uint8_t* sk) noexcept {
        const OQS_SIG* s = instance();
        std::size_t len = 0;
        if (s == nullptr || ctx.size() > MAX_CTX_BYTES ||
            OQS_SIG_sign_with_ctx_str(s, sig, &len, m, mlen, ctx.data(), ctx.size(), sk) != OQS_SUCCESS)
            return false;
        return len == SIG_BYTES;
    }

    [[nodiscard]] static bool verify(const uint8_t* m, std::size_t mlen, const uint8_t* sig,
                                     std::size_t siglen, std::span<const uint8_t> ctx,
                                     const uint8_t* pk) noexcept {
        const OQS_SIG* s = instance();
        return s != nullptr && siglen == SIG_BYTES && ctx.size() <= MAX_CTX_BYTES &&
               OQS_SIG_verify_with_ctx_str(s, m, mlen, sig, siglen, ctx.data(), ctx.size(), pk) ==
                   OQS_SUCCESS;
    }

private:
    struct Holder {
        OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
        bool ok = sig != nullptr && sig->length_public_key == PUBLIC_BYTES &&
                  sig->length_secret_key == SECRET_BYTES && sig->length_signature == SIG_BYTES &&
                  sig->sig_with_ctx_support;
        ~Holder() { if (sig != nullptr) OQS_SIG_free(sig); }
    };

    [[nodiscard]] static const OQS_SIG* instance() noexcept {
        static const Holder h;
        return h.ok ? h.sig : nullptr;
    }
};

}

#endif
