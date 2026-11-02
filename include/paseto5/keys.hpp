#pragma once

/**
 * The key types. Each purpose has its own type, so a local key cannot be
 * handed to the public functions or the other way round, and the raw bytes
 * of a key are reachable only through detail::KeyAccess, never from the
 * token API. Every key carries an optional key id (by default its PASERK
 * id) that the claims layer binds into the token footer and compares in
 * constant time.
 *
 * PASERK forms (k5.local, k5.public, k5.secret) and ids (k5.lid, k5.pid)
 * follow the PASERK shape: header || base64url(bytes), and an id is
 * header || base64url(BLAKE3(id-header || paserk)[0..33]).
 *
 *   LocalKey   32 bytes, k5.local, id k5.lid
 *   PublicKey  1984 bytes: Ed25519 pk (32) || ML-DSA-65 pk (1952), k5.public, id k5.pid
 *   SecretKey  6048 bytes: Ed25519 sk (64) || ML-DSA-65 sk (4032) || ML-DSA-65 pk (1952),
 *              k5.secret, id k5.pid of its public key
 *
 * The secret key carries its public key so that signing can bind the key
 * id without a second object, and so that a stored k5.secret alone
 * restores the pair. PublicKey and SecretKey exist only under
 * PASETO5_HAS_PQ.
 */

#include "detail/base64url.hpp"
#include "detail/blake3.hpp"
#include "detail/nonce.hpp"
#include "detail/pq.hpp"
#include "detail/secure.hpp"
#include "result.hpp"

#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace paseto5 {

namespace detail {

inline constexpr std::size_t PASERK_ID_BYTES = 33;

template <class Str>
[[nodiscard]] Str paserk_encode(std::string_view header, std::span<const uint8_t> bytes) {
    Str s(header.size() + b64::encoded_len(bytes.size()), '\0');
    std::memcpy(s.data(), header.data(), header.size());
    b64::encode(s.data() + header.size(), bytes.data(), bytes.size());
    return s;
}

[[nodiscard]] inline bool paserk_decode(std::string_view header, std::string_view text,
                                        uint8_t* out, std::size_t want) noexcept {
    if (text.size() != header.size() + b64::encoded_len(want) ||
        std::memcmp(text.data(), header.data(), header.size()) != 0)
        return false;
    std::size_t n = 0;
    return b64::decode(out, want, text.data() + header.size(), text.size() - header.size(), n) &&
           n == want;
}

[[nodiscard]] inline std::string paserk_id(std::string_view id_header, std::string_view paserk) {
    uint8_t digest[PASERK_ID_BYTES];
    Blake3 h;
    h.update(reinterpret_cast<const uint8_t*>(id_header.data()), id_header.size());
    h.update(reinterpret_cast<const uint8_t*>(paserk.data()), paserk.size());
    h.finalize(digest, sizeof digest);
    return paserk_encode<std::string>(id_header, {digest, sizeof digest});
}

struct KeyAccess;

}

/// A 32-byte symmetric key for v5.local tokens and k5.local-wrap.
class LocalKey {
public:
    static constexpr std::size_t BYTES = 32;
    static constexpr std::string_view PASERK_HEADER = "k5.local.";
    static constexpr std::string_view ID_HEADER = "k5.lid.";

    LocalKey(const LocalKey&) = delete;
    LocalKey& operator=(const LocalKey&) = delete;
    LocalKey(LocalKey&& o) noexcept : kid_(std::move(o.kid_)) {
        std::memcpy(k_, o.k_, BYTES);
        detail::wipe(o.k_, BYTES);
    }
    LocalKey& operator=(LocalKey&& o) noexcept {
        if (this != &o) {
            std::memcpy(k_, o.k_, BYTES);
            detail::wipe(o.k_, BYTES);
            kid_ = std::move(o.kid_);
        }
        return *this;
    }
    ~LocalKey() { detail::wipe(k_, BYTES); }

    /// A fresh key from libsodium's CSPRNG.
    [[nodiscard]] static Result<LocalKey> generate() {
        if (!detail::ensure_sodium()) return Result<LocalKey>::err(Error::internal);
        LocalKey k;
        detail::fresh_nonce(k.k_, BYTES);
        k.kid_ = k.paserk_id();
        return Result<LocalKey>::ok(std::move(k));
    }

    /// Imports exactly 32 bytes.
    [[nodiscard]] static Result<LocalKey> from_bytes(std::span<const uint8_t> bytes) {
        if (bytes.size() != BYTES) return Result<LocalKey>::err(Error::argument);
        LocalKey k;
        std::memcpy(k.k_, bytes.data(), BYTES);
        k.kid_ = k.paserk_id();
        return Result<LocalKey>::ok(std::move(k));
    }

    /// Imports a k5.local PASERK string.
    [[nodiscard]] static Result<LocalKey> from_paserk(std::string_view text) {
        LocalKey k;
        if (!detail::paserk_decode(PASERK_HEADER, text, k.k_, BYTES))
            return Result<LocalKey>::err(Error::argument);
        k.kid_ = k.paserk_id();
        return Result<LocalKey>::ok(std::move(k));
    }

    /// The k5.local form, in wiped memory.
    [[nodiscard]] SecureString to_paserk() const {
        return detail::paserk_encode<SecureString>(PASERK_HEADER, {k_, BYTES});
    }

    /// The k5.lid id of this key.
    [[nodiscard]] std::string paserk_id() const {
        const SecureString p = to_paserk();
        return detail::paserk_id(ID_HEADER, std::string_view(p.data(), p.size()));
    }

    /// The id bound into tokens, if any. Defaults to paserk_id().
    [[nodiscard]] const std::optional<std::string>& key_id() const noexcept { return kid_; }
    LocalKey& set_key_id(std::string id) { kid_ = std::move(id); return *this; }
    LocalKey& clear_key_id() noexcept { kid_.reset(); return *this; }

    /// An explicit copy; keys are never copied implicitly.
    [[nodiscard]] LocalKey clone() const {
        LocalKey k;
        std::memcpy(k.k_, k_, BYTES);
        k.kid_ = kid_;
        return k;
    }

private:
    friend struct detail::KeyAccess;
    LocalKey() noexcept : k_{} {}
    uint8_t k_[BYTES];
    std::optional<std::string> kid_;
};

#ifdef PASETO5_HAS_PQ

/// The hybrid verification key: Ed25519 || ML-DSA-65.
class PublicKey {
public:
    static constexpr std::size_t ED_BYTES = crypto_sign_PUBLICKEYBYTES;
    static constexpr std::size_t ML_BYTES = detail::MlDsa65::PUBLIC_BYTES;
    static constexpr std::size_t BYTES = ED_BYTES + ML_BYTES;
    static constexpr std::string_view PASERK_HEADER = "k5.public.";
    static constexpr std::string_view ID_HEADER = "k5.pid.";

    [[nodiscard]] static Result<PublicKey> from_bytes(std::span<const uint8_t> bytes) {
        if (bytes.size() != BYTES) return Result<PublicKey>::err(Error::argument);
        PublicKey k;
        k.pk_.assign(bytes.begin(), bytes.end());
        k.kid_ = k.paserk_id();
        return Result<PublicKey>::ok(std::move(k));
    }

    [[nodiscard]] static Result<PublicKey> from_paserk(std::string_view text) {
        PublicKey k;
        k.pk_.resize(BYTES);
        if (!detail::paserk_decode(PASERK_HEADER, text, k.pk_.data(), BYTES))
            return Result<PublicKey>::err(Error::argument);
        k.kid_ = k.paserk_id();
        return Result<PublicKey>::ok(std::move(k));
    }

    [[nodiscard]] std::string to_paserk() const {
        return detail::paserk_encode<std::string>(PASERK_HEADER, pk_);
    }

    /// The k5.pid id of this key.
    [[nodiscard]] std::string paserk_id() const {
        return detail::paserk_id(ID_HEADER, to_paserk());
    }

    [[nodiscard]] const std::optional<std::string>& key_id() const noexcept { return kid_; }
    PublicKey& set_key_id(std::string id) { kid_ = std::move(id); return *this; }
    PublicKey& clear_key_id() noexcept { kid_.reset(); return *this; }

    /// The raw 1984 bytes; public, so freely readable.
    [[nodiscard]] std::span<const uint8_t> bytes() const noexcept { return pk_; }

private:
    friend struct detail::KeyAccess;
    friend class SecretKey;
    PublicKey() = default;
    std::vector<uint8_t> pk_;
    std::optional<std::string> kid_;
};

/// The hybrid signing key: Ed25519 sk || ML-DSA-65 sk || ML-DSA-65 pk.
class SecretKey {
public:
    static constexpr std::size_t ED_BYTES = crypto_sign_SECRETKEYBYTES;
    static constexpr std::size_t ML_BYTES = detail::MlDsa65::SECRET_BYTES;
    static constexpr std::size_t BYTES = ED_BYTES + ML_BYTES + detail::MlDsa65::PUBLIC_BYTES;
    static constexpr std::string_view PASERK_HEADER = "k5.secret.";

    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;
    SecretKey(SecretKey&&) noexcept = default;
    SecretKey& operator=(SecretKey&&) noexcept = default;
    ~SecretKey() = default;

    /// A fresh pair from libsodium (Ed25519) and liboqs (ML-DSA-65).
    [[nodiscard]] static Result<SecretKey> generate() {
        if (!detail::ensure_sodium()) return Result<SecretKey>::err(Error::internal);
        if (!detail::MlDsa65::available()) return Result<SecretKey>::err(Error::unavailable);
        SecretKey k;
        k.sk_.resize(BYTES);
        uint8_t ed_pk[crypto_sign_PUBLICKEYBYTES];
        if (crypto_sign_keypair(ed_pk, k.sk_.data()) != 0 ||
            !detail::MlDsa65::keypair(k.sk_.data() + ED_BYTES + ML_BYTES, k.sk_.data() + ED_BYTES))
            return Result<SecretKey>::err(Error::internal);
        k.kid_ = k.public_key().paserk_id();
        return Result<SecretKey>::ok(std::move(k));
    }

    /// Imports exactly 6048 bytes.
    [[nodiscard]] static Result<SecretKey> from_bytes(std::span<const uint8_t> bytes) {
        if (bytes.size() != BYTES) return Result<SecretKey>::err(Error::argument);
        SecretKey k;
        k.sk_.assign(bytes.begin(), bytes.end());
        k.kid_ = k.public_key().paserk_id();
        return Result<SecretKey>::ok(std::move(k));
    }

    [[nodiscard]] static Result<SecretKey> from_paserk(std::string_view text) {
        SecretKey k;
        k.sk_.resize(BYTES);
        if (!detail::paserk_decode(PASERK_HEADER, text, k.sk_.data(), BYTES))
            return Result<SecretKey>::err(Error::argument);
        k.kid_ = k.public_key().paserk_id();
        return Result<SecretKey>::ok(std::move(k));
    }

    /// The k5.secret form, in wiped memory.
    [[nodiscard]] SecureString to_paserk() const {
        return detail::paserk_encode<SecureString>(PASERK_HEADER, sk_);
    }

    /// The matching public key, carrying the same key id.
    [[nodiscard]] PublicKey public_key() const {
        PublicKey p;
        p.pk_.reserve(PublicKey::BYTES);
        p.pk_.insert(p.pk_.end(), sk_.begin() + crypto_sign_SEEDBYTES, sk_.begin() + ED_BYTES);
        p.pk_.insert(p.pk_.end(), sk_.begin() + ED_BYTES + ML_BYTES, sk_.end());
        p.kid_ = kid_.has_value() ? kid_ : std::optional<std::string>(p.paserk_id());
        return p;
    }

    [[nodiscard]] const std::optional<std::string>& key_id() const noexcept { return kid_; }
    SecretKey& set_key_id(std::string id) { kid_ = std::move(id); return *this; }
    SecretKey& clear_key_id() noexcept { kid_.reset(); return *this; }

    [[nodiscard]] SecretKey clone() const {
        SecretKey k;
        k.sk_ = sk_;
        k.kid_ = kid_;
        return k;
    }

private:
    friend struct detail::KeyAccess;
    SecretKey() = default;
    SecureBytes sk_;
    std::optional<std::string> kid_;
};

#endif

namespace detail {

/// The only way the token code reaches raw key bytes.
struct KeyAccess {
    [[nodiscard]] static const uint8_t* local(const LocalKey& k) noexcept { return k.k_; }
#ifdef PASETO5_HAS_PQ
    [[nodiscard]] static const uint8_t* ed_public(const PublicKey& k) noexcept { return k.pk_.data(); }
    [[nodiscard]] static const uint8_t* ml_public(const PublicKey& k) noexcept {
        return k.pk_.data() + PublicKey::ED_BYTES;
    }
    [[nodiscard]] static const uint8_t* ed_secret(const SecretKey& k) noexcept { return k.sk_.data(); }
    [[nodiscard]] static const uint8_t* ml_secret(const SecretKey& k) noexcept {
        return k.sk_.data() + SecretKey::ED_BYTES;
    }
#endif
};

}

}
