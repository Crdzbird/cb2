#pragma once

/**
 * The key types. Each purpose has its own type, so a local key cannot be
 * handed to the public functions or the other way round, and the raw bytes
 * of a key are reachable only through detail::KeyAccess, never from the
 * token API. Every key carries an optional key id (by default its PASERK
 * id) that the claims layer binds into the token footer and compares in
 * constant time.
 *
 * PASERK forms (kcb2.local, kcb2.public, kcb2.secret) and ids (kcb2.lid, kcb2.pid)
 * follow the PASERK shape: header || base64url(bytes), and an id is
 * header || base64url(BLAKE3(id-header || paserk)[0..33]).
 *
 *   LocalKey   32 bytes, kcb2.local, id kcb2.lid
 *   PublicKey  1984 bytes: Ed25519 pk (32) || ML-DSA-65 pk (1952), kcb2.public, id kcb2.pid
 *   SecretKey  6048 bytes: Ed25519 sk (64) || ML-DSA-65 sk (4032) || ML-DSA-65 pk (1952),
 *              kcb2.secret, id kcb2.pid of its public key
 *
 * The secret key carries its public key so that signing can bind the key
 * id without a second object, and so that a stored kcb2.secret alone
 * restores the pair. Importing a secret key checks that the two public
 * halves it carries belong to the two secret halves, so a corrupted or
 * tampered key file is refused at import rather than producing tokens
 * nothing verifies. PublicKey and SecretKey exist only under
 * CB2_HAS_PQ.
 *
 * A local key must be uniformly random. Its default key id is a fast hash
 * of the key bytes and travels in clear in every token footer, so a key
 * with little entropy (a password, a password hash, a counter) can be
 * tested against one token at the cost of one short hash per guess. The
 * importers refuse the one weak key they can recognise, a key whose bytes
 * are all equal; everything else is the caller's responsibility.
 *
 * Every key also keeps the footer the claims layer binds its id into,
 * {"kid":"..."} or nothing, rebuilt whenever the id changes, so that a
 * token operation does not escape the id again.
 *
 * The bytes of a LocalKey and of a SecretKey are locked in memory for the
 * life of the object (sodium_mlock: no swapping, and no core dump where
 * the platform supports it) and wiped and unlocked when it dies. The lock
 * is best effort: a platform without it, or a limit that refuses it,
 * leaves the key wiped on release but swappable in between.
 */

#include "detail/base64url.hpp"
#include "detail/blake3.hpp"
#include "detail/nonce.hpp"
#include "detail/pq.hpp"
#include "detail/secure.hpp"
#include "json.hpp"
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

namespace cb2 {

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

/// Whether every byte of a key is the same byte: the one weak key an
/// importer can recognise without knowing where the key came from.
[[nodiscard]] inline bool constant_bytes(const uint8_t* p, std::size_t n) noexcept {
    unsigned diff = 0;
    for (std::size_t i = 1; i < n; ++i) diff |= static_cast<unsigned>(p[i] ^ p[0]);
    const bool weak = diff == 0;
    declassify(&weak, sizeof weak);
    return weak;
}

/// The footer a key id is bound into: {"kid":"..."}; empty for no id.
[[nodiscard]] inline std::string kid_footer(const std::optional<std::string>& kid) {
    if (!kid) return {};
    std::string f = "{\"kid\":";
    json::Writer::string(f, *kid);
    f += '}';
    return f;
}

[[nodiscard]] inline std::string paserk_id(std::string_view id_header, std::string_view paserk) {
    uint8_t digest[PASERK_ID_BYTES];
    Blake3 h;
    h.update(reinterpret_cast<const uint8_t*>(id_header.data()), id_header.size());
    h.update(reinterpret_cast<const uint8_t*>(paserk.data()), paserk.size());
    h.finalize(digest, sizeof digest);
    declassify(digest, sizeof digest);
    return paserk_encode<std::string>(id_header, {digest, sizeof digest});
}

struct KeyAccess;

}

/// A 32-byte symmetric key for cb2.local tokens and kcb2.local-wrap.
class LocalKey {
public:
    static constexpr std::size_t BYTES = 32;
    static constexpr std::string_view PASERK_HEADER = "kcb2.local.";
    static constexpr std::string_view ID_HEADER = "kcb2.lid.";

    LocalKey(const LocalKey&) = delete;
    LocalKey& operator=(const LocalKey&) = delete;
    LocalKey(LocalKey&& o) noexcept : kid_(std::move(o.kid_)), footer_(std::move(o.footer_)) {
        std::memcpy(k_, o.k_, BYTES);
        detail::wipe(o.k_, BYTES);
    }
    LocalKey& operator=(LocalKey&& o) noexcept {
        if (this != &o) {
            std::memcpy(k_, o.k_, BYTES);
            detail::wipe(o.k_, BYTES);
            kid_ = std::move(o.kid_);
            footer_ = std::move(o.footer_);
        }
        return *this;
    }
    ~LocalKey() { detail::unlock(k_, BYTES); }

    /// A fresh key from libsodium's CSPRNG.
    [[nodiscard]] static Result<LocalKey> generate() {
        if (!detail::ensure_sodium()) return Result<LocalKey>::err(Error::internal);
        LocalKey k;
        detail::fresh_nonce(k.k_, BYTES);
        k.set_kid(k.paserk_id());
        return Result<LocalKey>::ok(std::move(k));
    }

    /// Imports exactly 32 uniformly random bytes. A key whose bytes are
    /// all equal is refused with argument; see the file comment on why
    /// a key must not be derived from low-entropy material.
    [[nodiscard]] static Result<LocalKey> from_bytes(std::span<const uint8_t> bytes) {
        if (bytes.size() != BYTES || detail::constant_bytes(bytes.data(), BYTES))
            return Result<LocalKey>::err(Error::argument);
        LocalKey k;
        std::memcpy(k.k_, bytes.data(), BYTES);
        k.set_kid(k.paserk_id());
        return Result<LocalKey>::ok(std::move(k));
    }

    /// Imports a kcb2.local PASERK string, with the same weak-key check.
    [[nodiscard]] static Result<LocalKey> from_paserk(std::string_view text) {
        LocalKey k;
        if (!detail::paserk_decode(PASERK_HEADER, text, k.k_, BYTES) ||
            detail::constant_bytes(k.k_, BYTES))
            return Result<LocalKey>::err(Error::argument);
        k.set_kid(k.paserk_id());
        return Result<LocalKey>::ok(std::move(k));
    }

    /// The kcb2.local form, in wiped memory.
    [[nodiscard]] SecureString to_paserk() const {
        return detail::paserk_encode<SecureString>(PASERK_HEADER, {k_, BYTES});
    }

    /// The kcb2.lid id of this key.
    [[nodiscard]] std::string paserk_id() const {
        const SecureString p = to_paserk();
        return detail::paserk_id(ID_HEADER, std::string_view(p.data(), p.size()));
    }

    /// The id bound into tokens, if any. Defaults to paserk_id().
    [[nodiscard]] const std::optional<std::string>& key_id() const noexcept { return kid_; }
    LocalKey& set_key_id(std::string id) { set_kid(std::move(id)); return *this; }
    LocalKey& clear_key_id() noexcept { kid_.reset(); footer_.clear(); return *this; }
    /// The footer the claims layer binds this key's id into; empty for no id.
    [[nodiscard]] const std::string& footer() const noexcept { return footer_; }

    /// An explicit copy; keys are never copied implicitly.
    [[nodiscard]] LocalKey clone() const {
        LocalKey k;
        std::memcpy(k.k_, k_, BYTES);
        k.set_kid(kid_);
        return k;
    }

private:
    friend struct detail::KeyAccess;
    LocalKey() noexcept : k_{} { detail::lock(k_, BYTES); }
    void set_kid(std::optional<std::string> k) {
        kid_ = std::move(k);
        footer_ = detail::kid_footer(kid_);
    }
    uint8_t k_[BYTES];
    std::optional<std::string> kid_;
    std::string footer_;
};

#ifdef CB2_HAS_PQ

/// The hybrid verification key: Ed25519 || ML-DSA-65.
class PublicKey {
public:
    static constexpr std::size_t ED_BYTES = crypto_sign_PUBLICKEYBYTES;
    static constexpr std::size_t ML_BYTES = detail::MlDsa65::PUBLIC_BYTES;
    static constexpr std::size_t BYTES = ED_BYTES + ML_BYTES;
    static constexpr std::string_view PASERK_HEADER = "kcb2.public.";
    static constexpr std::string_view ID_HEADER = "kcb2.pid.";

    [[nodiscard]] static Result<PublicKey> from_bytes(std::span<const uint8_t> bytes) {
        if (bytes.size() != BYTES) return Result<PublicKey>::err(Error::argument);
        PublicKey k;
        k.pk_.assign(bytes.begin(), bytes.end());
        k.set_kid(k.paserk_id());
        return Result<PublicKey>::ok(std::move(k));
    }

    [[nodiscard]] static Result<PublicKey> from_paserk(std::string_view text) {
        PublicKey k;
        k.pk_.resize(BYTES);
        if (!detail::paserk_decode(PASERK_HEADER, text, k.pk_.data(), BYTES))
            return Result<PublicKey>::err(Error::argument);
        k.set_kid(k.paserk_id());
        return Result<PublicKey>::ok(std::move(k));
    }

    [[nodiscard]] std::string to_paserk() const {
        return detail::paserk_encode<std::string>(PASERK_HEADER, pk_);
    }

    /// The kcb2.pid id of this key.
    [[nodiscard]] std::string paserk_id() const {
        return detail::paserk_id(ID_HEADER, to_paserk());
    }

    [[nodiscard]] const std::optional<std::string>& key_id() const noexcept { return kid_; }
    PublicKey& set_key_id(std::string id) { set_kid(std::move(id)); return *this; }
    PublicKey& clear_key_id() noexcept { kid_.reset(); footer_.clear(); return *this; }
    [[nodiscard]] const std::string& footer() const noexcept { return footer_; }

    /// The raw 1984 bytes; public, so freely readable.
    [[nodiscard]] std::span<const uint8_t> bytes() const noexcept { return pk_; }

private:
    friend struct detail::KeyAccess;
    friend class SecretKey;
    PublicKey() = default;
    void set_kid(std::optional<std::string> k) {
        kid_ = std::move(k);
        footer_ = detail::kid_footer(kid_);
    }
    std::vector<uint8_t> pk_;
    std::optional<std::string> kid_;
    std::string footer_;
};

/// The hybrid signing key: Ed25519 sk || ML-DSA-65 sk || ML-DSA-65 pk.
class SecretKey {
public:
    static constexpr std::size_t ED_BYTES = crypto_sign_SECRETKEYBYTES;
    static constexpr std::size_t ML_BYTES = detail::MlDsa65::SECRET_BYTES;
    static constexpr std::size_t BYTES = ED_BYTES + ML_BYTES + detail::MlDsa65::PUBLIC_BYTES;
    static constexpr std::string_view PASERK_HEADER = "kcb2.secret.";

    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;
    SecretKey(SecretKey&&) noexcept = default;
    SecretKey& operator=(SecretKey&& o) noexcept {
        if (this != &o) {
            release();
            sk_ = std::move(o.sk_);
            kid_ = std::move(o.kid_);
            footer_ = std::move(o.footer_);
        }
        return *this;
    }
    ~SecretKey() { release(); }

    /// A fresh pair from libsodium (Ed25519) and liboqs (ML-DSA-65).
    [[nodiscard]] static Result<SecretKey> generate() {
        if (!detail::ensure_sodium()) return Result<SecretKey>::err(Error::internal);
        if (!detail::MlDsa65::available()) return Result<SecretKey>::err(Error::unavailable);
        SecretKey k;
        k.sk_.resize(BYTES);
        k.lock();
        uint8_t ed_pk[crypto_sign_PUBLICKEYBYTES];
        if (crypto_sign_keypair(ed_pk, k.sk_.data()) != 0 ||
            !detail::MlDsa65::keypair(k.sk_.data() + ED_BYTES + ML_BYTES, k.sk_.data() + ED_BYTES))
            return Result<SecretKey>::err(Error::internal);
        k.set_kid(k.public_key().paserk_id());
        return Result<SecretKey>::ok(std::move(k));
    }

    /// Imports exactly 6048 bytes and checks them: the Ed25519 public
    /// half must be the one its seed derives and the ML-DSA public half
    /// must verify a signature its secret half makes. A key that fails is
    /// argument; a build whose liboqs cannot run the check is unavailable.
    [[nodiscard]] static Result<SecretKey> from_bytes(std::span<const uint8_t> bytes) {
        if (bytes.size() != BYTES) return Result<SecretKey>::err(Error::argument);
        SecretKey k;
        k.sk_.assign(bytes.begin(), bytes.end());
        k.lock();
        return finish_import(std::move(k));
    }

    /// Imports a kcb2.secret PASERK string with the same checks.
    [[nodiscard]] static Result<SecretKey> from_paserk(std::string_view text) {
        SecretKey k;
        k.sk_.resize(BYTES);
        k.lock();
        if (!detail::paserk_decode(PASERK_HEADER, text, k.sk_.data(), BYTES))
            return Result<SecretKey>::err(Error::argument);
        return finish_import(std::move(k));
    }

    /// Whether the public halves this key carries belong to its secret
    /// halves. Costs one Ed25519 key derivation and one ML-DSA sign and
    /// verify; the importers call it, generate() does not need to.
    [[nodiscard]] bool consistent() const noexcept {
        if (!detail::ensure_sodium() || !detail::MlDsa65::available()) return false;
        uint8_t ed_pk[crypto_sign_PUBLICKEYBYTES];
        detail::SecureArray<crypto_sign_SECRETKEYBYTES> derived;
        if (crypto_sign_seed_keypair(ed_pk, derived.v, sk_.data()) != 0) return false;
        if (sodium_memcmp(ed_pk, sk_.data() + crypto_sign_SEEDBYTES, crypto_sign_PUBLICKEYBYTES) != 0)
            return false;
        static constexpr uint8_t PROBE[] = "cb2 secret key self-test";
        const std::span<const uint8_t> ctx = detail::as_bytes(SELF_TEST_CONTEXT);
        uint8_t sig[detail::MlDsa65::SIG_BYTES];
        if (!detail::MlDsa65::sign(sig, PROBE, sizeof PROBE, ctx, sk_.data() + ED_BYTES)) return false;
        return detail::MlDsa65::verify(PROBE, sizeof PROBE, sig, sizeof sig, ctx,
                                       sk_.data() + ED_BYTES + ML_BYTES);
    }

    /// The kcb2.secret form, in wiped memory.
    [[nodiscard]] SecureString to_paserk() const {
        return detail::paserk_encode<SecureString>(PASERK_HEADER, sk_);
    }

    /// The matching public key, carrying the same key id.
    [[nodiscard]] PublicKey public_key() const {
        PublicKey p;
        p.pk_.reserve(PublicKey::BYTES);
        p.pk_.insert(p.pk_.end(), sk_.begin() + crypto_sign_SEEDBYTES, sk_.begin() + ED_BYTES);
        p.pk_.insert(p.pk_.end(), sk_.begin() + ED_BYTES + ML_BYTES, sk_.end());
        p.set_kid(kid_.has_value() ? kid_ : std::optional<std::string>(p.paserk_id()));
        return p;
    }

    [[nodiscard]] const std::optional<std::string>& key_id() const noexcept { return kid_; }
    SecretKey& set_key_id(std::string id) { set_kid(std::move(id)); return *this; }
    SecretKey& clear_key_id() noexcept { kid_.reset(); footer_.clear(); return *this; }
    [[nodiscard]] const std::string& footer() const noexcept { return footer_; }

    [[nodiscard]] SecretKey clone() const {
        SecretKey k;
        k.sk_ = sk_;
        k.lock();
        k.set_kid(kid_);
        return k;
    }

private:
    friend struct detail::KeyAccess;
    SecretKey() = default;

    /// The ML-DSA context of the self-test signature, so that it can never
    /// be mistaken for a token signature.
    static constexpr std::string_view SELF_TEST_CONTEXT = "kcb2.secret.self-test";

    [[nodiscard]] static Result<SecretKey> finish_import(SecretKey k) {
        if (!detail::MlDsa65::available()) return Result<SecretKey>::err(Error::unavailable);
        if (!k.consistent()) return Result<SecretKey>::err(Error::argument);
        k.set_kid(k.public_key().paserk_id());
        return Result<SecretKey>::ok(std::move(k));
    }

    void lock() noexcept {
        if (!sk_.empty()) detail::lock(sk_.data(), sk_.size());
    }

    void release() noexcept {
        if (!sk_.empty()) detail::unlock(sk_.data(), sk_.size());
    }

    void set_kid(std::optional<std::string> k) {
        kid_ = std::move(k);
        footer_ = detail::kid_footer(kid_);
    }

    SecureBytes sk_;
    std::optional<std::string> kid_;
    std::string footer_;
};

#endif

namespace detail {

/// The only way the token code reaches raw key bytes.
struct KeyAccess {
    [[nodiscard]] static const uint8_t* local(const LocalKey& k) noexcept { return k.k_; }
#ifdef CB2_HAS_PQ
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
