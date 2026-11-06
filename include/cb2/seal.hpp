#pragma once

/**
 * kcb2.seal: a local key sealed to a recipient's public key, so that a
 * symmetric token key can be handed to the one party that holds the
 * matching secret, over any channel.
 *
 * The recipient key pair is X-Wing (draft-connolly-cfrg-xwing-kem), the
 * hybrid of ML-KEM-768 and X25519 with the SHA3-256 combiner, used
 * exactly as the draft defines it and checked against its test vectors:
 *
 *   recipient secret  sk, 32 random bytes; SHAKE256(sk, 96) expands to the
 *                     ML-KEM-768 seed (d, z) and the X25519 secret
 *   recipient public  pk = pk_M (1184) || pk_X (32), 1216 bytes
 *   encapsulate       ct = ct_M (1088) || ct_X (32), 1120 bytes, and
 *                     ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || label)
 *
 * The sealed key is the cb2.local construction of local_core.hpp with
 * the header "kcb2.seal." as the domain string, the shared secret ss as
 * the key, the 32-byte local key as the message, no footer and the KEM
 * ciphertext as the implicit assertion, so the tag covers the ciphertext
 * as well as the key:
 *
 *   kcb2.seal. || base64url(ct || n || c || t)        1216 bytes, 1632 characters
 *
 * Key strings follow the other kcb2 strings: kcb2.recipient. || base64url(pk),
 * kcb2.recipient-secret. || base64url(sk), and the id kcb2.rid. over the
 * recipient string. Present only when liboqs provides ML-KEM-768
 * (CB2_HAS_SEAL).
 */

#ifdef CB2_HAS_PQ

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_KEM_ml_kem_768)
#define CB2_HAS_SEAL 1

#include "detail/local_core.hpp"
#include "detail/secure.hpp"
#include "detail/sha3.hpp"
#include "keys.hpp"
#include "result.hpp"

#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

namespace cb2 {

namespace detail {

/// X-Wing as draft-connolly-cfrg-xwing-kem defines it, on liboqs's
/// ML-KEM-768, cb2's own SHA3 (detail/sha3.hpp) and libsodium's X25519.
class XWing {
public:
    static constexpr std::size_t SEED_BYTES = 32;
    static constexpr std::size_t ML_PK_BYTES = OQS_KEM_ml_kem_768_length_public_key;
    static constexpr std::size_t ML_SK_BYTES = OQS_KEM_ml_kem_768_length_secret_key;
    static constexpr std::size_t ML_CT_BYTES = OQS_KEM_ml_kem_768_length_ciphertext;
    static constexpr std::size_t PK_BYTES = ML_PK_BYTES + 32;
    static constexpr std::size_t CT_BYTES = ML_CT_BYTES + 32;
    static constexpr std::size_t SS_BYTES = 32;
    static constexpr std::size_t ESEED_BYTES = 64;
    /// The expanded decapsulation key: sk_M || sk_X || pk, never transmitted.
    static constexpr std::size_t EXPANDED_BYTES = ML_SK_BYTES + 32 + PK_BYTES;

    static_assert(ML_PK_BYTES == 1184 && ML_SK_BYTES == 2400 && ML_CT_BYTES == 1088 &&
                  OQS_KEM_ml_kem_768_length_shared_secret == 32 &&
                  OQS_KEM_ml_kem_768_length_keypair_seed == 64 &&
                  OQS_KEM_ml_kem_768_length_encaps_seed == 32);

    /// expandDecapsulationKey: writes sk_M || sk_X || pk_M || pk_X.
    [[nodiscard]] static bool expand(const uint8_t seed[SEED_BYTES], uint8_t* expanded) noexcept {
        SecureArray<96> e;
        Keccak::shake256(e.v, 96, seed, SEED_BYTES);
        uint8_t* sk_m = expanded;
        uint8_t* sk_x = expanded + ML_SK_BYTES;
        uint8_t* pk_m = expanded + ML_SK_BYTES + 32;
        uint8_t* pk_x = pk_m + ML_PK_BYTES;
        if (OQS_KEM_ml_kem_768_keypair_derand(pk_m, sk_m, e.v) != OQS_SUCCESS) return false;
        std::memcpy(sk_x, e.v + 64, 32);
        return crypto_scalarmult_curve25519_base(pk_x, sk_x) == 0;
    }

    /// EncapsulateDerand with a 64-byte eseed: the first 32 bytes drive
    /// ML-KEM, the last 32 are the X25519 ephemeral secret.
    [[nodiscard]] static bool encaps(const uint8_t pk[PK_BYTES], const uint8_t eseed[ESEED_BYTES],
                                     uint8_t ct[CT_BYTES], uint8_t ss[SS_BYTES]) noexcept {
        const uint8_t* pk_m = pk;
        const uint8_t* pk_x = pk + ML_PK_BYTES;
        uint8_t* ct_m = ct;
        uint8_t* ct_x = ct + ML_CT_BYTES;
        SecureArray<32> ss_m;
        SecureArray<32> ss_x;
        if (crypto_scalarmult_curve25519_base(ct_x, eseed + 32) != 0) return false;
        const int zero = crypto_scalarmult_curve25519(ss_x.v, eseed + 32, pk_x);
        declassify(&zero, sizeof zero);
        if (zero != 0 || OQS_KEM_ml_kem_768_encaps_derand(ct_m, ss_m.v, pk_m, eseed) != OQS_SUCCESS)
            return false;
        combine(ss_m.v, ss_x.v, ct_x, pk_x, ss);
        return true;
    }

    /// Decapsulate with the expanded key of expand().
    [[nodiscard]] static bool decaps(const uint8_t* expanded, const uint8_t ct[CT_BYTES],
                                     uint8_t ss[SS_BYTES]) noexcept {
        const uint8_t* sk_m = expanded;
        const uint8_t* sk_x = expanded + ML_SK_BYTES;
        const uint8_t* pk_x = expanded + ML_SK_BYTES + 32 + ML_PK_BYTES;
        const uint8_t* ct_m = ct;
        const uint8_t* ct_x = ct + ML_CT_BYTES;
        SecureArray<32> ss_m;
        SecureArray<32> ss_x;
        if (OQS_KEM_ml_kem_768_decaps(ss_m.v, ct_m, sk_m) != OQS_SUCCESS) return false;
        const int zero = crypto_scalarmult_curve25519(ss_x.v, sk_x, ct_x);
        declassify(&zero, sizeof zero);
        if (zero != 0) return false;
        combine(ss_m.v, ss_x.v, ct_x, pk_x, ss);
        return true;
    }

private:
    static void combine(const uint8_t ss_m[32], const uint8_t ss_x[32], const uint8_t ct_x[32],
                        const uint8_t pk_x[32], uint8_t ss[32]) noexcept {
        static constexpr uint8_t LABEL[6] = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c};
        SecureArray<32 + 32 + 32 + 32 + 6> in;
        std::memcpy(in.v, ss_m, 32);
        std::memcpy(in.v + 32, ss_x, 32);
        std::memcpy(in.v + 64, ct_x, 32);
        std::memcpy(in.v + 96, pk_x, 32);
        std::memcpy(in.v + 128, LABEL, 6);
        Keccak::sha3_256(ss, in.v, sizeof in.v);
    }
};

}

/// A recipient's public key: the X-Wing encapsulation key, 1216 bytes.
class RecipientPublicKey {
public:
    static constexpr std::size_t BYTES = detail::XWing::PK_BYTES;
    static constexpr std::string_view PASERK_HEADER = "kcb2.recipient.";
    static constexpr std::string_view ID_HEADER = "kcb2.rid.";

    [[nodiscard]] static Result<RecipientPublicKey> from_bytes(std::span<const uint8_t> bytes) {
        if (bytes.size() != BYTES) return Result<RecipientPublicKey>::err(Error::argument);
        RecipientPublicKey k;
        k.pk_.assign(bytes.begin(), bytes.end());
        return Result<RecipientPublicKey>::ok(std::move(k));
    }

    [[nodiscard]] static Result<RecipientPublicKey> from_paserk(std::string_view text) {
        RecipientPublicKey k;
        k.pk_.resize(BYTES);
        if (!detail::paserk_decode(PASERK_HEADER, text, k.pk_.data(), BYTES))
            return Result<RecipientPublicKey>::err(Error::argument);
        return Result<RecipientPublicKey>::ok(std::move(k));
    }

    [[nodiscard]] std::string to_paserk() const { return detail::paserk_encode<std::string>(PASERK_HEADER, pk_); }

    /// The kcb2.rid id of this key.
    [[nodiscard]] std::string paserk_id() const { return detail::paserk_id(ID_HEADER, to_paserk()); }

    [[nodiscard]] std::span<const uint8_t> bytes() const noexcept { return pk_; }

private:
    friend class RecipientKey;
    RecipientPublicKey() = default;
    std::vector<uint8_t> pk_;
};

/// A recipient's secret: the 32-byte X-Wing decapsulation key, kept with
/// its expansion so that unsealing does not derive it again. Only the 32
/// bytes ever leave the object, as kcb2.recipient-secret.
class RecipientKey {
public:
    static constexpr std::size_t BYTES = detail::XWing::SEED_BYTES;
    static constexpr std::string_view PASERK_HEADER = "kcb2.recipient-secret.";

    RecipientKey(const RecipientKey&) = delete;
    RecipientKey& operator=(const RecipientKey&) = delete;
    RecipientKey(RecipientKey&&) noexcept = default;
    RecipientKey& operator=(RecipientKey&& o) noexcept {
        if (this != &o) {
            release();
            seed_ = std::move(o.seed_);
            expanded_ = std::move(o.expanded_);
        }
        return *this;
    }
    ~RecipientKey() { release(); }

    [[nodiscard]] static Result<RecipientKey> generate() {
        if (!detail::ensure_sodium()) return Result<RecipientKey>::err(Error::internal);
        RecipientKey k;
        k.seed_.resize(BYTES);
        k.lock();
        randombytes_buf(k.seed_.data(), BYTES);
        return k.finish(std::move(k));
    }

    /// Imports the 32-byte decapsulation key and expands it.
    [[nodiscard]] static Result<RecipientKey> from_bytes(std::span<const uint8_t> bytes) {
        if (bytes.size() != BYTES) return Result<RecipientKey>::err(Error::argument);
        if (!detail::ensure_sodium()) return Result<RecipientKey>::err(Error::internal);
        RecipientKey k;
        k.seed_.assign(bytes.begin(), bytes.end());
        k.lock();
        return k.finish(std::move(k));
    }

    [[nodiscard]] static Result<RecipientKey> from_paserk(std::string_view text) {
        if (!detail::ensure_sodium()) return Result<RecipientKey>::err(Error::internal);
        RecipientKey k;
        k.seed_.resize(BYTES);
        k.lock();
        if (!detail::paserk_decode(PASERK_HEADER, text, k.seed_.data(), BYTES))
            return Result<RecipientKey>::err(Error::argument);
        return k.finish(std::move(k));
    }

    /// The kcb2.recipient-secret form, in wiped memory.
    [[nodiscard]] SecureString to_paserk() const {
        return detail::paserk_encode<SecureString>(PASERK_HEADER, seed_);
    }

    [[nodiscard]] RecipientPublicKey public_key() const {
        RecipientPublicKey p;
        const uint8_t* pk = expanded_.data() + detail::XWing::ML_SK_BYTES + 32;
        p.pk_.assign(pk, pk + detail::XWing::PK_BYTES);
        return p;
    }

    /// The kcb2.rid of the public key.
    [[nodiscard]] std::string paserk_id() const { return public_key().paserk_id(); }

#ifdef CB2_TEST_NONCE
    /// The expanded decapsulation key sk_M || sk_X || pk, for the
    /// constant-time probe to mark its secret parts.
    [[nodiscard]] std::span<const uint8_t> expanded_for_testing() const noexcept { return expanded_; }
#endif

    [[nodiscard]] RecipientKey clone() const {
        RecipientKey k;
        k.seed_ = seed_;
        k.expanded_ = expanded_;
        k.lock();
        return k;
    }

private:
    friend class Seal;
    RecipientKey() = default;

    [[nodiscard]] static Result<RecipientKey> finish(RecipientKey k) {
        k.expanded_.resize(detail::XWing::EXPANDED_BYTES);
        k.lock();
        if (!detail::XWing::expand(k.seed_.data(), k.expanded_.data())) return Result<RecipientKey>::err(Error::internal);
        return Result<RecipientKey>::ok(std::move(k));
    }

    void lock() noexcept {
        if (!seed_.empty()) detail::lock(seed_.data(), seed_.size());
        if (!expanded_.empty()) detail::lock(expanded_.data(), expanded_.size());
    }

    void release() noexcept {
        if (!seed_.empty()) detail::unlock(seed_.data(), seed_.size());
        if (!expanded_.empty()) detail::unlock(expanded_.data(), expanded_.size());
    }

    SecureBytes seed_;
    SecureBytes expanded_;
};

/// kcb2.seal: a LocalKey sealed to a recipient and opened by the recipient.
class Seal {
public:
    static constexpr std::string_view HEADER = "kcb2.seal.";
    static constexpr std::size_t CT_BYTES = detail::XWing::CT_BYTES;
    static constexpr std::size_t BODY_BYTES = CT_BYTES + detail::LOCAL_OVERHEAD + LocalKey::BYTES;
    static constexpr std::size_t TEXT_BYTES = HEADER.size() + detail::b64::encoded_len(BODY_BYTES);

    /// Seals key to the recipient with fresh randomness.
    [[nodiscard]] static Result<std::string> seal(const RecipientPublicKey& to, const LocalKey& key) {
        detail::SecureArray<detail::XWing::ESEED_BYTES> eseed;
        detail::SecureArray<detail::LOCAL_NONCE_BYTES> nonce;
        if (!detail::ensure_sodium()) return Result<std::string>::err(Error::internal);
        randombytes_buf(eseed.v, sizeof eseed.v);
        randombytes_buf(nonce.v, sizeof nonce.v);
        return seal_with(to, key, eseed.v, nonce.v);
    }

    /// Opens a kcb2.seal string with the recipient's secret. The key comes
    /// back with its default id.
    [[nodiscard]] static Result<LocalKey> unseal(std::string_view text, const RecipientKey& by) {
        if (text.size() != TEXT_BYTES || text.substr(0, HEADER.size()) != HEADER)
            return Result<LocalKey>::err(Error::invalid);
        uint8_t body[BODY_BYTES];
        std::size_t n = 0;
        if (!detail::b64::decode(body, sizeof body, text.data() + HEADER.size(), text.size() - HEADER.size(), n) ||
            n != BODY_BYTES)
            return Result<LocalKey>::err(Error::invalid);
        detail::SecureArray<detail::XWing::SS_BYTES> ss;
        if (!detail::XWing::decaps(by.expanded_.data(), body, ss.v)) return Result<LocalKey>::err(Error::invalid);
        detail::SecureArray<LocalKey::BYTES> key;
        const Status s = detail::LocalCore::open_body(HEADER, {key.v, LocalKey::BYTES}, {body + CT_BYTES, BODY_BYTES - CT_BYTES},
                                                     ss.v, {}, {body, CT_BYTES});
        if (s != Status::ok) return Result<LocalKey>::err(to_error(s));
        return LocalKey::from_bytes({key.v, LocalKey::BYTES});
    }

#ifdef CB2_TEST_NONCE
    [[nodiscard]] static Result<std::string>
    seal_with_randomness_for_testing(const RecipientPublicKey& to, const LocalKey& key,
                                     std::span<const uint8_t> eseed, std::span<const uint8_t> nonce) {
        if (eseed.size() != detail::XWing::ESEED_BYTES || nonce.size() != detail::LOCAL_NONCE_BYTES)
            return Result<std::string>::err(Error::argument);
        return seal_with(to, key, eseed.data(), nonce.data());
    }
#endif

private:
    [[nodiscard]] static Result<std::string> seal_with(const RecipientPublicKey& to, const LocalKey& key,
                                                       const uint8_t* eseed, const uint8_t* nonce) {
        if (!detail::ensure_sodium()) return Result<std::string>::err(Error::internal);
        uint8_t body[BODY_BYTES];
        detail::SecureArray<detail::XWing::SS_BYTES> ss;
        if (!detail::XWing::encaps(to.bytes().data(), eseed, body, ss.v)) return Result<std::string>::err(Error::argument);
        const Status s = detail::LocalCore::seal_body(HEADER, {body + CT_BYTES, BODY_BYTES - CT_BYTES}, ss.v,
                                                     {detail::KeyAccess::local(key), LocalKey::BYTES}, {},
                                                     {body, CT_BYTES}, nonce);
        if (s != Status::ok) return Result<std::string>::err(to_error(s));
        detail::declassify(body, BODY_BYTES);
        std::string out(TEXT_BYTES, '\0');
        std::memcpy(out.data(), HEADER.data(), HEADER.size());
        detail::b64::encode(out.data() + HEADER.size(), body, BODY_BYTES);
        detail::wipe(body, sizeof body);
        return Result<std::string>::ok(std::move(out));
    }
};

}

#endif
#endif
