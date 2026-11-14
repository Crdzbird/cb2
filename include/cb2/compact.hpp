#pragma once

/**
 * cb3: compact claims tokens, the experimental header family of the
 * compact-tokens branch (PROTOCOL.md section 15).
 *
 * cb3.local and cb3.public are the cb2.local and cb2.public constructions
 * unchanged under new headers: the same 32-byte nonce, key derivation and
 * 32-byte keyed-BLAKE3 tag, the same Ed25519 and ML-DSA-65 signature pair
 * with the header as the FIPS 204 context. Only the encoding differs. The
 * message is the claims in the strict CBOR profile of cbor.hpp, with the
 * registered claims under the integer keys 1 to 8 (iss, sub, aud, exp,
 * nbf, iat, jti, cnf), times as integers, a canonical UUID jti as 16
 * bytes and cnf as the key bytes. The footer is the 16-byte key digest
 * BLAKE3("kcb3.kid." || key id), authenticated like any footer.
 *
 * With a ClaimTable (section 15.5), an iss or aud found in the table is
 * written as its index and the table's digest is bound into the
 * implicit assertion, so the token opens only under the same table.
 *
 * Validation is the cb2 order: rules, size limit, authentication, then
 * parsing, then the claims rules and the holder proof, with the same
 * verdicts. A cb3 token never opens under a cb2 header nor the reverse:
 * the header is in the key derivation, the PAE and the ML-DSA context.
 */

#include "cbor.hpp"
#include "claim_table.hpp"
#include "claims.hpp"
#include "detail/blake3.hpp"
#include "detail/local_core.hpp"
#include "detail/nonce.hpp"
#include "detail/secure.hpp"
#include "holder.hpp"
#include "keys.hpp"
#include "local.hpp"
#include "public.hpp"
#include "result.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cb2 {

/// The cb3 claims payload: Claims to and from the CBOR profile.
class CompactClaims {
public:
    static constexpr uint64_t KEY_ISS = 1;
    static constexpr uint64_t KEY_SUB = 2;
    static constexpr uint64_t KEY_AUD = 3;
    static constexpr uint64_t KEY_EXP = 4;
    static constexpr uint64_t KEY_NBF = 5;
    static constexpr uint64_t KEY_IAT = 6;
    static constexpr uint64_t KEY_JTI = 7;
    static constexpr uint64_t KEY_CNF = 8;
    /// 0000-01-01T00:00:00Z and 9999-12-31T23:59:59Z, the instants an RFC
    /// 3339 time claim of cb2 can name.
    static constexpr Seconds MIN_TIME = -62167219200;
    static constexpr Seconds MAX_TIME = 253402300799;
    static constexpr uint8_t CNF_LOCAL = 1;
    static constexpr uint8_t CNF_PUBLIC = 2;
    static constexpr std::size_t CNF_PUBLIC_KEY_BYTES = 1984;
    static constexpr std::size_t UUID_BYTES = 16;

    /// The payload of a cb3 token. argument when an identifier breaks the
    /// policy, a time lies outside MIN_TIME..MAX_TIME, cnf is not a
    /// kcb2.local or kcb2.public key string, or a custom claim holds a
    /// number that is not an int64 integer in canonical form. With a
    /// table, an iss or aud equal to an entry is written as its index.
    [[nodiscard]] static Result<std::string> encode(const Claims& c, const ClaimTable* table = nullptr) {
        if (!c.text_ok()) return Result<std::string>::err(Error::argument);
        for (const auto& t : {&c.exp, &c.nbf, &c.iat}) {
            if (*t && (**t < MIN_TIME || **t > MAX_TIME)) return Result<std::string>::err(Error::argument);
        }
        std::string out;
        std::size_t count = c.custom_.size();
        for (const bool present : {c.iss.has_value(), c.sub.has_value(), c.aud.has_value(), c.exp.has_value(),
                                   c.nbf.has_value(), c.iat.has_value(), c.jti.has_value(), c.cnf.has_value()})
            count += present ? 1 : 0;
        cbor::Writer::head(out, cbor::MAJOR_MAP, count);
        auto key = [&out](uint64_t k) { cbor::Writer::head(out, cbor::MAJOR_UINT, k); };
        if (c.iss) { key(KEY_ISS); named(out, *c.iss, table); }
        if (c.sub) { key(KEY_SUB); cbor::Writer::text(out, *c.sub); }
        if (c.aud) { key(KEY_AUD); named(out, *c.aud, table); }
        if (c.exp) { key(KEY_EXP); cbor::Writer::integer(out, *c.exp); }
        if (c.nbf) { key(KEY_NBF); cbor::Writer::integer(out, *c.nbf); }
        if (c.iat) { key(KEY_IAT); cbor::Writer::integer(out, *c.iat); }
        if (c.jti) {
            key(KEY_JTI);
            uint8_t u[UUID_BYTES];
            if (uuid_bytes(*c.jti, u)) {
                cbor::Writer::bytes(out, {u, UUID_BYTES});
            } else {
                cbor::Writer::text(out, *c.jti);
            }
        }
        if (c.cnf) {
            key(KEY_CNF);
            if (!write_cnf(out, *c.cnf)) {
                detail::wipe(out.data(), out.size());
                return Result<std::string>::err(Error::argument);
            }
        }
        for (const auto& [name, value] : c.custom_) {
            cbor::Writer::text(out, name);
            if (!cbor::Writer::value(out, value)) {
                detail::wipe(out.data(), out.size());
                return Result<std::string>::err(Error::argument);
            }
        }
        return Result<std::string>::ok(std::move(out));
    }

    /// Claims from an authenticated cb3 payload; claims_malformed for
    /// anything outside the profile (PROTOCOL.md 15.3 and 15.5) or an
    /// identifier that breaks the policy. table is the one the token was
    /// authenticated under, or nullptr.
    [[nodiscard]] static Result<Claims> decode(std::span<const uint8_t> payload, const ClaimTable* table = nullptr) {
        cbor::Reader r(payload);
        cbor::Head h;
        if (!r.head(h) || h.major != cbor::MAJOR_MAP || h.arg > r.left() / 2) return malformed();
        Claims c;
        uint64_t last = 0;
        bool custom = false;
        for (uint64_t k = 0; k < h.arg; ++k) {
            cbor::Head kh;
            if (!r.head(kh)) return malformed();
            if (kh.major == cbor::MAJOR_UINT) {
                if (custom || kh.arg <= last || kh.arg > KEY_CNF || !registered(r, kh.arg, c, table)) return malformed();
                last = kh.arg;
                continue;
            }
            std::string name;
            if (!r.text_after(kh, name) || name.empty() || Claims::is_registered(name)) return malformed();
            for (const auto& [existing, v] : c.custom_) if (existing == name) return malformed();
            json::Value v;
            if (!r.value(v, 1, json::DEFAULT_MAX_DEPTH)) return malformed();
            c.custom_.emplace_back(std::move(name), std::move(v));
            custom = true;
        }
        if (!r.at_end() || !c.text_ok()) return malformed();
        return Result<Claims>::ok(std::move(c));
    }

    /// Whether s is a UUID in canonical form (36 characters, lowercase
    /// hex, hyphens after the 8th, 12th, 16th and 20th digit), and its 16
    /// bytes when it is.
    [[nodiscard]] static bool uuid_bytes(std::string_view s, uint8_t out[UUID_BYTES]) noexcept {
        if (s.size() != 36) return false;
        std::size_t o = 0;
        for (std::size_t i = 0; i < 36;) {
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (s[i] != '-') return false;
                ++i;
                continue;
            }
            const int hi = nibble(s[i]);
            const int lo = nibble(s[i + 1]);
            if (hi < 0 || lo < 0) return false;
            out[o++] = static_cast<uint8_t>(hi << 4 | lo);
            i += 2;
        }
        return true;
    }

    /// The canonical text of a 16-byte UUID.
    [[nodiscard]] static std::string uuid_text(const uint8_t* b) {
        static constexpr char HEX[] = "0123456789abcdef";
        std::string s;
        s.reserve(36);
        for (std::size_t i = 0; i < UUID_BYTES; ++i) {
            if (i == 4 || i == 6 || i == 8 || i == 10) s += '-';
            s += HEX[b[i] >> 4];
            s += HEX[b[i] & 0x0f];
        }
        return s;
    }

private:
    [[nodiscard]] static Result<Claims> malformed() { return Result<Claims>::err(Error::claims_malformed); }

    [[nodiscard]] static int nibble(char c) noexcept {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    }

    [[nodiscard]] static bool write_cnf(std::string& out, std::string_view cnf) {
        if (cnf.starts_with(Holder::CNF_LOCAL_PREFIX)) {
            detail::SecureArray<1 + LocalKey::BYTES> b;
            b.v[0] = CNF_LOCAL;
            if (!detail::paserk_decode(LocalKey::PASERK_HEADER, cnf, b.v + 1, LocalKey::BYTES)) return false;
            cbor::Writer::bytes(out, {b.v, sizeof b.v});
            return true;
        }
        if (!cnf.starts_with(Holder::CNF_PUBLIC_PREFIX)) return false;
        std::vector<uint8_t> b(1 + CNF_PUBLIC_KEY_BYTES);
        b[0] = CNF_PUBLIC;
        if (!detail::paserk_decode(Holder::CNF_PUBLIC_PREFIX, cnf, b.data() + 1, CNF_PUBLIC_KEY_BYTES)) return false;
        cbor::Writer::bytes(out, b);
        return true;
    }

    static void named(std::string& out, const std::string& value, const ClaimTable* table) {
        const auto index = table != nullptr ? table->index_of(value) : std::nullopt;
        if (index) {
            cbor::Writer::head(out, cbor::MAJOR_UINT, *index);
            return;
        }
        cbor::Writer::text(out, value);
    }

    /// An iss or aud: a text not in the table, or the index of an entry.
    [[nodiscard]] static bool read_named(cbor::Reader& r, const cbor::Head& h, const ClaimTable* table,
                                         std::optional<std::string>& out) {
        if (h.major == cbor::MAJOR_UINT) {
            const std::string* entry = table != nullptr ? table->at(h.arg) : nullptr;
            if (entry == nullptr) return false;
            out = *entry;
            return true;
        }
        return r.text_after(h, out.emplace()) && (table == nullptr || !table->index_of(*out));
    }

    [[nodiscard]] static bool registered(cbor::Reader& r, uint64_t key, Claims& c, const ClaimTable* table) {
        cbor::Head h;
        if (!r.head(h)) return false;
        switch (key) {
            case KEY_ISS: return read_named(r, h, table, c.iss);
            case KEY_SUB: return r.text_after(h, c.sub.emplace());
            case KEY_AUD: return read_named(r, h, table, c.aud);
            case KEY_EXP: return time(h, c.exp);
            case KEY_NBF: return time(h, c.nbf);
            case KEY_IAT: return time(h, c.iat);
            case KEY_JTI: return jti(r, h, c);
            case KEY_CNF: return read_cnf(r, h, c);
            default: return false;
        }
    }

    [[nodiscard]] static bool time(const cbor::Head& h, std::optional<Seconds>& out) noexcept {
        int64_t t = 0;
        if (!cbor::Reader::integer_after(h, t) || t < MIN_TIME || t > MAX_TIME) return false;
        out = t;
        return true;
    }

    [[nodiscard]] static bool jti(cbor::Reader& r, const cbor::Head& h, Claims& c) {
        if (h.major == cbor::MAJOR_BYTES) {
            std::span<const uint8_t> b;
            if (!r.take(h, b) || b.size() != UUID_BYTES) return false;
            c.jti = uuid_text(b.data());
            return true;
        }
        uint8_t u[UUID_BYTES];
        return r.text_after(h, c.jti.emplace()) && !uuid_bytes(*c.jti, u);
    }

    [[nodiscard]] static bool read_cnf(cbor::Reader& r, const cbor::Head& h, Claims& c) {
        std::span<const uint8_t> b;
        if (h.major != cbor::MAJOR_BYTES || !r.take(h, b) || b.empty()) return false;
        if (b[0] == CNF_LOCAL && b.size() == 1 + LocalKey::BYTES) {
            c.cnf = detail::paserk_encode<std::string>(LocalKey::PASERK_HEADER, b.subspan(1));
            return true;
        }
        if (b[0] != CNF_PUBLIC || b.size() != 1 + CNF_PUBLIC_KEY_BYTES) return false;
        c.cnf = detail::paserk_encode<std::string>(Holder::CNF_PUBLIC_PREFIX, b.subspan(1));
        return true;
    }
};

/// A key digest read from a cb3 footer before any verification. It may
/// be used to select a candidate key and for nothing else.
struct UnverifiedKeyDigest {
    std::array<uint8_t, 16> value{};
};

class CompactToken {
public:
    static constexpr std::string_view LOCAL_HEADER = "cb3.local.";
    static constexpr std::string_view PUBLIC_HEADER = "cb3.public.";
    static constexpr std::string_view KEY_DIGEST_DOMAIN = "kcb3.kid.";
    static constexpr std::size_t KEY_DIGEST_BYTES = 16;
    static constexpr std::size_t NONCE_BYTES = detail::LOCAL_NONCE_BYTES;

    /// The footer a key id is bound into: BLAKE3(KEY_DIGEST_DOMAIN || id)
    /// cut to 16 bytes; empty for no id.
    [[nodiscard]] static std::string footer_for(const std::optional<std::string>& kid) {
        if (!kid) return {};
        uint8_t d[KEY_DIGEST_BYTES];
        detail::Blake3 h;
        h.update(reinterpret_cast<const uint8_t*>(KEY_DIGEST_DOMAIN.data()), KEY_DIGEST_DOMAIN.size());
        h.update(reinterpret_cast<const uint8_t*>(kid->data()), kid->size());
        h.finalize(d, sizeof d);
        return std::string(reinterpret_cast<const char*>(d), sizeof d);
    }

    /// Reads the key digest from the footer of a cb3 token of either
    /// purpose without verifying anything. The token is bounded by
    /// max_token_bytes first.
    [[nodiscard]] static std::optional<UnverifiedKeyDigest>
    peek_key_digest(std::string_view token,
                    std::size_t max_token_bytes = ValidationRules::DEFAULT_MAX_TOKEN_BYTES) {
        if (token.size() > max_token_bytes) return std::nullopt;
        detail::Split s{};
        if (!detail::split_token(token, LOCAL_HEADER, true, s) && !detail::split_token(token, PUBLIC_HEADER, true, s))
            return std::nullopt;
        if (detail::b64::decoded_len(s.footer_len) != KEY_DIGEST_BYTES) return std::nullopt;
        UnverifiedKeyDigest d;
        std::size_t n = 0;
        if (!detail::b64::decode(d.value.data(), KEY_DIGEST_BYTES, s.footer, s.footer_len, n) ||
            n != KEY_DIGEST_BYTES)
            return std::nullopt;
        return d;
    }

    /// Seals claims as a cb3.local token. An implicit assertion that
    /// starts with ClaimTable::TABLE_DOMAIN is argument.
    [[nodiscard]] static Result<std::string>
    seal(const LocalKey& key, const Claims& claims, std::string_view implicit = {}) {
        return seal_fresh(key, claims, nullptr, implicit);
    }

    /// Seals claims as a cb3.local token under a claim table.
    [[nodiscard]] static Result<std::string>
    seal(const LocalKey& key, const Claims& claims, const ClaimTable& table, std::string_view implicit = {}) {
        return seal_fresh(key, claims, &table, implicit);
    }

#ifdef CB2_TEST_NONCE
    /// Test builds only: seal with a caller-chosen 32-byte nonce, to
    /// produce known-answer vectors.
    [[nodiscard]] static Result<std::string>
    seal_with_nonce_for_testing(const LocalKey& key, const Claims& claims, std::span<const uint8_t> nonce,
                                std::string_view implicit = {}) {
        if (nonce.size() != NONCE_BYTES) return Result<std::string>::err(Error::argument);
        return seal_with(key, claims, nullptr, implicit, nonce.data());
    }

    /// Test builds only: the same under a claim table.
    [[nodiscard]] static Result<std::string>
    seal_with_nonce_for_testing(const LocalKey& key, const Claims& claims, const ClaimTable& table,
                                std::span<const uint8_t> nonce, std::string_view implicit = {}) {
        if (nonce.size() != NONCE_BYTES) return Result<std::string>::err(Error::argument);
        return seal_with(key, claims, &table, implicit, nonce.data());
    }
#endif

    /// Opens a cb3.local token: rules and key checks, size limit,
    /// authentication, parsing, validation, in that order.
    [[nodiscard]] static Result<Claims>
    open(std::string_view token, const LocalKey& key, const ValidationRules& rules, std::string_view implicit = {}) {
        return open_with(token, key, rules, nullptr, implicit);
    }

    /// Opens a cb3.local token sealed under the same claim table; any
    /// other table, or none, is invalid.
    [[nodiscard]] static Result<Claims>
    open(std::string_view token, const LocalKey& key, const ValidationRules& rules, const ClaimTable& table,
         std::string_view implicit = {}) {
        return open_with(token, key, rules, &table, implicit);
    }

#ifdef CB2_HAS_PQ
    /// Signs claims as a cb3.public token. A kcb2.local cnf is argument,
    /// as in cb2.public.
    [[nodiscard]] static Result<std::string>
    sign(const SecretKey& key, const Claims& claims, std::string_view implicit = {}) {
        return sign_with(key, claims, nullptr, implicit);
    }

    /// Signs claims as a cb3.public token under a claim table.
    [[nodiscard]] static Result<std::string>
    sign(const SecretKey& key, const Claims& claims, const ClaimTable& table, std::string_view implicit = {}) {
        return sign_with(key, claims, &table, implicit);
    }

    /// Verifies a cb3.public token: rules and key checks, size limit,
    /// both signatures, parsing, validation, in that order.
    [[nodiscard]] static Result<Claims>
    verify(std::string_view token, const PublicKey& key, const ValidationRules& rules,
           std::string_view implicit = {}) {
        return verify_with(token, key, rules, nullptr, implicit);
    }

    /// Verifies a cb3.public token signed under the same claim table;
    /// any other table, or none, is invalid.
    [[nodiscard]] static Result<Claims>
    verify(std::string_view token, const PublicKey& key, const ValidationRules& rules, const ClaimTable& table,
           std::string_view implicit = {}) {
        return verify_with(token, key, rules, &table, implicit);
    }
#endif

private:
    /// The implicit assertion that is authenticated: bound to the table
    /// when there is one; without one, nullopt for a reserved assertion.
    [[nodiscard]] static std::optional<std::string> authenticated(const ClaimTable* table, std::string_view implicit) {
        if (table != nullptr) return table->bind(implicit);
        if (ClaimTable::reserved(implicit)) return std::nullopt;
        return std::string(implicit);
    }

    [[nodiscard]] static Result<void>
    precheck(std::string_view token, const std::optional<std::string>& kid, const ValidationRules& rules) {
        if (!rules.complete()) return Result<void>::err(Error::rules_incomplete);
        if (!Token::key_id_ok(kid) || !rules.expectations_ok()) return Result<void>::err(Error::argument);
        if (token.size() > rules.max_token_bytes()) return Result<void>::err(Error::too_large);
        return Result<void>::ok();
    }

    [[nodiscard]] static Result<std::string>
    seal_fresh(const LocalKey& key, const Claims& claims, const ClaimTable* table, std::string_view implicit) {
        uint8_t n[NONCE_BYTES];
        if (!detail::ensure_sodium()) return Result<std::string>::err(Error::internal);
        detail::fresh_nonce(n, NONCE_BYTES);
        return seal_with(key, claims, table, implicit, n);
    }

    [[nodiscard]] static Result<std::string>
    seal_with(const LocalKey& key, const Claims& claims, const ClaimTable* table, std::string_view implicit,
              const uint8_t* nonce) {
        if (!Token::key_id_ok(key.key_id())) return Result<std::string>::err(Error::argument);
        try {
            const auto assertion = authenticated(table, implicit);
            if (!assertion) return Result<std::string>::err(Error::argument);
            auto payload = CompactClaims::encode(claims, table);
            if (payload.is_err()) return payload;
            std::string& msg = payload.value();
            const std::string footer = footer_for(key.key_id());
            const std::size_t need = detail::LocalCore::token_len(LOCAL_HEADER, msg.size(), footer.size());
            if (need == 0) {
                detail::wipe(msg.data(), msg.size());
                return Result<std::string>::err(Error::argument);
            }
            std::string tok(need, '\0');
            std::size_t n = 0;
            const Status s = detail::LocalCore::seal(LOCAL_HEADER, {reinterpret_cast<uint8_t*>(tok.data()), tok.size()},
                                                     n, detail::KeyAccess::local(key), bytes(msg), bytes(footer),
                                                     bytes(*assertion), nonce);
            detail::wipe(msg.data(), msg.size());
            if (s != Status::ok) return Result<std::string>::err(to_error(s));
            return Result<std::string>::ok(std::move(tok));
        } catch (...) {
            return Result<std::string>::err(Error::internal);
        }
    }

    [[nodiscard]] static Result<Claims>
    open_with(std::string_view token, const LocalKey& key, const ValidationRules& rules, const ClaimTable* table,
              std::string_view implicit) {
        const auto pre = precheck(token, key.key_id(), rules);
        if (pre.is_err()) return Result<Claims>::err(pre.error());
        try {
            const auto assertion = authenticated(table, implicit);
            if (!assertion) return Result<Claims>::err(Error::argument);
            const std::string footer = footer_for(key.key_id());
            const std::size_t cap = detail::LocalCore::open_capacity(LOCAL_HEADER, token.size());
            if (cap == 0) return Result<Claims>::err(Error::invalid);
            SecureBytes buf(cap);
            std::size_t n = 0;
            const Status s = detail::LocalCore::open(LOCAL_HEADER, buf, n, token, detail::KeyAccess::local(key),
                                                     bytes(footer), bytes(*assertion));
            if (s != Status::ok) return Result<Claims>::err(to_error(s));
            auto claims = CompactClaims::decode({buf.data(), n}, table);
            if (claims.is_err()) return claims;
            return Token::finish_parsed(std::move(claims.value()), rules, token, false);
        } catch (...) {
            return Result<Claims>::err(Error::internal);
        }
    }

#ifdef CB2_HAS_PQ
    [[nodiscard]] static Result<std::string>
    sign_with(const SecretKey& key, const Claims& claims, const ClaimTable* table, std::string_view implicit) {
        if (!Token::key_id_ok(key.key_id())) return Result<std::string>::err(Error::argument);
        if (claims.cnf && claims.cnf->starts_with(Holder::CNF_LOCAL_PREFIX))
            return Result<std::string>::err(Error::argument);
        try {
            const auto assertion = authenticated(table, implicit);
            if (!assertion) return Result<std::string>::err(Error::argument);
            auto payload = CompactClaims::encode(claims, table);
            if (payload.is_err()) return payload;
            const std::string footer = footer_for(key.key_id());
            return detail::PublicCore::sign(PUBLIC_HEADER, key, bytes(payload.value()), bytes(footer),
                                            bytes(*assertion));
        } catch (...) {
            return Result<std::string>::err(Error::internal);
        }
    }

    [[nodiscard]] static Result<Claims>
    verify_with(std::string_view token, const PublicKey& key, const ValidationRules& rules, const ClaimTable* table,
                std::string_view implicit) {
        const auto pre = precheck(token, key.key_id(), rules);
        if (pre.is_err()) return Result<Claims>::err(pre.error());
        try {
            const auto assertion = authenticated(table, implicit);
            if (!assertion) return Result<Claims>::err(Error::argument);
            const std::string footer = footer_for(key.key_id());
            auto msg = detail::PublicCore::verify(PUBLIC_HEADER, token, key, bytes(footer), bytes(*assertion),
                                                  rules.max_token_bytes());
            if (msg.is_err()) return Result<Claims>::err(msg.error());
            auto claims = CompactClaims::decode(msg.value(), table);
            if (claims.is_err()) return claims;
            return Token::finish_parsed(std::move(claims.value()), rules, token, true);
        } catch (...) {
            return Result<Claims>::err(Error::internal);
        }
    }
#endif
};

}
