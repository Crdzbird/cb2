#pragma once

/**
 * The typed claims layer: Claims, ValidationRules and Token.
 *
 * Claims holds the registered PASETO claims (iss, sub, aud, exp, nbf, iat,
 * jti) as typed fields, with the three times as Unix seconds that are
 * written and read as RFC 3339 timestamps, plus custom claims. The
 * validator requires exp unless the caller opts out explicitly, checks nbf
 * and iat against a clock with a configurable skew, binds issuer, audience
 * and subject when expected, and refuses tokens over a size limit before
 * looking at a single byte of them. A verifier must say which audience
 * and which issuer it accepts, or say explicitly that any will do; rules
 * that say neither are refused before the token is read, so a token
 * minted for one service is never accepted by another through silence.
 * An optional replay check receives the jti of every token that passed
 * every other rule and may refuse it.
 *
 * Token composes the key types, the claims and the token classes: it binds
 * the key id into the footer as {"kid":"..."}, authenticates before it
 * parses, and only then validates. There is no function that returns
 * claims from a token that has not been authenticated; peek_key_id returns
 * an UnverifiedKeyId whose name says what it is.
 *
 * Text is UTF-8 throughout and compared byte for byte. The identifier
 * claims (iss, sub, aud, jti, cnf), custom claim names and key ids must
 * satisfy text::identifier_ok on both sides: the issuer gets
 * Error::argument before anything is sealed or signed, the verifier gets
 * claims_malformed after authentication. See text.hpp for the policy.
 *
 * A token whose cnf claim names a client key, or in a cb2.local token
 * carries a proof key, is sender-constrained: after every other rule it
 * is accepted only with a holder proof (HolderProof, holder.hpp) that the
 * presenter made under that key for this request and this token. A
 * verifier that does not check proofs must say so with
 * ignore_sender_constraint(); by default such a token without a proof is
 * missing_proof.
 */

#include "detail/secure.hpp"
#include "holder.hpp"
#include "json.hpp"
#include "keys.hpp"
#include "local.hpp"
#include "public.hpp"
#include "result.hpp"
#include "text.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cb2 {

class CompactClaims;
class CompactToken;

/// Unix time in seconds.
using Seconds = int64_t;

/// RFC 3339 timestamps, as PASETO's registered time claims use them.
/// Accepted: YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM), with T and
/// Z in either case. Produced: YYYY-MM-DDTHH:MM:SS+00:00.
class Rfc3339 {
public:
    [[nodiscard]] static bool parse(std::string_view s, Seconds& out) noexcept {
        if (s.size() < 20) return false;
        int64_t year = 0, mon = 0, day = 0, hour = 0, min = 0, sec = 0;
        if (!num(s, 0, 4, year) || s[4] != '-' || !num(s, 5, 2, mon) || s[7] != '-' ||
            !num(s, 8, 2, day) || (s[10] != 'T' && s[10] != 't') || !num(s, 11, 2, hour) ||
            s[13] != ':' || !num(s, 14, 2, min) || s[16] != ':' || !num(s, 17, 2, sec))
            return false;
        std::size_t i = 19;
        if (i < s.size() && s[i] == '.') {
            ++i;
            const std::size_t start = i;
            while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
            if (i == start) return false;
        }
        if (i >= s.size()) return false;
        int64_t offset = 0;
        if (s[i] == 'Z' || s[i] == 'z') {
            if (i + 1 != s.size()) return false;
        } else {
            if (i + 6 != s.size() || (s[i] != '+' && s[i] != '-')) return false;
            int64_t oh = 0, om = 0;
            if (!num(s, i + 1, 2, oh) || s[i + 3] != ':' || !num(s, i + 4, 2, om)) return false;
            if (oh > 23 || om > 59) return false;
            offset = (oh * 60 + om) * 60 * (s[i] == '-' ? -1 : 1);
        }
        if (mon < 1 || mon > 12 || day < 1 || day > days_in(year, mon) || hour > 23 || min > 59 ||
            sec > 60)
            return false;
        out = days_from_civil(year, mon, day) * 86400 + hour * 3600 + min * 60 + sec - offset;
        return true;
    }

    [[nodiscard]] static std::string format(Seconds t) {
        int64_t days = t / 86400;
        int64_t rem = t % 86400;
        if (rem < 0) { rem += 86400; --days; }
        int64_t y = 0, m = 0, d = 0;
        civil_from_days(days, y, m, d);
        char buf[32];
        const int n = std::snprintf(buf, sizeof buf, "%04lld-%02lld-%02lldT%02lld:%02lld:%02lld+00:00",
                                    static_cast<long long>(y), static_cast<long long>(m),
                                    static_cast<long long>(d), static_cast<long long>(rem / 3600),
                                    static_cast<long long>(rem % 3600 / 60),
                                    static_cast<long long>(rem % 60));
        return std::string(buf, n > 0 ? static_cast<std::size_t>(n) : 0);
    }

private:
    [[nodiscard]] static bool num(std::string_view s, std::size_t at, std::size_t len,
                                  int64_t& v) noexcept {
        if (at + len > s.size()) return false;
        v = 0;
        for (std::size_t k = 0; k < len; ++k) {
            const char c = s[at + k];
            if (c < '0' || c > '9') return false;
            v = v * 10 + (c - '0');
        }
        return true;
    }

    [[nodiscard]] static bool leap(int64_t y) noexcept {
        return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    }

    [[nodiscard]] static int64_t days_in(int64_t y, int64_t m) noexcept {
        static constexpr int64_t D[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        return m == 2 && leap(y) ? 29 : D[m - 1];
    }

    [[nodiscard]] static int64_t days_from_civil(int64_t y, int64_t m, int64_t d) noexcept {
        y -= m <= 2;
        const int64_t era = (y >= 0 ? y : y - 399) / 400;
        const int64_t yoe = y - era * 400;
        const int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
        const int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146097 + doe - 719468;
    }

    static void civil_from_days(int64_t z, int64_t& y, int64_t& m, int64_t& d) noexcept {
        z += 719468;
        const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
        const int64_t doe = z - era * 146097;
        const int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        y = yoe + era * 400;
        const int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        const int64_t mp = (5 * doy + 2) / 153;
        d = doy - (153 * mp + 2) / 5 + 1;
        m = mp + (mp < 10 ? 3 : -9);
        y += m <= 2;
    }
};

/// The registered claims plus custom claims. Custom claim names may not be
/// a registered name; string values are typed, any other JSON value is
/// kept as JSON text.
class Claims {
public:
    static constexpr std::string_view REGISTERED[] = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "cnf"};

    std::optional<std::string> iss;
    std::optional<std::string> sub;
    std::optional<std::string> aud;
    std::optional<Seconds> exp;
    std::optional<Seconds> nbf;
    std::optional<Seconds> iat;
    std::optional<std::string> jti;
    /// The key this token is bound to: a kcb2.public string (the public
    /// holder mode) or, in a cb2.local token only, a kcb2.local proof key
    /// (the local holder mode).
    std::optional<std::string> cnf;

    [[nodiscard]] static bool is_registered(std::string_view name) noexcept {
        for (const auto r : REGISTERED) if (r == name) return true;
        return false;
    }

    /// Sets a custom string claim. Fails for a registered or empty name,
    /// a name that is not an identifier, or a value that is not UTF-8.
    [[nodiscard]] bool set(std::string_view name, std::string_view value) {
        if (name.empty() || is_registered(name) || !text::identifier_ok(name)) return false;
        if (!text::valid_utf8(value)) return false;
        json::Value v;
        v.kind = json::Value::Kind::string;
        v.text.assign(value);
        put(name, std::move(v));
        return true;
    }

    /// Deepest nesting a custom claim value may have: one level less than
    /// the reader's limit, since the value sits inside the payload object.
    static constexpr std::size_t MAX_CUSTOM_DEPTH = json::DEFAULT_MAX_DEPTH - 1;

    /// Sets a custom claim from JSON text, which must be one valid value
    /// nested at most MAX_CUSTOM_DEPTH deep, so that the verifier's reader
    /// accepts it inside the payload.
    [[nodiscard]] bool set_json(std::string_view name, std::string_view json_text) {
        if (name.empty() || is_registered(name) || !text::identifier_ok(name)) return false;
        json::Value v;
        if (!json::Reader::parse(json_text, v, MAX_CUSTOM_DEPTH)) return false;
        put(name, std::move(v));
        return true;
    }

    /// A custom string claim, if present and a string.
    [[nodiscard]] std::optional<std::string_view> get(std::string_view name) const noexcept {
        for (const auto& [k, v] : custom_) {
            if (k == name) {
                if (v.is_string()) return std::string_view(v.text);
                return std::nullopt;
            }
        }
        return std::nullopt;
    }

    /// A custom claim of any kind as JSON text, if present.
    [[nodiscard]] std::optional<std::string> get_json(std::string_view name) const {
        for (const auto& [k, v] : custom_) {
            if (k == name) {
                std::string out;
                json::Writer::value(out, v);
                return out;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] const std::vector<std::pair<std::string, json::Value>>& custom() const noexcept {
        return custom_;
    }

    /// Whether every identifier claim and custom claim name satisfies the
    /// identifier policy. Token::seal and Token::sign refuse claims that
    /// do not, with Error::argument; from_json refuses them with
    /// claims_malformed.
    [[nodiscard]] bool text_ok() const noexcept {
        for (const auto& id : {&iss, &sub, &aud, &jti, &cnf}) {
            if (*id && !text::identifier_ok(**id)) return false;
        }
        for (const auto& [k, v] : custom_) {
            if (!text::identifier_ok(k)) return false;
        }
        return true;
    }

    /// The JSON object: registered claims in the order iss, sub, aud, exp,
    /// nbf, iat, jti, cnf, then custom claims in insertion order.
    [[nodiscard]] std::string to_json() const {
        std::string out = "{";
        bool first = true;
        auto member = [&](std::string_view k, std::string_view v) {
            if (!first) out += ',';
            first = false;
            json::Writer::string(out, k);
            out += ':';
            json::Writer::string(out, v);
        };
        if (iss) member("iss", *iss);
        if (sub) member("sub", *sub);
        if (aud) member("aud", *aud);
        if (exp) member("exp", Rfc3339::format(*exp));
        if (nbf) member("nbf", Rfc3339::format(*nbf));
        if (iat) member("iat", Rfc3339::format(*iat));
        if (jti) member("jti", *jti);
        if (cnf) member("cnf", *cnf);
        for (const auto& [k, v] : custom_) {
            if (!first) out += ',';
            first = false;
            json::Writer::string(out, k);
            out += ':';
            json::Writer::value(out, v);
        }
        out += '}';
        return out;
    }

    /// Parses a JSON object. Registered claims must be strings and the
    /// time claims valid RFC 3339; anything else is claims_malformed.
    [[nodiscard]] static Result<Claims> from_json(std::string_view text) {
        json::Value root;
        if (!json::Reader::parse(text, root) || !root.is_object())
            return Result<Claims>::err(Error::claims_malformed);
        Claims c;
        for (auto& [k, v] : root.members) {
            if (is_registered(k) && !v.is_string()) return Result<Claims>::err(Error::claims_malformed);
            if (k == "iss") { c.iss = std::move(v.text); continue; }
            if (k == "sub") { c.sub = std::move(v.text); continue; }
            if (k == "aud") { c.aud = std::move(v.text); continue; }
            if (k == "jti") { c.jti = std::move(v.text); continue; }
            if (k == "cnf") { c.cnf = std::move(v.text); continue; }
            if (k == "exp" || k == "nbf" || k == "iat") {
                Seconds t = 0;
                if (!Rfc3339::parse(v.text, t)) return Result<Claims>::err(Error::claims_malformed);
                (k == "exp" ? c.exp : k == "nbf" ? c.nbf : c.iat) = t;
                continue;
            }
            c.custom_.emplace_back(std::move(k), std::move(v));
        }
        if (!c.text_ok()) return Result<Claims>::err(Error::claims_malformed);
        return Result<Claims>::ok(std::move(c));
    }

private:
    void put(std::string_view name, json::Value v) {
        for (auto& [k, existing] : custom_) {
            if (k == name) { existing = std::move(v); return; }
        }
        custom_.emplace_back(std::string(name), std::move(v));
    }

    std::vector<std::pair<std::string, json::Value>> custom_;

    friend class CompactClaims;
};

/// What a verifier requires of a token. exp is required unless
/// allow_missing_exp() is called; an expected audience and issuer are
/// required unless allow_any_audience() and allow_any_issuer() are
/// called, and rules that name neither are rules_incomplete before the
/// token is read; an expectation that breaks the identifier policy is
/// argument before the token is read, since it could never match; the
/// size limit is enforced before any parsing; a maximum lifetime, when
/// set, bounds how far ahead of now an accepted exp may lie; every
/// string comparison is constant time. A replay check, when installed,
/// runs after the bindings: it receives the jti of a token that passed
/// every other rule and returns true to accept it, so a denylist never
/// records a token that was refused for another reason. The holder proof
/// of a sender-constrained token is checked last of all, with the proof
/// and the request given by with_holder_proof and a proof replay check
/// that is required whenever a proof is given.
class ValidationRules {
public:
    static constexpr std::size_t DEFAULT_MAX_TOKEN_BYTES = 16384;

    /// Receives a jti; true accepts the token, false reports replayed.
    using ReplayCheck = std::function<bool(std::string_view jti)>;

    ValidationRules& allow_missing_exp() noexcept { require_exp_ = false; return *this; }
    /// Accepts tokens of any audience. Say so on purpose.
    ValidationRules& allow_any_audience() noexcept { require_audience_ = false; return *this; }
    /// Accepts tokens of any issuer. Say so on purpose.
    ValidationRules& allow_any_issuer() noexcept { require_issuer_ = false; return *this; }
    /// Installs the replay check; a token without a jti is then missing_jti.
    ValidationRules& with_replay_check(ReplayCheck check) { replay_ = std::move(check); return *this; }
    ValidationRules& with_clock_skew(Seconds s) noexcept { skew_ = s < 0 ? 0 : s; return *this; }
    ValidationRules& with_max_token_bytes(std::size_t n) noexcept { max_token_ = n; return *this; }
    /// Refuses a token whose exp is more than s seconds after now, so a
    /// long-lived token is worth no more than s seconds to whoever holds
    /// it, whatever the issuer wrote.
    ValidationRules& with_max_lifetime(Seconds s) noexcept { max_lifetime_ = s < 0 ? 0 : s; return *this; }
    ValidationRules& expect_issuer(std::string s) { issuer_ = std::move(s); return *this; }
    ValidationRules& expect_audience(std::string s) { audience_ = std::move(s); return *this; }
    ValidationRules& expect_subject(std::string s) { subject_ = std::move(s); return *this; }
    /// Fixes the clock, for tests and for callers with their own time source.
    ValidationRules& at(Seconds now) noexcept { now_ = now; return *this; }

    /// The holder proof presented with the request and the request it must
    /// name. A proof replay check must be installed as well.
    ValidationRules& with_holder_proof(std::string proof, HolderRequest request) {
        proof_ = std::move(proof);
        request_ = std::move(request);
        return *this;
    }
    /// The most a proof may live: exp at most this far after iat and after now.
    ValidationRules& with_proof_lifetime(Seconds s) noexcept { proof_lifetime_ = s < 0 ? 0 : s; return *this; }
    /// Receives a proof's jti; false reports proof_replayed. Required with a proof.
    ValidationRules& with_proof_replay_check(ReplayCheck check) { proof_replay_ = std::move(check); return *this; }
    /// Refuses a token that carries no cnf claim.
    ValidationRules& require_sender_constraint() noexcept { require_cnf_ = true; return *this; }
    /// Accepts a token that carries cnf without a proof. Say so on purpose.
    ValidationRules& ignore_sender_constraint() noexcept { ignore_cnf_ = true; return *this; }

    [[nodiscard]] bool require_exp() const noexcept { return require_exp_; }
    [[nodiscard]] bool require_audience() const noexcept { return require_audience_; }
    [[nodiscard]] bool require_issuer() const noexcept { return require_issuer_; }
    [[nodiscard]] bool has_replay_check() const noexcept { return static_cast<bool>(replay_); }
    [[nodiscard]] const std::optional<std::string>& holder_proof() const noexcept { return proof_; }
    [[nodiscard]] const std::optional<HolderRequest>& holder_request() const noexcept { return request_; }
    [[nodiscard]] Seconds proof_lifetime() const noexcept { return proof_lifetime_; }
    [[nodiscard]] const ReplayCheck& proof_replay_check() const noexcept { return proof_replay_; }
    [[nodiscard]] bool requires_sender_constraint() const noexcept { return require_cnf_; }
    [[nodiscard]] bool ignores_sender_constraint() const noexcept { return ignore_cnf_; }

    /// Whether the rules say what audience and issuer they accept, by
    /// expectation or by explicit allowance, carry a proof replay check
    /// whenever they carry a proof, and do not both require and ignore the
    /// sender constraint. Incomplete rules are refused before any token
    /// is read.
    [[nodiscard]] bool complete() const noexcept {
        return (audience_ || !require_audience_) && (issuer_ || !require_issuer_) &&
               (!proof_ || static_cast<bool>(proof_replay_)) && !(require_cnf_ && ignore_cnf_);
    }
    /// Whether every expected issuer, audience and subject satisfies the
    /// identifier policy the claims themselves must satisfy. One that
    /// breaks it could never match a claim and is refused as argument
    /// before any token is read.
    [[nodiscard]] bool expectations_ok() const noexcept {
        return (!issuer_ || text::identifier_ok(*issuer_)) &&
               (!audience_ || text::identifier_ok(*audience_)) &&
               (!subject_ || text::identifier_ok(*subject_));
    }
    [[nodiscard]] Seconds clock_skew() const noexcept { return skew_; }
    [[nodiscard]] std::size_t max_token_bytes() const noexcept { return max_token_; }
    [[nodiscard]] const std::optional<Seconds>& max_lifetime() const noexcept { return max_lifetime_; }
    [[nodiscard]] const std::optional<std::string>& issuer() const noexcept { return issuer_; }
    [[nodiscard]] const std::optional<std::string>& audience() const noexcept { return audience_; }
    [[nodiscard]] const std::optional<std::string>& subject() const noexcept { return subject_; }

    [[nodiscard]] Seconds now() const noexcept {
        if (now_) return *now_;
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    }

    /// Validates authenticated claims. Call only on claims that came out
    /// of Token::open or Token::verify, or that are otherwise trusted.
    [[nodiscard]] Result<void> check(const Claims& c) const noexcept {
        if (!complete()) return Result<void>::err(Error::rules_incomplete);
        if (!expectations_ok()) return Result<void>::err(Error::argument);
        const Seconds t = now();
        if (require_exp_ && !c.exp) return Result<void>::err(Error::missing_exp);
        if (c.exp && *c.exp <= t - skew_) return Result<void>::err(Error::expired);
        if (c.nbf && *c.nbf > t + skew_) return Result<void>::err(Error::not_yet_valid);
        if (c.iat && *c.iat > t + skew_) return Result<void>::err(Error::issued_in_future);
        if (max_lifetime_ && c.exp && *c.exp > t + *max_lifetime_)
            return Result<void>::err(Error::lifetime_exceeded);
        if (issuer_ && (!c.iss || !detail::ct_equal(*c.iss, *issuer_)))
            return Result<void>::err(Error::issuer_mismatch);
        if (audience_ && (!c.aud || !detail::ct_equal(*c.aud, *audience_)))
            return Result<void>::err(Error::audience_mismatch);
        if (subject_ && (!c.sub || !detail::ct_equal(*c.sub, *subject_)))
            return Result<void>::err(Error::subject_mismatch);
        if (replay_) {
            if (!c.jti) return Result<void>::err(Error::missing_jti);
            bool fresh = false;
            try {
                fresh = replay_(*c.jti);
            } catch (...) {
                return Result<void>::err(Error::internal);
            }
            if (!fresh) return Result<void>::err(Error::replayed);
        }
        return Result<void>::ok();
    }

private:
    bool require_exp_ = true;
    bool require_audience_ = true;
    bool require_issuer_ = true;
    ReplayCheck replay_;
    Seconds skew_ = 0;
    std::size_t max_token_ = DEFAULT_MAX_TOKEN_BYTES;
    std::optional<Seconds> max_lifetime_;
    std::optional<std::string> proof_;
    std::optional<HolderRequest> request_;
    Seconds proof_lifetime_ = Holder::DEFAULT_LIFETIME;
    ReplayCheck proof_replay_;
    bool require_cnf_ = false;
    bool ignore_cnf_ = false;
    std::optional<std::string> issuer_;
    std::optional<std::string> audience_;
    std::optional<std::string> subject_;
    std::optional<Seconds> now_;
};

/// Holder proofs: made by the client for one request and one access token
/// under the key the token's cnf claim binds, checked by the verifier under
/// that key. The local mode tags with the 32-byte proof key the issuer
/// wrote into cnf of a cb2.local access token (cb2.holder-local.); the
/// public mode signs with the client's key pair (cb2.holder-public.,
/// present only under CB2_HAS_PQ).
class HolderProof {
public:
    /// The claims a proof carries for a request made at now: jti, iat,
    /// exp = now + lifetime, htm, htu normalised, and nonce when the
    /// request has one. argument when the target does not normalise or
    /// an identifier breaks the policy.
    [[nodiscard]] static Result<Claims>
    claims_for(const HolderRequest& request, std::string_view jti, Seconds now,
               Seconds lifetime = Holder::DEFAULT_LIFETIME) {
        const auto target = Holder::normalize_target(request.target);
        if (!target || jti.empty()) return Result<Claims>::err(Error::argument);
        Claims c;
        c.jti = std::string(jti);
        c.iat = now;
        c.exp = now + (lifetime < 0 ? 0 : lifetime);
        if (!c.set("htm", request.method) || !c.set("htu", *target)) return Result<Claims>::err(Error::argument);
        if (request.nonce && !c.set("nonce", *request.nonce)) return Result<Claims>::err(Error::argument);
        if (!c.text_ok()) return Result<Claims>::err(Error::argument);
        return Result<Claims>::ok(std::move(c));
    }

    /// Binds claims of a cb2.local access token to a fresh proof key: the
    /// key is generated here, written into cnf as its kcb2.local string and
    /// returned for the client, which receives it with the token. argument
    /// when the claims already carry cnf.
    [[nodiscard]] static Result<LocalKey> bind_local(Claims& claims) {
        if (claims.cnf) return Result<LocalKey>::err(Error::argument);
        auto key = LocalKey::generate();
        if (key.is_err()) return key;
        const SecureString text = key.value().to_paserk();
        claims.cnf = std::string(text.data(), text.size());
        return key;
    }

    /// A proof under the proof key of a local-mode access token: a
    /// cb2.holder-local. token of claims_for, whose footer binds the proof
    /// key's kcb2.lid and whose implicit assertion is the access token text.
    [[nodiscard]] static Result<std::string>
    make_local(const LocalKey& proof_key, const HolderRequest& request, std::string_view access_token,
               std::string_view jti, Seconds now, Seconds lifetime = Holder::DEFAULT_LIFETIME) {
        if (!detail::ensure_sodium()) return Result<std::string>::err(Error::internal);
        uint8_t n[detail::LOCAL_NONCE_BYTES];
        detail::fresh_nonce(n, sizeof n);
        return seal_local(proof_key, request, access_token, jti, now, lifetime, n);
    }

#ifdef CB2_TEST_NONCE
    /// Test builds only: make_local with a caller-chosen 32-byte nonce, to
    /// produce known-answer vectors.
    [[nodiscard]] static Result<std::string>
    make_local_with_nonce_for_testing(const LocalKey& proof_key, const HolderRequest& request,
                                      std::string_view access_token, std::string_view jti, Seconds now,
                                      Seconds lifetime, std::span<const uint8_t> nonce) {
        if (nonce.size() != detail::LOCAL_NONCE_BYTES) return Result<std::string>::err(Error::argument);
        return seal_local(proof_key, request, access_token, jti, now, lifetime, nonce.data());
    }
#endif

    /// Checks the proof the rules carry under the proof key for
    /// access_token: authentication (proof_invalid), parsing
    /// (proof_malformed), times (proof_expired), the request and nonce
    /// (proof_mismatch) and the proof replay check (proof_replayed), in
    /// that order. Returns the proof's claims.
    [[nodiscard]] static Result<Claims>
    check_local(const LocalKey& proof_key, std::string_view access_token, const ValidationRules& rules) {
        return check_local_key(detail::KeyAccess::local(proof_key), proof_key.paserk_id(), access_token, rules);
    }

#ifdef CB2_HAS_PQ
    /// A proof under the client's key for access_token: a cb2.holder-public.
    /// token of claims_for, whose footer binds the client key's kcb2.pid and
    /// whose implicit assertion is the access token text.
    [[nodiscard]] static Result<std::string>
    make(const SecretKey& client, const HolderRequest& request, std::string_view access_token,
         std::string_view jti, Seconds now, Seconds lifetime = Holder::DEFAULT_LIFETIME) {
        auto c = claims_for(request, jti, now, lifetime);
        if (c.is_err()) return Result<std::string>::err(c.error());
        try {
            const std::string payload = c.value().to_json();
            const std::string footer = footer_for_id(client.public_key().paserk_id());
            return detail::PublicCore::sign(Holder::PUBLIC_HEADER, client, bytes(payload), bytes(footer),
                                            bytes(access_token));
        } catch (...) {
            return Result<std::string>::err(Error::internal);
        }
    }

    /// Checks the proof the rules carry under client for access_token,
    /// with the verdicts and in the order of check_local.
    [[nodiscard]] static Result<Claims>
    check(const PublicKey& client, std::string_view access_token, const ValidationRules& rules) {
        return checked(rules, [&](const std::string& proof) -> Result<std::vector<uint8_t>> {
            const std::string footer = footer_for_id(client.paserk_id());
            auto msg = detail::PublicCore::verify(Holder::PUBLIC_HEADER, proof, client, bytes(footer),
                                                  bytes(access_token), rules.max_token_bytes());
            if (msg.is_err()) return Result<std::vector<uint8_t>>::err(Error::proof_invalid);
            return msg;
        });
    }
#endif

private:
    friend class Token;

    /// check_local under the 32 key bytes at key whose kcb2.lid is id: the
    /// verifier's path, which reads the key out of cnf into wiped stack
    /// memory instead of building a LocalKey for every request.
    [[nodiscard]] static Result<Claims>
    check_local_key(const uint8_t* key, std::string_view id, std::string_view access_token,
                    const ValidationRules& rules) {
        return checked(rules, [&](const std::string& proof) -> Result<SecureBytes> {
            const std::string footer = footer_for_id(id);
            const std::size_t cap = detail::LocalCore::open_capacity(Holder::LOCAL_HEADER, proof.size());
            if (cap == 0) return Result<SecureBytes>::err(Error::proof_invalid);
            SecureBytes buf(cap);
            std::size_t n = 0;
            const Status s = detail::LocalCore::open(Holder::LOCAL_HEADER, buf, n, proof, key, bytes(footer),
                                                     bytes(access_token));
            if (s == Status::internal) return Result<SecureBytes>::err(Error::internal);
            if (s != Status::ok) return Result<SecureBytes>::err(Error::proof_invalid);
            buf.resize(n);
            return Result<SecureBytes>::ok(std::move(buf));
        });
    }

    [[nodiscard]] static std::string footer_for_id(std::string_view id) {
        std::string f = "{\"kid\":";
        json::Writer::string(f, id);
        f += '}';
        return f;
    }

    [[nodiscard]] static Result<std::string>
    seal_local(const LocalKey& proof_key, const HolderRequest& request, std::string_view access_token,
               std::string_view jti, Seconds now, Seconds lifetime, const uint8_t* nonce) {
        auto c = claims_for(request, jti, now, lifetime);
        if (c.is_err()) return Result<std::string>::err(c.error());
        try {
            const std::string payload = c.value().to_json();
            const std::string footer = footer_for_id(proof_key.paserk_id());
            const std::size_t need = detail::LocalCore::token_len(Holder::LOCAL_HEADER, payload.size(), footer.size());
            if (need == 0) return Result<std::string>::err(Error::argument);
            std::string out(need, '\0');
            std::size_t n = 0;
            const Status s = detail::LocalCore::seal(
                Holder::LOCAL_HEADER, {reinterpret_cast<uint8_t*>(out.data()), out.size()}, n,
                detail::KeyAccess::local(proof_key), bytes(payload), bytes(footer), bytes(access_token), nonce);
            if (s != Status::ok) return Result<std::string>::err(to_error(s));
            return Result<std::string>::ok(std::move(out));
        } catch (...) {
            return Result<std::string>::err(Error::internal);
        }
    }

    /// The order both modes share: rules, request target, size limit,
    /// authentication by open (proof_invalid or internal), parsing, then
    /// the claims.
    template <typename Open>
    [[nodiscard]] static Result<Claims> checked(const ValidationRules& rules, Open&& open) {
        if (!rules.complete()) return Result<Claims>::err(Error::rules_incomplete);
        if (!rules.holder_proof() || !rules.holder_request()) return Result<Claims>::err(Error::missing_proof);
        const auto target = Holder::normalize_target(rules.holder_request()->target);
        if (!target) return Result<Claims>::err(Error::argument);
        const std::string& proof = *rules.holder_proof();
        if (proof.size() > rules.max_token_bytes()) return Result<Claims>::err(Error::proof_invalid);
        try {
            auto msg = open(proof);
            if (msg.is_err()) return Result<Claims>::err(msg.error());
            auto c = Claims::from_json(std::string_view(reinterpret_cast<const char*>(msg.value().data()),
                                                        msg.value().size()));
            if (c.is_err()) return Result<Claims>::err(Error::proof_malformed);
            const auto v = validate(c.value(), *target, rules);
            if (v.is_err()) return Result<Claims>::err(v.error());
            return c;
        } catch (...) {
            return Result<Claims>::err(Error::internal);
        }
    }

    [[nodiscard]] static Result<void>
    validate(const Claims& c, std::string_view target, const ValidationRules& rules) {
        const auto htm = c.get("htm");
        const auto htu = c.get("htu");
        if (!c.jti || !c.iat || !c.exp || !htm || !htu) return Result<void>::err(Error::proof_malformed);
        const Seconds t = rules.now();
        const Seconds s = rules.clock_skew();
        const Seconds life = rules.proof_lifetime();
        if (*c.exp <= t - s || *c.iat > t + s || *c.exp - *c.iat > life || *c.exp > t + s + life)
            return Result<void>::err(Error::proof_expired);
        const HolderRequest& r = *rules.holder_request();
        if (!detail::ct_equal(*htm, r.method) || !detail::ct_equal(*htu, target))
            return Result<void>::err(Error::proof_mismatch);
        if (r.nonce) {
            const auto nonce = c.get("nonce");
            if (!nonce || !detail::ct_equal(*nonce, *r.nonce)) return Result<void>::err(Error::proof_mismatch);
        }
        bool fresh = false;
        try {
            fresh = rules.proof_replay_check()(*c.jti);
        } catch (...) {
            return Result<void>::err(Error::internal);
        }
        if (!fresh) return Result<void>::err(Error::proof_replayed);
        return Result<void>::ok();
    }
};

/// A key id read from a token footer before any verification. It may be
/// used to select a candidate key and for nothing else.
struct UnverifiedKeyId {
    std::string value;
};

class Token {
public:
    /// The footer a key id is bound into: {"kid":"..."}; empty for none.
    [[nodiscard]] static std::string footer_for(const std::optional<std::string>& kid) {
        return detail::kid_footer(kid);
    }

    /// Reads the kid from the footer of a token of either purpose without
    /// verifying anything. The token is bounded by max_token_bytes first.
    [[nodiscard]] static std::optional<UnverifiedKeyId>
    peek_key_id(std::string_view token, std::size_t max_token_bytes = ValidationRules::DEFAULT_MAX_TOKEN_BYTES) {
        if (token.size() > max_token_bytes) return std::nullopt;
        detail::Split s{};
        if (!detail::split_token(token, Local::HEADER, true, s) &&
            !detail::split_token(token, "cb2.public.", true, s) &&
            !detail::split_token(token, Holder::PUBLIC_HEADER, true, s) &&
            !detail::split_token(token, Holder::LOCAL_HEADER, true, s))
            return std::nullopt;
        const std::size_t need = detail::b64::decoded_len(s.footer_len);
        if (need == static_cast<std::size_t>(-1)) return std::nullopt;
        std::string footer(need, '\0');
        std::size_t n = 0;
        if (!detail::b64::decode(reinterpret_cast<uint8_t*>(footer.data()), need, s.footer,
                                 s.footer_len, n))
            return std::nullopt;
        json::Value v;
        if (!json::Reader::parse(footer, v) || !v.is_object()) return std::nullopt;
        const json::Value* kid = v.get("kid");
        if (kid == nullptr || !kid->is_string() || !text::identifier_ok(kid->text)) return std::nullopt;
        return UnverifiedKeyId{kid->text};
    }

    /// Whether a key id, if any, satisfies the identifier policy.
    [[nodiscard]] static bool key_id_ok(const std::optional<std::string>& kid) noexcept {
        return !kid || text::identifier_ok(*kid);
    }

    /// Seals claims as a cb2.local token; the key id, if any, goes into
    /// the footer.
    [[nodiscard]] static Result<std::string>
    seal(const LocalKey& key, const Claims& claims, std::string_view implicit = {}) {
        if (!claims.text_ok() || !key_id_ok(key.key_id())) return Result<std::string>::err(Error::argument);
        try {
            const std::string payload = claims.to_json();
            const std::string& footer = key.footer();
            return Local::seal(key, bytes(payload), bytes(footer), bytes(implicit));
        } catch (...) {
            return Result<std::string>::err(Error::internal);
        }
    }

    /// Opens a cb2.local token: rules and key checks, size limit,
    /// authentication, parsing, validation, in that order.
    [[nodiscard]] static Result<Claims>
    open(std::string_view token, const LocalKey& key, const ValidationRules& rules,
         std::string_view implicit = {}) {
        if (!rules.complete()) return Result<Claims>::err(Error::rules_incomplete);
        if (!key_id_ok(key.key_id()) || !rules.expectations_ok()) return Result<Claims>::err(Error::argument);
        if (token.size() > rules.max_token_bytes()) return Result<Claims>::err(Error::too_large);
        try {
            const std::string& footer = key.footer();
            auto plain = Local::open(token, key, bytes(footer), bytes(implicit), rules.max_token_bytes());
            if (plain.is_err()) return Result<Claims>::err(plain.error());
            return finish(std::string_view(reinterpret_cast<const char*>(plain.value().data()),
                                           plain.value().size()), rules, token, false);
        } catch (...) {
            return Result<Claims>::err(Error::internal);
        }
    }

#ifdef CB2_HAS_PQ
    /// Signs claims as a cb2.public token; the key id, if any, goes into
    /// the footer. A kcb2.local cnf is argument: a proof key in a payload
    /// anyone can read would bind nothing.
    [[nodiscard]] static Result<std::string>
    sign(const SecretKey& key, const Claims& claims, std::string_view implicit = {}) {
        if (!claims.text_ok() || !key_id_ok(key.key_id())) return Result<std::string>::err(Error::argument);
        if (claims.cnf && claims.cnf->starts_with(Holder::CNF_LOCAL_PREFIX))
            return Result<std::string>::err(Error::argument);
        try {
            const std::string payload = claims.to_json();
            const std::string& footer = key.footer();
            return Public::sign(key, bytes(payload), bytes(footer), bytes(implicit));
        } catch (...) {
            return Result<std::string>::err(Error::internal);
        }
    }

    /// Verifies a cb2.public token: rules and key checks, size limit,
    /// signature, parsing, validation, in that order.
    [[nodiscard]] static Result<Claims>
    verify(std::string_view token, const PublicKey& key, const ValidationRules& rules,
           std::string_view implicit = {}) {
        if (!rules.complete()) return Result<Claims>::err(Error::rules_incomplete);
        if (!key_id_ok(key.key_id()) || !rules.expectations_ok()) return Result<Claims>::err(Error::argument);
        if (token.size() > rules.max_token_bytes()) return Result<Claims>::err(Error::too_large);
        try {
            const std::string& footer = key.footer();
            auto msg = Public::verify(token, key, bytes(footer), bytes(implicit), rules.max_token_bytes());
            if (msg.is_err()) return Result<Claims>::err(msg.error());
            return finish(std::string_view(reinterpret_cast<const char*>(msg.value().data()),
                                           msg.value().size()), rules, token, true);
        } catch (...) {
            return Result<Claims>::err(Error::internal);
        }
    }
#endif

private:
    [[nodiscard]] static Result<Claims> finish(std::string_view payload, const ValidationRules& rules,
                                               std::string_view token, bool public_purpose) {
        auto claims = Claims::from_json(payload);
        if (claims.is_err()) return claims;
        return finish_parsed(std::move(claims.value()), rules, token, public_purpose);
    }

    /// Steps four and five of validation on claims already parsed from an
    /// authenticated payload; shared with the cb3 headers (compact.hpp).
    [[nodiscard]] static Result<Claims> finish_parsed(Claims claims, const ValidationRules& rules,
                                                      std::string_view token, bool public_purpose) {
        const auto verdict = rules.check(claims);
        if (verdict.is_err()) return Result<Claims>::err(verdict.error());
        const auto holder = holder_step(claims, rules, token, public_purpose);
        if (holder.is_err()) return Result<Claims>::err(holder.error());
        return Result<Claims>::ok(std::move(claims));
    }

    friend class CompactToken;

    /// Step five of validation: the sender constraint. Nothing when the
    /// rules ignore it; a bearer token when cnf is absent and not required;
    /// otherwise the proof is checked under the key cnf carries: a
    /// kcb2.local proof key in a cb2.local token, a kcb2.public client key
    /// in either purpose.
    [[nodiscard]] static Result<void> holder_step(const Claims& c, const ValidationRules& rules,
                                                  std::string_view token, bool public_purpose) {
        if (rules.ignores_sender_constraint()) return Result<void>::ok();
        if (!c.cnf) {
            if (rules.requires_sender_constraint()) return Result<void>::err(Error::missing_cnf);
            return Result<void>::ok();
        }
        if (!rules.holder_proof()) return Result<void>::err(Error::missing_proof);
        if (c.cnf->starts_with(Holder::CNF_LOCAL_PREFIX)) {
            if (public_purpose) return Result<void>::err(Error::claims_malformed);
            detail::SecureArray<LocalKey::BYTES> proof_key;
            if (!detail::paserk_decode(LocalKey::PASERK_HEADER, *c.cnf, proof_key.v, LocalKey::BYTES) ||
                detail::constant_bytes(proof_key.v, LocalKey::BYTES))
                return Result<void>::err(Error::claims_malformed);
            const std::string id = detail::paserk_id(LocalKey::ID_HEADER, *c.cnf);
            auto proof = HolderProof::check_local_key(proof_key.v, id, token, rules);
            if (proof.is_err()) return Result<void>::err(proof.error());
            return Result<void>::ok();
        }
        if (!c.cnf->starts_with(Holder::CNF_PUBLIC_PREFIX)) return Result<void>::err(Error::claims_malformed);
#ifdef CB2_HAS_PQ
        auto client = PublicKey::from_paserk(*c.cnf);
        if (client.is_err()) return Result<void>::err(Error::claims_malformed);
        auto proof = HolderProof::check(client.value(), token, rules);
        if (proof.is_err()) return Result<void>::err(proof.error());
        return Result<void>::ok();
#else
        (void)token;
        return Result<void>::err(Error::unavailable);
#endif
    }
};

}
