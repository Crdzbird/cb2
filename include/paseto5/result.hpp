#pragma once

/**
 * paseto5::Result and paseto5::Error.
 *
 * Every operation returns a Result. A failure that depends on the bytes of
 * a token that has not been authenticated yet is always reported as
 * Error::invalid, with no further detail, so the verdict cannot be used as
 * an oracle. The claim errors are reported only after the token has been
 * authenticated, when the content is known to come from the key holder.
 */

#include <cstdint>
#include <cstdlib>
#include <optional>
#include <utility>

namespace paseto5 {

/// The failures paseto5 reports. invalid: any failure that depends on an
/// unverified token (header, encoding, footer, key id, tag or signature).
/// too_large: the token exceeds the size limit, decided before parsing.
/// argument: a caller error that does not depend on token content.
/// rules_incomplete: the verifier's rules name no expected audience or
/// issuer and do not say that any is acceptable; decided before the
/// token is read. internal: a backend call failed. unavailable: the
/// operation needs a backend this build does not have. The remaining
/// values are claim failures of an authenticated token; replayed and
/// missing_jti come from the verifier's replay check.
enum class Error : uint8_t {
    invalid,
    too_large,
    argument,
    rules_incomplete,
    internal,
    unavailable,
    claims_malformed,
    missing_exp,
    expired,
    not_yet_valid,
    issued_in_future,
    issuer_mismatch,
    audience_mismatch,
    subject_mismatch,
    missing_jti,
    replayed,
};

/// Stable name of an error, for logs.
[[nodiscard]] inline const char* error_name(Error e) noexcept {
    switch (e) {
        case Error::invalid: return "invalid";
        case Error::too_large: return "too_large";
        case Error::argument: return "argument";
        case Error::rules_incomplete: return "rules_incomplete";
        case Error::internal: return "internal";
        case Error::unavailable: return "unavailable";
        case Error::claims_malformed: return "claims_malformed";
        case Error::missing_exp: return "missing_exp";
        case Error::expired: return "expired";
        case Error::not_yet_valid: return "not_yet_valid";
        case Error::issued_in_future: return "issued_in_future";
        case Error::issuer_mismatch: return "issuer_mismatch";
        case Error::audience_mismatch: return "audience_mismatch";
        case Error::subject_mismatch: return "subject_mismatch";
        case Error::missing_jti: return "missing_jti";
        case Error::replayed: return "replayed";
    }
    return "unknown";
}

/// A value or an Error. Reading the value of a failed Result aborts the
/// process instead of being undefined behaviour.
template <class T>
class [[nodiscard]] Result {
public:
    [[nodiscard]] static Result ok(T v) { return Result(std::move(v)); }
    [[nodiscard]] static Result err(Error e) noexcept { return Result(e); }

    [[nodiscard]] bool is_ok() const noexcept { return value_.has_value(); }
    [[nodiscard]] bool is_err() const noexcept { return !value_.has_value(); }
    [[nodiscard]] explicit operator bool() const noexcept { return is_ok(); }
    [[nodiscard]] Error error() const noexcept { return err_; }

    [[nodiscard]] T& value() & { check(); return *value_; }
    [[nodiscard]] const T& value() const& { check(); return *value_; }
    [[nodiscard]] T&& value() && { check(); return std::move(*value_); }

private:
    explicit Result(T v) : value_(std::move(v)), err_(Error::internal) {}
    explicit Result(Error e) noexcept : err_(e) {}
    void check() const noexcept { if (!value_.has_value()) std::abort(); }
    std::optional<T> value_;
    Error err_;
};

template <>
class [[nodiscard]] Result<void> {
public:
    [[nodiscard]] static Result ok() noexcept { return Result(true, Error::internal); }
    [[nodiscard]] static Result err(Error e) noexcept { return Result(false, e); }
    [[nodiscard]] bool is_ok() const noexcept { return ok_; }
    [[nodiscard]] bool is_err() const noexcept { return !ok_; }
    [[nodiscard]] explicit operator bool() const noexcept { return ok_; }
    [[nodiscard]] Error error() const noexcept { return err_; }

private:
    Result(bool ok, Error e) noexcept : ok_(ok), err_(e) {}
    bool ok_;
    Error err_;
};

}
